"""Minimal CrowdSec client: the LAPI as a bouncer sees it, plus the engine's
own Prometheus endpoint.

Stdlib only, for the same reason as the sibling servers' clients: this process
talks to two loopback endpoints on one host, so its whole transport is an HTTP
GET -- no third-party client.

Two surfaces, two credentials, and the difference is the point of this server:

  GET /v1/decisions   bouncer key (`cscli bouncers add`). Read-only by
                      construction: a bouncer can pull decisions and nothing
                      else.
  GET /v1/alerts      machine credentials. A machine may also *create and
                      delete* decisions and push alerts, so wiring one in would
                      hand this server ban/unban authority. That is why there is
                      no alert tool here, and why the key this module takes is
                      never a machine password.

Shapes pinned (CrowdSec v1.8):

  /v1/decisions?ip=&scope=&type=&scenario=&origin=&limit=
      a JSON array, or the literal `null` when nothing matches
  /metrics (the engine's Prometheus endpoint, a different port, no auth)
      the text exposition format
"""

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

DEFAULT_TIMEOUT = 5.0

# Both answers are read into memory whole, so both need a ceiling: a wedged
# peer must not be able to make this process allocate without bound. The real
# decisions list is a handful of KiB; a full metrics exposition is a few dozen.
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class LapiError(Exception):
    """A failed CrowdSec request.

    `message` is what a model should read -- the LAPI's own text when it sent
    one, or this module's description of a transport failure. `status` is the
    HTTP status when there was a response.
    """

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


def _error_detail(raw: bytes) -> str:
    """The LAPI's own message out of its `{"code":..,"message":..}` body."""
    text = raw.decode("utf-8", "replace").strip()
    try:
        body = json.loads(text)
    except ValueError:
        return text[:200] or "no detail"
    if isinstance(body, dict):
        message = body.get("message")
        if isinstance(message, str) and message:
            return message[:200]
    return "no detail"


def _get(url: str, headers: dict[str, str], timeout: float, what: str) -> bytes:
    """GET one URL, mapping every failure onto LapiError."""
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body: bytes = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as err:
        detail = _error_detail(err.read(MAX_RESPONSE_BYTES))
        if err.code in (401, 403):
            raise LapiError(
                f"CrowdSec refused the API key ({err.code}): {detail}. This "
                "server needs a bouncer key; a machine password is a different "
                "credential, and the key minted by `cscli bouncers add` is the "
                "read-only one.",
                err.code,
            ) from err
        raise LapiError(f"CrowdSec answered {err.code} for {what}: {detail}", err.code) from err
    except (urllib.error.URLError, TimeoutError, OSError) as err:
        raise LapiError(f"CrowdSec is unreachable at {url}: {err}") from err
    if len(body) > MAX_RESPONSE_BYTES:
        raise LapiError(
            f"CrowdSec answered {what} with more than {MAX_RESPONSE_BYTES} bytes; "
            "that is not a response this server should read whole"
        )
    return body


class LapiClient:
    """The Local API, addressed by base URL and keyed by a bouncer key."""

    def __init__(self, url: str, key: str, timeout: float = DEFAULT_TIMEOUT) -> None:
        self.url = url.rstrip("/")
        self.key = key
        self.timeout = timeout

    def decisions(self, **filters: Any) -> list[dict[str, Any]]:
        """Active decisions, optionally filtered.

        The LAPI applies `ip`, `scope`, `type`, `scenario`, `origin`, `limit`
        (and `contains`/`sort_by`, unused here). Expired decisions are not in
        this endpoint at all -- the bouncer's view is "what is enforced now",
        which is exactly what an agent asking "is this address blocked"
        wants, and why the tool descriptions say so.
        """
        params = {name: str(value) for name, value in filters.items() if value not in (None, "")}
        query = urllib.parse.urlencode(params)
        url = f"{self.url}/v1/decisions" + (f"?{query}" if query else "")
        raw = _get(
            url,
            {"Accept": "application/json", "X-Api-Key": self.key},
            self.timeout,
            "/v1/decisions",
        )
        if not raw.strip():
            return []
        try:
            body = json.loads(raw.decode("utf-8", "replace"))
        except ValueError as err:
            raise LapiError(
                "CrowdSec answered /v1/decisions with something that is not JSON"
            ) from err
        # No match is the literal `null`, not `[]`. stack-bouncer documents the
        # same trap: reading it as a protocol error is how a quiet host looks
        # broken.
        if body is None:
            return []
        if not isinstance(body, list):
            raise LapiError(
                f"CrowdSec answered /v1/decisions with {type(body).__name__}, not a list"
            )
        return [row for row in body if isinstance(row, dict)]


def fetch_metrics(url: str, timeout: float = DEFAULT_TIMEOUT) -> str:
    """The engine's Prometheus exposition text, unauthenticated on loopback."""
    body = _get(url.rstrip("/") + "/metrics", {"Accept": "text/plain"}, timeout, "/metrics")
    return body.decode("utf-8", "replace")


def _unescape(value: str) -> str:
    """Undo the exposition format's label escaping (`\\\\`, `\\"`, `\\n`)."""
    out: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value):
            escaped = value[index + 1]
            out.append({"n": "\n"}.get(escaped, escaped))
            index += 2
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _labels(raw: str) -> dict[str, str] | None:
    """`a="1",b="x,y"` -> {"a": "1", "b": "x,y"}.

    Commas inside quotes are label *values*, so this scans rather than splits:
    a naive split turns `reason="a,b"` into two labels and silently mislabels
    every series.
    """
    labels: dict[str, str] = {}
    index = 0
    length = len(raw)
    while index < length:
        equals = raw.find("=", index)
        if equals == -1:
            return None
        name = raw[index:equals].strip()
        if not name or equals + 1 >= length or raw[equals + 1] != '"':
            return None
        cursor = equals + 2
        chars: list[str] = []
        while cursor < length:
            char = raw[cursor]
            if char == "\\" and cursor + 1 < length:
                chars.append(raw[cursor : cursor + 2])
                cursor += 2
                continue
            if char == '"':
                break
            chars.append(char)
            cursor += 1
        if cursor >= length:
            return None
        labels[name] = _unescape("".join(chars))
        cursor += 1
        if cursor < length and raw[cursor] == ",":
            cursor += 1
        index = cursor
    return labels


def parse_exposition(text: str) -> dict[str, list[tuple[dict[str, str], float]]]:
    """Parse the exposition text into `{name: [(labels, value), ...]}`.

    Only what this server reads: sample lines, no metadata. A line it cannot
    parse is skipped rather than raised on -- Prometheus text is an interface
    with optional extras (timestamps, exemplars), and a new one upstream must
    not turn the health tool into an error.
    """
    series: dict[str, list[tuple[dict[str, str], float]]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        brace = line.find("{")
        if brace == -1:
            name, _, rest = line.partition(" ")
            labels: dict[str, str] = {}
        else:
            name = line[:brace]
            end = line.find("}", brace)
            if end == -1:
                continue
            parsed = _labels(line[brace + 1 : end])
            if parsed is None:
                continue
            labels = parsed
            rest = line[end + 1 :].strip()
        value_text = rest.split(" ")[0] if rest else ""
        try:
            value = float(value_text)
        except ValueError:
            continue
        series.setdefault(name.strip(), []).append((labels, value))
    return series
