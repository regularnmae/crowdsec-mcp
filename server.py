import asyncio
import hmac
import ipaddress
import json
import logging
import os
import time
from collections.abc import Callable
from typing import Annotated, Any, Literal, get_args

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from pydantic import Field

import crowdsec
from crowdsec import LapiError

logger = logging.getLogger("crowdsec-mcp")

# The SDK types log_level as a closed set, so an unrecognised LOG_LEVEL has to
# be resolved to one of its levels here -- the raw env string is not
# assignable, and an unknown level falling back to INFO beats the import-time
# raise that the SDK would otherwise produce.
_LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
_LEVELS: tuple[_LogLevel, ...] = get_args(_LogLevel)


def _log_level() -> _LogLevel:
    requested = os.environ.get("LOG_LEVEL", "INFO").upper()
    return requested if requested in _LEVELS else "INFO"


def _env_float(name: str, default: float) -> float:
    """A float env var, or the default when unset or unparseable.

    A typo'd timeout should not stop the server from starting, so a bad value
    warns and falls back rather than raising at import.
    """
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        logger.warning("ignoring non-numeric %s=%r; using %s", name, raw, default)
        return default


mcp = MCPServer(
    "CrowdSec",
    instructions=(
        "Read-only view of this host's CrowdSec engine: the active decisions it "
        "has taken from nginx-proxy-manager's access log, and the engine's own "
        "health counters. list_decisions answers what is being blocked and why; "
        "check_ip answers whether one address is blocked right now; "
        "get_engine_health reports the engine's version, per-scenario decisions "
        "and detections, and how old the local agent's heartbeat is. Decisions "
        "are TTL'd, so only active ones are visible -- an expired ban is not "
        "here, and individual past alerts need a machine credential this server "
        "deliberately does not hold. Nothing here writes, deletes or changes "
        "anything: enforcement belongs to the host's own bouncer, which also "
        "refuses private space and the host's own addresses."
    ),
    log_level=_log_level(),
)

# Every tool here only reads, and the bouncer key it holds can do nothing else.
# Saying so lets a well-behaved client skip a confirmation prompt.
_CROWDSEC_TOOLS = ToolAnnotations(read_only_hint=True, open_world_hint=False)

# Both endpoints are loopback binds on the host this container shares
# (Network=host in the stack's unit): the LAPI because stack-bouncer polls it
# from root, the metrics port because nothing else needs it. Neither is
# reachable from npm-network, which is why this server is the exception.
CROWDSEC_LAPI_URL = os.environ.get("CROWDSEC_LAPI_URL", "http://127.0.0.1:8080")
CROWDSEC_METRICS_URL = os.environ.get("CROWDSEC_METRICS_URL", "http://127.0.0.1:6060")
CROWDSEC_LAPI_KEY = os.environ.get("CROWDSEC_LAPI_KEY", "")
CROWDSEC_LAPI_TIMEOUT = _env_float("CROWDSEC_LAPI_TIMEOUT", 5.0)
# A metrics scrape is one fixed-size document, not a decision lookup; it gets
# its own, slightly longer bound because the engine writes it under load.
CROWDSEC_METRICS_TIMEOUT = _env_float("CROWDSEC_METRICS_TIMEOUT", 10.0)

# Set to "1" to serve the endpoint with no token at all. Without it a missing
# token is a startup error, not a warning.
MCP_ALLOW_ANONYMOUS = os.environ.get("MCP_ALLOW_ANONYMOUS", "") == "1"

# Unauthenticated liveness path, for pollers that hold no token.
HEALTH_PATH = "/health"

# Readiness path: /health says the process is up, this says the LAPI answers.
# Deliberately separate -- an engine outage must not fail a liveness probe, or
# the container restarts in a loop while CrowdSec recovers.
READY_PATH = "/ready"
READY_TIMEOUT = 3.0
# /ready is unauthenticated, and every probe is a request to the LAPI, so the
# answer is cached for a few seconds: a poller hammering the path then costs
# one round trip per TTL instead of one per request.
READY_CACHE_TTL = 5.0
_ready_cache: tuple[float, dict[str, Any], int] | None = None
# Created lazily, inside the running loop: an asyncio.Lock binds to the loop
# that first awaits it, and this server has exactly one in production.
_ready_lock: asyncio.Lock | None = None

# The env var the bearer token is read from (also the name in the quadlet
# unit's EnvironmentFile and in the client configs).
TOKEN_ENV = "CROWDSEC_MCP_TOKEN"

client = crowdsec.LapiClient(CROWDSEC_LAPI_URL, CROWDSEC_LAPI_KEY, CROWDSEC_LAPI_TIMEOUT)

if not CROWDSEC_LAPI_KEY:
    logger.warning("CROWDSEC_LAPI_KEY is not set; every tool will report it")

# --- output caps -------------------------------------------------------
# A decision list is small, but the engine's metrics are not, and both answers
# are read into a model's context window. These bounds are the same shape as
# the sibling servers': a default a model can read in one go, and a hard
# ceiling for a caller that asks for everything.
DEFAULT_LIMIT = 50
MAX_LIMIT = 200
# Per-request groups kept from the metrics report (scenarios, bouncers, ...).
MAX_GROUPS = 20
# The decision fields worth returning. The LAPI also sends nothing else today,
# but a raw row must never fill a context window by accident.
_DECISION_FIELDS = ("value", "scope", "type", "scenario", "origin", "duration")


def _clamp(limit: int) -> int:
    """Clamp a limit into the range the tools advertise."""
    return max(1, min(int(limit), MAX_LIMIT))


def _render(payload: Any) -> str:
    """A tool result as text."""
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _decision(row: dict[str, Any]) -> dict[str, Any]:
    """One decision reduced to the fields a client can use."""
    out: dict[str, Any] = {}
    for key in _DECISION_FIELDS:
        value = row.get(key)
        if isinstance(value, str) and value:
            out[key] = value
    identifier = row.get("id")
    if isinstance(identifier, int):
        out["id"] = identifier
    if row.get("simulated") is True:
        out["simulated"] = True
    return out


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """One address, or a ValueError a model can act on."""
    text = value.strip()
    try:
        return ipaddress.ip_address(text)
    except ValueError as err:
        raise ValueError(
            f"ip must be a single IPv4 or IPv6 address like 203.0.113.9, not {value!r}"
        ) from err


def _number(value: float) -> int | float:
    """A Prometheus sample as an int when it is one, else a trimmed float."""
    return int(value) if float(value).is_integer() else round(value, 3)


def _sum(series: dict[str, list[tuple[dict[str, str], float]]], name: str) -> float:
    return sum(value for _, value in series.get(name, []))


def _first_label(
    series: dict[str, list[tuple[dict[str, str], float]]], name: str, label: str
) -> str | None:
    for labels, _ in series.get(name, []):
        value = labels.get(label)
        if value:
            return value
    return None


def _groups(
    series: dict[str, list[tuple[dict[str, str], float]]], name: str, fields: tuple[str, ...]
) -> list[dict[str, Any]]:
    """Samples of one series folded by `fields`, largest first, capped."""
    totals: dict[tuple[str, ...], float] = {}
    for labels, value in series.get(name, []):
        key = tuple(labels.get(field, "") for field in fields)
        totals[key] = totals.get(key, 0.0) + value
    rows: list[dict[str, Any]] = []
    for key, total in totals.items():
        row: dict[str, Any] = {field: part for field, part in zip(fields, key, strict=True)}
        row["count"] = _number(total)
        rows.append(row)
    rows.sort(key=lambda row: -float(row["count"]))
    return rows[:MAX_GROUPS]


def _machines(
    series: dict[str, list[tuple[dict[str, str], float]]],
) -> list[dict[str, Any]]:
    """Local agents and how old their last heartbeat is.

    The exposition carries the heartbeat as an epoch timestamp, so age is
    computable from one scrape -- the one freshness signal this endpoint
    offers. There is no equivalent for a bouncer (its key pulls decisions
    without a heartbeat), which is why enforcement freshness is the host's
    own `audit/bouncer.status` and not a tool here.
    """
    now = time.time()
    rows: list[dict[str, Any]] = []
    for labels, value in series.get("cs_machines_last_heartbeat_timestamp", []):
        if value <= 0:
            continue
        rows.append(
            {
                "machine": labels.get("machine", ""),
                "heartbeat_age_seconds": int(max(0.0, now - value)),
            }
        )
    rows.sort(key=lambda row: -int(row["heartbeat_age_seconds"]))
    return rows[:MAX_GROUPS]


def _guard(label: str, action: Callable[[], Any]) -> str:
    """Run a tool body, turning its known failures into a tool error.

    `label` names the intent that failed, so a log line says what broke
    without every tool repeating the same `except` clauses. Failures raise
    `ToolError`, which the SDK returns as `is_error=True` with the same text
    the model would otherwise have read -- so a client can tell "the engine
    did not answer" from "nothing is blocked".
    """
    try:
        return _render(action())
    except ValueError as err:
        raise ToolError(str(err)) from err
    except LapiError as err:
        logger.warning("%s failed: %s", label, err.message)
        raise ToolError(err.message) from err
    except ToolError:
        raise
    except Exception as err:  # noqa: BLE001 - surfaced as text, never hidden
        logger.exception("unexpected error in %s", label)
        raise ToolError(f"Unexpected error calling {label}: {err}") from err


def _list_decisions(
    ip: str | None,
    scenario: str | None,
    decision_type: str | None,
    scope: str | None,
    origin: str | None,
    limit: int,
) -> dict[str, Any]:
    filters = {
        "ip": str(_parse_ip(ip)) if ip else None,
        "scenario": scenario,
        "type": decision_type,
        "scope": scope,
        "origin": origin,
        "limit": _clamp(limit),
    }
    rows = client.decisions(**filters)
    payload: dict[str, Any] = {
        "count": len(rows),
        "decisions": [_decision(row) for row in rows],
    }
    applied = {name: value for name, value in filters.items() if value not in (None, "")}
    payload["filters"] = applied
    # The LAPI has no "more results" flag, so the honest hint is the cap being
    # reached: the caller can narrow the filters instead of assuming this is
    # the whole list.
    if len(rows) >= int(applied["limit"]):
        payload["truncated"] = True
    return payload


def _check_ip(ip: str) -> dict[str, Any]:
    address = _parse_ip(ip)
    rows = client.decisions(ip=str(address), limit=MAX_LIMIT)
    payload: dict[str, Any] = {
        "ip": str(address),
        "banned": bool(rows),
        "enforceable": address.is_global,
        "decisions": [_decision(row) for row in rows],
    }
    if not address.is_global:
        payload["note"] = (
            "This address is private, loopback, link-local, reserved or "
            "otherwise non-global. stack-bouncer refuses private space and "
            "every address the host holds, so a decision here would not be "
            "enforced."
        )
    if len(rows) >= MAX_LIMIT:
        payload["truncated"] = True
    return payload


def _engine_health() -> dict[str, Any]:
    """The engine's own view of itself, from its Prometheus exposition.

    Two questions in one answer, because they fail differently: the counters
    say whether detection is doing anything (buckets, overflows, parser
    errors, decisions taken), and the agent heartbeat says whether the log
    processor is still pushing. Counters are cumulative since the engine
    started -- this is a snapshot, not a rate, and history lives in the
    metrics store if the host publishes it. `bouncer_requests` names which
    clients are pulling decisions (this server included) and is how the
    engine's own attribution looks.
    """
    series = crowdsec.parse_exposition(
        crowdsec.fetch_metrics(CROWDSEC_METRICS_URL, CROWDSEC_METRICS_TIMEOUT)
    )
    active = _groups(series, "cs_active_decisions", ("reason", "action", "origin"))
    report: dict[str, Any] = {
        "active_decisions": {
            "total": _number(_sum(series, "cs_active_decisions")),
            "by_scenario": active,
        },
        "alerts": {
            "total": _number(_sum(series, "cs_alerts")),
            "by_scenario": _groups(series, "cs_alerts", ("kind", "reason")),
        },
        "detection": {
            "buckets_in_flight": _groups(series, "cs_buckets", ("name",)),
            "overflowed_total": _groups(series, "cs_bucket_overflowed_total", ("name",)),
            "parser_hits": {
                "ok": _number(_sum(series, "cs_parser_hits_ok_total")),
                "ko": _number(_sum(series, "cs_parser_hits_ko_total")),
            },
        },
        "machines": _machines(series),
        "bouncer_requests": _groups(
            series, "cs_lapi_bouncer_requests_total", ("bouncer", "route")
        ),
    }
    version = _first_label(series, "cs_info", "version")
    if version:
        report["version"] = version
    return report


@mcp.tool(structured_output=False, annotations=_CROWDSEC_TOOLS)
def list_decisions(
    ip: Annotated[str | None, Field(max_length=64)] = None,
    scenario: Annotated[str | None, Field(max_length=200)] = None,
    type: Annotated[str | None, Field(max_length=20)] = None,
    scope: Annotated[str | None, Field(max_length=20)] = None,
    origin: Annotated[str | None, Field(max_length=40)] = None,
    limit: Annotated[int, Field(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
) -> str:
    """List the decisions CrowdSec is enforcing right now, newest first.

    A decision is one block: `value` is the address (or range) it applies to,
    `scenario` is the detection that produced it (`stack/http-probing`,
    `stack/http-authfail`, ...), and `duration` is what is left of its TTL.
    Only *active* decisions are visible -- an expired ban is gone from here,
    and a policy that never fired is invisible. Over-threshold detections
    appear as `buckets_in_flight` in get_engine_health before they become
    decisions.

    Args:
        ip: Only decisions for one address, e.g. `203.0.113.9`.
        scenario: Only this scenario, e.g. `stack/http-probing`.
        type: Only this decision type: `ban` (the stack only ever bans).
        scope: Only this scope: `Ip`.
        origin: Only this origin: `crowdsec` (this host's own logs).
        limit: Maximum decisions to return (1-200, default 50).
    """
    return _guard(
        "list_decisions", lambda: _list_decisions(ip, scenario, type, scope, origin, limit)
    )


@mcp.tool(structured_output=False, annotations=_CROWDSEC_TOOLS)
def check_ip(ip: Annotated[str, Field(min_length=1, max_length=64)]) -> str:
    """Answer whether one address is blocked right now, and why.

    The single-address view: `banned` is the yes/no, `decisions` is the same
    objects list_decisions returns for that address, and `enforceable` says
    whether the host's bouncer would apply a decision for it at all. Use this
    for "is this client blocked" and list_decisions for "what is blocked".

    An expired decision is not visible here; that history needs the engine's
    alert store, which this server deliberately cannot read.

    Args:
        ip: One IPv4 or IPv6 address, e.g. `203.0.113.9`.
    """
    return _guard("check_ip", lambda: _check_ip(ip))


@mcp.tool(structured_output=False, annotations=_CROWDSEC_TOOLS)
def get_engine_health() -> str:
    """Report what the engine is doing and whether it is still fed.

    `active_decisions` and `alerts` are folded per scenario so one call shows
    which detections are firing. `detection.parser_hits.ko` above zero means
    access-log lines this host's parser could not read -- the way a silent
    log-format change shows up. `machines` carries the local agent's
    heartbeat age; if it grows, detection has stopped even though the API is
    up. `bouncer_requests` names the clients pulling decisions, cumulative
    since the engine started (this server's own pulls included).

    Counters are not rates: ask twice to see movement. Enforcement freshness
    is not here -- it lives in the host's `audit/bouncer.status`.
    """
    return _guard("get_engine_health", _engine_health)


async def _readiness() -> tuple[dict[str, Any], int]:
    """`/ready`'s answer, cached for READY_CACHE_TTL seconds.

    The path is unauthenticated, so without the cache any client could turn
    one HTTP request into one LAPI request. The cache is a plain module
    global: a five-second-old liveness answer is still the right answer. The
    lock means a burst of concurrent requests produces one probe rather than
    one each.
    """
    global _ready_cache, _ready_lock
    if _ready_lock is None:
        _ready_lock = asyncio.Lock()
    async with _ready_lock:
        cached = _ready_cache
        if cached is not None and time.monotonic() - cached[0] < READY_CACHE_TTL:
            return cached[1], cached[2]
        body, status_code = await _probe_readiness()
        _ready_cache = (time.monotonic(), body, status_code)
        return body, status_code


def _lapi_probe() -> None:
    """One cheap read, bounded by READY_TIMEOUT rather than the tool timeout.

    A separate client on purpose: the readiness answer must not wait five
    seconds on a wedged LAPI, and it must not inherit whatever timeout the
    tools were configured with.
    """
    crowdsec.LapiClient(CROWDSEC_LAPI_URL, CROWDSEC_LAPI_KEY, READY_TIMEOUT).decisions(limit=1)


async def _probe_readiness() -> tuple[dict[str, Any], int]:
    """Ask the LAPI for one decision, off the event loop with a short timeout."""
    if not CROWDSEC_LAPI_KEY:
        return {"status": "unready", "error": "CROWDSEC_LAPI_KEY is not set"}, 503
    try:
        await asyncio.to_thread(_lapi_probe)
    except LapiError as err:
        logger.warning("/ready: CrowdSec is not answering: %s", err.message)
        return {"status": "unready", "error": err.message}, 503
    except Exception as err:  # noqa: BLE001 - reported, never raised at a probe
        logger.exception("/ready: unexpected error")
        return {"status": "unready", "error": str(err)}, 503
    return {"status": "ready", "lapi": "ok"}, 200


async def _json_response(
    scope: Any,
    receive: Any,
    send: Any,
    body: dict[str, Any],
    status_code: int,
    headers: dict[str, str] | None = None,
) -> None:
    """Send one JSON response, with no body for a HEAD request."""
    from starlette.responses import JSONResponse

    response = JSONResponse(body, status_code=status_code, headers=headers)
    if scope.get("method") == "HEAD":
        # JSONResponse has already set Content-Length for the body it would
        # have sent; HEAD promises the headers and no body.
        response.body = b""
    await response(scope, receive, send)


class BearerAuthMiddleware:
    """Pure-ASGI bearer auth in front of the streamable-HTTP app.

    The endpoint is published on the LAN through nginx-proxy-manager, so a
    missing token is a hard error rather than a warning: serving every tool
    unauthenticated for as long as the env var is absent is not a failure mode
    worth keeping. Set MCP_ALLOW_ANONYMOUS=1 to run it open on purpose, which
    is what debugging from inside the host wants.

    GET /health stays unauthenticated so a poller can say "up" without holding
    the token; it says nothing else. GET /ready does the same and adds whether
    the LAPI answers, on a short timeout, for the same reason. Both answer
    only GET and HEAD -- a write method on a status path is a client bug, not
    something to answer 200 to.
    """

    def __init__(self, app: Any, token: str | None) -> None:
        self.app = app
        self.token = token or ""
        if not self.token:
            if not MCP_ALLOW_ANONYMOUS:
                raise RuntimeError(
                    f"{TOKEN_ENV} is not set, and this endpoint is published "
                    "on the LAN. Set the token, or set MCP_ALLOW_ANONYMOUS=1 "
                    "to serve without authentication."
                )
            logger.warning(
                "%s not set and MCP_ALLOW_ANONYMOUS=1: endpoint is UNAUTHENTICATED",
                TOKEN_ENV,
            )

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        if scope.get("path") in (HEALTH_PATH, READY_PATH):
            if scope.get("method") not in ("GET", "HEAD"):
                await _json_response(
                    scope,
                    receive,
                    send,
                    {"error": "method not allowed"},
                    405,
                    {"allow": "GET, HEAD"},
                )
                return
            if scope.get("path") == HEALTH_PATH:
                await _json_response(scope, receive, send, {"status": "ok"}, 200)
                return
            body, status_code = await _readiness()
            await _json_response(scope, receive, send, body, status_code)
            return

        if self.token and not self._authorised(scope):
            await _json_response(scope, receive, send, {"error": "unauthorized"}, 401)
            return

        await self.app(scope, receive, send)

    def _authorised(self, scope: Any) -> bool:
        """Compare the presented credential in constant time."""
        headers = dict(scope.get("headers") or [])
        header = headers.get(b"authorization", b"").decode("latin-1").strip()
        # RFC 7235 makes the scheme case-insensitive; a client sending
        # "bearer <token>" is not a typo worth a 401, and neither is a stray
        # space inside the header.
        scheme, _, presented = header.partition(" ")
        if scheme.lower() != "bearer":
            return False
        return hmac.compare_digest(presented.strip().encode(), self.token.encode())


if __name__ == "__main__":
    import uvicorn

    # Accept any Host header: DNS-rebinding protection is disabled because the
    # bearer token gates every request.
    app = BearerAuthMiddleware(
        mcp.streamable_http_app(
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False)
        ),
        os.environ.get(TOKEN_ENV),
    )

    # 0.0.0.0 is the SDK's usual container bind; the stack's unit sets
    # MCP_HOST=127.0.0.1 because this container shares the host's network
    # namespace and must not listen on the LAN. Loopback is also what a smoke
    # test wants, hence the env overrides.
    uvicorn.run(
        app,
        host=os.environ.get("MCP_HOST", "0.0.0.0"),
        port=int(os.environ.get("MCP_PORT", "8000")),
        log_level=_log_level().lower(),
    )
