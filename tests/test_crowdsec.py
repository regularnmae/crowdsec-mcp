"""The stdlib CrowdSec client: transport, shapes and error mapping.

`urllib.request.urlopen` is monkeypatched, so the contract under test is what
this module sends and what it does with the answer -- no engine is involved.
The `null` answer is the interesting one: it is how the LAPI says "nothing
matches", and reading it as a protocol error is a bug stack-bouncer has
already documented once.
"""

from __future__ import annotations

import email.message
import io
import json
import urllib.error
import urllib.parse
import urllib.request

import pytest

import crowdsec
from crowdsec import LapiClient, LapiError, fetch_metrics, parse_exposition


class _Response:
    def __init__(self, body: bytes, status: int = 200) -> None:
        self.body = body
        self.status = status

    def read(self, size: int = -1) -> bytes:
        return self.body if size is None or size < 0 else self.body[:size]

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


def _capture(monkeypatch: pytest.MonkeyPatch, response: object) -> list[urllib.request.Request]:
    """Answer every urlopen with `response`, recording the requests asked for."""
    requests: list[urllib.request.Request] = []

    def fake_urlopen(request: urllib.request.Request, timeout: float | None = None):
        requests.append(request)
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    return requests


def _http_error(code: int, message: str) -> urllib.error.HTTPError:
    body = io.BytesIO(json.dumps({"code": code, "message": message}).encode())
    return urllib.error.HTTPError(
        "http://127.0.0.1:8080/v1/decisions", code, message, email.message.Message(), body
    )


def test_decisions_sends_the_key_and_the_filters(monkeypatch: pytest.MonkeyPatch) -> None:
    body = json.dumps([{"value": "203.0.113.9", "scenario": "stack/http-probing"}]).encode()
    requests = _capture(monkeypatch, _Response(body))
    rows = LapiClient("http://127.0.0.1:8080", "bouncer-key").decisions(
        ip="203.0.113.9", type="ban", limit=5
    )
    assert rows[0]["scenario"] == "stack/http-probing"
    request = requests[0]
    assert request.get_header("X-api-key") == "bouncer-key"
    parsed = urllib.parse.urlparse(request.full_url)
    assert parsed.path == "/v1/decisions"
    assert urllib.parse.parse_qs(parsed.query) == {
        "ip": ["203.0.113.9"],
        "type": ["ban"],
        "limit": ["5"],
    }
    # The unfiltered keys must not be sent as empty strings: the LAPI reads
    # `scenario=` as a filter for the empty scenario, not as "any".
    assert "scenario" not in parsed.query


def test_the_lapi_null_answer_is_an_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
    _capture(monkeypatch, _Response(b"null"))
    assert LapiClient("http://127.0.0.1:8080", "k").decisions(ip="203.0.113.9") == []


def test_an_empty_body_is_an_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
    _capture(monkeypatch, _Response(b""))
    assert LapiClient("http://127.0.0.1:8080", "k").decisions() == []


def test_a_refused_key_names_the_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    _capture(monkeypatch, _http_error(403, "access forbidden"))
    with pytest.raises(LapiError) as caught:
        LapiClient("http://127.0.0.1:8080", "machine-password").decisions()
    assert caught.value.status == 403
    assert "refused the API key" in caught.value.message
    assert "bouncer" in caught.value.message


def test_an_unreachable_lapi_names_the_url(monkeypatch: pytest.MonkeyPatch) -> None:
    _capture(monkeypatch, urllib.error.URLError("connection refused"))
    with pytest.raises(LapiError) as caught:
        LapiClient("http://127.0.0.1:8080", "k").decisions()
    assert "unreachable at http://127.0.0.1:8080" in caught.value.message


def test_a_body_that_is_not_json_is_a_protocol_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _capture(monkeypatch, _Response(b"<html>oops</html>"))
    with pytest.raises(LapiError) as caught:
        LapiClient("http://127.0.0.1:8080", "k").decisions()
    assert "not JSON" in caught.value.message


def test_a_body_that_is_not_a_list_is_a_protocol_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _capture(monkeypatch, _Response(b'{"decisions": []}'))
    with pytest.raises(LapiError) as caught:
        LapiClient("http://127.0.0.1:8080", "k").decisions()
    assert "not a list" in caught.value.message


def test_metrics_are_fetched_from_its_own_port(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = _capture(monkeypatch, _Response(b"cs_info{version=\"v1.8.2\"} 0\n"))
    text = fetch_metrics("http://127.0.0.1:6060")
    assert "cs_info" in text
    assert requests[0].full_url == "http://127.0.0.1:6060/metrics"


def test_exposition_parsing_keeps_labels_with_commas_and_escapes() -> None:
    text = (
        "# HELP cs_alerts something\n"
        "# TYPE cs_alerts gauge\n"
        'cs_alerts{kind="crowdsec",reason="stack/http-flood"} 3\n'
        'cs_lapi_bouncer_requests_total{bouncer="firewall@127.0.0.1",route="/v1/decisions"} 298\n'
        'cs_info{version="v1.8.2-3d369d64",note="a\\"b,c"} 0\n'
        "cs_machines_last_heartbeat_timestamp{machine=\"stack-ids\"} 1.7936241134648225e+09\n"
        "not a sample line\n"
        "cs_buckets{name=\"broken\" nan\n"
    )
    series = parse_exposition(text)
    assert series["cs_alerts"] == [({"kind": "crowdsec", "reason": "stack/http-flood"}, 3.0)]
    assert series["cs_lapi_bouncer_requests_total"][0][1] == 298.0
    assert series["cs_info"][0][0]["note"] == 'a"b,c'
    heartbeat = series["cs_machines_last_heartbeat_timestamp"][0][1]
    assert heartbeat == pytest.approx(1.7936241134648225e09)
    # The malformed line is skipped, and nothing invented it.
    assert "cs_buckets" not in series


def test_exposition_parsing_reads_a_bare_sample() -> None:
    assert parse_exposition("cs_postoverflow_dropped_total 7\n") == {
        "cs_postoverflow_dropped_total": [({}, 7.0)]
    }


def test_unescaping_handles_newlines() -> None:
    assert crowdsec._unescape(r"a\nb") == "a\nb"
