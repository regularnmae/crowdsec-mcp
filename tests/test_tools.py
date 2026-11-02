"""The tools: the filters they build, the fields they return, the report they
give.

`fake_lapi` records every call, so these tests pin the query a tool sends --
the LAPI's filter names are the contract, and a filter that silently changes
shape (a missing limit, an empty string where "any" was meant) is the bug
worth catching without a live engine.
"""

from __future__ import annotations

import json
import time
from typing import Any

import server
from crowdsec import LapiError

DECISION = {
    "id": 61,
    "value": "203.0.113.9",
    "scope": "Ip",
    "type": "ban",
    "scenario": "stack/http-probing",
    "origin": "crowdsec",
    "duration": "1h57m13s",
    "simulated": False,
    "capacity": 10,  # not a decision field: must never be echoed
}


def _payload(text: str) -> dict[str, Any]:
    return json.loads(text)


def test_list_decisions_passes_the_filters_and_a_limit(call, fake_lapi) -> None:
    fake_lapi.rows = [DECISION]
    payload = _payload(call("list_decisions", ip="203.0.113.9", scenario="stack/http-probing"))
    assert fake_lapi.calls == [
        {
            "ip": "203.0.113.9",
            "scenario": "stack/http-probing",
            "type": None,
            "scope": None,
            "origin": None,
            "limit": 50,
        }
    ]
    assert payload["count"] == 1
    assert payload["decisions"] == [
        {
            "value": "203.0.113.9",
            "scope": "Ip",
            "type": "ban",
            "scenario": "stack/http-probing",
            "origin": "crowdsec",
            "duration": "1h57m13s",
            "id": 61,
        }
    ]


def test_list_decisions_reports_only_the_filters_it_applied(call, fake_lapi) -> None:
    payload = _payload(call("list_decisions", type="ban", limit=10))
    assert payload["filters"] == {"type": "ban", "limit": 10}
    assert "truncated" not in payload


def test_list_decisions_hints_when_the_cap_was_reached(call, fake_lapi) -> None:
    fake_lapi.rows = [DECISION] * 5
    payload = _payload(call("list_decisions", limit=5))
    assert payload["truncated"] is True


def test_list_decisions_refuses_an_ip_it_cannot_parse(error_call, fake_lapi) -> None:
    text = error_call("list_decisions", ip="not-an-ip")
    assert "ip must be a single IPv4 or IPv6 address" in text
    assert fake_lapi.calls == []


def test_check_ip_answers_a_global_address(call, fake_lapi) -> None:
    fake_lapi.rows = [DECISION]
    payload = _payload(call("check_ip", ip="159.89.12.166"))
    assert payload["banned"] is True
    assert payload["enforceable"] is True
    assert "note" not in payload
    assert fake_lapi.calls == [{"ip": "159.89.12.166", "limit": 200}]


def test_check_ip_answers_an_unbanned_address(call, fake_lapi) -> None:
    payload = _payload(call("check_ip", ip="198.51.100.7"))
    assert payload["banned"] is False
    assert payload["decisions"] == []


def test_check_ip_marks_private_space_unenforceable(call, fake_lapi) -> None:
    for address in ("10.89.0.5", "127.0.0.1", "169.254.1.1", "192.168.1.112", "fd00::1"):
        payload = _payload(call("check_ip", ip=address))
        assert payload["enforceable"] is False, address
        assert "not be enforced" in payload["note"]


def test_check_ip_refuses_a_range(error_call) -> None:
    text = error_call("check_ip", ip="203.0.113.0/24")
    assert "single IPv4 or IPv6 address" in text


def test_a_lapi_failure_becomes_a_tool_error(error_call, fake_lapi) -> None:
    fake_lapi.error = LapiError("CrowdSec is unreachable at http://127.0.0.1:8080: refused")
    text = error_call("list_decisions")
    assert "unreachable" in text


def _metrics() -> str:
    now = time.time()
    return "\n".join(
        [
            'cs_info{version="v1.8.2-3d369d64"} 0',
            'cs_active_decisions{action="ban",origin="crowdsec",reason="stack/http-probing"} 3',
            'cs_active_decisions{action="ban",origin="crowdsec",reason="stack/http-authfail"} 1',
            'cs_alerts{kind="crowdsec",reason="stack/http-probing"} 43',
            'cs_alerts{kind="cscli",reason="bouncer smoke test"} 1',
            'cs_buckets{name="stack/http-flood"} 11',
            'cs_bucket_overflowed_total{name="stack/http-probing"} 22',
            'cs_parser_hits_ok_total{source="/var/log/npm/a.log"} 100',
            'cs_parser_hits_ko_total{source="/var/log/npm/a.log"} 2',
            f'cs_machines_last_heartbeat_timestamp{{machine="stack-ids"}} {now - 30}',
            'cs_lapi_bouncer_requests_total{bouncer="firewall@127.0.0.1",'
            'route="/v1/decisions"} 298',
            'cs_lapi_bouncer_requests_total{bouncer="mcp@127.0.0.1",route="/v1/decisions"} 12',
        ]
    )


def test_get_engine_health_folds_the_counters(call, fake_metrics) -> None:
    fake_metrics(_metrics())
    payload = _payload(call("get_engine_health"))
    assert payload["version"] == "v1.8.2-3d369d64"
    assert payload["active_decisions"]["total"] == 4
    assert payload["active_decisions"]["by_scenario"][0] == {
        "reason": "stack/http-probing",
        "action": "ban",
        "origin": "crowdsec",
        "count": 3,
    }
    assert payload["alerts"]["total"] == 44
    assert payload["alerts"]["by_scenario"][0] == {
        "kind": "crowdsec",
        "reason": "stack/http-probing",
        "count": 43,
    }
    assert payload["detection"]["buckets_in_flight"] == [{"name": "stack/http-flood", "count": 11}]
    assert payload["detection"]["overflowed_total"] == [
        {"name": "stack/http-probing", "count": 22}
    ]
    assert payload["detection"]["parser_hits"] == {"ok": 100, "ko": 2}
    assert payload["machines"][0]["machine"] == "stack-ids"
    assert 25 <= payload["machines"][0]["heartbeat_age_seconds"] <= 35
    assert payload["bouncer_requests"][0] == {
        "bouncer": "firewall@127.0.0.1",
        "route": "/v1/decisions",
        "count": 298,
    }


def test_get_engine_health_survives_an_empty_exposition(call, fake_metrics) -> None:
    payload = _payload(call("get_engine_health"))
    assert payload["active_decisions"] == {"total": 0, "by_scenario": []}
    assert "version" not in payload
    assert payload["machines"] == []


def test_get_engine_health_reports_an_unreachable_engine(
    error_call, monkeypatch
) -> None:
    def boom(url: str, timeout: float = 10.0) -> str:
        raise LapiError("CrowdSec is unreachable at http://127.0.0.1:6060: refused")

    monkeypatch.setattr(server.crowdsec, "fetch_metrics", boom)
    assert "unreachable" in error_call("get_engine_health")
