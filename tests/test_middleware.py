"""The ASGI middleware: bearer auth, /health, /ready and the method gate.

Driven directly with a stub app and a captured `send`, so these tests pin the
routing decisions without binding a port or opening a socket.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest

import server
from crowdsec import LapiError

TOKEN = "test-token"


class _StubApp:
    """Stands in for the streamable-HTTP app behind the middleware."""

    def __init__(self) -> None:
        self.called = False

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        self.called = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"app"})


def _scope(path: str, method: str = "GET", token: str | None = None) -> dict[str, Any]:
    headers = []
    if token is not None:
        headers.append((b"authorization", f"Bearer {token}".encode()))
    return {"type": "http", "path": path, "method": method, "headers": headers}


async def _receive() -> dict[str, Any]:
    return {"type": "http.request"}


async def _call(
    app: _StubApp, scope: dict[str, Any], token: str | None = TOKEN
) -> tuple[int, dict[bytes, bytes], bytes]:
    messages: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    middleware = server.BearerAuthMiddleware(app, token)
    await middleware(scope, _receive, send)
    start = next(m for m in messages if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    return start["status"], dict(start.get("headers") or []), body


@pytest.fixture(autouse=True)
def _clear_ready_cache() -> Iterator[None]:
    server._ready_cache = None
    server._ready_lock = None
    yield
    server._ready_cache = None
    server._ready_lock = None


@pytest.mark.anyio
async def test_health_is_open_and_says_only_ok() -> None:
    app = _StubApp()
    status, _, body = await _call(app, _scope("/health"))
    assert status == 200
    assert json.loads(body) == {"status": "ok"}
    assert not app.called


@pytest.mark.anyio
async def test_health_answers_a_head_without_a_body() -> None:
    app = _StubApp()
    status, headers, body = await _call(app, _scope("/health", method="HEAD"))
    assert status == 200
    assert body == b""
    # HEAD promises the headers the GET would have sent.
    assert int(headers[b"content-length"]) > 0


@pytest.mark.anyio
async def test_a_write_method_on_health_is_refused() -> None:
    app = _StubApp()
    status, _, _ = await _call(app, _scope("/health", method="POST"))
    assert status == 405
    assert not app.called


@pytest.mark.anyio
async def test_the_mcp_path_requires_the_token() -> None:
    app = _StubApp()
    status, _, body = await _call(app, _scope("/mcp"), TOKEN)
    assert status == 401
    assert json.loads(body) == {"error": "unauthorized"}
    assert not app.called


@pytest.mark.anyio
async def test_a_wrong_token_is_refused_and_a_right_one_passes() -> None:
    app = _StubApp()
    status, _, _ = await _call(app, _scope("/mcp", token="wrong"))
    assert status == 401
    assert not app.called

    status, _, body = await _call(app, _scope("/mcp", token=TOKEN))
    assert status == 200
    assert body == b"app"
    assert app.called


@pytest.mark.anyio
async def test_the_scheme_is_case_insensitive() -> None:
    app = _StubApp()
    scope = _scope("/mcp")
    scope["headers"] = [(b"authorization", b"bearer test-token")]
    status, _, _ = await _call(app, scope)
    assert status == 200


def test_a_missing_token_refuses_to_start() -> None:
    with pytest.raises(RuntimeError, match="CROWDSEC_MCP_TOKEN"):
        server.BearerAuthMiddleware(_StubApp(), "")


@pytest.mark.anyio
async def test_ready_reports_the_lapi(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "CROWDSEC_LAPI_KEY", "bouncer-key")
    monkeypatch.setattr(server, "_lapi_probe", lambda: None)
    app = _StubApp()
    status, _, body = await _call(app, _scope("/ready"))
    assert status == 200
    assert json.loads(body) == {"status": "ready", "lapi": "ok"}


@pytest.mark.anyio
async def test_ready_is_503_when_the_lapi_is_down(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "CROWDSEC_LAPI_KEY", "bouncer-key")

    def boom() -> None:
        raise LapiError("CrowdSec is unreachable at http://127.0.0.1:8080: refused")

    monkeypatch.setattr(server, "_lapi_probe", boom)
    app = _StubApp()
    status, _, body = await _call(app, _scope("/ready"))
    assert status == 503
    assert json.loads(body)["status"] == "unready"


@pytest.mark.anyio
async def test_ready_without_a_key_does_not_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "CROWDSEC_LAPI_KEY", "")
    app = _StubApp()
    status, _, body = await _call(app, _scope("/ready"))
    assert status == 503
    assert "CROWDSEC_LAPI_KEY is not set" in json.loads(body)["error"]


@pytest.mark.anyio
async def test_ready_is_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "CROWDSEC_LAPI_KEY", "bouncer-key")
    probes = []
    monkeypatch.setattr(server, "_lapi_probe", lambda: probes.append(1))
    app = _StubApp()
    for _ in range(3):
        status, _, _ = await _call(app, _scope("/ready"))
        assert status == 200
    assert len(probes) == 1
