"""Shared fixtures.

Every test talks to the server through the SDK's in-memory client, so no test
opens a socket. CrowdSec itself is replaced by `fake_lapi` (the decision list)
and `fake_metrics` (the exposition text) -- the tools, their filters and their
output caps are what is under test, not a live engine.

The in-memory session is opened inside `anyio.run` rather than by an async
fixture: pytest 9 refuses to resolve an async fixture for a sync test, and
these tests are sync on purpose (a tool call is one blocking round trip).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import anyio
import pytest
from mcp import Client

import server
from crowdsec import LapiError


def _tool_call(name: str, arguments: dict[str, Any]) -> Any:
    """One tool call over a fresh in-memory MCP session."""

    async def _run() -> Any:
        async with Client(server.mcp, raise_exceptions=True) as c:
            return await c.call_tool(name, arguments)

    return anyio.run(_run)


class FakeLapi:
    """Stands in for `server.client`.

    Records the filters each tool built and answers with `rows` (or raises
    `error` when a test wants a failure). A live LAPI's "nothing matches" is
    the empty list by the time it reaches a tool, because the client has
    already turned the literal `null` into `[]` -- that mapping is
    test_crowdsec.py's job.
    """

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.rows: list[dict[str, Any]] = []
        self.error: Exception | None = None

    def decisions(self, **filters: Any) -> list[dict[str, Any]]:
        self.calls.append(filters)
        if self.error is not None:
            raise self.error
        return self.rows


@pytest.fixture
def fake_lapi(monkeypatch: pytest.MonkeyPatch) -> FakeLapi:
    """Replace the live LAPI with a scripted fake, restoring it after."""
    fake = FakeLapi()
    monkeypatch.setattr(server.client, "decisions", fake.decisions)
    return fake


@pytest.fixture
def fake_metrics(monkeypatch: pytest.MonkeyPatch) -> Callable[[str], None]:
    """Script the exposition `get_engine_health` parses, and return a setter."""

    def _set(text: str) -> None:
        monkeypatch.setattr(
            server.crowdsec,
            "fetch_metrics",
            lambda url, timeout=10.0: text,
        )

    _set("")
    return _set


@pytest.fixture
def call() -> Callable[..., str]:
    """Call a tool and hand back the text the model would read."""

    def _call(name: str, **arguments: Any) -> str:
        result = _tool_call(name, arguments)
        assert not result.is_error, f"tool {name} failed: {result.content}"
        return result.content[0].text  # type: ignore[union-attr]

    return _call


@pytest.fixture
def error_call() -> Callable[..., str]:
    """Call a tool that is expected to fail, and return its error text."""

    def _call(name: str, **arguments: Any) -> str:
        result = _tool_call(name, arguments)
        assert result.is_error, f"tool {name} succeeded, want a tool error"
        return result.content[0].text  # type: ignore[union-attr]

    return _call


__all__ = ["FakeLapi", "LapiError", "error_call", "fake_lapi", "fake_metrics", "call"]
