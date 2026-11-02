"""What the server advertises in `tools/list`.

The schema is the contract a client validates against, and the tool set is
also this server's security boundary: every tool is a read, and the set is
exactly these three. A fourth name appearing here -- `ban`, `unban`,
`add_decision`, `list_alerts` -- is the change this file exists to catch, so
it fails the build rather than shipping.
"""

from __future__ import annotations

import anyio
import pytest
from mcp import Client

import server

TOOLS = {"list_decisions", "check_ip", "get_engine_health"}


@pytest.fixture
def advertised() -> dict:
    """The tools/list result, fetched once per test through a real client."""

    async def _list():
        async with Client(server.mcp) as c:
            return await c.list_tools()

    listing = anyio.run(_list)
    return {tool.name: tool for tool in listing.tools}


def test_the_tool_set_is_read_only(advertised: dict) -> None:
    assert set(advertised) == TOOLS, (
        "the tool set changed; every tool here must be a read, and the bouncer "
        "key this server holds cannot write"
    )


@pytest.mark.parametrize("name", sorted(TOOLS))
def test_text_tools_publish_no_output_schema(advertised: dict, name: str) -> None:
    assert advertised[name].output_schema is None, (
        f"{name} publishes an output schema, which means its str return is "
        "serialised twice; pass structured_output=False to @mcp.tool()"
    )


def test_every_tool_declares_itself_read_only(advertised: dict) -> None:
    for name, tool in advertised.items():
        assert tool.annotations is not None, f"{name} publishes no annotations"
        assert tool.annotations.read_only_hint is True, f"{name} is not marked read-only"
        # This is the host's own state, not an open-world network.
        assert tool.annotations.open_world_hint is False, f"{name} claims open-world"


def test_decision_limits_are_bounded(advertised: dict) -> None:
    properties = advertised["list_decisions"].input_schema["properties"]
    assert properties["limit"]["maximum"] == 200
    assert properties["limit"]["minimum"] == 1
    assert properties["limit"]["default"] == 50
    # Every filter is optional: the bare call is "what is blocked".
    assert advertised["list_decisions"].input_schema.get("required", []) == []


def test_check_ip_requires_the_address(advertised: dict) -> None:
    schema = advertised["check_ip"].input_schema
    assert schema.get("required") == ["ip"]
    assert schema["properties"]["ip"]["maxLength"] == 64
