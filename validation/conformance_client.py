"""MCPRadar client entry point for the official MCP conformance runner.

The runner appends its ephemeral server URL and selects the scenario/version
through environment variables. MCPRadar exercises the same v1 and v2 protocol
adapters used by production scans, without running detection rules.
"""

from __future__ import annotations

import asyncio
import os
import sys

from mcp import ClientSession, types
from mcp.client.streamable_http import streamable_http_client

from mcpradar.scanner.protocol import MCP_V2_PROFILE
from mcpradar.scanner.protocol_adapter import StatelessHttpSession


async def run(server_url: str, scenario: str, protocol_version: str) -> None:
    if scenario not in {"initialize", "tools-call", "tools_call"}:
        raise ValueError(f"unsupported conformance scenario: {scenario}")
    if protocol_version == "draft" or protocol_version.startswith(MCP_V2_PROFILE):
        async with StatelessHttpSession(server_url) as session:
            discovery = await session.discover()
            supported = getattr(discovery, "supportedVersions", [])
            if MCP_V2_PROFILE not in supported:
                raise RuntimeError("conformance server did not advertise the requested profile")
            await session.list_tools()
            if scenario in {"tools-call", "tools_call"}:
                await session.call_tool("add_numbers", {"a": 2, "b": 3})
        return

    client_info = types.Implementation(name="mcpradar-conformance", version="1.0.0")
    async with (
        streamable_http_client(server_url) as (read, write, _get_session_id),
        ClientSession(read, write, client_info=client_info) as session,
    ):
        await session.initialize()
        await session.list_tools()
        if scenario in {"tools-call", "tools_call"}:
            await session.call_tool("add_numbers", {"a": 2, "b": 3})


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: conformance_client.py <server-url>")
    scenario = os.environ.get("MCP_CONFORMANCE_SCENARIO", "")
    protocol_version = os.environ.get("MCP_CONFORMANCE_PROTOCOL_VERSION", "2025-11-25")
    asyncio.run(run(sys.argv[1], scenario, protocol_version))


if __name__ == "__main__":
    main()
