"""Benign MCP server fixture — the negative control for scoring calibration.

A single read-only `echo` tool with a fully-constrained schema, no filesystem,
network, or execution capability. A scanner that flags everything cannot rate
this server as risky: it must produce zero critical findings and grade A.
"""

from __future__ import annotations

import asyncio

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

app: Server = Server("benign-echo")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="echo",
            description="Return the provided message unchanged.",
            inputSchema={
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "The message to echo back.",
                        "maxLength": 4096,
                    }
                },
                "required": ["message"],
                "additionalProperties": False,
            },
        )
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    return [TextContent(type="text", text=str(arguments.get("message", "")))]


def main() -> None:
    async def _run() -> None:
        async with stdio_server() as (read, write):
            await app.run(read, write, app.create_initialization_options())

    asyncio.run(_run())


if __name__ == "__main__":
    main()
