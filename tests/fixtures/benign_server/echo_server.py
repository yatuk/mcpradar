"""Minimal benign MCP server — single echo tool, clean schema.

Used as negative control for regression gate.
Should trigger 0 CRITICAL findings and 0 or very few findings total.
"""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Benign Echo Server")


@mcp.tool()
def echo(text: str = "") -> str:
    """Echo back the provided text. No side effects, no file or network access.

    Args:
        text: The text to echo back. Any string is accepted.
    """
    return f"Echo: {text}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
