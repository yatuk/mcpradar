"""MCPRadar -- MCP server tool poisoning and security scanner.

Public SDK:
    from mcpradar import sanitize, SandboxPolicy, SandboxValidator

    validator = SandboxValidator()
    safe_args = sanitize({"cmd": "rm -rf"})
"""

__version__ = "1.0.0-rc4"

from mcpradar.probe.sandbox import SandboxPolicy, SandboxValidator  # noqa: E402, F401


def sanitize(args: dict, policy: SandboxPolicy | None = None) -> dict:
    """Sanitize tool arguments before calling an MCP tool.

    Import and use in your own MCP server to prevent command injection
    and dangerous argument values.

    Args:
        args: The tool arguments dict to sanitize.
        policy: Optional SandboxPolicy; uses safe defaults if omitted.

    Returns:
        A new sanitized dict (original is not mutated).

    Example:
        from mcpradar import sanitize

        async def handle_call_tool(name, arguments):
            safe_args = sanitize(arguments)
            return await actual_tool(name, safe_args)
    """
    validator = SandboxValidator(policy)
    return validator.sanitize_args(args)
