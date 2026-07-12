"""Scan MCP / agent client config files for poisoning.

A malicious MCP server entry or a weaponized agent hook is added to a config
file (``claude_desktop_config.json``, ``.mcp.json``, ``.cursor/mcp.json``,
``.claude/settings.json`` …), not to the server's own code — so it is invisible
to server-side scanning. This module inspects the launch commands, hook
commands, and permission grants in those files for download-to-shell RCE,
credential exfiltration, reverse shells, and over-broad permissions.
"""

from mcpradar.config_scan.scanner import ConfigScanner, scan_config_path

__all__ = ["ConfigScanner", "scan_config_path"]
