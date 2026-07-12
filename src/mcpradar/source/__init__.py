"""Static source-code analysis for MCP servers (scan without running).

Parses a server's Python source with the ``ast`` module and flags security
issues that schema-level scanning cannot see — SSRF, unsafe deserialization,
command/SQL injection, and Description-Code Inconsistency (a tool that presents
itself as read-only while its handler writes to disk, sends to the network, or
executes commands).
"""

from mcpradar.source.analyzer import SourceAnalyzer, analyze_path

__all__ = ["SourceAnalyzer", "analyze_path"]
