# MCP protocol profiles

MCPRadar separates protocol compatibility from security findings.

- `v1` uses the maintained Python SDK stateful lifecycle and supports stdio,
  SSE, and Streamable HTTP.
- `2026-07-28` is an opt-in stateless HTTP adapter using `server/discover`,
  `MCP-Protocol-Version`, `Mcp-Method`, optional `Mcp-Name`, and per-request
  `_meta` client/protocol metadata.
- `auto` tries stateless discovery on HTTP and falls back to v1 only when the
  server explicitly indicates the new method is unsupported.

All list surfaces are paginated with a hard page cap: tools, prompts, resources,
and resource templates. Server instructions are analyzed as a first-class
surface. Each surface reports `complete`, `partial`, `failed`, or `unsupported`;
a partial enumeration is never silently represented as a clean scan.

Session-based v1 behavior is reported as migration readiness when evaluating a
future profile. It is not mislabeled as an authentication vulnerability.

The CI suite runs the official MCP conformance `initialize` and `tools_call`
client scenarios for the latest published stateful profile. The official suite
does not yet publish stateless core draft scenarios; the v2 adapter is therefore
covered directly with request-header, discovery, metadata, error, pagination,
and named-call tests until those scenarios exist.
