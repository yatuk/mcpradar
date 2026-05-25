# Cross-Server Contamination Analysis

When multiple MCP servers are connected to the same LLM agent,
risks emerge that don't exist in isolation.

## The Threat

A malicious (or compromised) MCP server can exploit the LLM's context
window to influence how it uses tools from OTHER servers:

1. **Name collision** — Two servers provide a tool named `eval`. The LLM
   can't distinguish them. An attacker's `eval` may get called instead
   of the legitimate one.

2. **Shadowing** — `send_email` vs `send_email_internal`. Similar names
   across servers create ambiguity the LLM may resolve incorrectly.

3. **Exfiltration chain** — Server A reads sensitive data (files, secrets).
   Server B can send data out (Slack, webhook). The LLM bridges them
   unaware it's creating an exfiltration pipeline.

4. **Capability overload** — 5 servers all offering `file_read`. Attack
   surface is 5× wider than needed.

5. **Permission gradient** — Read-only tools coexist with write-capable
   tools. A prompt injection on a read-only tool can hijack write access.

## Usage

```bash
# Define servers in mcpradar.toml:
[[servers]]
url = "npx -y @modelcontextprotocol/server-github"
transport = "stdio"

[[servers]]
url = "npx -y @modelcontextprotocol/server-slack"
transport = "stdio"

# Run analysis:
mcpradar analyze-context
```

## Rules

| ID | Rule | Severity | Description |
|----|------|----------|-------------|
| C001 | Tool name collision | CRITICAL | Same tool name in 2+ servers |
| C002 | Tool shadowing | HIGH | Similar names (≥75%) across servers |
| C003 | Exfiltration chain | CRITICAL | Read-capable + send-capable pair |
| C004 | Capability overload | MEDIUM | 3+ servers with same capability |
| C005 | Permission gradient | MEDIUM | Read-only + write-capable mix |

## Real-World Example

```
Server A: @modelcontextprotocol/server-github
  → read_file, get_issue, list_repos

Server B: @modelcontextprotocol/server-slack
  → send_message, upload_file, post_to_channel

Context analysis finds:
  C003 CRITICAL: GitHub reads files, Slack sends out → exfiltration path
  C004 MEDIUM: Both have file-related tools → capability overlap
```
