# Threat Model

## What MCPRadar Detects

### 1. Tool Poisoning (Supply Chain)
**Vector:** An MCP server developer publishes malicious tool definitions.
- R001: Dangerous names like `eval`, `exec`, `rm`
- R105: Capabilities different from what the tool name implies

### 2. Prompt Injection via Tool Metadata
**Vector:** Patterns that manipulate the LLM are hidden in the tool
description/schema.
- R102: 10 prompt injection patterns
- R103: Injection hidden with Base64/hex
- R104: Injection hidden with HTML/Markdown

### 3. Hidden Text Attacks
**Vector:** Altering tool name or description using Unicode tricks.
- R101: Zero-width characters, BOM, directional override

## What MCPRadar Does NOT Detect

### Runtime Exploits
MCPRadar performs **static analysis** — it examines tool definitions, not runtime
behavior. It cannot catch:
- Buffer overflows in the actual tool implementation
- API keys being logged
- Network traffic being sniffed

### Server Infrastructure
- CVEs in the MCP server itself
- Transport-level security (TLS, auth bypass)
- Resource exhaustion / DoS

### Behavioral Anomalies
- Anomalies in tool call frequency
- Unexpected tool combinations (cross-tool attack)
- Patterns of user input being passed to tools

## Attack Surface

```
[User] → [LLM Client] → [MCP Protocol] → [MCP Server] → [Tool Implementation]
                                                  ↑
                                          MCPRadar scans here
                                     (tool definitions only)
```

## Severity Classification

| Severity | Meaning | Example |
|---|---|---|
| CRITICAL | Direct LLM manipulation, remote code execution risk | Prompt injection in description |
| HIGH | Hidden attack vector, requires user interaction | ZWSP in tool name |
| MEDIUM | Suspicious pattern, needs investigation | Base64 blob without clear payload |
| LOW | Informational, likely benign | Scope mismatch with bridge context |

## Responsible Disclosure

If you find a real security vulnerability with MCPRadar:
1. Give the affected MCP server's maintainer 30 days
2. Request a CVE
3. Follow the steps in MCPRadar's [SECURITY.md](../SECURITY.md)

If you find a security vulnerability in MCPRadar itself:
Report it to the `security@` address or with the GPG key.
