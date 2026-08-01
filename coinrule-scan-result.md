## MCPRadar Scan Results — Coinrule MCP

**Scan Date:** 2026-07-23  
**Scanner Version:** v1.1.0-rc1  
**Target:** `https://cloud.coinrule.com/mcp`  
**Repository:** `https://github.com/coinrule-com/coinrule-mcp-ai-trading`

---

### ✅ Source Code Analysis — **CLEAN** (0 findings)

Scanned the GitHub repository with `mcpradar scan-source`:
- **4 files analyzed** (README.md, server.json, docs/, examples/)
- **0 security findings**
- **Note:** This is a manifest-only repository — no Python/JS server source code to statically analyze. The actual server implementation is closed-source and hosted.

### ✅ Configuration Scan — **CLEAN** (0 findings)

Scanned `server.json` with `mcpradar scan-config`:
- Well-formed MCP server manifest
- Standard `$schema` reference
- No configuration poisoning detected

### ⚠️ Live Protocol Scan — **BLOCKED** (401 Unauthorized)

The live MCP endpoint returns **HTTP 401** — the server requires **OAuth authentication**.

MCPRadar currently does not support scanning OAuth-protected MCP servers without credentials. This is a known limitation. The OAuth protection is itself a **positive security signal** — the server is not openly accessible.

### 🔒 Server Security Headers (from HTTP response)

| Header | Value |
|--------|-------|
| HSTS | `max-age=31536000; includeSubDomains; preload` |
| XSS Protection | `1; mode=block` |
| Content-Type-Options | `nosniff` |
| Frame-Options | `SAMEORIGIN` |
| Referrer-Policy | `same-origin` |
| Hosted on | **Cloudflare** ✅ |

### 📊 Leaderboard Status

Added to the MCPRadar leaderboard with **"pending"** status (59 pending, 99 scanned, 158 total). Will be rescanned when OAuth support is added to MCPRadar.

### 📋 Summary

| Check | Result |
|-------|--------|
| Source (static) | ✅ Clean |
| Config (server.json) | ✅ Clean |
| Live (protocol) | 🔒 Blocked — OAuth |
| Dependencies (OSV) | N/A — no lockfile |
| Security headers | ✅ Good |

### 🔮 Recommendation

Coinrule MCP is a **well-configured, OAuth-protected Streamable HTTP MCP server**. The public artifacts are clean. For a full protocol-level security audit, OAuth credential support in MCPRadar is needed (tracked as a feature request). No action required at this time.

---

🤖 Scanned with [MCPRadar](https://github.com/yatuk/mcpradar) v1.1.0-rc1
