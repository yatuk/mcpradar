# API-Free / Local-First MCP Servers

A curated catalog of MCP servers that require **no API keys, no cloud subscriptions, and no external authentication**. These servers run entirely on local hardware via stdio transport.

## Why API-Free?

As the MCP ecosystem grows, two distinct paradigms have emerged:

| Dimension | Cloud/API-Based MCP | API-Free (Local-First) MCP |
|-----------|--------------------|----------------------------|
| **Data Privacy** | Data transmitted to cloud; leakage risk | Data stays on machine; stdio-isolated |
| **Cost Model** | Per-query, per-token, or monthly subscription | Completely free, zero per-query cost |
| **Authentication** | OAuth 2.0, API keys, tenant-admin consent | Operating system permissions (e.g., macOS TCC) |
| **Latency** | Network latency + API rate-limit constraints | Disk/CPU bound only; sub-millisecond |
| **Offline Capability** | Internet required | Fully offline and air-gapped capable |

The October 2025 hosted-MCP path traversal vulnerability that exposed 3,000+ servers and API keys reinforced the value of local execution models.

---

## Server Catalog

### 1. local-mcp — Desktop Automation

| Property | Value |
|----------|-------|
| **Package** | `npx -y local-mcp` |
| **Transport** | stdio |
| **Category** | Desktop Automation |
| **Platform** | macOS |

182+ local tools connecting LLMs to native macOS applications without OAuth or API keys. Reads local app SQLite/LevelDB caches (Teams, Slack, Mail, iMessage) directly from disk.

**Architecture:** Native macOS process calling system frameworks. No data leaves the machine. iMessage, Calendar, Contacts, Reminders, Notes, OmniFocus, Safari bookmarks, Finder search, Office documents (Word/Excel/PPT/PDF) — all accessible via stdio.

**Security:** macOS TCC (Transparency, Consent, and Control) permissions. Destructive operations (send email, delete file, cancel calendar event) require user preview and explicit consent before execution.

**Audience:** Individual productivity users, executives, workflow automators.

---

### 2. dotMD — Markdown Knowledge Base & Hybrid RAG

| Property | Value |
|----------|-------|
| **Package** | `uvx dotmd` |
| **Transport** | stdio |
| **Category** | Knowledge / RAG |
| **Platform** | Cross-platform (Python) |

A fully embedded, zero-cost knowledge retrieval engine for Markdown files (Obsidian vaults, engineering notes, research summaries).

**Architecture (3-layer search):**
- **Vector layer:** LanceDB (embedded, file-based YSA engine) for semantic search
- **Graph layer:** LadybugDB (forked Kuzu, local Cypher graph DB) with GLiNER zero-shot NER for entity extraction
- **Keyword layer:** BM25 algorithm for exact matching
- **Fusion:** Reciprocal Rank Fusion (RRF) + optional cross-encoder reranking
- **Metadata:** SQLite for statistics and metadata

**Security:** All data stays on disk. No embedding API calls, no vector DB cloud service. LanceDB runs as an embedded library within the process.

**Audience:** Researchers, technical writers, software developers, anyone with large Markdown knowledge bases.

---

### 3. Chrome DevTools MCP — Browser Debugging & Automation

| Property | Value |
|----------|-------|
| **Package** | `npx -y chrome-devtools-mcp` |
| **Transport** | stdio |
| **Category** | Browser / DevTools |
| **Platform** | Cross-platform (Node.js) |

Official Google MCP server providing full Chrome DevTools Protocol (CDP) access.

**Architecture:** Direct CDP connection to local Chrome instance. No cloud browser service needed.

**Capabilities:**
- `take_heapsnapshot` / `compare_heapsnapshots` — memory leak detection
- `performance_start_trace` — performance bottleneck analysis
- `get_network_requests` — HTTP traffic inspection
- `evaluate_script` — direct DOM manipulation
- `get_console_error_summary` — JS error classification
- **Headful mode:** Uses user's real profile (cookies, extensions) to bypass CAPTCHA/Cloudflare on login-walled pages

**Security:** Runs against local Chrome; no remote browser infrastructure. User's existing sessions and cookies stay on machine.

**Audience:** Frontend developers, performance engineers, QA testers.

---

### 4. db-mcp-server — Multi-Database Unified Interface

| Property | Value |
|----------|-------|
| **Package** | `npx -y db-mcp-server` |
| **Transport** | stdio |
| **Category** | Database |
| **Platform** | Cross-platform (Node.js) |

Connects AI assistants to MySQL, PostgreSQL, SQLite, and Oracle databases through a single, unified interface.

**Architecture:** Direct database driver connections on localhost or LAN. "Lazy Loading" initializes connections only on first query — critical for environments with 10+ databases.

**Security:** Local/LAN database connections only. No cloud proxy. Use with read-only database users for safety.

**Audience:** Backend developers, DBAs, data analysts.

---

### 5. SearXNG MCP — Privacy-Focused Metasearch

| Property | Value |
|----------|-------|
| **Package** | `uvx searxng-mcp` |
| **Transport** | stdio |
| **Category** | Web Search |
| **Platform** | Cross-platform (Python) |

MCP wrapper for self-hosted SearXNG metasearch engine. Aggregates results from multiple search engines, anonymizes queries, returns structured JSON.

**Architecture:** Queries a SearXNG instance running locally (Docker or native). `/search?format=json` endpoint returns clean, parseable results — no HTML scraping fragility.

**Security:** All queries anonymized. No API keys, no search provider rate limits, no tracking. User controls the entire pipeline.

**Audience:** OSINT researchers, privacy-conscious developers, air-gapped environments.

---

### 6. DuckDuckGo MCP — Zero-Key Web Search

| Property | Value |
|----------|-------|
| **Package** | `npx -y duckduckgo-mcp` |
| **Transport** | stdio |
| **Category** | Web Search |
| **Platform** | Cross-platform (Node.js) |

Lightweight search using DuckDuckGo's public endpoints. 2,400+ installs. No API registration required.

**Architecture:** Direct HTTP queries to DuckDuckGo's public instant answer API. No authentication, no API key provisioning.

**Security:** Public endpoints; queries are not tracked. Suitable for quick lookups and lightweight web context.

**Audience:** Developers needing instant web context without API setup overhead.

---

### 7. Wardn — Encrypted Credential Vault

| Property | Value |
|----------|-------|
| **Package** | `npx -y wardn-mcp` |
| **Transport** | stdio |
| **Category** | Security |
| **Platform** | Cross-platform (Node.js) |

Encrypted vault with token injection proxy. Prevents LLMs from ever seeing real API keys.

**Architecture (Zero-Trust Credential Injection):**
1. Developer stores API keys in AES-256-GCM encrypted local vault
2. Agent calls `get_credential_ref` tool — receives a placeholder token (`wdn_placeholder_...`)
3. Agent uses the placeholder in API calls
4. Local Wardn proxy intercepts outbound requests and substitutes the real key just before network egress
5. Real key never enters LLM context window, prompt logs, or system logs

**Security:** If the LLM is compromised or leaks context, attackers only obtain worthless placeholder tokens. The window between proxy and network egress is the only place real keys exist.

**Audience:** System security architects, DevSecOps teams, anyone exposing LLMs to production APIs.

---

### 8. ha-mcp — Home Assistant Integration

| Property | Value |
|----------|-------|
| **Package** | `uvx ha-mcp` |
| **Transport** | stdio |
| **Category** | IoT / Smart Home |
| **Platform** | Cross-platform (Python) |

MCP integration for Home Assistant — the leading open-source home automation platform.

**Architecture:** WebSocket connection to local Home Assistant instance. Reads entity states, calls services, manages automations via YAML.

**Capabilities:** Sensor data analysis, automation script management, device state queries, scene activation.

**Security:** All communication on local network. No cloud dependency. Home Assistant's own RBAC controls apply.

**Audience:** Smart home developers, maker community, home automation enthusiasts.

---

### 9. Frigate MCP — NVR Camera Configuration

| Property | Value |
|----------|-------|
| **Package** | `uvx frigate-mcp` |
| **Transport** | stdio |
| **Category** | IoT / Smart Home |
| **Platform** | Cross-platform (Python) |

MCP integration for Frigate — open-source NVR with real-time object detection.

**Capabilities:** Camera configuration analysis, person/vehicle detection tuning, zone management, false alarm reduction, YAML config optimization.

**Architecture:** Direct API calls to local Frigate instance. Reads and modifies Frigate's YAML configuration files.

**Security:** LAN-only communication. No camera feeds leave the local network.

**Audience:** Security camera system administrators, smart home integrators.

---

### 10. Sequential Thinking — Cognitive Scaffolding

| Property | Value |
|----------|-------|
| **Package** | `npx -y @modelcontextprotocol/server-sequential-thinking` |
| **Transport** | stdio |
| **Category** | Cognitive Framework |
| **Platform** | Cross-platform (Node.js) |

Anthropic reference implementation for structured reasoning. Not a data tool — a thinking tool that scaffolds complex problem-solving.

**Architecture:** Breaks large problems into manageable sub-steps (thoughts). Supports revision (`isRevision`, `revisesThought`) and branching (`branchFromThought`) for exploring alternatives.

**Security:** Pure computation; no external data access.

**Audience:** AI agent developers, general LLM users tackling complex multi-step problems.

---

## Deployment Patterns

| Pattern | Command | Used By |
|---------|---------|---------|
| **npx (Node.js)** | `npx -y <package>` | local-mcp, chrome-devtools-mcp, duckduckgo-mcp, db-mcp-server, wardn-mcp, sequential-thinking |
| **uvx (Python)** | `uvx <package>` | dotmd, searxng-mcp, ha-mcp, frigate-mcp |
| **Docker Compose** | `docker compose up -d` | Equibles (self-hosted financial data) |

### Claude Desktop Config Example

```json
{
  "mcpServers": {
    "local-mcp": {
      "command": "npx",
      "args": ["-y", "local-mcp"]
    },
    "dotmd": {
      "command": "uvx",
      "args": ["dotmd"]
    },
    "chrome-devtools": {
      "command": "npx",
      "args": ["-y", "chrome-devtools-mcp"]
    }
  }
}
```

## Integration with MCPRadar

These servers are listed in the [MCPRadar Security Leaderboard](https://yatuk.github.io/mcpradar/) with:
- **MRS security scores** computed from static + behavioral analysis
- **Scope tags** including `local-first` for API-free servers
- **Category filters** for Desktop Automation, Knowledge/RAG, Browser/DevTools, IoT/Smart Home, Security
- **Vulnerability type filters** (Command Injection, Path Traversal, Schema Poisoning, etc.)

See also:
- [Enterprise Integration Guide](enterprise.md) — SIEM/Splunk/Elastic ingestion
- [Detection Rules](detection-rules.md) — How MCPRadar finds vulnerabilities
- [CLI Reference](cli-reference.md) — Full CLI command documentation

## References

- [Model Context Protocol Specification](https://modelcontextprotocol.io)
- [MCP Server Registry](https://registry.modelcontextprotocol.io)
- [Reddit r/LocalLLaMA](https://reddit.com/r/LocalLLaMA) — Community discussion on local MCP servers
- [Reddit r/ClaudeCode](https://reddit.com/r/ClaudeCode) — User experiences with API-free servers
