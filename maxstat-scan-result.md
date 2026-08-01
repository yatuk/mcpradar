## MCPRadar Scan Results — MaxStat MCP

**Scan Date:** 2026-08-01
**Scanner Version:** v1.1.0-rc1
**Target:** `https://maxstat.ru/api/mcp`
**Registry ID:** `io.github.fbmdata/maxstat-mcp` (v1.2.3, active)
**Repository:** `https://github.com/fbmdata/maxstat-mcp`
**Grade:** **C · 3.0/10** — 0 critical / 0 high / 0 medium, 25 low

---

### 🐳 How the authenticated scan was run

The endpoint requires an `X-API-Token` header, which MCPRadar's HTTP transport cannot supply directly. Rather than send credentialed traffic from the host, the scan was bridged through `mcp-remote` **inside a disposable container**:

```
mcpradar scan "npx -y mcp-remote@latest https://maxstat.ru/api/mcp --header X-API-Token:<TOKEN> --transport http-only" \
  --transport stdio --sandbox --sandbox-network bridge --allow-unrestricted-egress -s low
```

`--sandbox` gives `node:22-slim` pinned by digest, `--cap-drop ALL`, `no-new-privileges`, a non-root user, pids/memory/CPU limits, and an ephemeral tmpfs filesystem that vanishes with the container. The token existed only in the container's process arguments and was never written to this repository — verified by grep over the full tree.

**Probing was deliberately skipped.** Tool calls here consume paid credits and `create_*_subscription` would register real webhooks, so only schema-level analysis was performed.

### ✅ Live Protocol Scan — **21 tools enumerated**, 0 medium+ findings

Protocol version negotiated: `2025-11-25`. Capabilities: `tools` only (`listChanged: false`); no prompts, resources, or resource templates. **`server_instructions` is empty** — no server-level instruction block to hide anything in.

All 21 tool descriptions are plain analytics documentation (cost banner + response example). **No tool poisoning, no hidden instructions, no zero-width characters, no cross-server references, no shadowing.**

**25 low-severity findings, all schema hygiene:**

| Rule | Count | Tools | What it means |
|------|-------|-------|---------------|
| `R114` Unbounded input | 21 | `search_channels`, `search_posts`, `get_channel_*`, `get_post_*`, `get_subscriptions`, `update_subscription` | String params (`search`, `date_from`, `subscription_type`, `callback_url`) carry no `maxLength` / `pattern` |
| `R109` Schema poisoning indicator | 4 | `get_account_usage`, `search_channels`, `search_posts`, `get_subscriptions` | No required fields — empty input is acceptable |

The `R109` hits are effectively **false positives**: these are listing/search endpoints where every parameter is legitimately optional. The `R114` hits are real but minor — worth adding `maxLength` to the free-text `search` fields and `format: "date"` to the `date_from` / `date_to` params.

One genuine nit: `update_subscription.callback_url` declares `format: uri` inside its `anyOf` branch, but the flattened top-level `type: "string"` drops it — so a client reading only the outer type loses the URI constraint. `create_channel_subscription` gets this right (`format: uri`, `minLength: 1`, required).

### ✅ Source Code Analysis — **CLEAN** (0 findings)

`mcpradar scan-source` over the cloned repository: **2 source files** (`scripts/*.mjs`), **0 findings**. No zero-width characters, prompt-injection markers, or committed credentials in `README.md`, `SKILL.md`, or the client config templates. The server implementation itself is hosted and closed-source, so the tool handlers cannot be statically analyzed.

### ✅ Configuration Scan — **CLEAN** (0 findings)

5 manifests — `server.json`, `plugins/maxstat/.mcp.json`, `configs/claude-desktop.json`, `gemini-extension.json`, `.claude-plugin/marketplace.json` — all well-formed with standard `$schema` references. The API token is referenced through an environment placeholder everywhere, never inlined. Positive signal: the repo ships its own CI check (`validate-integrations.mjs`) that fails the build on token-like values committed to the tree.

### 🔒 Transport & Auth Posture

| Check | Result |
|-------|--------|
| Transport | `streamable-http` |
| Auth | Static API key via `X-API-Token` header (`isSecret: true` in registry) |
| Token in URL? | ❌ No — header only; unauthenticated `GET` also rejected with 401 |
| HTTP → HTTPS | ✅ 301 redirect |
| Hosted on | Yandex Cloud (`server: ycalb`) |
| Dependencies | Zero third-party runtime deps, no lockfile — nothing for OSV to check |

**Security headers on the API endpoint:** `HSTS`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and `CSP` are all absent. Not exploitable for a JSON API consumed by an MCP client, but `Strict-Transport-Security` and `nosniff` are cheap hardening.

### 📉 Why C and not A, with zero medium+ findings

The score is **not** driven by findings — the breakdown is `base 0.0`, `weighted_findings 0`, `dep_risk 0.0`. It comes entirely from the **capability term**: `aars 6.0`, `capability_term 3.0`, `driver: capability`. MCPRadar classifies the server as `db_write` because `add_channel`, `create_channel_subscription`, `create_keyword_subscription`, `update_subscription`, and `delete_subscription` mutate server-side state. A read-only analytics server with the same clean findings would grade A.

### ⚠️ Callback URL surface

Three tools accept a caller-supplied `callback_url`. The schema requires HTTPS-shaped URIs, but schema validation is not egress control — whether the server refuses to POST to RFC1918 ranges or `169.254.169.254` can only be confirmed server-side. **Recommendation for the maintainer:** enforce an egress allowlist and reject internal/link-local callback targets at subscription-creation time.

### 📊 Leaderboard Status

Listed on the [MCPRadar leaderboard](https://yatuk.github.io/mcpradar/leaderboard/) with status **`scanned`**, coverage `live`, grade **C · 3.0/10**, confidence 1.0. Badge: `docs/leaderboard/badges/io.github.fbmdata-maxstat-mcp.svg`.

### 📋 Summary

| Check | Result |
|-------|--------|
| Live (protocol) | ✅ 21 tools, 0 medium+ findings, 25 low |
| Source (static) | ✅ Clean |
| Config (manifests) | ✅ Clean |
| Dependencies (OSV) | N/A — no runtime deps / lockfile |
| Security headers | ⚠️ Minimal |

### 🔮 Recommendation

MaxStat MCP is a **clean, well-documented MCP server**. Nothing found that would put a user's agent at risk: no poisoning, no hidden instructions, correct secret handling, sane schemas with real constraints on most numeric fields. The C grade reflects its write capability, not a defect. Suggested improvements — `maxLength` on free-text search fields, `format: date` on date params, a top-level `format: uri` on `update_subscription.callback_url`, callback egress allowlisting, and standard security headers.

---

🤖 Scanned with [MCPRadar](https://github.com/yatuk/mcpradar) v1.1.0-rc1
