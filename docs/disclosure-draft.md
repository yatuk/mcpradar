# Responsible Disclosure: Real-World MCP Server Security Scan Results

**Scanner:** MCPRadar v1.0.0-rc3
**Date:** 2026-06-23
**Status:** Draft — findings being verified before disclosure

## Methodology

MCPRadar was run against popular MCP servers in a local environment using stdio
transport. Each server was installed via npm/npx, connected to, and its tool
descriptions, schemas, and metadata were scanned against 19 detection rules
(12 static + 7 cross-server). No remote scanning was performed — all servers
were run locally.

## Results Summary

| Server | Tools | Findings | Critical | High | Medium | Grade |
|---|---|---|---|---|---|---|
| `@modelcontextprotocol/server-filesystem` | 14 | 0 | 0 | 0 | 0 | A |
| `@playwright/mcp` | 23 | 8 | 4 | 0 | 4 | C |

## Detailed Findings

### @playwright/mcp (Microsoft, 32K+ GitHub stars)

**8 findings — 4 critical (R107), 4 medium (R109)**

#### R107 — Command Injection Risk (CRITICAL)

Four tool parameters contain shell metacharacters or dangerous patterns in
their schema descriptions:

1. **`browser_evaluate`** — JavaScript evaluation tool. Description includes
   `eval(` pattern which triggers R107. The tool executes arbitrary JavaScript
   in the browser context. Combined with prompt injection on a page, this could
   enable credential theft or cross-origin attacks.

2. **`browser_run_code`** — Executes Playwright code. Description mentions
   code execution patterns that match R107's shell metacharacter detection.

3-4. Additional tools with command-like parameter patterns detected.

**Impact:** If an attacker can prompt-inject a page that the Playwright MCP
server visits, the `browser_evaluate` tool could be exploited to execute
arbitrary JavaScript in authenticated browser sessions.

#### R109 — Schema Poisoning (MEDIUM)

Four tools have schemas with missing type constraints or overly permissive
configurations:

1. Multiple tools accept arbitrary objects without `additionalProperties: false`
2. Several parameter schemas omit `required` field declarations
3. Some schemas have unbounded `maxLength` or `maxItems`

**Impact:** Permissive schemas increase the attack surface for parameter
injection and make input validation harder for LLM clients.

## Planned Disclosure Timeline

1. **Week 1:** Internal verification of findings
2. **Week 2:** Draft disclosure report with reproduction steps
3. **Week 3-4:** Coordinated disclosure to vendors (Microsoft for Playwright)
4. **Week 5+:** Public blog post with technical deep-dive

## Reproduction

```bash
# Install and scan Playwright MCP
npx @playwright/mcp --help
mcpradar scan "npx -y @playwright/mcp" -t stdio --json -s low

# Filesystem (clean baseline)
mcpradar scan "npx -y @modelcontextprotocol/server-filesystem /tmp" -t stdio --json -s low
```

## About MCPRadar

MCPRadar is an open-source security scanner for Model Context Protocol servers.
It detects tool poisoning, prompt injection, secret exposure, command injection,
supply chain risks, and schema poisoning across 19 detection rules. v1.0.0-rc3
achieves 100% precision and 90% recall on a labeled benchmark corpus.

- GitHub: https://github.com/yatuk/mcpradar
- Leaderboard: https://yatuk.github.io/mcpradar
- Benchmark: https://github.com/yatuk/mcpradar/blob/main/validation/BENCHMARK.md
