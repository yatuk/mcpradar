# Changelog

All notable changes to MCPRadar will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added
- **Package fetch** — `scan-source`, `scan-config`, and `deps` now accept a
  package reference in place of a local path: `npm:<pkg>`, `pip:<pkg>`, or a
  GitHub URL / `gh:owner/repo`. The distribution is downloaded and extracted
  from the registry (npm tarball / PyPI sdist) or shallow-cloned — never
  *installed* — so no `postinstall` / `setup.py` lifecycle script runs, and an
  untrusted package can be scanned safely. Archive extraction is path-traversal
  safe. Makes `mcpradar deps npm:@modelcontextprotocol/server-filesystem` work
  end to end. New module `src/mcpradar/fetch/`.

### Changed
- **Capability-aware AIVSS scoring** — the leaderboard could not discriminate
  (51 A / 2 B / 2 C across 55 servers, avg 0.20/10); an arbitrary-shell-execution
  server scored the same grade A as a calculator because a tool's *capability*
  was not an input. Scoring now follows the OWASP AIVSS structure
  `((base + AARS) / 2) × ThM`: the finding-derived base is combined with an
  agentic-capability layer (AARS) tagging each tool's blast radius
  (`code_exec`/`browser_control`/`db_write`/`fs_write`/`secret_access`/
  `net_egress`/`fs_read`/`pure_compute`), floored so capability can only raise
  risk. Same 55 servers → **15 A / 21 B / 18 C / 1 D**, avg 2.00; `mcp-shell`
  → C, `mcp-server-filesystem` → B (schema + fs-write, not a CVE),
  `mcp-server-calculator` → A. New module `src/mcpradar/scoring/capability.py`;
  model in `docs/scoring-model.md`, root cause in `docs/rootcause.md`.
- **R109 `additionalProperties: true` downgraded to LOW** — it fired on every
  tool of flexible-schema servers, drowning real signal; the capability layer
  now carries the actual risk.

### Fixed
- **Enumeration robustness** — `tools/list` is now cursor-paginated with a hard
  page cap, per-tool rule errors are isolated (a crashing rule no longer drops
  the remaining tools), and a partial/failed enumeration is marked `incomplete`
  instead of being scored a clean grade A ("scan incomplete" on the site).
- **Positive/negative controls** — `demo/malicious_server.py` is scanned into
  the leaderboard (grade F) and a `benign_server` fixture (grade A, 0 critical)
  anchors the clean end. A scoring-calibration regression gate enforces both and
  runs before the leaderboard is published in CI.

### Added
- **S010 — token passthrough / confused deputy**: `scan-source` flags a handler
  that forwards the *incoming* request's Authorization token into an *outbound*
  HTTP call (`requests`/`httpx` with `headers={"Authorization": request.headers[...]}`,
  including via an intermediate variable or an `f"Bearer {tok}"` wrapper). Token
  passthrough is forbidden by the MCP spec and is the confused-deputy root cause.
  Light intra-function taint keeps it precise: the server using its **own**
  credential (`os.getenv(...)`) or reading a non-auth header is not flagged.
- **S009 — network exposure (`0.0.0.0` bind / DNS rebinding)**: `scan-source`
  now flags a server binding to all interfaces (`host="0.0.0.0"`/`"::"`,
  `socket.bind(("0.0.0.0", …))`, `mcp.settings.host = "0.0.0.0"`). A local-only
  MCP server reachable over the network enables DNS-rebinding RCE — the class
  behind CVE-2025-49596 (MCP Inspector) and the "0.0.0.0-day" advisory
  (~200k exposed instances). Loopback binds are not flagged.
- **T001 — typosquatting detection**: `scan-config` resolves the package a
  server launches (`npx -y <pkg>`, `uvx <pkg>`, …) and flags names that closely
  resemble a curated list of popular MCP packages via bounded Levenshtein
  distance (`twittter-mcp` → `twitter-mcp`, `@modlecontextprotocol/...` → the
  official scope). Exact known names and unrelated names are not flagged. New
  module `src/mcpradar/supply/typosquat.py`.
- **Config poisoning scan (`mcpradar scan-config <path>`)**: inspects MCP /
  agent config files (`claude_desktop_config.json`, `.mcp.json`,
  `.cursor/mcp.json`, `.vscode/mcp.json`, `.claude/settings.json`, …) for the
  "malicious server / poisoned hook added to your config" threat that
  server-side scanning cannot see. New `M` rule namespace: M001 download-to-shell
  RCE (curl|bash), M002 base64-decode-to-shell, M003 credential read + network
  egress, M004 exfiltration to a known collector host, M005 reverse shell, M006
  over-broad permission (`Bash(*)`, `bypassPermissions`), M007 destructive
  launch command. Scans MCP server launch commands, agent hook commands, and
  permission grants. New module `src/mcpradar/config_scan/`, 13 tests.
  (Inspired by patterns in Pantheon-Security/medusa.)
- **Trojan Source detection (S008)**: `scan-source` now flags bidirectional-
  control and invisible unicode (CVE-2021-42574) in source — code that does not
  read the way it executes. Runs on raw text, so it fires even when the file
  won't parse.
- **Dependency vulnerability scan (`mcpradar deps <path>`)**: the end-to-end
  SBOM → OSV path. Resolves a server's dependency list from its manifests
  (package.json / package-lock.json / requirements.txt / pyproject.toml /
  uv.lock, preferring lockfiles for exact versions), batch-queries the OSV.dev
  database, hydrates each advisory via `/vulns/{id}`, and reports every
  known-vulnerable dependency as a **D001** finding. Severity is the real CVSS
  v3.x base score computed from the advisory vector (with a GitHub-Advisory
  label fallback). `--list` prints resolved dependencies offline. Verified
  against the Appsecco `outdated-packages` server (82 advisories) and
  `malicious-code-exec` (10, incl. 3 CVEs in an old `@modelcontextprotocol/sdk`).
  New module `src/mcpradar/supply/`, `OSVClient.get_vuln` + CVSS scorer, 12 tests.
- **Source-code analysis (`mcpradar scan-source <path>`)**: static AST analysis
  of MCP server Python source, no server execution required. New `S` rule
  namespace:
  - S001 cloud-metadata SSRF (169.254.169.254 / metadata.google.internal)
  - S002 outbound request to an attacker-controllable host (host-pinned URLs
    are not flagged)
  - S003 unsafe deserialization (pickle / `yaml.load` without SafeLoader /
    marshal)
  - S004 dynamic code execution (`eval`/`exec` on a non-literal)
  - S005 SQL injection (`execute()` built with an f-string / concat / %-format)
  - S006 shell execution (`subprocess(..., shell=True)` / `os.system` / `os.popen`)
  - S007 **Description-Code Inconsistency** — a tool that presents as read-only
    (get/list/read/search…) whose handler writes to disk or executes commands.
    Network I/O is deliberately not a DCI signal (a read tool fetching from an
    API is normal), keeping the false-positive rate low.
  New module `src/mcpradar/source/`, 18 tests. Verified against the Appsecco
  corpus (wikipedia server: 0 false positives after the host-pinning and
  network-DCI guards).
- **Container sandbox (`--sandbox`)**: Untrusted stdio servers now run in a
  disposable Docker/Podman container during a scan — egress locked
  (`--network none` by default), ephemeral filesystem (`--rm` + tmpfs), all
  capabilities dropped, `no-new-privileges`, and bounded pids/memory/cpu. The
  working directory is mounted read-only at `/workspace`. New
  `--sandbox-image` and `--sandbox-network` flags; the base image is
  auto-picked (python:3.12-slim / node:22-slim) from the launch command.
  New module `src/mcpradar/sandbox/`, 21 tests.

### Fixed
- **R109 (schema poisoning) false positives** surfaced by scanning real
  servers (yatuk/itu-mcp, 55 tools):
  - No longer scans **output** schemas — `additionalProperties: true` there is
    not an injection surface and structured-output frameworks (FastMCP) emit it
    for every dict-returning tool. This fired a HIGH on all 55 itu-mcp tools.
  - "No required fields" downgraded from MEDIUM to LOW — a tool accepting
    optional input is common and benign, not schema poisoning.
  - "Missing type" now recognizes `anyOf`/`oneOf`/`allOf`/`$ref`/`enum`/`const`
    as valid typing; Pydantic/FastMCP emit `anyOf: [{type: X}, {type: null}]`
    for every `Optional[...]` param, which was wrongly flagged 32× on itu-mcp.
- **Leaderboard deduplication**: the catalog carried 39 servers under two
  filename conventions, rendering as duplicate rows. The generator now
  deduplicates by server name, keeping the scanned copy over a pending stub
  (145 result files → 103 unique servers).
- **Leaderboard honesty**: 139 of 144 catalog entries had never actually been
  scanned yet were shown as clean grade-A passes. The generator now marks any
  result without scan evidence (no tools, scan id, or timestamp) as `pending`
  with no grade; the site renders these as "not scanned", sorts them to the
  bottom, excludes them from averages, and adds a scanned/pending filter.
- **Leaderboard grading** now scores on MEDIUM+ findings only (matching the
  accuracy benchmark). LOW informational lint (e.g. R114) is surfaced as a
  separate count but no longer drags clean reference servers toward a failing
  grade — the official filesystem server went from a bogus grade F (45 findings)
  to a defensible grade B (5 schema-laxity findings).
- **R107 (command injection)** no longer scans property `description` fields for
  shell metacharacters — those are prose/Markdown docs where backticks and
  operators appear legitimately, which produced CRITICAL false positives on
  well-documented servers (e.g. 4 on @playwright/mcp). It now scans only value
  fields (`default`, `example`); payloads hidden in prose remain R102/R104's job.
- **R107 (command injection)** had 0% recall on real servers: the
  dangerous-default check compared a lowercased value against a mixed-case set
  and used exact matching, so entries like `DROP TABLE` were unreachable and
  variants like `rm -rf /tmp/cache` never matched. Replaced with a
  case-insensitive prefix regex.
- **R106 (secret exposure)** flagged URL path segments as CRITICAL secrets —
  the "base64-like" pattern claimed an entropy check it never applied. Now
  gated on Shannon entropy > 4.5 and reported at HIGH.
- **R113 (path traversal)** over-reported: schema-constraint-absence findings
  demoted to LOW (MEDIUM for write-capable tools), and traversal-language
  matches inside protective documentation ("prevents path traversal") are no
  longer flagged.

### Changed
- **Benchmark**: `validation/` now scans an 11-target corpus (demo server + 3
  official reference servers as negative controls + 7 Appsecco lab servers)
  instead of a single self-made target. Metrics computed on MEDIUM+ findings;
  statically-undetectable classes labeled as known limitations. Measured:
  precision 87.5%, recall 100%, F1 0.93.

## v1.0.0-rc3 — 2026-06-23

### Added
- **R112 — Authorization Hardening**: New rule for 2026-07-28 spec compliance.
  Detects missing `iss` parameter (RFC 9207), missing `application_type` in
  Dynamic Client Registration, and deprecated `Mcp-Session-Id` header usage.
- **R111 — Mcp-Method/Mcp-Name header checks**: Extended transport security
  checks to verify required headers on Streamable HTTP responses.
- **Real-world scan results**: `@playwright/mcp` (23 tools, 8 findings — 4
  critical R107, 4 medium R109). `@modelcontextprotocol/server-filesystem`
  confirmed clean (14 tools, 0 findings).

### Changed
- **Engine**: Replaced deprecated `streamablehttp_client` import with
  `streamable_http_client` (MCP SDK 1.28+).
- **README**: Removed phantom features — scan-source, AST+Semgrep,
  typosquatting, sandbox containers marked as planned v1.1.
  Added "What's Real vs Planned" section. Comparison table updated with
  `🔜 planned` tags.
- **Version**: 1.0.0-rc2 → 1.0.0-rc3.

### Added (v1.0.0-rc2)
- **Registry API client**: Official MCP Registry integration at
  `registry.modelcontextprotocol.io`. New commands: `mcpradar registry fetch`,
  `mcpradar registry list`.
- **AIVSS scoring engine**: 0-10 score with A-F letter grades and confidence
  ratings. `mcpradar leaderboard generate` command with automated scoring.
- **Leaderboard v2**: No placeholder entries, AIVSS scores, grade badges,
  sortable/filterable HTML table, reproducibility metadata (tool hash, version).
- **Precision/Recall benchmark**: Measured 100% precision, 90% recall, 94.7%
  F1 on labeled demo corpus. Benchmark runner at `validation/run_benchmark.py`.
- **FP reduction**: Fixed R107 shell metachar regex (removed bare `[|><]`
  character class), R108 documentation context suppression, R105 bridge
  keywords expansion (10→18 terms).

## v1.0.0-rc1 — 2026-06-23

### Added
- **Parallel scanning**: `ParallelScanner` class with `asyncio.Semaphore` — scan multiple MCP servers concurrently
  - `mcpradar scan-all --parallel --max-concurrency 5`
- **SBOM export**: CycloneDX 1.5 JSON generation via `mcpradar sbom [-o output.json]` (zero dependencies, stdlib only)
- **Documentation**: 4 new pages — getting-started, cli-reference, ci-integration (GitHub Actions, GitLab CI, CircleCI, pre-commit), owasp-mapping
- **Performance benchmarks**: 3 benchmark tests (rule engine latency, SARIF generation, SQLite batch insert)

### Changed
- **Validation pipeline**: Async `ValidationRunner` with precision/recall/F1 metrics and per-rule breakdown
- **README**: Updated status badge (Alpha → Release Candidate), Sprint 6 marked complete, OWASP 10/10 coverage confirmed
- **SECURITY.md**: Added supported versions table
- **pyproject.toml**: Version 1.0.0-rc1, Development Status 5 - Production/Stable, coverage config added, pytest-benchmark dev dependency

### Infrastructure
- OWASP MCP Top 10: 10/10 full coverage ✅
- 400+ tests passing
- Coverage configuration with `[tool.coverage]` in pyproject.toml
- Zero new runtime dependencies

## v0.6.0 — 2026-06-23

### Added
- **Audit trail** (`src/mcpradar/audit/`): Structured audit event logging for all scan, diff, and alert operations (OWASP MCP08)
  - `AuditEvent` dataclass with event_id, timestamp, event_type, severity, target, detail
  - `AuditLogger` with convenience methods: `log_scan_start`, `log_scan_complete`, `log_diff`, `log_alert`, `log_error`
  - Query by time range, event type, and target; export to JSON/JSONL/CSV
- **Statistics engine** (`src/mcpradar/audit/stats.py`): Per-server and global security statistics with 30-day trend analysis
  - `server_stats(target)`: total scans, findings by severity, top triggered rules, recent diffs
  - `global_stats()`: aggregate across all targets, top scanned targets, top rules
  - `trend_analysis(target, days)`: improving/worsening/stable direction with per-severity trends
- **NVD API 2.0 integration** (`src/mcpradar/cvefeed/syncer.py`): Automated CVE synchronization from NVD
  - `NVDAPISyncer` class with keyword search, pagination, exponential backoff on rate limits
  - CVSS v3.1/v3.0 severity extraction from NVD JSON responses
  - Local JSON cache with merge-on-update semantics
- **Enhanced CVE matching**: Multi-factor scoring (40% keyword Jaccard + 40% CWE mapping + 20% severity correlation)
  - `CVEMatch` dataclass with scored, deduplicated results
  - `RULE_CWE_MAPPING`: 21 rule IDs mapped to CWE IDs
- **New CLI commands**:
  - `mcpradar audit [--target] [--type] [--since] [--limit] [--json] [--export]` — View and export the audit trail
  - `mcpradar stats [target] [--days] [--json]` — Security statistics and trend analysis
  - `mcpradar cve sync` — Full NVD API synchronization
  - `mcpradar cve match <scan_id> [--min-score]` — Match scan findings to CVEs
  - `mcpradar cve list [--severity] [--search] [--limit]` — List cached CVEs
  - `mcpradar feed-update --full` — NVD API sync via existing command

### Changed
- **Scanner** (`engine.py`): Added optional `audit` parameter — emits `scan_started` and `scan_completed` events
- **Watcher** (`watcher.py`): Added optional `audit` parameter — emits `diff_detected` and `alert_sent` events
- **Store** (`store.py`): Added `audit_log` table with indexes and CRUD methods (`save_audit_event`, `query_audit_events`, `delete_audit_events`, `purge_audit_log`)
- **CVE feed** (`cvefeed/syncer.py`): `match_findings_to_cves()` now returns `list[CVEMatch]` with multi-factor scoring

### Infrastructure
- OWASP MCP08 (Lack of Audit & Telemetry): ✅ Covered
- 395+ tests passing (362 existing + 38 new)
- Zero new dependencies (stdlib + existing httpx, rich, typer)

## [0.5.0] - 2026-06-23

### Added
- **Runtime probing engine** (`src/mcpradar/probe/`): Safe runtime execution of read-only MCP tools
  - `ReadOnlyProber`: Identifies safe tools by name pattern, calls them with minimal args, analyzes responses
  - `SandboxValidator`: Pre-probe argument safety validation — rejects forbidden values, deep nesting, long strings
  - `ProbeResult`: Captures response metadata — URLs, scripts, secrets (R106 re-run), prompt injection (R102 re-run)
  - CLI: `mcpradar probe <target> --safe-only` with Rich table output and `--json` support
- **C006 — Attack Path Chain** (MCP03/MCP10): Graph-based cross-server attack path detection
  - Schema type matching between tool outputs and inputs across servers
  - BFS chain enumeration with classification: exfiltration (CRITICAL), command injection (CRITICAL), long chains (HIGH)
  - Manual graph algorithms — zero new dependencies (`collections.deque` BFS)
- **C007 — Privilege Escalation** (MCP02): Read-only → write/exec cross-server chain detection
  - Direct edge and multi-hop path detection for read-to-write escalation
- **Risk scoring**: 0–100 score per server group (severity-weighted + server density + tool density)
- **GraphViz DOT output**: `analyze-context --deep --graph risk.dot` with color-coded nodes
- **CLI**: `mcpradar probe` command, `analyze-context --deep` and `--graph` flags

### Changed
- `ContextAnalyzer` now accepts `deep: bool` parameter for C006/C007 activation
- `ContextAnalysisReport` includes `risk_score` and `attack_graph_dot` fields
- `ScanReport` includes `probe_results` field for runtime probe data
- `Scanner` supports optional `prober` parameter for runtime tool probing
- `SARIF` RULE_HELP expanded to 14 entries (R001–R111 + C001–C007)

### Fixed
- CI ruff format compliance — all files auto-formatted

## [0.4.0] - 2026-06-23

### Added
- **fingerprint** CLI command group: `mcpradar fingerprint {create,compare,list}`
- Fingerprint system: `Fingerprinter` (SHA256-based server identity), `TransportChecker` (TLS/cert/HSTS validation)
- `ServerFingerprint` and `TLSInfo` data models
- 2 new detection rules:
  - R110: Version Anomaly Detection — version rollback, major upgrade, tool list change detection
  - R111: Insecure Transport Detection — plain HTTP, old TLS, expired cert, self-signed cert, missing HSTS
- `ScanReport`: `server_version`, `protocol_version`, `capabilities` fields added
- `Scanner`: Captures server identity info from `initialize()` response
- `Store`: `fingerprints` table + CRUD (save/load/list/delete)
- `DiffDelta`: `fingerprint_changes` field (version, protocol, capabilities, tool count changes)
- `RuleEngine.pre_scan_check()`: fingerprint-based pre-scan check hook

### Security
- OWASP MCP07 (Insufficient AuthN/AuthZ): Covered by R111 (transport security)
- OWASP MCP09 (Shadow MCP Servers): Covered by R110 + fingerprint system

## [0.3.0] - 2026-06-23

### Added
- **plugin** CLI command group: `mcpradar plugin {init,validate,list,install,uninstall}`
- Plugin system: `PluginManager` (pip install/uninstall), `PluginValidator` (6-stage validation), `Scaffolder` (template-based package generation)
- `plugins/mcpradar-rule-deprecated/` — 2nd example community plugin (X002: Deprecated/legacy API pattern detection)
- Template tests: `plugins/template/tests/test_rule.py`
- Plugin CLI tests: `tests/test_plugin_cli.py` (11 tests)

### Changed
- `plugins/template/`: test directory added, used as scaffolder source

## [0.2.0] - 2026-06-23

### Added
- 4 new detection rules:
  - R106: Secret/Token Exposure — 16 known secret format regexes + Shannon entropy-based detection
  - R107: Command Injection via Tool Parameters — recursive schema walk for shell metacharacters, dangerous default values, and command-like enum detection
  - R108: Supply Chain Risk Indicator — curl-bash, pip/npm install, eval/exec, dynamic code loading detection
  - R109: Schema Poisoning Indicator — additionalProperties:true, missing type constraints, excessive maxLength/maxItems detection
- Helper functions: `_shannon_entropy()`, `_decompose_name()`, `_walk_schema_props()`, `_collect_all_texts()`
- R105 Permission Scope Mismatch improvements: 10+ scope pairs, bridge keyword suppression, snake_case/camelCase name decomposition

### Changed
- R105: LOW severity downgrade removed, replaced with bridge keyword + name decomposition based false positive suppression
- R105: minimum severity fixed at MEDIUM
- E2E mock server `safe_tool`: `required` field added to schema (R109 compliance)

### Security
- OWASP MCP01 (Token Mismanagement): Covered by R106
- OWASP MCP04 (Supply Chain): Covered by R108
- OWASP MCP05 (Command Injection): Strengthened with R107
- OWASP MCP03 (Tool Poisoning): Expanded with R109

## [0.1.0] - 2026-05-25

### Added
- **scan** command — HTTP, SSE, stdio transport support via MCP Python SDK
- **diff** command — schema-aware comparison with cosmetic/behavioral/security classification
- **watch** command — periodic scanning with webhook and shell command alerts
- **list** / **show** / **export** / **purge** — SQLite snapshot browser commands
- **init** command — `mcpradar.toml` config file generator
- **scan-all** command — scan all servers defined in config file
- **registry-scan** command — public MCP server leaderboard generation
- 6 detection rules:
  - R001: Dangerous tool name (eval, exec, rm, curl...)
  - R101: Zero-width Unicode character detection (ZWSP, LRM, BOM)
  - R102: Prompt injection pattern detection (10 patterns)
  - R103: Encoded blob detection (base64/hex)
  - R104: Hidden HTML/Markdown content detection
  - R105: Permission scope mismatch detection
- SARIF v2.1.0 output format for GitHub Code Scanning integration
- SQLite snapshot storage with platformdirs for default path
- Rich terminal output with git-diff style diff visualization
- UTF-8 enforcement on Windows + Turkish localization
- Config file reading pipeline (TOML) via `mcpradar/config.py`
- Extensible rule engine — subclass `Rule`, implement `check()`, register
- Mock MCP server (`demo/malicious_server.py`) — triggers all 6 rules
- E2E tests with memory-stream MCP protocol round-trip
- Theme-aware logo (light + dark SVG) via `<picture>` element
- GitHub Actions CI matrix: Python 3.11/3.12/3.13 × ubuntu/macos/windows
- Pre-commit hooks (ruff, mypy)
- Release workflow (tag → PyPI publish + GitHub Release)
- Validation pipeline (`validation/`) with auto-triage
- Documentation: architecture, detection rules, contributing guide, threat model
- Community files: CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, issue templates
