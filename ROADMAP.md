# MCPRadar Strategic Development Roadmap

> **Last update:** 2026-06-25 · **Current version:** v1.0.0-rc3 · **Target:** v1.0.0 (GA)

---

## Vision

MCPRadar aims to become the **reference security tool** for the Model Context Protocol (MCP) ecosystem. An open source standard that every MCP server developer runs in their CI pipeline and every enterprise security team consults when auditing AI agents.

## Mission

Catch tool poisoning, prompt injection, supply-chain rug pull, and cross-server contamination attacks **before the LLM agent makes a tool call**. Make deterministic, CI-friendly, SARIF-compliant security scanning a natural part of the developer workflow.

---

## Current Status — v0.1.0 (2026-05-25)

### Completed Features

| Component | Status | Detail |
|---|---|---|
| Detection rules | ✅ 6 rules | R001, R101, R102 (10 patterns), R103, R104, R105 |
| Transport layer | ✅ 3 protocols | HTTP (streamable), SSE, stdio |
| Database | ✅ SQLite (WAL) | scans, tools, prompts, resources, findings tables |
| Diff engine | ✅ 3 levels | cosmetic / behavioral / security classification |
| Output formats | ✅ 3 formats | Rich terminal, JSON, SARIF v2.1.0 |
| CI/CD | ✅ Full matrix | Python 3.11–3.13 × ubuntu/macos/windows |
| PyPI publish | ✅ OIDC | GitHub Actions → PyPI trusted publishing |
| Plugin discovery | ✅ Basic | `entry_points(group="mcpradar.rules")` auto-loading |
| Cross-server analysis | ✅ 5 rules | C001–C005 (basic level) |
| CVE feed | ✅ Seed data | 2 MCP-related CVEs, keyword matching |
| Watch mode | ✅ Basic | Periodic scanning + webhook/shell alert |
| Public leaderboard | ✅ GitHub Pages | Static markdown, manual update |
| VS Code extension | ✅ Scaffold | `vscode-mcpradar/` directory |
| Validation pipeline | ⚠️ Targets defined | 10 servers, not yet fully executed |

### OWASP MCP Top 10 (2025) Coverage Matrix

| OWASP ID | Category | Current Coverage | Level |
|---|---|---|---|
| **MCP01** | Token Mismanagement & Secret Exposure | — | ❌ Not covered |
| **MCP02** | Privilege Escalation via Scope Creep | R105 (scope pairs) | 🟡 Basic |
| **MCP03** | Tool Poisoning | R001, R104, C001, C002 | 🟡 Partial |
| **MCP04** | Supply Chain Attacks | — | ❌ Not covered |
| **MCP05** | Command Injection & Execution | R001 (name matching) | 🔴 Minimal |
| **MCP06** | Prompt Injection | R102, R103, R104 | 🟢 Strong |
| **MCP07** | Insufficient AuthN/AuthZ | — | ❌ Not covered |
| **MCP08** | Lack of Audit & Telemetry | — | ❌ Not covered |
| **MCP09** | Shadow MCP Servers | — | ❌ Not covered |
| **MCP10** | Context Injection & Over-Sharing | C001–C005 | 🟡 Partial |

**Coverage rate: 3/10 full coverage, 3/10 partial, 4/10 not covered**

### Competitor Comparison

| Tool | Approach | MCPRadar Differentiator |
|---|---|---|
| **Cisco mcp-scanner** | YARA + LLM + VirusTotal, static only | Transport variety, diff, SARIF, MIT license |
| **Snyk agent-scan** | LLM classifier, CI-focused, platform-dependent | Platform independent, works offline |
| **Pipelock** | Runtime proxy (Go), live traffic | Deterministic, no runtime overhead |
| **Hermes** | Rust, fuzzing + probing, OWASP-compliant | Python ecosystem, simpler rule authoring |
| **agent-audit** | SAST, 40+ rules, taint analysis | MCP transport awareness |
| **MCP Guardian** | Policy-as-code, YAML rules, proxy | Agent-independent, no proxy required |
| **MCPSafetyScanner** | Dynamic fuzzing via LLM agent | Deterministic results, reproducible in CI |

---

## Sprint Plan

All sprints are 2 weeks each. Each sprint targets a version increment and closes specific OWASP coverage gaps.

---

### 🚀 Sprint 1: "Detection Depth" — New Detection Rules

**Target Version:** v0.2.0 · **Duration:** 2 weeks · **OWASP:** MCP01, MCP04, MCP05

#### Goal

Close the three largest OWASP coverage gaps: secret credential exposure (MCP01), dependency manipulation (MCP04), and command injection via parameters (MCP05). 4 new rules and 1 existing rule improvement.

#### New Rules

**R106 — Secret/Token Exposure** (`Severity.CRITICAL`)
- Shannon entropy-based high-entropy string detection
- 15+ known secret format regexes: `sk-*`, `ghp_*`, `xoxb-*`, `eyJ*` (JWT), AWS access key, GitHub token, Slack token, OpenAI key, connection strings
- Tool name, description, input_schema default values, output_schema scanned
- Entropy > 4.5 AND known format → CRITICAL; only entropy > 4.5 → HIGH

**R107 — Command Injection via Tool Parameters** (`Severity.CRITICAL`)
- Recursive walk of `input_schema` properties
- Shell metacharacters: `$()`, `backticks`, `|`, `;`, `&&`, `||`, `>`, `<`
- Dangerous default values: `"rm -rf"`, `"DROP TABLE"`, `"shutdown"`
- Overly broad regex patterns in `pattern`/`regex` fields
- Command-like strings in `enum` values

**R108 — Supply Chain Risk Indicator** (`Severity.MEDIUM`/`HIGH`)
- External package installation references in tool description: `pip install`, `npm install`, `cargo add`
- Running scripts from URLs: `curl \| bash`, `wget -O - \| sh`
- Dynamic code loading: `importlib`, `require()`, `eval()`
- `curl|bash` pattern → HIGH, others → MEDIUM

**R109 — Schema Poisoning Indicator** (`Severity.HIGH`)
- `additionalProperties: true` (open to arbitrary injection)
- Missing type constraints on all parameters
- No required fields (accepting empty input)
- Excessively large `maxLength`/`maxItems` (buffer overflow risk)

**R105 Improvement — Permission Scope Mismatch v2**
- `SCOPE_PAIRS` expansion from 3 pairs to 10+ pairs (crypto/wallet, browser/system, notification/execution)
- snake_case/camelCase tool name parsing (`_decompose_name()` helper)
- Remove LOW downgrade logic, replace with "bridge keyword" check

#### File Changes

| File | Action |
|---|---|
| `src/mcpradar/scanner/rules.py` | R106, R107, R108, R109 classes; R105 expansion; RuleEngine registration |
| `tests/test_rules.py` | 4 new test classes, 80+ test cases |
| `src/mcpradar/output/sarif.py` | RULE_HELP dict expansion |
| `docs/detection-rules.md` | 4 new rule documentation pages |
| `CHANGELOG.md` | v0.2.0 entry |

#### Completion Criteria

- [x] R106: 25+ parameterized tests, 15+ secret format detections
- [x] R107: 20+ tests, shell metacharacter + dangerous default + recursive walk
- [x] R108: 15+ tests, pip/npm/curl-bash patterns
- [x] R109: 15+ tests, schema poisoning vectors
- [x] R105: 10+ new scope pairs, 10+ tests
- [x] mypy strict: zero errors
- [x] CI full matrix passes
- [x] Test coverage for new code ≥ 95%

---

### 🧩 Sprint 2: "Plugin Engine" — Community Rule Ecosystem

**Target Version:** v0.3.0 · **Duration:** 2 weeks · **OWASP:** Cross-cutting (community contribution for all categories)

#### Goal

Transform the existing `entry_points` discovery mechanism into a full-fledged plugin lifecycle management system.

#### New Module: `src/mcpradar/plugin/`

```
src/mcpradar/plugin/
    __init__.py
    manager.py      # PluginManager: install, uninstall, list, metadata
    validator.py    # PluginValidator: schema check, compatibility, test runner
    scaffolder.py   # Scaffolder: generate plugin package from template
```

#### New CLI Commands

```bash
mcpradar plugin init <name> [-o ./plugins]     # Create new plugin skeleton
mcpradar plugin validate <directory>            # Validate plugin structure
mcpradar plugin list                            # List installed community plugins
mcpradar plugin install <package>               # pip install + validate
mcpradar plugin uninstall <package>             # pip uninstall
```

#### Plugin System Features

- **Scaffolder:** Cookiecutter-like template variable substitution; auto-generates `pyproject.toml`, `src/<name>/__init__.py`, `src/<name>/rule.py`, `tests/test_rule.py`, `README.md`
- **Validator:** Entry point presence, Rule class inheritance, rule_id format (X###), test validity
- **Manager:** Plugin metadata extraction (version, author), `_discover_plugins()` integration

#### File Changes

| File | Action |
|---|---|
| `src/mcpradar/plugin/__init__.py` | **New** package |
| `src/mcpradar/plugin/manager.py` | **New** (~200 lines) |
| `src/mcpradar/plugin/validator.py` | **New** (~150 lines) |
| `src/mcpradar/plugin/scaffolder.py` | **New** (~100 lines) |
| `src/mcpradar/cli.py` | `plugin_app` typer subcommands |
| `src/mcpradar/scanner/rules.py` | `_discover_plugins()` metadata enhancement |
| `plugins/template/` | test/, README.md, CI template additions |
| `tests/test_plugin_loading.py` | 20+ new tests |
| `docs/writing-rules.md` | Complete plugin development guide |

#### Completion Criteria

- [x] `mcpradar plugin init` produces a fully working plugin package
- [x] `mcpradar plugin validate` catches errors: missing entry_point, malformed rule_id, no Rule inheritance, import error
- [x] `mcpradar plugin list` shows all plugins with version/author info
- [x] 2 example community plugins (under `plugins/`)
- [x] All existing plugin tests pass unchanged

---

### 🔍 Sprint 3: "Fingerprint & Transport Security" — Server Identity

**Target Version:** v0.4.0 · **Duration:** 2 weeks · **OWASP:** MCP07, MCP09

#### Goal

Fingerprint system to detect shadow MCP servers and unauthorized server changes. Transport layer security validation.

#### New Module: `src/mcpradar/fingerprint/`

```python
@dataclass
class ServerFingerprint:
    server_id: str            # SHA256(endpoint + capabilities + tools_hash)
    endpoint: str
    transport: str
    server_version: str       # from initialize() response
    protocol_version: str
    capabilities: dict
    tool_names_hash: str      # SHA256(sorted tool names)
    tool_count: int
    first_seen: str
    last_seen: str
    tls_info: TLSInfo | None

@dataclass
class TLSInfo:
    version: str              # "TLSv1.3"
    cert_issuer: str
    cert_expiry: str
    cert_valid: bool
    self_signed: bool
```

#### New Rules

**R110 — Version Anomaly** (`Severity.HIGH`)
- Cross-scan: compare with previous fingerprint
- Version downgrade (rollback attack) → CRITICAL
- Unexpected major version jump → HIGH
- First scan (no baseline) → MEDIUM

**R111 — Insecure Transport** (`Severity.HIGH`)
- Plain HTTP (no TLS) → HIGH
- TLS < 1.2 → CRITICAL
- Certificate expired → HIGH
- Self-signed certificate → MEDIUM
- HSTS header missing → MEDIUM

#### New CLI Commands

```bash
mcpradar fingerprint <target>                # Create fingerprint
mcpradar fingerprint --compare <target>      # Compare with baseline
```

#### File Changes

| File | Action |
|---|---|
| `src/mcpradar/fingerprint/__init__.py` | **New** |
| `src/mcpradar/fingerprint/fingerprinter.py` | **New** (~250 lines) |
| `src/mcpradar/fingerprint/transport_check.py` | **New** (~150 lines) |
| `src/mcpradar/scanner/rules.py` | R110, R111 classes; `pre_scan_check()` hook |
| `src/mcpradar/scanner/engine.py` | TransportChecker integration into Scanner |
| `src/mcpradar/storage/store.py` | `fingerprints` table; fingerprint CRUD |
| `src/mcpradar/cli.py` | `fingerprint` command |
| `tests/test_fingerprint.py` | **New** 30+ tests |
| `tests/test_transport_check.py` | **New** 20+ tests |

#### Completion Criteria

- [x] Fingerprint: endpoint hash, version, capabilities, tools hash, TLS info
- [x] Comparison: tool list change, version deviation, endpoint change, TLS downgrade
- [x] TransportChecker: TLS ≥ 1.2, certificate valid, not self-signed, HSTS present
- [x] Fingerprints stored in SQLite
- [x] R110 integrated with diff pipeline

---

### 🔗 Sprint 4: "Deep Cross-Server & Runtime Probing"

**Target Version:** v0.5.0 · **Duration:** 2 weeks · **OWASP:** MCP02, MCP03, MCP10

#### Goal

Elevate cross-server analysis from static name matching to runtime attack path discovery. Safe probing of read-only tools. Increase C-rules from 5 to 7.

#### New Module: `src/mcpradar/probe/`

```python
class ReadOnlyProber:
    """Safely probes MCP tools classified as read-only."""
    SAFE_TOOL_PATTERNS = [r"^(get|list|read|fetch|search|query|browse|show|describe)"]
    MAX_PROBE_COUNT = 20
    PROBE_TIMEOUT = 5.0  # seconds/tool

    async def probe_tool(self, session, tool) -> ProbeResult:
        """Runs the tool with minimal safe input, analyzes the response."""
```

**ProbeResult:** `tool_name`, `success`, `response_time_ms`, `response_preview`, `contains_urls`, `contains_scripts`, `contains_secrets` (R106 re-run), `contains_prompt_injection` (R102 re-run)

#### New Cross-Server Rules

**C006 — Attack Path Chain** (MCP03/MCP10)
- Directed graph of (server, tool) nodes
- Edges: type-based match between tool A's output schema and tool B's input schema
- Detection: "read sensitive" → "send external" (exfiltration chain), "receive input" → "execute command" (RCE chain), chains ≥3 length

**C007 — Privilege Escalation via Cross-Server Chaining** (MCP02)
- Cases where read-only tool output can become write/exec tool input
- Unauthorized privilege escalation paths

#### New CLI

```bash
mcpradar probe <target> --safe-only          # Only probe read-only tools
mcpradar analyze-context --deep              # Full graph analysis
mcpradar analyze-context --graph -o risk.dot # GraphViz output
```

#### File Changes

| File | Action |
|---|---|
| `src/mcpradar/probe/__init__.py` | **New** |
| `src/mcpradar/probe/prober.py` | **New** (~250 lines) |
| `src/mcpradar/probe/sandbox.py` | **New** (~100 lines) |
| `src/mcpradar/analyzer/context.py` | C006, C007; graph builder; risk scorer |
| `src/mcpradar/analyzer/report.py` | `risk_score` field |
| `src/mcpradar/cli.py` | `probe` command; `--deep`, `--graph` flags |
| `src/mcpradar/scanner/engine.py` | Prober integration |
| `tests/test_probe.py` | **New** 30+ tests |
| `tests/test_context_analysis.py` | C006, C007 tests |

#### Completion Criteria

- [ ] Prober safely identifies and runs read-only tools
- [ ] Timeout: does not hang on slow/broken tools
- [ ] ProbeResult re-runs R106 (secrets) and R102 (prompt injection)
- [ ] C006 detects attack chains ≥2 length via type-based edge similarity
- [ ] C007 detects privilege escalation chains across server boundaries
- [ ] Risk score 0-100 calculated for each server group
- [ ] GraphViz DOT output
- [ ] Total 7 cross-server rules (C001–C007)

---

### 📊 Sprint 5: "Audit Trail & CVE Automation"

**Target Version:** v0.6.0 · **Duration:** 2 weeks · **OWASP:** MCP08

#### Goal

Structured audit trail for all scan activities. Automated CVE synchronization from NVD API. Mapping findings to CVEs with CVSS scores. Security statistics and trend analysis.

#### New Module: `src/mcpradar/audit/`

```python
@dataclass
class AuditEvent:
    event_id: str
    timestamp: str          # ISO 8601
    event_type: str         # scan_started, scan_completed, finding_created,
                            #   diff_detected, alert_sent, plugin_loaded, error
    severity: str           # info, warning, error
    target: str
    detail: dict

class AuditLogger:
    def log_scan_start(self, target, transport) -> str: ...
    def log_scan_complete(self, scan_id, findings_count) -> None: ...
    def log_diff(self, server, change_count, security_count) -> None: ...
    def query(self, since, event_type, target) -> list[AuditEvent]: ...
    def export_audit_log(self, path, format="json") -> None: ...

class StatsEngine:
    def server_stats(self, target) -> ServerStats: ...
    def global_stats(self) -> GlobalStats: ...
    def trend_analysis(self, target, days=30) -> TrendReport: ...

class NVDAPISyncer:
    """Syncs MCP-related CVEs via NVD API 2.0."""
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    def search_mcp_cves(self) -> list[CVEEntry]: ...
    def sync_all(self) -> int: ...
```

#### SQLite Schema Expansion

```sql
CREATE TABLE IF NOT EXISTS audit_log (
    event_id    TEXT PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'info',
    target      TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_log(event_type);
```

#### New CLI

```bash
mcpradar audit                            # Recent audit events
mcpradar audit --target <url>             # Filter by server
mcpradar audit --type diff_detected       # Filter by event type
mcpradar stats                            # Global security statistics
mcpradar stats <target>                   # Per-server stats + trend
mcpradar cve sync                         # Full NVD synchronization
mcpradar cve match <scan_id>              # Match findings to CVEs
mcpradar cve list                         # List cached CVEs
```

#### File Changes

| File | Action |
|---|---|
| `src/mcpradar/audit/__init__.py` | **New** |
| `src/mcpradar/audit/auditor.py` | **New** (~200 lines) |
| `src/mcpradar/audit/stats.py` | **New** (~200 lines) |
| `src/mcpradar/storage/store.py` | `audit_log` table; audit CRUD |
| `src/mcpradar/cvefeed/syncer.py` | NVDAPISyncer; enhanced CVE matching |
| `src/mcpradar/cli.py` | `audit`, `stats`, `cve sync/match/list` commands |
| `src/mcpradar/scanner/engine.py` | Scanner emits audit events |
| `src/mcpradar/diff/differ.py` | Differ emits audit events |
| `tests/test_audit.py` | **New** 25+ tests |
| `tests/test_stats.py` | **New** 20+ tests |
| `tests/test_cvefeed.py` | **New** 20+ tests (mock NVD API) |

#### Completion Criteria

- [ ] AuditLogger: scan_start, scan_complete, finding_created, diff_detected, alert_sent, error
- [ ] Audit querying: time range, event type, target filtering
- [ ] StatsEngine: trend slope, most triggered rules, severity distribution
- [ ] NVD API: fetches real CVEs with CVSS scores (rate-limited, cached)
- [ ] CVE matching: CWE mapping + keyword overlap scoring
- [ ] `mcpradar cve match <scan_id>` enriches findings with CVE references

---

### 🏁 Sprint 6: "Validation, Performance & v1.0 Polish"

**Target Version:** v0.7.0 → v1.0.0-rc1 · **Duration:** 2 weeks · **OWASP:** 10/10 full coverage

#### Goal

Complete the 10-server real-world validation pipeline. Performance optimization (parallel scanning). Complete documentation. Preparation for v1.0 release candidate.

#### Validation Pipeline

```python
class ValidationRunner:
    async def run_all(self) -> ValidationReport:
        # Scan 10 servers from targets.yaml
        # Run all R and C rules
        # TP/FP/uncertain classification for each finding (auto-triage)
        # Calculate per-rule precision/recall

    def generate_report(self) -> str:
        # Markdown report: per-server finding table,
        #   false positive analysis, rule effectiveness metrics
```

#### Performance Optimization

```python
class ParallelScanner:
    """Scans multiple servers concurrently."""
    async def scan_all(self, servers, max_concurrency=5) -> list[ScanReport]:
        # asyncio.gather + semaphore
```

```bash
mcpradar scan-all --parallel --max-concurrency 10
```

#### Benchmark

```python
# tests/test_benchmark.py
class TestBenchmarks:
    def test_rule_engine_latency(self, benchmark): ...     # ≤5ms/tool (100 tools)
    def test_sarif_generation_scale(self): ...             # ≤50ms (100 findings)
    def test_sqlite_insert_batch(self): ...                # ≤10ms (100 findings)
```

#### Documentation (8 new pages)

| Page | Content |
|---|---|
| `docs/getting-started.md` | Installation, first scan |
| `docs/cli-reference.md` | Full CLI reference (all commands, flags) |
| `docs/plugin-authoring.md` | Plugin development guide |
| `docs/api-reference.md` | Python API documentation |
| `docs/fingerprinting.md` | Fingerprint guide |
| `docs/ci-integration.md` | CI/CD integration examples (GitHub Actions, GitLab CI, CircleCI) |
| `docs/owasp-mapping.md` | OWASP MCP Top 10 coverage matrix |
| `docs/benchmarks.md` | Performance data |

#### Pre-v1.0 Hardening

- mypy strict: zero errors
- ruff: zero warnings
- Test coverage ≥ 90%
- Security audit of own dependencies
- SBOM generation (cyclonedx or spdx)
- `SECURITY.md` update

#### File Changes

| File | Action |
|---|---|
| `validation/run_validation.py` | ValidationRunner full implementation |
| `src/mcpradar/scanner/engine.py` | ParallelScanner class |
| `src/mcpradar/cli.py` | `--parallel` flag |
| `tests/test_benchmark.py` | **New** performance benchmarks |
| `docs/getting-started.md` | **New** |
| `docs/cli-reference.md` | **New** |
| `docs/plugin-authoring.md` | **New** |
| `docs/api-reference.md` | **New** |
| `docs/fingerprinting.md` | **New** |
| `docs/ci-integration.md` | **New** |
| `docs/owasp-mapping.md` | **New** |
| `docs/benchmarks.md` | **New** |
| `CHANGELOG.md` | v0.7.0 and v1.0.0-rc1 entries |

#### Completion Criteria

- [ ] 10-server validation completed, results published
- [ ] False positive analysis: precision ≥ 85% (all rules)
- [ ] False negative analysis: recall ≥ 90% (malicious_server.py baseline)
- [ ] Parallel scanning: ≥ 5 servers/second
- [ ] Rule engine: ≤ 5ms/tool (100 tools)
- [ ] SARIF generation: ≤ 50ms (100 findings)
- [ ] Documentation: 8 pages completed
- [ ] mypy + ruff + pytest: zero errors/warnings
- [ ] SBOM generated
- [ ] v1.0.0-rc1 published on PyPI

---

## Long-Term Goals (v1.1+)

### v1.1 — Runtime Behavioral Analysis
- WebSocket transport support (emerging MCP transport)
- Tool call interception proxy mode (Pipelock-like, optional)
- ML classifier for anomaly detection in tool descriptions
- LLM-as-a-judge integration (response quality assessment)

### v1.2 — Ecosystem Integration
- MCP server registry verification service (automated leaderboard)
- Badge/shield system: `![MCPRadar Score](https://img.shields.io/mcpradar/score/<server>)`
- IDE plugins (VS Code, JetBrains) — `vscode-mcpradar/` already scaffolded
- Pre-commit hook: `- repo: https://github.com/yatuk/mcpradar`

### v1.3+ — Enterprise Features
- Multi-tenant database (namespace-isolated shared SQLite)
- Policy-as-code rules (YAML-defined, no Python required — MCP Guardian-like but open source)
- Web dashboard (FastAPI + htmx, self-hosted)
- OPA/Rego integration (advanced policy evaluation)

---

## Rule ID Registry

### Detection Rules (R-series)

| ID | Name | Sprint | OWASP | Severity |
|---|---|---|---|---|
| R001 | Dangerous Tool Name | v0.1.0 | MCP03 | CRITICAL |
| R101 | Zero-Width Unicode Detection | v0.1.0 | MCP06 | HIGH/CRITICAL |
| R102 | Prompt Injection Detection | v0.1.0 | MCP06 | HIGH/CRITICAL |
| R103 | Encoded Blob Detection | v0.1.0 | MCP06 | MEDIUM/HIGH |
| R104 | Hidden Content Detection | v0.1.0 | MCP03/MCP06 | HIGH |
| R105 | Permission Scope Mismatch | v0.1.0 | MCP02 | LOW/MEDIUM |
| **R106** | **Secret/Token Exposure** | **Sprint 1** | **MCP01** | **CRITICAL** |
| **R107** | **Command Injection via Parameters** | **Sprint 1** | **MCP05** | **CRITICAL** |
| **R108** | **Supply Chain Risk Indicator** | **Sprint 1** | **MCP04** | **MEDIUM/HIGH** |
| **R109** | **Schema Poisoning Indicator** | **Sprint 1** | **MCP03** | **HIGH** |
| **R110** | **Version Anomaly** | **Sprint 3** | **MCP09** | **HIGH/CRITICAL** |
| **R111** | **Insecure Transport** | **Sprint 3** | **MCP07** | **HIGH/CRITICAL** |

### Cross-Server Rules (C-series)

| ID | Name | Sprint | OWASP |
|---|---|---|---|
| C001 | Tool Name Collision | v0.1.0 | MCP10 |
| C002 | Tool Name Shadowing | v0.1.0 | MCP10 |
| C003 | Data Exfiltration Chain | v0.1.0 | MCP10 |
| C004 | Capability Overlap | v0.1.0 | MCP10 |
| C005 | Permission Gradient | v0.1.0 | MCP10 |
| **C006** | **Attack Path Chain** | **Sprint 4** | **MCP03/MCP10** |
| **C007** | **Privilege Escalation Chain** | **Sprint 4** | **MCP02** |

### Community Rules (X-series, reserved)

Community plugins use the `X` + 3-digit number format (X001–X999). Prevents conflicts with built-in rules.

---

## Command Matrix (Full CLI)

| Command | Version | Description |
|---|---|---|
| `mcpradar scan <target> -t <transport>` | v0.1.0 | Scan a single MCP server |
| `mcpradar scan-all [--config] [--parallel]` | v0.1.0 | Scan all servers |
| `mcpradar diff [server] [-a] [-b] [--since]` | v0.1.0 | Compare two snapshots |
| `mcpradar watch <target> [-i] [--alert-cmd] [--alert-webhook]` | v0.1.0 | Periodic scan + alert |
| `mcpradar list [target] [-n]` | v0.1.0 | Snapshot history |
| `mcpradar show <scan_id>` | v0.1.0 | Single snapshot detail |
| `mcpradar export <scan_id> [-f] [-o]` | v0.1.0 | JSON/SARIF/CSV export |
| `mcpradar purge [--older-than] [--keep-last]` | v0.1.0 | Old snapshot cleanup |
| `mcpradar init [-o]` | v0.1.0 | Generate mcpradar.toml |
| `mcpradar registry-scan [-o]` | v0.1.0 | Generate leaderboard |
| `mcpradar rules list` | v0.1.0 | List rules |
| `mcpradar rules info <rule_id>` | v0.1.0 | Rule detail |
| `mcpradar rules disable <rule_id>` | v0.1.0 | Disable rule |
| `mcpradar analyze-context [--config] [--deep] [--graph]` | v0.1.0 | Cross-server analysis |
| `mcpradar feed-update` | v0.1.0 | Update CVE feed |
| `mcpradar plugin init <name> [-o]` | Sprint 2 | New plugin skeleton |
| `mcpradar plugin validate <directory>` | Sprint 2 | Plugin validation |
| `mcpradar plugin list` | Sprint 2 | List plugins |
| `mcpradar plugin install <package>` | Sprint 2 | Install plugin |
| `mcpradar plugin uninstall <package>` | Sprint 2 | Uninstall plugin |
| `mcpradar fingerprint <target> [--compare]` | Sprint 3 | Fingerprint |
| `mcpradar probe <target> [--safe-only \| --all]` | Sprint 4 | Runtime probing |
| `mcpradar audit [--target] [--type] [--since]` | Sprint 5 | Audit trail |
| `mcpradar stats [target]` | Sprint 5 | Security statistics |
| `mcpradar cve sync` | Sprint 5 | NVD synchronization |
| `mcpradar cve match <scan_id>` | Sprint 5 | CVE matching |
| `mcpradar cve list` | Sprint 5 | CVE listing |

---

## Success Metrics

| Metric | v0.1.0 (Current) | v0.7.0 Target | v1.0 Target |
|---|---|---|---|
| OWASP MCP Top 10 coverage | 3/10 | 10/10 | 10/10 |
| Detection rule count | 6 | 11 | 11 |
| Cross-server rule count | 5 | 7 | 7 |
| Transport protocols | 3 | 3 | 4 (WebSocket) |
| Test coverage | ~80% | ≥ 90% | ≥ 92% |
| Test code (lines) | ~2,150 | 4,000+ | 4,500+ |
| Scan latency (per tool) | ~10ms | ≤ 5ms | ≤ 3ms |
| Parallel scan speed | — | 5 servers/s | 10 servers/s |
| Community plugins | 0 | 2 examples | 5+ |
| Validation servers | 0/10 | 10/10 | CI automation |
| NVD CVE database | 2 seeds | 50+ MCP-related | 100+ automated |
| SARIF integration | 6 rules | 11 rules + CVE | Code Scanning alerts |

---

## Risk Assessment

| Risk | Impact | Probability | Mitigation |
|---|---|---|---|
| **Breaking change in MCP protocol** | High | Medium | Pin MCP SDK version; multi-SDK CI testing; monitor MCP spec repo |
| **Plugin API instability** | Medium | High | SemVer for Plugin API; deprecation warning for 2 minor releases |
| **False positive fatigue** | High | Medium | Sprint 1+6 FP analysis; per-rule precision tracking; `--severity` filtering; rule disable UI |
| **NVD API rate limiting** | Low | High | Local cache with TTL; exponential backoff; seed data fallback |
| **Community plugin quality** | Medium | Medium | Plugin validation CLI; test template; plugin review checklist |
| **Performance regression with rule growth** | Medium | Low | Sprint 6 benchmarks; CI perf regression test; per-rule profiling |
| **OWASP MCP Top 10 updates** | Low | Low | Sprint 6 OWASP mapping doc; monthly OWASP update tracking |
| **Competitor feature parity pressure** | Low | Low | Focus on differentiation: deterministic + CI-friendly + MIT license + Python ecosystem |

---

## Appendix: Detected MCP CVEs and MCPRadar Coverage (2025–2026)

Critical CVEs discovered by OX Security researchers that MCPRadar targets:

| CVE ID | Product | Description | Status | MCPRadar Coverage |
|---|---|---|---|---|
| CVE-2025-54136 | Cursor IDE | STDIO Command Injection / RCE | ✅ Patched | R107 (parameter injection) |
| CVE-2026-30623 | LiteLLM | Unauthenticated Command Injection | ✅ Patched | R107 |
| CVE-2025-49596 | MCP Inspector | DNS Rebinding / RCE | ✅ Patched | R111 (transport security) |
| CVE-2026-30615 | Windsurf | RCE via Configuration | ❌ Unpatched | R107 + R108 |
| CVE-2026-30616 | Jaaz | STDIO Privilege Escalation | ❌ Unpatched | R107 |
| CVE-2026-30617 | Langchain-Chatchat | STDIO RCE | ❌ Unpatched | R107 |
| CVE-2026-30618 | Fay Framework | STDIO RCE | ❌ Unpatched | R107 |
| CVE-2026-30624 | Agent Zero | STDIO RCE | ❌ Unpatched | R107 |
| CVE-2026-30625 | Upsonic | Hardening Bypass | ⚠️ Warning added | R107 + R108 |
| CVE-2026-33224 | Bisheng | STDIO RCE | ✅ Patched | R107 |
| CVE-2026-40933 | Flowise | Auth RCE (CVSS 10) | ✅ Patched | R107 |
| CVE-2026-30861 | WeKnora | Allowlist Bypass RCE | ❌ Unpatched | R107 + R108 |
| CVE-2025-65720 | GPT Researcher | STDIO RCE | ❌ Unpatched | R107 |
| CVE-2026-22252 | LibreChat | STDIO RCE | ✅ Patched | R107 |

> **Note:** Only 6 of the 17 assigned CVEs are patched. MCPRadar's R107 (Command Injection via Parameters), R108 (Supply Chain Risk), and R111 (Insecure Transport) rules aim to provide protection against most of these CVEs.

---

## References

- [OWASP MCP Top 10 (2025)](https://owasp.org/www-project-mcp-top-10/)
- [MCP Supply Chain Advisory — OX Security](https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/)
- [Don't believe everything you read: MCP Behavior under Misleading Tool Descriptions — arXiv](https://arxiv.org/abs/2510.21236)
- [Breaking the Protocol: Security Analysis of MCP Spec — arXiv](https://arxiv.org/abs/2601.17549)
- [CVE-2025-54136: Cursor IDE RCE — SentinelOne](https://sentinelone.com)
- [MCP Scanner Comparison: Cisco vs Snyk vs Pipelock](https://dev.to/luckypipewrench/mcp-scanner-comparison-cisco-vs-snyk-vs-pipelock-32kd)
- [10 Tools for Securing MCP Servers — Nordic APIs](https://nordicapis.com/10-tools-for-securing-mcp-servers/)
- [ClawHub Security Signals — arXiv](https://arxiv.org/abs/2601.17549)
- [OpenClaw + NVIDIA Agent Skill Security](https://openclaw.ai)

---

<p align="center">
  <b>📋 This roadmap is a living document.</b><br/>
  <sub>It will be updated as sprints are completed. To contribute, see <a href="CONTRIBUTING.md">CONTRIBUTING.md</a>.</sub>
</p>
