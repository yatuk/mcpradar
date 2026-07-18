# MCPRadar Risk Score (MRS-v1)

MRS-v1 is MCPRadar's own versioned 0–10 risk signal. It combines a
severity-weighted finding base, an agentic capability layer, an environmental
multiplier, and a separately capped dependency term. It is not CVSS and is not
published as OWASP AIVSS.

## Why the old model failed

The previous score was purely finding-driven:

```
score = weighted(critical*10 + high*7 + medium*4) / max(tool_count, 3)
```

A tool's **capability — what it can actually do** was not an input. In the
historical 55-server snapshot, this produced **51 A / 2 B / 2 C, average
0.20/10**. A server exposing arbitrary shell execution (`mcp-shell`) scored 0.0
/ grade A, identical to a calculator. See [`rootcause.md`](rootcause.md).

## The model

MRS-v1 uses this formula:

```
base  = severity-weighted MEDIUM+ findings / max(tool_count, 3)
        (critical → floor 5.0, high → floor 3.0)
AARS  = agentic capability blast radius of the server's tools (0–10)
ThM   = environmental threat multiplier (insecure transport)

score = min(10, max(base, ((base + AARS) / 2) × ThM))
```

The `max(base, …)` is deliberate: the capability layer can only **raise** risk,
never discount a real finding. A single critical still lands at its base floor
even on a low-capability server.

## AARS — the agentic capability layer

Each tool is tagged with capability classes from its name, description, and input
schema (`src/mcpradar/scoring/capability.py`). Per-class AARS weight, ordered by
blast radius:

| Capability | Weight | Rationale |
|---|---:|---|
| `code_exec` | 8.0 | Arbitrary command/code execution — the maximum agentic blast radius; a prompt-injected agent gets an RCE primitive. |
| `browser_control` | 6.0 | Drives a real browser (navigate/click/screenshot/run-JS) — SSRF, credential theft, arbitrary web actions. |
| `db_write` | 5.0 | Mutates a database — destructive and hard to audit. |
| `fs_write` | 4.0 | Creates / edits / deletes files — persistence and tampering. |
| `secret_access` | 3.0 | Handles credentials / tokens / vault — exfiltration target. |
| `net_egress` | 2.0 | Sends data outbound (fetch / webhook / email) — exfiltration channel. |
| `fs_read` | 1.0 | Reads files — information disclosure. |
| `pure_compute` | 0.0 | No side effect (calculate, format, convert). |

```
AARS(server) = max(weight of classes present)
             + 0.5 for each additional distinct class with weight ≥ 2
             (capped at 10)
```

The dominant term is the single highest-blast-radius capability; the breadth
bonus reflects that a server which can both execute code **and** egress data is
riskier than one that only executes code.

These eight weights are the model's only tunable coefficients. They are ordinal
(exec > browser > db-write > fs-write > secrets > egress > read > none), matching
the model principle that autonomy and tool-use amplify a baseline. They are kept
in one place (`CAPABILITY_WEIGHTS`) and are not otherwise hardcoded into the
pipeline.

## Dependency risk (supply chain)

When a result is enriched (`leaderboard enrich`), the server's published package
is fetched and its dependencies checked against OSV; each vulnerable dependency
is a **D001** finding. These are scored *separately* from the server's own
findings:

```
dep_risk = min(4.9, critical×1.0 + high×0.4 + medium×0.15)
score    = min(10, max(base, ((base + AARS)/2) × ThM, dep_risk))
```

Rationale: almost every Python MCP server bundles the same vulnerable transitive
dependencies (a CVE in the `mcp` SDK itself, `h11`, `click`, …), so treating a
transitive CVE like the server's own vulnerability would push every server —
even a calculator — to a failing grade. The weights are gentle and the term is
**capped at 4.9 (grade C)**: vulnerable dependencies can nudge a grade and
surface genuinely-outdated servers (e.g. one with 18 vulnerable deps → C), but a
worse-than-C grade must come from the server's *own* code or schema, never from
transitive dependencies alone. Reachability is unknown, so the signal is
deliberately secondary. The vulnerable-dependency count is surfaced separately
(`vulnerable_deps`).

## ThM — environmental threat multiplier

`ThM = 1.15` when the scan found an insecure transport (R111), else `1.0`.
A network-reachable server amplifies every capability.

## Grade bands

`A` ≤ 0.9 · `B` ≤ 2.9 · `C` ≤ 4.9 · `D` ≤ 6.9 · `F` ≤ 10.0.

## Calibration (positive + negative controls)

Enforced by the regression gate (`tests/test_scoring_calibration.py`):

- **Positive** — `demo/malicious_server.py` (intentionally vulnerable): grade **F**.
- **Negative** — `tests/fixtures/benign_server` (one `echo` tool, clean schema, no
  I/O): **0 critical**, grade **A**.
- **Intermediate** — an exec-only server with no CVE and a clean schema: **not
  grade A** (capability floor engages).

## Current public corpus snapshot

The generated 2026-07-18 public dataset contains 56 completed scans. Recomputing
their risk rows with MRS-v1 yields:

| A | B | C | D | F | Average |
|---:|---:|---:|---:|---:|---:|
| 8 | 21 | 23 | 3 | 1 | 2.85 |

This distribution is descriptive operational data, not a precision/recall
benchmark. The labeled benchmark publishes its evidence gaps separately.

`mcp-shell` (arbitrary exec) → C; `mcp-server-calculator` → A;
`@modelcontextprotocol/server-filesystem` → **B** (schema R113 + fs-write
capability, not a CVE). The F ceiling is represented by the
`demo/malicious_server.py` positive control in the corpus.
