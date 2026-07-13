# Leaderboard scoring — root cause analysis

**Question:** why does the public leaderboard fail to discriminate (51 A / 2 B /
2 C across 55 scanned servers, average risk 0.2/10, only 7 servers scoring above
0.0)? Investigated with evidence *before* changing any scoring code.

## Anomaly 1 — "many servers show exactly 1 tool" → NOT an enumeration bug

The prompt suspected pagination truncation. **Verified false** by re-scanning the
named servers directly:

| Server | Command | Tools enumerated | Reality |
|---|---|---|---|
| `searxng-mcp` | `uvx mcp-searxng` | 1 (`search`) | genuinely single-tool |
| `mcp-shell` | `npx -y mcp-shell` | 1 (`run_command`) | genuinely single-tool |
| `markitdown-mcp` | `uvx markitdown-mcp` | 1 (`convert_to_markdown`) | genuinely single-tool |
| `mcp-server-calculator`, `mcp-pandoc`, `mcp-youtube-transcript`, `server-sentry`, `server-sequential-thinking` | — | 1 each | all genuinely single-tool |

These are real single-tool servers. `tools/list` returns them in one page; there
is no truncation. **The "1 tool" count is correct, not the root cause.**

That said, the enumerator has genuine robustness gaps worth fixing defensively
(see `scanner/engine.py:_collect_all`):

- The whole tools block is wrapped in a blanket `contextlib.suppress(Exception)`.
  If a rule raises on tool *N*, every later tool is silently dropped and the scan
  is still reported as a clean success — a partial failure can masquerade as
  grade A.
- No cursor-based pagination (`nextCursor`). A server whose tool list spans
  multiple pages would be under-counted.
- A failed/partial enumeration is not distinguished from a genuinely empty one.

Fix: paginate, isolate per-tool rule errors, and mark partial scans
`incomplete` instead of silently scoring them A.

## Anomaly 2 — capability / blast-radius is not scored (THE root cause)

Evidence: only **7 of 55** scanned servers score above 0.0, and every one of them
has finding-driven severity. The score is computed purely from MEDIUM+ finding
severity per tool:

```
score = weighted(critical*10 + high*7 + medium*4) / max(tool_count, 3)
```

A tool's **capability — what it can actually do** (execute commands, write/delete
files, control a browser, egress data, read secrets) — is not an input at all.

Consequence, verified from the live data:

- `mcp-shell` exposes `run_command`, i.e. **arbitrary shell execution**, and
  scores **0.0 / grade A** — identical to `mcp-server-calculator`. A security
  scanner that rates an arbitrary-command server the same as a calculator is not
  discriminating on the dimension that matters most.

This is the OWASP **AIVSS** insight: a CVSS-style base score must be combined
with an *agentic capability* layer (AARS) that captures how much the tool's
design amplifies risk. MCPRadar computes only the base and drops the AARS term.
See `docs/scoring-model.md` for the fix.

## Anomaly 3 — schema findings DO reach the score, but design risk is under-weighted

`@modelcontextprotocol/server-filesystem` is **grade B (1.4)** driven by 5 MEDIUM
`R113` path-parameter findings — i.e. schema/design risk *does* propagate, not
only CVEs. The gap is that a powerful-but-clean server (no MEDIUM+ finding) has no
way to rise above A, because capability is absent from the formula (Anomaly 2).
Binding capability into the score fixes both.

## Anomaly 4 — chrome-devtools 29 tools / 29 findings

Not a blanket/fingerprint bug. The 29 findings are all **R109
`additionalProperties: true`**, one per tool, because every chrome-devtools tool
declares a flexible input schema. It is a real per-tool pattern — uniform, so
low-signal. It should weigh less than an actual capability signal, which the
capability-aware model achieves (the browser-control capability, not the 29
uniform schema notes, becomes the dominant term).

## Anomaly 5 — the positive control is never scanned

`demo/malicious_server.py` (9 intentionally vulnerable tools, the top of the
scale) is `status: pending` in the leaderboard. Without it, nothing proves the
scale reaches F. Fix: scan it into the leaderboard as the calibration ceiling.

## Fix summary

1. **Enumeration:** cursor pagination + per-tool error isolation + an
   `incomplete` scan state (a partial scan is never scored A).
2. **Capability-aware AIVSS scoring:** tag every tool with capability classes and
   add the AARS layer — `AIVSS = ((base + AARS) / 2) × ThM` — so an exec /
   fs-write / browser-control server is non-A even with no CVE and a clean schema.
3. **Calibration controls:** `demo/malicious_server.py` (positive, F) and a
   `benign_server` fixture (negative, 0 critical) wired into a regression gate.
