# MCPRadar roadmap

> **Updated:** 2026-07-18 · **Current:** v1.1.0-rc1 · **Next milestone:** v1.1.0 GA

## Product direction

MCPRadar is a deterministic, CI-friendly security scanner for MCP servers,
packages, source code, dependencies, and agent configuration. It should make a
clear distinction between observed evidence, heuristic risk, incomplete scans,
and unsupported protocol surfaces.

The project does not claim that a rule mapping equals complete OWASP coverage.
MCPRadar Risk Score (MRS-v1) is an owned risk signal, not CVSS or OWASP AIVSS.

## v1.1 release-candidate baseline

The release candidate includes:

- 42 rules in one generated `RuleDescriptor` catalog, covering MCP metadata,
  cross-server context, Python and JavaScript/TypeScript source, configuration,
  dependencies, and package identity.
- Cursor-complete enumeration of tools, prompts, resources, and resource
  templates, plus server instructions and explicit complete/partial/failed state.
- Maintained MCP v1 support and an opt-in stateless `2026-07-28` adapter with
  discovery, per-request metadata, and migration-readiness reporting.
- Safe-by-default network fetching, explicit stdio host-execution consent,
  disposable container scanning, and isolated hash-pinned plugins.
- JSON Schema 2020-12 bounded traversal, target-specific CycloneDX 1.7 SBOMs,
  OSV dependency analysis, and npm/pnpm/Yarn/uv/Poetry/PDM lockfile support.
- SARIF 2.1.0 with complete descriptors, JSON report schema 1.1, transactional
  storage migrations, signed Ed25519 snapshots, and strict policy-as-code gates.
- MRS-v1 public scoring with capability, environment, finding, and bounded
  dependency terms.
- Instance-level and per-surface benchmark metrics that publish calibration gaps
  instead of treating missing evidence as zero.
- Fuzz, performance, coverage, wheel-install, artifact-attestation, and protocol
  conformance gates in CI.

## v1.1.0 GA exit criteria

A GA tag is ready only when all of these remain green on the release commit:

| Gate | Requirement |
|---|---|
| Unit/regression | Complete test suite passes |
| Core coverage | At least 80% aggregate |
| Critical modules | At least 90% each |
| Static quality | Ruff and strict mypy pass |
| Platform matrix | Python 3.11–3.13 on Linux, macOS, and Windows |
| Protocol | Official maintained-profile scenarios pass |
| Transition profile | Direct adapter contract tests pass until official draft core scenarios exist |
| Performance | 100 tools, 5,000 schema properties, and 1,000 SARIF results stay within budgets |
| Packaging | Wheel builds, installs in an empty environment, and the CLI starts |
| Supply chain | Release SBOM and GitHub artifact attestations are produced |
| Documentation | Rule catalog, protocol profiles, policy, CLI, changelog, and public data are synchronized |

Benchmark coverage gaps are visible release evidence, not a hidden blocker. A
rule is called calibrated only after at least three labeled positive instances
and three hard-negative instances. Uncalibrated rules remain usable but must not
be advertised with unsupported precision or recall claims.

## Compatibility policy

- The production scanner stays on `mcp>=1.27,<2` while the stateful v1 SDK line
  is maintained.
- The stateless transition profile is opt-in and cannot silently change a v1
  scan.
- Protocol-profile incompatibility is migration readiness, not a security
  vulnerability by itself.
- Report and snapshot schema changes are versioned; stored data migrates
  transactionally with a backup.

## Post-GA work

### Runtime enforcement proxy

A transparent MCP traffic proxy is intentionally outside v1.1. It would add
live request/response inspection, policy enforcement, and runtime output
injection controls. This changes the trust and availability model substantially,
so it requires a separate threat model, latency budget, bypass analysis, and
deployment design before implementation.

### Corpus growth

Continue adding independently reviewed positive and hard-negative examples for
every rule and every supported surface. Promote confidence only from published
evidence; do not tune solely against the intentionally malicious demo server.

### Ecosystem interoperability

Expand official conformance coverage as the MCP conformance suite publishes
core scenarios for newer profiles. Keep the internal adapter tests as a
transition safety net, not as a substitute for official scenarios.

## Non-goals

- Executing an arbitrary local stdio command without explicit consent.
- Treating a high-capability server as malicious solely because it is powerful.
- Claiming vulnerabilities from an incomplete scan or a registry placeholder.
- Silently downloading mutable packages, following unsafe redirects, or loading
  unapproved plugins.
- Hiding false-positive or calibration limitations behind a single score.
