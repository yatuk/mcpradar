# MCPRadar Precision/Recall Benchmark

**Generated:** 2026-07-12 11:34 UTC
**Scanner version:** 1.0.0-rc4

## Methodology

Each target server has a ground-truth label in `validation/labels.json` specifying which MCPRadar rules *should* fire (`expected_rules`). The scanner runs against each target, and detected rules are compared to expected rules.

- **True Positive (TP):** Rule fired AND was expected
- **False Positive (FP):** Rule fired but was NOT expected
- **False Negative (FN):** Rule was expected but did NOT fire

Metrics are computed on findings of **MEDIUM severity and above**. LOW findings are informational lint (e.g. R114 unconstrained-string notes) and are reported per target but excluded from precision/recall. Vulnerability classes that are invisible to static schema scanning (runtime output poisoning, implementation-level RCE, dependency CVEs, typosquatting) are labeled `expected_rules: []` with a KNOWN LIMITATION note rather than counted as detections — see the notes column in `labels.json`.

## Overall Results

| Metric | Value |
|---|---|
| Precision | 87.5% |
| Recall | 100.0% |
| F1 Score | 93.3% |
| Targets scanned | 11 |
| Total findings | 16 |

## Per-Rule Metrics

| Rule ID | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| R001 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| R101 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| R102 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| R103 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| R104 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| R105 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| R106 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| R107 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| R108 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| R109 | 4 | 1 | 0 | 80.0% | 100.0% | 88.9% |
| R113 | 1 | 1 | 0 | 50.0% | 100.0% | 66.7% |

## Per-Target Results

| Target | Status | Tools | Findings | Low (info) | Expected Rules | Detected (medium+) |
|--------|--------|-------|----------|-----------|---------------|-----------------|
| @modelcontextprotocol/server-everything | ✅ | 13 | 8 | 4 | (clean) | R109 |
| @modelcontextprotocol/server-filesystem | ✅ | 14 | 43 | 38 | (clean) | R113 |
| @modelcontextprotocol/server-memory | ✅ | 9 | 35 | 35 | (clean) | (none) |
| appsecco/filesystem-workspace-actions | ✅ | 4 | 10 | 8 | R109, R113 | R109, R113 |
| appsecco/indirect-prompt-injection | ✅ | 2 | 2 | 2 | (clean) | (none) |
| appsecco/malicious-code-exec | ✅ | 1 | 2 | 1 | R109 | R109 |
| appsecco/malicious-tools | ✅ | 2 | 0 | 0 | (clean) | (none) |
| appsecco/namespace-typosquatting | ✅ | 2 | 2 | 2 | (clean) | (none) |
| appsecco/outdated-packages | ✅ | 5 | 8 | 8 | (clean) | (none) |
| appsecco/secrets-pii | ✅ | 3 | 2 | 1 | R109 | R109 |
| demo/malicious_server.py | ✅ | 9 | 46 | 11 | R001, R101, R102, R103, R104, R105, R106, R107, R108, R109 | R001, R101, R102, R103, R104, R105, R106, R107, R108, R109 |

## Test Corpus

### Demo Malicious Server (`demo/malicious_server.py`)
Intentionally vulnerable MCP server with 9 tools covering rules R001-R109.

### Appsecco Vulnerable MCP Servers Lab
External corpus: intentionally vulnerable MCP servers covering path traversal, prompt injection, RCE, typosquatting, secrets exposure, and outdated packages. Several of these vulnerability classes live in runtime behavior or implementation code and are statically undetectable by design; those targets are labeled as clean-for-static-scan with KNOWN LIMITATION notes.
Repository: https://github.com/appsecco/vulnerable-mcp-servers-lab

### Official MCP Reference Servers
Clean negative controls from https://github.com/modelcontextprotocol/servers. Expected to produce zero MEDIUM+ findings — any detection is a false positive.
