# MCPRadar Precision/Recall Benchmark

**Generated:** 2026-06-23 19:25 UTC
**Scanner version:** 1.0.0-rc2

## Methodology

Each target server has a ground-truth label in `validation/labels.json` specifying which MCPRadar rules *should* fire (`expected_rules`). The scanner runs against each target, and detected rules are compared to expected rules.

- **True Positive (TP):** Rule fired AND was expected
- **False Positive (FP):** Rule fired but was NOT expected
- **False Negative (FN):** Rule was expected but did NOT fire

## Overall Results

| Metric | Value |
|---|---|
| Precision | 100.0% |
| Recall | 90.0% |
| F1 Score | 94.7% |
| Targets scanned | 1 |
| Total findings | 9 |

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
| R107 | 0 | 0 | 1 | 0.0% | 0.0% | 0.0% |
| R108 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| R109 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |

## Per-Target Results

| Target | Status | Tools | Findings | Expected Rules | Detected |
|--------|--------|-------|----------|---------------|----------|
| demo/malicious_server.py | ✅ | 9 | 34 | R001, R101, R102, R103, R104, R105, R106, R107, R108, R109 | R001, R101, R102, R103, R104, R105, R106, R108, R109 |

## Test Corpus

### Demo Malicious Server (`demo/malicious_server.py`)
Intentionally vulnerable MCP server with 9 tools covering rules R001-R109.

### Appsecco Vulnerable MCP Servers Lab
External corpus: 9 intentionally vulnerable MCP servers covering path traversal, prompt injection, RCE, typosquatting, secrets exposure, and outdated packages.
Repository: https://github.com/appsecco/vulnerable-mcp-servers-lab

### Official MCP Reference Servers
Clean negative controls from https://github.com/modelcontextprotocol/servers. Expected to produce zero findings — any detection is a false positive.
