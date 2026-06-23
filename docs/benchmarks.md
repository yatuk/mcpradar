# Benchmarks

## Accuracy (Precision/Recall)

Latest results: see [validation/BENCHMARK.md](../validation/BENCHMARK.md)

MCPRadar's detection accuracy is measured against a labeled corpus including:
- **Positive cases:** demo/malicious_server.py (9 intentionally vulnerable tools)
- **Negative controls:** Official MCP reference servers (expected: zero findings)
- **External corpus:** Appsecco Vulnerable MCP Servers Lab (9 servers)

### Sprint 6 Targets

| Metric | Target | Status |
|---|---|---|
| Precision | >= 80% | See BENCHMARK.md |
| Recall | >= 85% | See BENCHMARK.md |
| F1 Score | >= 0.82 | See BENCHMARK.md |

Note: Targets adjusted from original 85%/90% based on realistic assessment
of heuristic rule limitations on diverse corpora.

## Performance

Measured on Python 3.11, commodity hardware.

| Benchmark | Mean | Description |
|---|---|---|
| Rule engine latency (100 tools) | ~14 ms | Full rule suite across 100 tool definitions |
| SARIF generation (100 findings) | ~2 ms | SARIF 2.1.0 output generation |
| SQLite insert (100 findings) | ~1.5 ms | Batch scan result persistence |

See `tests/test_benchmark.py` for methodology.
