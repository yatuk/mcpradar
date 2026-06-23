# Getting Started with MCPRadar

## Installation

```bash
# One-shot (no install)
uvx mcpradar scan "npx -y @modelcontextprotocol/server-filesystem /tmp" -t stdio

# Permanent install
pip install mcpradar
```

## Your First Scan

```bash
# Scan an HTTP MCP server
mcpradar scan http://localhost:8080

# Scan a local stdio server
mcpradar scan stdio -- npx -y @modelcontextprotocol/server-filesystem /tmp

# Only show critical and high findings
mcpradar scan http://localhost:8080 -s high

# Export to JSON
mcpradar scan http://localhost:8080 -f json -o results.json

# SARIF for GitHub Code Scanning
mcpradar scan http://localhost:8080 -f sarif -o results.sarif
```

## CI/CD Integration

Add MCPRadar to your CI pipeline to catch MCP vulnerabilities before deployment:

```yaml
# GitHub Actions
- name: Scan MCP server
  run: uvx mcpradar scan ${{ inputs.server }} --format sarif -o results.sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

See [CI Integration](ci-integration.md) for more examples.

## Next Steps

- [CLI Reference](cli-reference.md) — all commands and flags
- [Detection Rules](detection-rules.md) — what MCPRadar catches
- [OWASP Coverage](owasp-mapping.md) — MCP Top 10 mapping
- [Architecture](architecture.md) — how MCPRadar works internally
