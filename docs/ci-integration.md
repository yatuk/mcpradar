# CI/CD Integration

## GitHub Actions

### Basic SARIF Upload

```yaml
name: MCP Security Scan
on:
  push:
    branches: [main]
  schedule:
    - cron: '0 8 * * 1'  # weekly

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Scan MCP server
        run: |
          uvx mcpradar scan ${{ secrets.MCP_SERVER_URL }} \
            --format sarif \
            -o results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Scan-All with Config

```yaml
- name: Generate config
  run: |
    uvx mcpradar init
    # Edit mcpradar.toml to list your servers

- name: Scan all servers
  run: uvx mcpradar scan-all --parallel -f sarif -o results.sarif
```

### Diff on PR

```yaml
- name: Scan current
  run: uvx mcpradar scan $TARGET -f json -o current.json

- name: Diff against main
  run: |
    git stash
    git checkout main
    uvx mcpradar scan $TARGET -f json -o baseline.json
    git checkout -
    git stash pop
    uvx mcpradar diff --snapshot-a $(cat baseline.json | jq -r .id) --snapshot-b $(cat current.json | jq -r .id)
```

## GitLab CI

```yaml
mcp-scan:
  image: python:3.12
  script:
    - pip install mcpradar
    - mcpradar scan $MCP_TARGET --format sarif -o results.sarif
  artifacts:
    reports:
      sast: results.sarif
```

## CircleCI

```yaml
jobs:
  mcp-scan:
    docker:
      - image: cimg/python:3.12
    steps:
      - run: pip install mcpradar
      - run: mcpradar scan $MCP_TARGET --format sarif -o results.sarif
      - store_artifacts:
          path: results.sarif
```

## Pre-Commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: mcpradar
        name: MCPRadar security scan
        entry: uvx mcpradar scan
        args: ["http://localhost:8080", "-s", "high"]
        language: system
        pass_filenames: false
```
