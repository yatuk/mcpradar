# Changelog

All notable changes to MCPRadar will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
