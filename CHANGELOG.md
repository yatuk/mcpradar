# Changelog

All notable changes to MCPRadar will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] — Unreleased

### Added
- Initial release
- `scan` command — HTTP, SSE, stdio transport support
- 6 detection rules (R001, R101-R105)
- `diff` command — schema-aware comparison with cosmetic/behavioral/security classification
- `watch` command — periodic scanning with webhook/cmd alerts
- `init` command — `mcpradar.toml` config generator
- `scan-all` command — scan all servers from config
- `list` / `show` / `export` / `purge` — snapshot browser commands
- `registry-scan` command — public leaderboard
- SARIF v2.1.0 output + GitHub Action example
- SQLite snapshot storage (`platformdirs` for default path)
- Rich terminal output with git-diff style diff
- UTF-8 enforcement on Windows + Turkish localization
- Config file reading pipeline (TOML)
- E2E tests with in-memory mock MCP server
- CI matrix: Python 3.11/3.12/3.13 × ubuntu/macos/windows
- Pre-commit hooks (ruff, mypy)
- Validation pipeline (`validation/`)
- Documentation: README, architecture, detection rules, contributing, threat model
- Community files: CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, issue templates
