# Changelog

All notable changes to MCPRadar will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-06-23

### Added
- **plugin** CLI komut grubu: `mcpradar plugin {init,validate,list,install,uninstall}`
- Plugin sistemi: `PluginManager` (pip kurulum/kaldırma), `PluginValidator` (6 aşamalı doğrulama), `Scaffolder` (şablondan paket oluşturma)
- `plugins/mcpradar-rule-deprecated/` — 2. örnek topluluk eklentisi (X002: Deprecated/legacy API pattern tespiti)
- Şablon testleri: `plugins/template/tests/test_rule.py`
- Plugin CLI testleri: `tests/test_plugin_cli.py` (11 test)

### Changed
- `plugins/template/`: test dizini eklendi, scaffolder kaynağı olarak kullanılıyor

## [0.2.0] - 2026-06-23

### Added
- 4 yeni tespit kuralı:
  - R106: Secret/Token Exposure — 16 bilinen gizli format regex'i + Shannon entropi tabanlı tespit
  - R107: Command Injection via Tool Parameters — recursive schema walk ile shell metakarakter, tehlikeli varsayılan değer ve komut benzeri enum tespiti
  - R108: Supply Chain Risk Indicator — curl-bash, pip/npm install, eval/exec, dinamik kod yükleme tespiti
  - R109: Schema Poisoning Indicator — additionalProperties:true, eksik tip kısıtlaması, aşırı maxLength/maxItems tespiti
- Yardımcı fonksiyonlar: `_shannon_entropy()`, `_decompose_name()`, `_walk_schema_props()`, `_collect_all_texts()`
- R105 Permission Scope Mismatch iyileştirmesi: 10+ scope çifti, bridge keyword suppression, snake_case/camelCase isim ayrıştırma

### Changed
- R105: LOW severity downgrade kaldırıldı, yerine bridge keyword + isim ayrıştırma tabanlı false positive suppression
- R105: minimum severity MEDIUM olarak sabitlendi
- E2E mock server `safe_tool`: schema'ya `required` alanı eklendi (R109 uyumluluğu)

### Security
- OWASP MCP01 (Token Mismanagement): R106 ile kapsanıyor
- OWASP MCP04 (Supply Chain): R108 ile kapsanıyor
- OWASP MCP05 (Command Injection): R107 ile güçlendirildi
- OWASP MCP03 (Tool Poisoning): R109 ile genişletildi

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
