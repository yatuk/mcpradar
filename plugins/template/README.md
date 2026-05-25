# MCPRadar Community Rule Template

Use this template to create your own detection rule for MCPRadar.

## Quick Start

```bash
cp -r plugins/template mcpradar-rule-mycustom
cd mcpradar-rule-mycustom
# Edit src/mcpradar_rule_example/rule.py with your logic
# Update pyproject.toml with your package name
pip install -e .
mcpradar rules list  # Your rule should appear
```

## Anatomy of a Rule

```python
from mcpradar.scanner.report import Finding, Severity, ToolInfo
from mcpradar.scanner.rules import Rule

class MyRule(Rule):
    rule_id = "X001"          # Unique, X-prefixed for community
    title = "My custom check" # Short description
    severity = Severity.HIGH  # LOW, MEDIUM, HIGH, CRITICAL

    def check(self, tool: ToolInfo) -> list[Finding]:
        findings = []
        # Your detection logic here
        # Use self._finding(tool_name, description, **detail)
        return findings
```

## Package Structure

```
mcpradar-rule-mycustom/
├── pyproject.toml          # entry point → mcpradar.rules group
└── src/
    └── mcpradar_rule_example/
        ├── __init__.py
        └── rule.py          # Your Rule subclass
```

## Entry Point

The magic is in `pyproject.toml`:

```toml
[project.entry-points."mcpradar.rules"]
mycustom = "mcpradar_rule_mine.rule:MyRule"
```

When the user `pip install`s your package, MCPRadar automatically
discovers and loads your rule.

## Publish to PyPI

```bash
uv build
uv publish
```

Users install with: `pip install mcpradar-rule-mine`
