# Writing Community Rules

Community rules are Python packages published to PyPI.
MCPRadar auto-discovers them via entry points.

## 1. Create your package

```bash
cp -r plugins/template mcpradar-rule-mine
cd mcpradar-rule-mine
```

## 2. Write your rule

```python
# src/mcpradar_rule_mine/rule.py
from mcpradar.scanner.report import Finding, Severity, ToolInfo
from mcpradar.scanner.rules import Rule

class MyRule(Rule):
    rule_id = "X001"          # Community rules use X-prefix
    title = "My custom check"
    severity = Severity.HIGH

    def check(self, tool: ToolInfo) -> list[Finding]:
        findings = []
        if "dangerous" in tool.description.lower():
            findings.append(self._finding(
                tool.name,
                "Suspicious description detected",
                matched="dangerous",
            ))
        return findings
```

## 3. Register the entry point

In `pyproject.toml`:

```toml
[project.entry-points."mcpradar.rules"]
myrule = "mcpradar_rule_mine.rule:MyRule"
```

## 4. Install and test

```bash
pip install -e .
mcpradar rules list  # Your rule should appear
mcpradar rules info X001
```

## 5. Publish

```bash
uv build
uv publish
```

Users install your rule with: `pip install mcpradar-rule-mine`

## Rule Design Guidelines

- **Rule ID:** Community rules use `X` prefix (X001, X002...). Built-in rules use `R`.
- **Minimize false positives.** Test against real MCP servers before publishing.
- **Use `detail=` dict.** Pass evidence like matched patterns, positions.
- **Description matters.** Write human-readable descriptions for each finding.
- **No network calls.** Rules only inspect tool metadata, never make HTTP requests.

## Examples

### Detect suspicious default parameters

```python
class DangerousDefault(Rule):
    rule_id = "X002"
    title = "Suspicious default parameter"
    severity = Severity.HIGH

    def check(self, tool: ToolInfo) -> list[Finding]:
        findings = []
        for param, schema in tool.input_schema.get("properties", {}).items():
            default = schema.get("default", "")
            if isinstance(default, str) and "rm -rf" in default:
                findings.append(self._finding(
                    tool.name,
                    f"Parameter '{param}' has dangerous default: {default[:60]}",
                    param=param,
                    default_value=default[:100],
                ))
        return findings
```

### Detect long, obfuscated descriptions

```python
class ObfuscatedDescription(Rule):
    rule_id = "X003"
    title = "Obfuscated tool description"
    severity = Severity.MEDIUM

    def check(self, tool: ToolInfo) -> list[Finding]:
        # Descriptions that are unusually long and repetitive
        desc = tool.description
        if len(desc) > 2000 and len(set(desc.split())) < 20:
            return [self._finding(
                tool.name,
                f"Description is {len(desc)} chars with only "
                f"{len(set(desc.split()))} unique words — possible padding",
                length=len(desc),
                unique_words=len(set(desc.split())),
            )]
        return []
```
