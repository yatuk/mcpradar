# Contributing

## Requesting a Server Scan

Use the
[MCP Server Scan Request](https://github.com/yatuk/mcpradar/issues/new?template=scan_request.yml)
form to suggest a server for the public leaderboard. Include its official
Registry, source, or package URL and the smallest command that starts it. Never
put credentials or private URLs in an issue.

Opening an issue does not execute the submitted command. A maintainer reviews
the request, performs an isolated scan, and decides whether to publish the
result. Contributors do not need to edit generated leaderboard or result files.

## Setup

```bash
git clone https://github.com/yatuk/mcpradar
cd mcpradar
uv sync
uv pip install ruff mypy pytest pytest-asyncio pytest-cov
```

## Quality Gates

```bash
ruff check .         # Lint
ruff format --check . # Format
mypy src/            # Type check
pytest               # Tests (skip e2e: pytest -m "not e2e")
```

## Adding a New Detection Rule

### Step 1: Create the rule class

```python
# src/mcpradar/scanner/rules.py

class DangerousParameterDefault(Rule):
    rule_id = "R106"
    title = "Suspicious default parameter value"
    severity = Severity.HIGH

    def check(self, tool: ToolInfo) -> list[Finding]:
        findings = []
        props = tool.input_schema.get("properties", {})
        for param_name, param_schema in props.items():
            default = param_schema.get("default")
            if default and isinstance(default, str) and len(default) > 100:
                findings.append(
                    self._finding(
                        tool.name,
                        f"Parameter '{param_name}' has unusually long default value",
                        param=param_name,
                        default_preview=default[:80],
                    )
                )
        return findings
```

### Step 2: Register in RuleEngine

```python
# src/mcpradar/scanner/rules.py — RuleEngine.__init__

self._rules: list[Rule] = [
    DangerousNameDetection(),
    ZeroWidthDetection(),
    PromptInjectionDetection(),
    EncodedBlobDetection(),
    HiddenContentDetection(),
    PermissionScopeMismatch(),
    DangerousParameterDefault(),  # <-- add here
]
```

### Step 3: Add to SARIF mapping (optional)

```python
# src/mcpradar/output/sarif.py — RULE_HELP

RULE_HELP["R106"] = "Suspicious default parameter value detected"
```

### Step 4: Write tests

```python
# tests/test_rules.py

class TestDangerousParameterDefault:
    def test_long_default_detected(self) -> None:
        rule = DangerousParameterDefault()
        tool = ToolInfo(
            name="config",
            description="Set config",
            input_schema={
                "properties": {
                    "template": {
                        "type": "string",
                        "default": "A" * 200 + " rm -rf /"
                    }
                }
            },
        )
        findings = rule.check(tool)
        assert any(f.rule_id == "R106" for f in findings)

    def test_normal_default_clean(self) -> None:
        rule = DangerousParameterDefault()
        tool = ToolInfo(
            name="config",
            input_schema={
                "properties": {
                    "timeout": {"type": "integer", "default": 30}
                }
            },
        )
        findings = rule.check(tool)
        assert len(findings) == 0
```

### Step 5: Quality check

```bash
ruff check . && mypy src/ && pytest
```

All green? PR ready.

## Rule Design Guidelines

- **Minimize false positives.** Every rule should be tested in the real world
- **Severity matters.** CRITICAL = immediate danger, LOW = informational
- **Evidence.** Add evidence like match location, decoded text, etc. to the
  `_finding()` method via the `detail=` dict
- **Performance.** Rules run synchronously, regex should be compiled
- **No network calls.** Rules only look at tool metadata,
  they don't reach out to the outside world

## Commit Convention

Conventional Commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`

```bash
feat: add R106 dangerous parameter default detection
fix: prevent double analyze() in engine.py
docs: update README with R106 example
test: add tests for R106
```
