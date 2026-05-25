# Contributing

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

- **Minimize false positives.** Her kural gerçek dünyada test edilmeli
- **Severity matters.** CRITICAL = immediate danger, LOW = informational
- **Evidence.** `_finding()` metoduna `detail=` dict'i ile match konumu, 
  decode edilmiş text gibi kanıtlar ekleyin
- **Performance.** Kurallar senkron çalışır, regex compile edilmeli
- **No network calls.** Kurallar sadece tool metadata'sına bakar, 
  dış dünyaya çıkmaz

## Commit Convention

Conventional Commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`

```bash
feat: add R106 dangerous parameter default detection
fix: prevent double analyze() in engine.py
docs: update README with R106 example
test: add tests for R106
```
