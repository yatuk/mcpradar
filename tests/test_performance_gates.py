"""Stable upper-bound gates for scanner hot paths."""

from __future__ import annotations

from time import perf_counter

from mcpradar.output.sarif import to_sarif
from mcpradar.scanner.report import Finding, ScanReport, Severity, ToolInfo
from mcpradar.scanner.rules import RuleEngine
from mcpradar.schema.walker import iter_schema_properties


def test_rule_engine_100_tools_under_one_second() -> None:
    engine = RuleEngine(min_severity=Severity.LOW)
    tools = [
        ToolInfo(
            name=f"search_{index}",
            description="Search a public catalog by a constrained query.",
            input_schema={
                "type": "object",
                "properties": {"query": {"type": "string", "maxLength": 100}},
                "required": ["query"],
                "additionalProperties": False,
            },
        )
        for index in range(100)
    ]
    started = perf_counter()
    for tool in tools:
        engine.analyze(tool)
    assert perf_counter() - started < 1.0


def test_schema_walker_5000_properties_under_one_second() -> None:
    schema = {
        "type": "object",
        "properties": {
            f"field_{index}": {"type": "string", "maxLength": 100} for index in range(5_000)
        },
    }
    started = perf_counter()
    assert len(list(iter_schema_properties(schema, timeout_seconds=1.0))) == 5_000
    assert perf_counter() - started < 1.0


def test_sarif_1000_findings_under_one_second() -> None:
    report = ScanReport(target="https://example.com/mcp", transport="http")
    for index in range(1_000):
        report.add_finding(
            Finding(
                rule_id="R001",
                title="Dangerous tool",
                description="A deliberately repeated benchmark finding.",
                severity=Severity.HIGH,
                target=f"tool-{index}",
                location="tool",
            )
        )
    started = perf_counter()
    assert len(to_sarif(report)["runs"][0]["results"]) == 1_000
    assert perf_counter() - started < 1.0
