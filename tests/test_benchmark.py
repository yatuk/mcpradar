"""Performance benchmarks for MCPRadar."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from mcpradar.output.sarif import to_sarif
from mcpradar.scanner.report import Finding, ScanReport, Severity, ToolInfo
from mcpradar.scanner.rules import RuleEngine
from mcpradar.storage.store import Store


def _make_tool(name: str, description: str = "") -> ToolInfo:
    """Helper: create a ToolInfo with typical schema sizes."""
    return ToolInfo(
        name=name,
        description=description or f"Tool {name} for testing purposes",
        input_schema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
                "limit": {"type": "integer", "default": 10},
            },
            "required": ["query"],
        },
        output_schema={
            "type": "object",
            "properties": {
                "results": {"type": "array", "items": {"type": "string"}},
                "count": {"type": "integer"},
            },
        },
    )


def _make_finding(rule_id: str, severity: Severity, tool_name: str = "test") -> Finding:
    """Helper: create a Finding with realistic content."""
    return Finding(
        rule_id=rule_id,
        title=f"{rule_id} finding",
        description=f"Security issue detected by {rule_id} in tool {tool_name}. "
        "This is a realistic finding description with enough text "
        "to approximate real-world usage patterns.",
        severity=severity,
        target=tool_name,
        location="tool",
        evidence="match: dangerous_pattern_found_here",
    )


class TestBenchmarks:
    """Performance benchmarks for critical paths."""

    def test_rule_engine_latency(self, benchmark) -> None:  # noqa: ANN001
        """Rule engine should process 100 tools in reasonable time."""
        # Create 100 diverse tools
        tools = [
            _make_tool(
                name=f"tool_{i}",
                description=(
                    f"This is tool number {i}. "
                    "It provides various functionality including file operations, "
                    "network access, database queries, and system commands. "
                    "The tool is designed for general-purpose use."
                )
                if i % 3 == 0
                else f"Get information about item {i} from the catalog.",
            )
            for i in range(100)
        ]

        engine = RuleEngine()

        def run_all_tools() -> int:
            total_findings = 0
            for tool in tools:
                findings = engine.analyze(tool)
                total_findings += len(findings)
            return total_findings

        result = benchmark(run_all_tools)
        # Verify it completes and produces results
        assert isinstance(result, int)

    def test_sarif_generation_scale(self, benchmark) -> None:  # noqa: ANN001
        """SARIF generation with 100 findings should be fast."""
        report = ScanReport(target="http://example.com", transport="http")
        for i in range(100):
            sev = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL][i % 4]
            rule_id = ["R001", "R102", "R106", "R107", "R108", "R109"][i % 6]
            report.add_finding(_make_finding(rule_id, sev, f"tool_{i}"))

        def generate() -> dict:
            return to_sarif(report)

        result = benchmark(generate)
        assert "runs" in result
        assert len(result["runs"][0]["results"]) == 100

    def test_sqlite_insert_batch(self, benchmark) -> None:  # noqa: ANN001
        """SQLite insert of 100-finding scan should be fast."""
        with TemporaryDirectory() as tmp:
            store = Store(db_path=Path(tmp) / "test.db")

            report = ScanReport(target="http://example.com", transport="http")
            for i in range(100):
                sev = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL][i % 4]
                rule_id = ["R001", "R102", "R106", "R107", "R108", "R109"][i % 6]
                report.add_finding(_make_finding(rule_id, sev, f"tool_{i}"))

            def save_report() -> str:
                return store.save(report)

            scan_id = benchmark(save_report)
            assert scan_id
            store.close()  # Windows: release file lock before cleanup
