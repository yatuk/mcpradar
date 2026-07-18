"""SARIF output tests."""

from mcpradar.output.sarif import to_sarif
from mcpradar.scanner.report import Finding, ScanReport, Severity


class TestSARIF:
    def test_empty_report(self) -> None:
        report = ScanReport(target="http://test", id="abc")
        data = to_sarif(report)

        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        assert data["runs"][0]["tool"]["driver"]["name"] == "MCPRadar"

    def test_with_findings(self) -> None:
        report = ScanReport(target="http://test", id="abc", scanned_at="2026-01-01T00:00:00")
        report.add_finding(
            Finding(
                rule_id="R001",
                title="Dangerous tool",
                description="Tool 'eval' matches dangerous name",
                severity=Severity.CRITICAL,
                target="eval",
                evidence="eval",
            )
        )
        report.add_finding(
            Finding(
                rule_id="R101",
                title="ZWSP detected",
                description="Hidden character in description",
                severity=Severity.HIGH,
                target="get_weather",
                evidence="\\u200b",
            )
        )

        data = to_sarif(report)

        assert len(data["runs"][0]["results"]) == 2
        r0 = data["runs"][0]["results"][0]
        assert r0["ruleId"] == "R001"
        assert r0["level"] == "error"
        r1 = data["runs"][0]["results"][1]
        assert r1["ruleId"] == "R101"
        assert r1["level"] == "error"

    def test_rules_included(self) -> None:
        report = ScanReport(target="http://x", id="abc")
        data = to_sarif(report)

        rules = data["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        assert "R001" in rule_ids
        assert "R101" in rule_ids
        assert "R102" in rule_ids
        assert "R114" in rule_ids
        assert "C001" in rule_ids
        assert "S011" in rule_ids
        assert "M007" in rule_ids
        assert "D001" in rule_ids
        assert "T001" in rule_ids

    def test_severity_mapping(self) -> None:
        report = ScanReport(target="http://x", id="abc")
        report.add_finding(
            Finding(
                rule_id="R104",
                title="Hidden",
                description="Hidden content",
                severity=Severity.LOW,
                target="x",
            )
        )

        data = to_sarif(report)
        assert data["runs"][0]["results"][0]["level"] == "note"

    def test_source_location_uses_artifact_and_region(self) -> None:
        report = ScanReport(target="repo", id="abc")
        report.add_finding(
            Finding(
                rule_id="S004",
                title="eval",
                description="dynamic eval",
                severity=Severity.CRITICAL,
                target="src/server.py:42",
                location="source",
                detail={"line": 42},
            )
        )
        location = to_sarif(report)["runs"][0]["results"][0]["locations"][0]
        assert location["physicalLocation"]["artifactLocation"]["uri"] == "src/server.py"
        assert location["physicalLocation"]["region"]["startLine"] == 42

    def test_incomplete_scan_marks_invocation_failed(self) -> None:
        report = ScanReport(target="x", incomplete=True, incomplete_reason="timeout")
        invocation = to_sarif(report)["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is False
