"""Console output tests — Rich snapshot."""

from __future__ import annotations

from io import StringIO

from rich.console import Console

from mcpradar.output.console import RadarConsole
from mcpradar.scanner.report import Finding, ScanReport, Severity, ToolInfo


class TestRadarConsole:
    def test_print_report_empty(self) -> None:
        buf = StringIO()
        rc = RadarConsole()
        rc._console = Console(file=buf, force_terminal=True, legacy_windows=False)
        report = ScanReport(target="http://test", id="abc", transport="http")
        report.tools.append(ToolInfo(name="safe", description="Safe tool"))
        report.summary["clean"] = 1
        report.summary["total_tools"] = 1

        rc.print_report(report)
        output = buf.getvalue()
        assert "MCPRadar" in output
        assert "http://test" in output
        assert "safe" in output

    def test_print_report_with_findings(self) -> None:
        buf = StringIO()
        rc = RadarConsole()
        rc._console = Console(file=buf, force_terminal=True, legacy_windows=False)
        report = ScanReport(target="http://test", id="abc", transport="http")
        report.tools.append(ToolInfo(name="eval", description="Dangerous"))
        report.add_finding(
            Finding(
                rule_id="R001",
                title="Dangerous name",
                description="Tool 'eval' matches dangerous name",
                severity=Severity.CRITICAL,
                target="eval",
            )
        )
        report.add_finding(
            Finding(
                rule_id="R101",
                title="ZWSP",
                description="Hidden char",
                severity=Severity.HIGH,
                target="safe",
            )
        )

        rc.print_report(report)
        output = buf.getvalue()
        assert "R001" in output
        assert "R101" in output
        assert "eval" in output
        assert "CRIT" in output or "CRITICAL" in output

    def test_print_diff_basic(self) -> None:
        from mcpradar.diff.differ import Differ

        buf = StringIO()
        rc = RadarConsole()
        rc._console = Console(file=buf, force_terminal=True, legacy_windows=False)

        a = ScanReport(id="a", target="srv", scanned_at="2026-01-01")
        a.tools.append(ToolInfo(name="weather", description="Get weather"))
        b = ScanReport(id="b", target="srv", scanned_at="2026-01-02")
        b.tools.append(ToolInfo(name="weather", description="Get weather"))
        b.tools.append(ToolInfo(name="new_tool", description="New"))

        differ = Differ()
        delta = differ.compare(a, b)
        rc.print_diff(delta)
        output = buf.getvalue()
        assert "new_tool" in output or "NEW" in output.upper()
        assert "srv" in output

    def test_print_diff_no_changes(self) -> None:
        from mcpradar.diff.differ import Differ

        buf = StringIO()
        rc = RadarConsole()
        rc._console = Console(file=buf, force_terminal=True, legacy_windows=False)

        a = ScanReport(id="a", target="srv")
        b = ScanReport(id="b", target="srv")

        differ = Differ()
        delta = differ.compare(a, b)
        rc.print_diff(delta)
        output = buf.getvalue()
        assert "No changes" in output or "no change" in output.lower()

    def test_print_method(self) -> None:
        rc = RadarConsole()
        # print method should not raise
        rc.print("test message")

    def test_status_context(self) -> None:
        rc = RadarConsole()
        # status returns a context manager — just verify it exists
        ctx = rc.status("testing")
        assert ctx is not None
