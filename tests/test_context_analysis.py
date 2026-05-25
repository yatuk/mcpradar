"""Cross-server context analysis tests."""

from __future__ import annotations

from mcpradar.analyzer.context import (
    ContextAnalyzer,
    _check_capability_overlap,
    _check_exfiltration,
    _check_name_collisions,
    _check_permission_gradient,
    _check_shadowing,
)
from mcpradar.scanner.report import ScanReport, Severity, ToolInfo


class TestC001NameCollision:
    def test_same_name_in_two_servers(self) -> None:
        a = ScanReport(target="srv-a")
        a.tools.append(ToolInfo(name="eval", description="Run code"))
        b = ScanReport(target="srv-b")
        b.tools.append(ToolInfo(name="eval", description="Run code"))

        findings = _check_name_collisions([a, b])
        assert any(f.rule_id == "C001" for f in findings)
        c001 = [f for f in findings if f.rule_id == "C001"]
        assert len(c001) == 1
        assert c001[0].severity == Severity.CRITICAL
        assert "srv-a" in c001[0].servers
        assert "srv-b" in c001[0].servers

    def test_unique_names_no_collision(self) -> None:
        a = ScanReport(target="srv-a")
        a.tools.append(ToolInfo(name="weather", description="Get weather"))
        b = ScanReport(target="srv-b")
        b.tools.append(ToolInfo(name="search", description="Search web"))

        findings = _check_name_collisions([a, b])
        assert len(findings) == 0


class TestC002Shadowing:
    def test_similar_names_across_servers(self) -> None:
        a = ScanReport(target="srv-a")
        a.tools.append(ToolInfo(name="send_email", description="Send email"))
        b = ScanReport(target="srv-b")
        b.tools.append(ToolInfo(name="send_emails", description="Send emails"))

        findings = _check_shadowing([a, b])
        assert any(f.rule_id == "C002" for f in findings)

    def test_identical_names_not_shadowing(self) -> None:
        a = ScanReport(target="srv-a")
        a.tools.append(ToolInfo(name="eval", description="Run"))
        b = ScanReport(target="srv-b")
        b.tools.append(ToolInfo(name="eval", description="Run"))

        findings = _check_shadowing([a, b])
        c002 = [f for f in findings if f.rule_id == "C002"]
        assert len(c002) == 0


class TestC003Exfiltration:
    def test_read_on_a_send_on_b(self) -> None:
        a = ScanReport(target="srv-a")
        a.tools.append(
            ToolInfo(
                name="read_file",
                description="Read a file from disk and return its contents as text",
            )
        )
        b = ScanReport(target="srv-b")
        b.tools.append(
            ToolInfo(
                name="upload_to_slack",
                description="Upload a message to Slack channel via webhook",
            )
        )

        findings = _check_exfiltration([a, b])
        assert any(f.rule_id == "C003" for f in findings)

    def test_no_exfil_without_pair(self) -> None:
        a = ScanReport(target="srv-a")
        a.tools.append(ToolInfo(name="read_file", description="Read a file"))
        b = ScanReport(target="srv-b")
        b.tools.append(ToolInfo(name="calc", description="Do math"))

        findings = _check_exfiltration([a, b])
        c003 = [f for f in findings if f.rule_id == "C003"]
        assert len(c003) == 0


class TestC004CapabilityOverlap:
    def test_three_servers_file_read(self) -> None:
        scans = []
        for i in range(3):
            s = ScanReport(target=f"srv-{i}")
            s.tools.append(
                ToolInfo(name="read_file", description="Read a file from disk")
            )
            scans.append(s)

        findings = _check_capability_overlap(scans)
        assert any(f.rule_id == "C004" for f in findings)

    def test_two_servers_no_overlap_finding(self) -> None:
        scans = []
        for i in range(2):
            s = ScanReport(target=f"srv-{i}")
            s.tools.append(ToolInfo(name="read_file", description="Read file"))
            scans.append(s)

        findings = _check_capability_overlap(scans)
        c004 = [f for f in findings if f.rule_id == "C004"]
        assert len(c004) == 0  # Need 3+ for overlap warning


class TestC005PermissionGradient:
    def test_read_only_with_write_capable(self) -> None:
        a = ScanReport(target="read-srv")
        a.tools.append(ToolInfo(name="get_weather", description="Get weather data"))
        b = ScanReport(target="write-srv")
        b.tools.append(
            ToolInfo(name="delete_files", description="Delete files from disk")
        )

        findings = _check_permission_gradient([a, b])
        assert any(f.rule_id == "C005" for f in findings)

    def test_all_read_only_no_gradient(self) -> None:
        a = ScanReport(target="srv-a")
        a.tools.append(ToolInfo(name="get_weather", description="Get weather"))
        b = ScanReport(target="srv-b")
        b.tools.append(ToolInfo(name="search_docs", description="Search documents"))

        findings = _check_permission_gradient([a, b])
        c005 = [f for f in findings if f.rule_id == "C005"]
        assert len(c005) == 0


class TestContextAnalyzer:
    def test_full_analysis(self) -> None:
        a = ScanReport(target="srv-a")
        a.tools.append(ToolInfo(name="eval", description="Run code"))
        a.tools.append(ToolInfo(name="read_file", description="Read file from disk"))

        b = ScanReport(target="srv-b")
        b.tools.append(ToolInfo(name="eval", description="Run code"))
        b.tools.append(
            ToolInfo(name="post_to_api", description="Post data to remote API")
        )

        analyzer = ContextAnalyzer([a, b])
        report = analyzer.analyze()

        assert report.server_count == 2
        assert report.tool_count == 4
        # C001: eval collision
        assert any(f.rule_id == "C001" for f in report.findings)
        # C003: read_file + post_to_api = exfil chain
        assert any(f.rule_id == "C003" for f in report.findings)
        # Risk graph should have entries
        assert len(report.risk_graph) > 0

    def test_to_dict(self) -> None:
        a = ScanReport(target="srv-a")
        a.tools.append(ToolInfo(name="eval", description="Run"))
        b = ScanReport(target="srv-b")
        b.tools.append(ToolInfo(name="eval", description="Run"))

        analyzer = ContextAnalyzer([a, b])
        report = analyzer.analyze()
        d = report.to_dict()

        assert d["server_count"] == 2
        assert len(d["findings"]) >= 1
        assert "risk_graph" in d
