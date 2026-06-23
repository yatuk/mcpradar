"""Tests for statistics engine."""

from __future__ import annotations

import tempfile
from pathlib import Path

from mcpradar.audit import stats as stats_module
from mcpradar.audit.auditor import AuditLogger
from mcpradar.audit.stats import StatsEngine
from mcpradar.scanner.report import Finding, ScanReport, Severity
from mcpradar.storage.store import Store


def _make_finding(
    rule_id: str, severity: Severity, title: str = "test", target: str = "test_tool"
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        description=f"Finding from {rule_id}",
        severity=severity,
        target=target,
    )


class TestStatsEngine:
    """Tests for the StatsEngine class."""

    def setup_method(self) -> None:
        # Clear the module-level stats cache to ensure isolation
        # between tests that use separate Store instances.
        stats_module._stats_cache.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(db_path=Path(self.tmp.name) / "test.db")
        self.engine = StatsEngine(store=self.store)

    def teardown_method(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def _seed_scan(self, target: str, findings: list[Finding] | None = None) -> str:
        """Helper: save a scan with optional findings and return the scan_id."""
        report = ScanReport(target=target, transport="http")
        if findings:
            for f in findings:
                report.add_finding(f)
        return self.store.save(report)

    def test_server_stats_empty_target(self) -> None:
        stats = self.engine.server_stats("http://no-data.com")
        assert stats.target == "http://no-data.com"
        assert stats.total_scans == 0
        assert stats.total_findings == 0

    def test_server_stats_basic(self) -> None:
        self._seed_scan("http://example.com")
        stats = self.engine.server_stats("http://example.com")
        assert stats.total_scans == 1
        assert stats.first_scan != ""
        assert stats.last_scan != ""

    def test_server_stats_findings_by_severity(self) -> None:
        findings = [
            _make_finding("R001", Severity.CRITICAL),
            _make_finding("R001", Severity.CRITICAL),
            _make_finding("R102", Severity.HIGH),
            _make_finding("R104", Severity.MEDIUM),
            _make_finding("R105", Severity.LOW),
        ]
        self._seed_scan("http://example.com", findings)
        stats = self.engine.server_stats("http://example.com")
        assert stats.total_findings == 5
        assert stats.findings_by_severity["critical"] == 2
        assert stats.findings_by_severity["high"] == 1
        assert stats.findings_by_severity["medium"] == 1
        assert stats.findings_by_severity["low"] == 1

    def test_server_stats_top_rules(self) -> None:
        findings = [
            _make_finding("R001", Severity.CRITICAL),
            _make_finding("R001", Severity.CRITICAL),
            _make_finding("R001", Severity.CRITICAL),
            _make_finding("R102", Severity.HIGH),
            _make_finding("R102", Severity.HIGH),
            _make_finding("R104", Severity.MEDIUM),
        ]
        self._seed_scan("http://example.com", findings)
        stats = self.engine.server_stats("http://example.com")
        assert len(stats.top_rules) >= 3
        # R001 should be top
        assert stats.top_rules[0][0] == "R001"
        assert stats.top_rules[0][1] == 3

    def test_global_stats(self) -> None:
        self._seed_scan("http://a.com", [_make_finding("R001", Severity.CRITICAL)])
        self._seed_scan("http://b.com", [_make_finding("R102", Severity.HIGH)])
        stats = self.engine.global_stats()
        assert stats.total_targets == 2
        assert stats.total_scans == 2
        assert stats.total_findings == 2

    def test_global_stats_empty_db(self) -> None:
        stats = self.engine.global_stats()
        assert stats.total_targets == 0
        assert stats.total_scans == 0
        assert stats.total_findings == 0

    def test_trend_analysis_no_data(self) -> None:
        trend = self.engine.trend_analysis("http://no-data.com", days=30)
        assert trend.target == "http://no-data.com"
        assert trend.days == 30
        assert trend.trend_direction == "stable"
        assert len(trend.daily_scans) == 0

    def test_trend_analysis_stable(self) -> None:
        # Same findings every day = stable
        self._seed_scan("http://example.com", [_make_finding("R001", Severity.LOW)])
        trend = self.engine.trend_analysis("http://example.com", days=365)
        # With only one scan, should be stable
        assert trend.trend_direction == "stable"

    def test_server_stats_recent_diffs(self) -> None:
        # Seed a scan
        self._seed_scan("http://example.com")
        # Add a diff audit event
        logger = AuditLogger(store=self.store)
        logger.log_diff("http://example.com", 5, 2)
        stats = self.engine.server_stats("http://example.com")
        assert stats.recent_diffs == 1
        assert stats.security_diffs == 1
