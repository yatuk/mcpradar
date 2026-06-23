"""Tests for audit logging module."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from mcpradar.audit.auditor import AuditEvent, AuditLogger
from mcpradar.storage.store import Store


class TestAuditEvent:
    """Tests for the AuditEvent dataclass."""

    def test_create_defaults(self) -> None:
        event = AuditEvent(
            event_id="evt_test123",
            timestamp="2026-06-23T10:00:00+00:00",
            event_type="scan_started",
            severity="info",
            target="http://example.com",
        )
        assert event.event_id == "evt_test123"
        assert event.event_type == "scan_started"
        assert event.severity == "info"
        assert event.detail == {}

    def test_event_id_format(self) -> None:
        """event_id should start with 'evt_'."""
        event = AuditEvent(
            event_id="evt_abc123def456",
            timestamp="2026-06-23T10:00:00+00:00",
            event_type="scan_completed",
            severity="warning",
            target="http://example.com",
        )
        assert event.event_id.startswith("evt_")
        assert len(event.event_id) == 16  # evt_ + 12 hex chars

    def test_detail_serializable(self) -> None:
        event = AuditEvent(
            event_id="evt_test",
            timestamp="2026-06-23T10:00:00+00:00",
            event_type="diff_detected",
            severity="warning",
            target="http://example.com",
            detail={"change_count": 5, "security_count": 2},
        )
        d = event.to_dict()
        assert d["detail"]["change_count"] == 5
        assert json.dumps(d)  # must be JSON-serializable


class TestAuditLogger:
    """Tests for the AuditLogger class."""

    def setup_method(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(db_path=Path(self.tmp.name) / "test.db")
        self.logger = AuditLogger(store=self.store)

    def teardown_method(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def test_log_scan_start_returns_event_id(self) -> None:
        event_id = self.logger.log_scan_start("http://example.com")
        assert event_id.startswith("evt_")

    def test_log_scan_complete_no_findings(self) -> None:
        self.logger.log_scan_complete("scan123", 0)
        events = self.logger.query(event_type="scan_completed")
        assert len(events) == 1
        assert events[0].severity == "info"
        assert events[0].detail["findings_count"] == 0

    def test_log_scan_complete_with_findings_is_warning(self) -> None:
        self.logger.log_scan_complete("scan456", 5)
        events = self.logger.query(event_type="scan_completed")
        assert events[0].severity == "warning"

    def test_log_diff_with_security_issues(self) -> None:
        self.logger.log_diff("http://example.com", 10, 3)
        events = self.logger.query(event_type="diff_detected")
        assert len(events) == 1
        assert events[0].severity == "warning"
        assert events[0].detail["security_count"] == 3

    def test_log_diff_no_security_issues(self) -> None:
        self.logger.log_diff("http://example.com", 5, 0)
        events = self.logger.query(event_type="diff_detected")
        assert events[0].severity == "info"

    def test_log_alert(self) -> None:
        self.logger.log_alert("http://example.com", "webhook")
        events = self.logger.query(event_type="alert_sent")
        assert len(events) == 1
        assert events[0].detail["alert_type"] == "webhook"

    def test_log_error(self) -> None:
        self.logger.log_error("http://example.com", "Connection refused")
        events = self.logger.query(event_type="error")
        assert len(events) == 1
        assert events[0].severity == "error"
        assert "Connection refused" in events[0].detail["error_message"]

    def test_query_all(self) -> None:
        self.logger.log_scan_start("http://a.com")
        self.logger.log_scan_start("http://b.com")
        events = self.logger.query()
        assert len(events) == 2

    def test_query_by_type(self) -> None:
        self.logger.log_scan_start("http://a.com")
        self.logger.log_error("http://b.com", "fail")
        events = self.logger.query(event_type="error")
        assert len(events) == 1
        assert events[0].event_type == "error"

    def test_query_by_target(self) -> None:
        self.logger.log_scan_start("http://a.com")
        self.logger.log_scan_start("http://b.com")
        events = self.logger.query(target="http://a.com")
        assert len(events) == 1
        assert events[0].target == "http://a.com"

    def test_query_by_since(self) -> None:
        self.logger.log_scan_start("http://a.com")
        events = self.logger.query(since="2020-01-01T00:00:00+00:00")
        assert len(events) == 1

    def test_query_limit(self) -> None:
        for i in range(10):
            self.logger.log_scan_start(f"http://{i}.com")
        events = self.logger.query(limit=3)
        assert len(events) == 3

    def test_export_json(self) -> None:
        self.logger.log_scan_start("http://a.com")
        self.logger.log_scan_complete("scan1", 2)
        export_path = Path(self.tmp.name) / "audit.json"
        self.logger.export_audit_log(export_path, fmt="json")
        assert export_path.exists()
        data = json.loads(export_path.read_text())
        assert len(data) == 2

    def test_export_jsonl(self) -> None:
        self.logger.log_scan_start("http://a.com")
        export_path = Path(self.tmp.name) / "audit.jsonl"
        self.logger.export_audit_log(export_path, fmt="jsonl")
        lines = export_path.read_text().strip().split("\n")
        assert len(lines) == 1

    def test_export_csv(self) -> None:
        self.logger.log_scan_start("http://a.com")
        export_path = Path(self.tmp.name) / "audit.csv"
        self.logger.export_audit_log(export_path, fmt="csv")
        content = export_path.read_text()
        assert "event_id" in content

    def test_export_invalid_format(self) -> None:
        export_path = Path(self.tmp.name) / "audit.txt"
        try:
            self.logger.export_audit_log(export_path, fmt="invalid")
        except ValueError:
            pass  # expected
        else:
            raise AssertionError("Expected ValueError for invalid format")

    def test_injectable_store_isolation(self) -> None:
        """Verify two loggers with different stores are isolated."""
        tmp2 = tempfile.TemporaryDirectory()
        store2 = Store(db_path=Path(tmp2.name) / "test2.db")
        logger2 = AuditLogger(store=store2)

        self.logger.log_scan_start("http://store1.com")
        logger2.log_scan_start("http://store2.com")

        assert len(self.logger.query()) == 1
        assert len(logger2.query()) == 1
        assert self.logger.query()[0].target == "http://store1.com"
        assert logger2.query()[0].target == "http://store2.com"

        store2.close()
        tmp2.cleanup()

    def test_default_store_creates_real_store(self) -> None:
        """Even without injecting, a default Store should work."""
        logger = AuditLogger()
        event_id = logger.log_scan_start("http://default-test.com")
        events = logger.query(target="http://default-test.com")
        assert len(events) >= 1
        # Clean up
        logger._store.delete_audit_events([event_id])
