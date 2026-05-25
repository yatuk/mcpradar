"""Watch modulu ve SQLite store testleri."""

import json
import tempfile
from pathlib import Path

from mcpradar.scanner.report import (
    Finding,
    PromptInfo,
    ResourceInfo,
    ScanReport,
    Severity,
    ToolInfo,
)
from mcpradar.storage.store import Store


class TestStore:
    def test_save_and_load(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(db_path=Path(tmp) / "test.db")
            report = ScanReport(target="http://test", id="test123")
            report.tools.append(ToolInfo(name="t1", description="d1"))

            sid = store.save(report)
            assert sid == "test123"

            loaded = store.load("test123")
            assert loaded.id == "test123"
            assert loaded.target == "http://test"
            assert len(loaded.tools) == 1
            assert loaded.tools[0].name == "t1"
            store.close()

    def test_export_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(db_path=Path(tmp) / "test.db")
            report = ScanReport(target="http://x", id="exp1")
            out = Path(tmp) / "exported.json"
            store.export_json(report, out)
            store.close()

            data = json.loads(out.read_text())
            assert data["id"] == "exp1"

    def test_load_nonexistent_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(db_path=Path(tmp) / "test.db")
            try:
                store.load("nonexistent")
                raise AssertionError("LookupError bekleniyordu")
            except LookupError:
                pass
            finally:
                store.close()

    def test_latest_scans(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(db_path=Path(tmp) / "test.db")
            r1 = ScanReport(target="http://srv", id="s1", scanned_at="2026-01-01T00:00:00")
            r2 = ScanReport(target="http://srv", id="s2", scanned_at="2026-01-02T00:00:00")
            store.save(r1)
            store.save(r2)

            latest = store.latest_scans("http://srv", 2)
            assert len(latest) == 2
            assert latest[0] == "s2"
            store.close()

    def test_scan_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(db_path=Path(tmp) / "test.db")
            assert store.scan_count("http://srv") == 0

            store.save(ScanReport(target="http://srv", id="c1"))
            assert store.scan_count("http://srv") == 1
            store.close()

    def test_list_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(db_path=Path(tmp) / "test.db")
            store.save(ScanReport(target="http://a", id="a1"))
            store.save(ScanReport(target="http://b", id="b1"))

            targets = store.list_targets()
            assert "http://a" in targets
            assert "http://b" in targets
            store.close()

    def test_save_with_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(db_path=Path(tmp) / "test.db")
            report = ScanReport(target="http://srv", id="f1")
            report.add_finding(
                Finding(
                    rule_id="R001",
                    title="Bad",
                    description="Dangerous",
                    severity=Severity.CRITICAL,
                    target="eval",
                    evidence="eval",
                )
            )

            store.save(report)
            loaded = store.load("f1")
            assert len(loaded.findings) == 1
            assert loaded.findings[0].rule_id == "R001"
            assert loaded.summary["critical"] == 1
            store.close()

    def test_save_with_prompts_and_resources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(db_path=Path(tmp) / "test.db")
            report = ScanReport(target="http://srv", id="pr1")
            report.prompts.append(PromptInfo(name="greet", description="Greeting"))
            report.resources.append(ResourceInfo(uri="file:///data", name="data"))

            store.save(report)
            loaded = store.load("pr1")
            assert len(loaded.prompts) == 1
            assert loaded.prompts[0].name == "greet"
            assert len(loaded.resources) == 1
            assert loaded.resources[0].uri == "file:///data"
            store.close()

    def test_scan_since_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(db_path=Path(tmp) / "test.db")
            r1 = ScanReport(target="http://srv", id="s1", scanned_at="2026-01-01")
            r2 = ScanReport(target="http://srv", id="s2", scanned_at="2026-01-03")
            r3 = ScanReport(target="http://srv", id="s3", scanned_at="2026-01-05")
            store.save(r1)
            store.save(r2)
            store.save(r3)

            ids = store.scan_since("http://srv", "2026-01-03")
            assert set(ids) == {"s2", "s3"}
            store.close()

    def test_scan_since_scan_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(db_path=Path(tmp) / "test.db")
            store.save(ScanReport(target="http://srv", id="old", scanned_at="2026-01-01"))
            store.save(ScanReport(target="http://srv", id="mid", scanned_at="2026-01-02"))
            store.save(ScanReport(target="http://srv", id="new", scanned_at="2026-01-03"))

            ids = store.scan_since("http://srv", "old")
            assert "new" in ids
            assert "mid" in ids
            assert "old" not in ids
            store.close()

    def test_scans_older_than(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(db_path=Path(tmp) / "test.db")
            store.save(ScanReport(target="http://srv", id="old", scanned_at="2025-01-01"))
            store.save(ScanReport(target="http://srv", id="new", scanned_at="2026-06-01"))

            ids = store.scans_older_than("2026-01-01")
            assert "old" in ids
            assert "new" not in ids
            store.close()

    def test_scans_beyond_keep(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(db_path=Path(tmp) / "test.db")
            for i in range(5):
                store.save(
                    ScanReport(
                        target="http://srv",
                        id=f"s{i}",
                        scanned_at=f"2026-01-0{i + 1}",
                    )
                )

            ids = store.scans_beyond_keep("http://srv", 2)
            assert len(ids) == 3  # keep 2, delete 3
            store.close()

    def test_delete_scans(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(db_path=Path(tmp) / "test.db")
            store.save(ScanReport(target="http://srv", id="del1"))
            store.save(ScanReport(target="http://srv", id="keep"))
            store.save(ScanReport(target="http://srv", id="del2"))

            store.delete_scans(["del1", "del2"])
            assert store.scan_count("http://srv") == 1
            try:
                store.load("del1")
                raise AssertionError("Silinmedi!")
            except LookupError:
                pass
            store.load("keep")  # should not raise
            store.close()

    def test_repeated_save_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(db_path=Path(tmp) / "test.db")
            r1 = ScanReport(target="http://srv", id="same")
            r1.tools.append(ToolInfo(name="t1", description="first"))
            store.save(r1)

            r2 = ScanReport(target="http://srv", id="same")
            r2.tools.append(ToolInfo(name="t2", description="second"))
            store.save(r2)

            loaded = store.load("same")
            assert len(loaded.tools) == 1
            assert loaded.tools[0].name == "t2"
            store.close()
