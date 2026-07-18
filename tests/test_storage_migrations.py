"""Versioned SQLite migration and rich-report round-trip tests."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from mcpradar.scanner.protocol import ReadinessIssue
from mcpradar.scanner.report import (
    ResourceTemplateInfo,
    ScanReport,
    SurfaceState,
    SurfaceStatus,
)
from mcpradar.storage.store import LATEST_SCHEMA_VERSION, Store


def test_legacy_database_migrates_transactionally_with_backup(tmp_path: Path) -> None:
    database = tmp_path / "legacy.db"
    connection = sqlite3.connect(database)
    connection.execute(
        "CREATE TABLE scans (id TEXT PRIMARY KEY, target TEXT NOT NULL, "
        "transport TEXT NOT NULL DEFAULT 'http', scanned_at TEXT NOT NULL, "
        "summary TEXT NOT NULL DEFAULT '{}')"
    )
    connection.commit()
    connection.close()

    with Store(database) as store:
        version = store._conn.execute("PRAGMA user_version").fetchone()[0]
        migrations = store._conn.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()
    assert version == LATEST_SCHEMA_VERSION
    assert migrations == [(1,), (2,), (3,)]
    assert database.with_suffix(".db.bak-v0").exists()


def test_rich_report_round_trip(tmp_path: Path) -> None:
    report = ScanReport(
        id="rich",
        target="https://server/mcp",
        protocol_version="2025-11-25",
        server_instructions="Use safely",
        incomplete=True,
        incomplete_reason="resources timed out",
    )
    report.resource_templates.append(
        ResourceTemplateInfo(
            uri_template="file:///{path}",
            name="files",
            description="Project files",
            mime_type="text/plain",
        )
    )
    report.surface_status["resources"] = SurfaceStatus(
        state=SurfaceState.PARTIAL,
        count=2,
        pages=1,
        error="timeout",
        ttl_ms=1000,
        cache_scope="private",
    )
    report.migration_readiness.append(
        ReadinessIssue(
            code="MCP2026_SESSION_STATE",
            title="migration",
            description="session state",
        )
    )
    with Store(tmp_path / "roundtrip.db") as store:
        store.save(report)
        loaded = store.load("rich")
    assert loaded.report_schema_version == "1.1"
    assert loaded.incomplete is True
    assert loaded.server_instructions == "Use safely"
    assert loaded.resource_templates[0].uri_template == "file:///{path}"
    assert loaded.surface_status["resources"].state is SurfaceState.PARTIAL
    assert loaded.migration_readiness[0].code == "MCP2026_SESSION_STATE"
