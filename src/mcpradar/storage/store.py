"""SQLite tabanli snapshot saklama."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from platformdirs import user_data_dir

from mcpradar.scanner.report import ScanReport

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    transport   TEXT NOT NULL DEFAULT 'http',
    scanned_at  TEXT NOT NULL,
    summary     TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS tools (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    input_schema  TEXT NOT NULL DEFAULT '{}',
    output_schema TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS prompts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    arguments   TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS resources (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    uri         TEXT NOT NULL,
    name        TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    mime_type   TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    rule_id     TEXT NOT NULL,
    title       TEXT NOT NULL,
    description TEXT NOT NULL,
    severity    TEXT NOT NULL,
    target      TEXT NOT NULL DEFAULT '',
    location    TEXT NOT NULL DEFAULT '',
    evidence    TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON scans(scanned_at);
CREATE INDEX IF NOT EXISTS idx_tools_scan ON tools(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule_id);
"""


class Store:
    def __init__(self, db_path: Path | str | None = None) -> None:
        if db_path is None:
            data_dir = Path(user_data_dir("mcpradar", ensure_exists=True))
            path = data_dir / "mcpradar.db"
        else:
            path = Path(db_path)
        self.db_path = path
        self._conn = sqlite3.connect(str(path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------

    def save(self, report: ScanReport) -> str:
        self._conn.execute(
            "INSERT OR REPLACE INTO scans(id, target, transport, scanned_at, summary) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                report.id,
                report.target,
                report.transport,
                report.scanned_at,
                json.dumps(report.summary, ensure_ascii=False),
            ),
        )

        # Delete old children and re-insert (idempotent save)
        self._conn.execute("DELETE FROM tools WHERE scan_id = ?", (report.id,))
        self._conn.execute("DELETE FROM prompts WHERE scan_id = ?", (report.id,))
        self._conn.execute("DELETE FROM resources WHERE scan_id = ?", (report.id,))
        self._conn.execute("DELETE FROM findings WHERE scan_id = ?", (report.id,))

        for t in report.tools:
            self._conn.execute(
                "INSERT INTO tools(scan_id, name, description, input_schema, output_schema) "
                "VALUES (?,?,?,?,?)",
                (
                    report.id,
                    t.name,
                    t.description,
                    json.dumps(t.input_schema, ensure_ascii=False),
                    json.dumps(t.output_schema, ensure_ascii=False),
                ),
            )

        for p in report.prompts:
            self._conn.execute(
                "INSERT INTO prompts(scan_id, name, description, arguments) "
                "VALUES (?,?,?,?)",
                (
                    report.id,
                    p.name,
                    p.description,
                    json.dumps(p.arguments, ensure_ascii=False),
                ),
            )

        for r in report.resources:
            self._conn.execute(
                "INSERT INTO resources(scan_id, uri, name, description, mime_type) "
                "VALUES (?,?,?,?,?)",
                (report.id, r.uri, r.name, r.description, r.mime_type),
            )

        for f in report.findings:
            self._conn.execute(
                "INSERT INTO findings(scan_id, rule_id, title, description, "
                "severity, target, location, evidence, detail) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    report.id,
                    f.rule_id,
                    f.title,
                    f.description,
                    f.severity.value,
                    f.target,
                    f.location,
                    f.evidence,
                    json.dumps(f.detail, ensure_ascii=False),
                ),
            )

        self._conn.commit()
        return report.id

    # ------------------------------------------------------------------
    # Load
    # ------------------------------------------------------------------

    def load(self, scan_id: str) -> ScanReport:
        from mcpradar.scanner.report import (
            Finding,
            PromptInfo,
            ResourceInfo,
            ScanReport,
            Severity,
            ToolInfo,
        )

        row = self._conn.execute(
            "SELECT id, target, transport, scanned_at, summary FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()

        if row is None:
            raise LookupError(f"Snapshot bulunamadi: {scan_id}")

        report = ScanReport(
            id=row[0],
            target=row[1],
            transport=row[2],
            scanned_at=row[3],
        )
        report.summary = json.loads(row[4])

        for trow in self._conn.execute(
            "SELECT name, description, input_schema, output_schema "
            "FROM tools WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        ):
            report.tools.append(
                ToolInfo(
                    name=trow[0],
                    description=trow[1],
                    input_schema=json.loads(trow[2]),
                    output_schema=json.loads(trow[3]),
                )
            )

        for prow in self._conn.execute(
            "SELECT name, description, arguments FROM prompts WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        ):
            report.prompts.append(
                PromptInfo(
                    name=prow[0],
                    description=prow[1],
                    arguments=json.loads(prow[2]),
                )
            )

        for rrow in self._conn.execute(
            "SELECT uri, name, description, mime_type FROM resources WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        ):
            report.resources.append(
                ResourceInfo(
                    uri=rrow[0],
                    name=rrow[1],
                    description=rrow[2],
                    mime_type=rrow[3],
                )
            )

        for frow in self._conn.execute(
            "SELECT rule_id, title, description, severity, target, location, evidence, detail "
            "FROM findings WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        ):
            report.findings.append(
                Finding(
                    rule_id=frow[0],
                    title=frow[1],
                    description=frow[2],
                    severity=Severity(frow[3]),
                    target=frow[4],
                    location=frow[5],
                    evidence=frow[6],
                    detail=json.loads(frow[7]),
                )
            )

        return report

    # ------------------------------------------------------------------
    # Query helpers for diff
    # ------------------------------------------------------------------

    def latest_scans(self, target: str, limit: int = 2) -> list[str]:
        """Return scan IDs for a target, newest first."""
        rows = self._conn.execute(
            "SELECT id FROM scans WHERE target = ? ORDER BY scanned_at DESC LIMIT ?",
            (target, limit),
        ).fetchall()
        return [r[0] for r in rows]

    def scan_since(self, target: str, since: str) -> list[str]:
        """Return scan IDs since a given ISO timestamp or scan ID."""
        # Try as ISO timestamp first
        rows = self._conn.execute(
            "SELECT id FROM scans WHERE target = ? AND scanned_at >= ? "
            "ORDER BY scanned_at DESC",
            (target, since),
        ).fetchall()
        if rows:
            return [r[0] for r in rows]

        # Try as scan ID — get its timestamp, then find newer
        ref = self._conn.execute(
            "SELECT scanned_at FROM scans WHERE id = ?", (since,)
        ).fetchone()
        if ref is None:
            return []
        rows = self._conn.execute(
            "SELECT id FROM scans WHERE target = ? AND scanned_at > ? "
            "ORDER BY scanned_at DESC",
            (target, ref[0]),
        ).fetchall()
        return [r[0] for r in rows]

    def list_targets(self) -> list[str]:
        rows = self._conn.execute(
            "SELECT DISTINCT target FROM scans ORDER BY target"
        ).fetchall()
        return [r[0] for r in rows]

    def scan_count(self, target: str) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM scans WHERE target = ?", (target,)
        ).fetchone()
        return row[0] if row else 0

    def scans_older_than(self, cutoff: str, target: str | None = None) -> list[str]:
        if target:
            rows = self._conn.execute(
                "SELECT id FROM scans WHERE target = ? AND scanned_at < ?",
                (target, cutoff),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT id FROM scans WHERE scanned_at < ?",
                (cutoff,),
            ).fetchall()
        return [r[0] for r in rows]

    def scans_beyond_keep(self, target: str | None, keep: int) -> list[str]:
        if target:
            rows = self._conn.execute(
                "SELECT id FROM scans WHERE target = ? ORDER BY scanned_at DESC",
                (target,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT id FROM scans ORDER BY scanned_at DESC",
            ).fetchall()
        return [r[0] for r in rows[keep:]]

    def delete_scans(self, scan_ids: list[str]) -> None:
        for sid in scan_ids:
            self._conn.execute("DELETE FROM scans WHERE id = ?", (sid,))
        self._conn.commit()

    # ------------------------------------------------------------------
    # JSON export (keep for backwards compat)
    # ------------------------------------------------------------------

    def export_json(self, report: ScanReport, path: Path) -> None:
        path.write_text(
            json.dumps(report.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def close(self) -> None:
        self._conn.close()
