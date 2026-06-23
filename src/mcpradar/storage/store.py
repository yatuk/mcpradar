"""SQLite tabanli snapshot saklama."""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING, Any

from platformdirs import user_data_dir

from mcpradar.scanner.report import ScanReport

if TYPE_CHECKING:
    from mcpradar.fingerprint.models import ServerFingerprint

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

CREATE TABLE IF NOT EXISTS fingerprints (
    server_id         TEXT PRIMARY KEY,
    endpoint          TEXT NOT NULL,
    transport         TEXT NOT NULL DEFAULT 'http',
    server_version    TEXT NOT NULL DEFAULT '',
    protocol_version  TEXT NOT NULL DEFAULT '',
    capabilities      TEXT NOT NULL DEFAULT '{}',
    tool_names_hash   TEXT NOT NULL DEFAULT '',
    tool_count        INTEGER NOT NULL DEFAULT 0,
    first_seen        TEXT NOT NULL,
    last_seen         TEXT NOT NULL,
    tls_version       TEXT NOT NULL DEFAULT '',
    tls_cert_issuer   TEXT NOT NULL DEFAULT '',
    tls_cert_subject  TEXT NOT NULL DEFAULT '',
    tls_cert_expiry   TEXT NOT NULL DEFAULT '',
    tls_cert_valid    INTEGER NOT NULL DEFAULT 1,
    tls_self_signed   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_fp_endpoint ON fingerprints(endpoint);

CREATE TABLE IF NOT EXISTS audit_log (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    target TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log(target);
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

        # Migrations for v0.4.0
        with contextlib.suppress(Exception):
            self._conn.execute(
                "ALTER TABLE scans ADD COLUMN server_version TEXT NOT NULL DEFAULT ''"
            )
        with contextlib.suppress(Exception):
            self._conn.execute(
                "ALTER TABLE scans ADD COLUMN protocol_version TEXT NOT NULL DEFAULT ''"
            )
        with contextlib.suppress(Exception):
            self._conn.execute(
                "ALTER TABLE scans ADD COLUMN capabilities TEXT NOT NULL DEFAULT '{}'"
            )

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------

    def save(self, report: ScanReport) -> str:
        self._conn.execute(
            "INSERT OR REPLACE INTO scans(id, target, transport, scanned_at, summary, "
            "server_version, protocol_version, capabilities) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                report.id,
                report.target,
                report.transport,
                report.scanned_at,
                json.dumps(report.summary, ensure_ascii=False),
                report.server_version,
                report.protocol_version,
                json.dumps(report.capabilities, default=str, ensure_ascii=False),
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
                "INSERT INTO prompts(scan_id, name, description, arguments) VALUES (?,?,?,?)",
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
            "SELECT id, target, transport, scanned_at, summary, "
            "server_version, protocol_version, capabilities FROM scans WHERE id = ?",
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
        report.server_version = row[5] or ""
        report.protocol_version = row[6] or ""
        report.capabilities = json.loads(row[7]) if row[7] else {}

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
            "SELECT id FROM scans WHERE target = ? AND scanned_at >= ? ORDER BY scanned_at DESC",
            (target, since),
        ).fetchall()
        if rows:
            return [r[0] for r in rows]

        # Try as scan ID — get its timestamp, then find newer
        ref = self._conn.execute("SELECT scanned_at FROM scans WHERE id = ?", (since,)).fetchone()
        if ref is None:
            return []
        rows = self._conn.execute(
            "SELECT id FROM scans WHERE target = ? AND scanned_at > ? ORDER BY scanned_at DESC",
            (target, ref[0]),
        ).fetchall()
        return [r[0] for r in rows]

    def list_targets(self) -> list[str]:
        rows = self._conn.execute("SELECT DISTINCT target FROM scans ORDER BY target").fetchall()
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

    # ------------------------------------------------------------------
    # Fingerprint CRUD
    # ------------------------------------------------------------------

    def save_fingerprint(self, fp: ServerFingerprint) -> None:
        """Save or update a server fingerprint."""
        tls = fp.tls_info
        self._conn.execute(
            """INSERT OR REPLACE INTO fingerprints
               (server_id, endpoint, transport, server_version, protocol_version,
                capabilities, tool_names_hash, tool_count, first_seen, last_seen,
                tls_version, tls_cert_issuer, tls_cert_subject, tls_cert_expiry,
                tls_cert_valid, tls_self_signed)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                fp.server_id,
                fp.endpoint,
                fp.transport,
                fp.server_version,
                fp.protocol_version,
                json.dumps(fp.capabilities, default=str),
                fp.tool_names_hash,
                fp.tool_count,
                fp.first_seen,
                fp.last_seen,
                tls.version if tls else "",
                tls.cert_issuer if tls else "",
                tls.cert_subject if tls else "",
                tls.cert_expiry if tls else "",
                1 if (tls and tls.cert_valid) else 0,
                1 if (tls and tls.self_signed) else 0,
            ),
        )
        self._conn.commit()

    def load_fingerprint(self, endpoint: str, transport: str) -> ServerFingerprint | None:
        """Load the most recent fingerprint for an endpoint+transport pair."""
        from mcpradar.fingerprint.models import ServerFingerprint, TLSInfo

        row = self._conn.execute(
            """SELECT server_id, endpoint, transport, server_version, protocol_version,
                      capabilities, tool_names_hash, tool_count, first_seen, last_seen,
                      tls_version, tls_cert_issuer, tls_cert_subject, tls_cert_expiry,
                      tls_cert_valid, tls_self_signed
               FROM fingerprints
               WHERE endpoint = ? AND transport = ?
               ORDER BY last_seen DESC LIMIT 1""",
            (endpoint, transport),
        ).fetchone()

        if row is None:
            return None

        return ServerFingerprint(
            server_id=row[0],
            endpoint=row[1],
            transport=row[2],
            server_version=row[3],
            protocol_version=row[4],
            capabilities=json.loads(row[5]),
            tool_names_hash=row[6],
            tool_count=row[7],
            first_seen=row[8],
            last_seen=row[9],
            tls_info=TLSInfo(
                version=row[10],
                cert_issuer=row[11],
                cert_subject=row[12],
                cert_expiry=row[13],
                cert_valid=bool(row[14]),
                self_signed=bool(row[15]),
            )
            if row[10]
            else None,
        )

    def list_fingerprints(self) -> list[ServerFingerprint]:
        """List all stored fingerprints."""
        from mcpradar.fingerprint.models import ServerFingerprint, TLSInfo

        rows = self._conn.execute(
            """SELECT server_id, endpoint, transport, server_version, protocol_version,
                      capabilities, tool_names_hash, tool_count, first_seen, last_seen,
                      tls_version, tls_cert_issuer, tls_cert_subject, tls_cert_expiry,
                      tls_cert_valid, tls_self_signed
               FROM fingerprints
               ORDER BY last_seen DESC"""
        ).fetchall()

        results: list[ServerFingerprint] = []
        for row in rows:
            results.append(
                ServerFingerprint(
                    server_id=row[0],
                    endpoint=row[1],
                    transport=row[2],
                    server_version=row[3],
                    protocol_version=row[4],
                    capabilities=json.loads(row[5]),
                    tool_names_hash=row[6],
                    tool_count=row[7],
                    first_seen=row[8],
                    last_seen=row[9],
                    tls_info=TLSInfo(
                        version=row[10],
                        cert_issuer=row[11],
                        cert_subject=row[12],
                        cert_expiry=row[13],
                        cert_valid=bool(row[14]),
                        self_signed=bool(row[15]),
                    )
                    if row[10]
                    else None,
                )
            )
        return results

    def delete_fingerprint(self, server_id: str) -> bool:
        """Delete a fingerprint by server_id. Returns True if deleted."""
        cursor = self._conn.execute("DELETE FROM fingerprints WHERE server_id = ?", (server_id,))
        self._conn.commit()
        return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Audit log CRUD
    # ------------------------------------------------------------------

    def save_audit_event(
        self,
        event_id: str,
        timestamp: str,
        event_type: str,
        severity: str,
        target: str,
        detail: dict[str, Any],
    ) -> None:
        """Persist a single audit event."""
        self._conn.execute(
            "INSERT INTO audit_log (event_id, timestamp, event_type, severity, target, detail) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                event_id,
                timestamp,
                event_type,
                severity,
                target,
                json.dumps(detail, ensure_ascii=False),
            ),
        )
        self._conn.commit()

    def query_audit_events(
        self,
        since: str | None = None,
        event_type: str | None = None,
        target: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Query audit events with optional filters. Returns list of dicts."""
        query = (
            "SELECT event_id, timestamp, event_type, severity, target, detail "
            "FROM audit_log WHERE 1=1"
        )
        params: list[Any] = []

        if since is not None:
            query += " AND timestamp >= ?"
            params.append(since)
        if event_type is not None:
            query += " AND event_type = ?"
            params.append(event_type)
        if target is not None:
            query += " AND target = ?"
            params.append(target)

        query += " ORDER BY timestamp DESC"

        if limit > 0:
            query += " LIMIT ?"
            params.append(limit)

        rows = self._conn.execute(query, params).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            results.append(
                {
                    "event_id": row[0],
                    "timestamp": row[1],
                    "event_type": row[2],
                    "severity": row[3],
                    "target": row[4],
                    "detail": json.loads(row[5]) if row[5] else {},
                }
            )
        return results

    def delete_audit_events(self, event_ids: list[str]) -> None:
        """Delete specific audit events by ID."""
        if not event_ids:
            return
        placeholders = ",".join("?" for _ in event_ids)
        self._conn.execute(
            f"DELETE FROM audit_log WHERE event_id IN ({placeholders})",
            event_ids,
        )
        self._conn.commit()

    def purge_audit_log(self, older_than: str) -> int:
        """Delete audit events older than a timestamp. Returns count of deleted rows."""
        cursor = self._conn.execute("DELETE FROM audit_log WHERE timestamp < ?", (older_than,))
        self._conn.commit()
        return cursor.rowcount

    def close(self) -> None:
        self._conn.close()
