"""Structured audit logging for MCPRadar operations."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4


@dataclass
class AuditEvent:
    """A single security-relevant operational event."""

    event_id: str
    timestamp: str  # ISO 8601 UTC
    event_type: str  # scan_started|scan_completed|diff_detected|alert_sent|error
    severity: str  # info|warning|error
    target: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "severity": self.severity,
            "target": self.target,
            "detail": self.detail,
        }


class AuditLogger:
    """Yapilandirilmis denetim gunlugu (Store uzerinden SQLite destegi).

    Tum kolaylik metotlari log_event() uzerinden gecer boylece depolamaya
    tek bir kod yolu vardir. Store enjekte edilebilir; None ise varsayilan
    Store() olusturulur.
    """

    def __init__(self, store: Any | None = None) -> None:
        # Dairesel bagimliligi onlemek icin modul seviyesinde degil burada import
        from mcpradar.storage.store import Store

        self._store: Store = store if store is not None else Store()

    # -- Kolaylik metotlari --------------------------------------------------

    def log_scan_start(self, target: str, transport: str = "http") -> str:
        """Taramaya baslandigini kaydet. event_id dondurur."""
        return self.log_event(
            "scan_started",
            target,
            {"transport": transport},
            severity="info",
        )

    def log_scan_complete(self, scan_id: str, findings_count: int) -> None:
        """Tarama tamamlandigini bulgu ozetiyle kaydet."""
        sev = "warning" if findings_count > 0 else "info"
        self.log_event(
            "scan_completed",
            "",  # target detayda saklaniyor
            {"scan_id": scan_id, "findings_count": findings_count},
            severity=sev,
        )

    def log_diff(self, server: str, change_count: int, security_count: int) -> None:
        """Iki tarama anlik goruntusu arasindaki farki kaydet."""
        sev = "warning" if security_count > 0 else "info"
        self.log_event(
            "diff_detected",
            server,
            {"change_count": change_count, "security_count": security_count},
            severity=sev,
        )

    def log_alert(self, server: str, alert_type: str) -> None:
        """Uyari gonderimini kaydet (shell_cmd veya webhook)."""
        self.log_event(
            "alert_sent",
            server,
            {"alert_type": alert_type},
            severity="warning",
        )

    def log_error(self, target: str, error_message: str) -> None:
        """Operasyonel hatayi kaydet."""
        self.log_event(
            "error",
            target,
            {"error_message": error_message},
            severity="error",
        )

    # -- Ana gunluk metodu --------------------------------------------------

    def log_event(
        self,
        event_type: str,
        target: str,
        detail: dict[str, Any],
        severity: str = "info",
    ) -> str:
        """Genel amacli denetim olayi. event_id dondurur."""
        event_id = f"evt_{uuid4().hex[:12]}"
        timestamp = datetime.now(UTC).isoformat()
        self._store.save_audit_event(
            event_id=event_id,
            timestamp=timestamp,
            event_type=event_type,
            severity=severity,
            target=target,
            detail=detail,
        )
        return event_id

    # -- Sorgu --------------------------------------------------------------

    def query(
        self,
        since: str | None = None,
        event_type: str | None = None,
        target: str | None = None,
        limit: int = 50,
    ) -> list[AuditEvent]:
        """Denetim olaylarini istege bagli filtrelerle sorgula."""
        rows = self._store.query_audit_events(
            since=since,
            event_type=event_type,
            target=target,
            limit=limit,
        )
        return [
            AuditEvent(
                event_id=r["event_id"],
                timestamp=r["timestamp"],
                event_type=r["event_type"],
                severity=r["severity"],
                target=r["target"],
                detail=r["detail"],
            )
            for r in rows
        ]

    # -- Disa aktar ---------------------------------------------------------

    def export_audit_log(self, path: Path, fmt: str = "json") -> None:
        """Denetim gunlugunu dosyaya aktar.

        Formatlar: json (liste), jsonl (satir basina bir nesne), csv (duz).
        """
        # Tum olaylari yukle (sinirsiz)
        events = self.query(limit=0)

        if fmt == "json":
            data = [e.to_dict() for e in events]
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        elif fmt == "jsonl":
            with path.open("w", encoding="utf-8") as f:
                for e in events:
                    f.write(json.dumps(e.to_dict(), ensure_ascii=False) + "\n")
        elif fmt == "csv":
            with path.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=[
                        "event_id",
                        "timestamp",
                        "event_type",
                        "severity",
                        "target",
                        "detail",
                    ],
                )
                writer.writeheader()
                for e in events:
                    row = e.to_dict()
                    row["detail"] = json.dumps(row["detail"], ensure_ascii=False)
                    writer.writerow(row)
        else:
            raise ValueError(f"Desteklenmeyen disa aktarim formati: {fmt}")
