"""Guvenlik istatistikleri ve egilim analizi motoru."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, cast


@dataclass
class ServerStats:
    """Sunucu bazli guvenlik istatistikleri."""

    target: str
    total_scans: int = 0
    first_scan: str = ""
    last_scan: str = ""
    total_findings: int = 0
    findings_by_severity: dict[str, int] = field(
        default_factory=lambda: {
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0,
        }
    )
    top_rules: list[tuple[str, int]] = field(default_factory=list)
    recent_diffs: int = 0
    security_diffs: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "total_scans": self.total_scans,
            "first_scan": self.first_scan,
            "last_scan": self.last_scan,
            "total_findings": self.total_findings,
            "findings_by_severity": self.findings_by_severity,
            "top_rules": [{"rule_id": r, "count": c} for r, c in self.top_rules],
            "recent_diffs": self.recent_diffs,
            "security_diffs": self.security_diffs,
        }


@dataclass
class GlobalStats:
    """Tum taranan hedefler arasinda toplu istatistikler."""

    total_targets: int = 0
    total_scans: int = 0
    total_findings: int = 0
    findings_by_severity: dict[str, int] = field(
        default_factory=lambda: {
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0,
        }
    )
    top_triggered_rules: list[tuple[str, int]] = field(default_factory=list)
    top_scanned_targets: list[tuple[str, int]] = field(default_factory=list)
    audit_event_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_targets": self.total_targets,
            "total_scans": self.total_scans,
            "total_findings": self.total_findings,
            "findings_by_severity": self.findings_by_severity,
            "top_triggered_rules": [
                {"rule_id": r, "count": c} for r, c in self.top_triggered_rules
            ],
            "top_scanned_targets": [{"target": t, "count": c} for t, c in self.top_scanned_targets],
            "audit_event_count": self.audit_event_count,
        }


@dataclass
class TrendReport:
    """Tek bir hedef icin zaman serisi egilim analizi."""

    target: str
    days: int
    daily_scans: list[dict[str, Any]] = field(default_factory=list)
    daily_findings: list[dict[str, Any]] = field(default_factory=list)
    trend_direction: str = "stable"  # improving|worsening|stable
    severity_trend: dict[str, str] = field(
        default_factory=lambda: {
            "low": "stable",
            "medium": "stable",
            "high": "stable",
            "critical": "stable",
        }
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "days": self.days,
            "daily_scans": self.daily_scans,
            "daily_findings": self.daily_findings,
            "trend_direction": self.trend_direction,
            "severity_trend": self.severity_trend,
        }


# Modul seviyesinde 5 dakika TTL'li bellek ici onbellek
_stats_cache: dict[str, tuple[float, Any]] = {}
_CACHE_TTL = 300  # 5 dakika


def _cache_key(method: str, *args: Any) -> str:
    return f"{method}:{'|'.join(str(a) for a in args)}"


def _cache_get(key: str) -> Any | None:
    entry = _stats_cache.get(key)
    if entry is None:
        return None
    ts, val = entry
    if time.monotonic() - ts > _CACHE_TTL:
        del _stats_cache[key]
        return None
    return val


def _cache_set(key: str, val: Any) -> None:
    _stats_cache[key] = (time.monotonic(), val)


class StatsEngine:
    """SQLite Store verilerinden guvenlik istatistikleri hesaplar."""

    def __init__(self, store: Any | None = None) -> None:
        from mcpradar.storage.store import Store

        self._store: Store = store if store is not None else Store()

    # -- Sunucu Istatistikleri ---------------------------------------------

    def server_stats(self, target: str) -> ServerStats:
        """Hedef sunucu bazinda istatistik hesapla."""
        cache_key = _cache_key("server_stats", target)
        cached = _cache_get(cache_key)
        if cached is not None:
            return cast(ServerStats, cached)

        stats = ServerStats(target=target)
        conn = self._store._conn

        # Bu hedef icin toplam tarama sayisi
        row = conn.execute("SELECT COUNT(*) FROM scans WHERE target = ?", (target,)).fetchone()
        stats.total_scans = row[0] if row else 0

        if stats.total_scans == 0:
            _cache_set(cache_key, stats)
            return stats

        # Ilk ve son tarama zaman damgalari
        row = conn.execute(
            "SELECT MIN(scanned_at), MAX(scanned_at) FROM scans WHERE target = ?",
            (target,),
        ).fetchone()
        if row:
            stats.first_scan = row[0] or ""
            stats.last_scan = row[1] or ""

        # Bu hedefin tum taramalarindaki toplam bulgu sayisi
        row = conn.execute(
            """
            SELECT COUNT(*) FROM findings
            WHERE scan_id IN (SELECT id FROM scans WHERE target = ?)
            """,
            (target,),
        ).fetchone()
        stats.total_findings = row[0] if row else 0

        # Onem derecesine gore bulgu sayilari
        for sev in ("low", "medium", "high", "critical"):
            row = conn.execute(
                """
                SELECT COUNT(*) FROM findings
                WHERE scan_id IN (SELECT id FROM scans WHERE target = ?)
                AND severity = ?
                """,
                (target, sev),
            ).fetchone()
            stats.findings_by_severity[sev] = row[0] if row else 0

        # Bu hedef icin en cok tetiklenen 5 kural
        rows = conn.execute(
            """
            SELECT rule_id, COUNT(*) as cnt FROM findings
            WHERE scan_id IN (SELECT id FROM scans WHERE target = ?)
            GROUP BY rule_id ORDER BY cnt DESC LIMIT 5
            """,
            (target,),
        ).fetchall()
        stats.top_rules = [(r[0], r[1]) for r in rows]

        # Son 30 gundeki farkliliklar (denetim gunlugunden)
        rows = conn.execute(
            """
            SELECT COUNT(*) FROM audit_log
            WHERE event_type = 'diff_detected' AND target = ?
            AND timestamp >= datetime('now', '-30 days')
            """,
            (target,),
        ).fetchone()
        stats.recent_diffs = rows[0] if rows else 0

        # Guvenlik etkili farkliliklar (security_count > 0)
        rows = conn.execute(
            """
            SELECT COUNT(*) FROM audit_log
            WHERE event_type = 'diff_detected' AND target = ?
            AND json_extract(detail, '$.security_count') > 0
            AND timestamp >= datetime('now', '-30 days')
            """,
            (target,),
        ).fetchone()
        stats.security_diffs = rows[0] if rows else 0

        _cache_set(cache_key, stats)
        return stats

    # -- Kuresel Istatistikler ---------------------------------------------

    def global_stats(self) -> GlobalStats:
        """Tum hedefler arasinda kuresel istatistik hesapla."""
        cache_key = _cache_key("global_stats")
        cached = _cache_get(cache_key)
        if cached is not None:
            return cast(GlobalStats, cached)

        stats = GlobalStats()
        conn = self._store._conn

        # Toplam hedef sayisi (benzersiz)
        row = conn.execute("SELECT COUNT(DISTINCT target) FROM scans").fetchone()
        stats.total_targets = row[0] if row else 0

        # Toplam tarama sayisi
        row = conn.execute("SELECT COUNT(*) FROM scans").fetchone()
        stats.total_scans = row[0] if row else 0

        # Toplam bulgu sayisi
        row = conn.execute("SELECT COUNT(*) FROM findings").fetchone()
        stats.total_findings = row[0] if row else 0

        # Onem derecesine gore bulgular
        for sev in ("low", "medium", "high", "critical"):
            row = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE severity = ?", (sev,)
            ).fetchone()
            stats.findings_by_severity[sev] = row[0] if row else 0

        # Kuresel en cok tetiklenen 5 kural
        rows = conn.execute(
            "SELECT rule_id, COUNT(*) as cnt FROM findings "
            "GROUP BY rule_id ORDER BY cnt DESC LIMIT 5"
        ).fetchall()
        stats.top_triggered_rules = [(r[0], r[1]) for r in rows]

        # En cok taranan 5 hedef
        rows = conn.execute(
            "SELECT target, COUNT(*) as cnt FROM scans GROUP BY target ORDER BY cnt DESC LIMIT 5"
        ).fetchall()
        stats.top_scanned_targets = [(r[0], r[1]) for r in rows]

        # Toplam denetim olayi sayisi
        row = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()
        stats.audit_event_count = row[0] if row else 0

        _cache_set(cache_key, stats)
        return stats

    # -- Egilim Analizi ----------------------------------------------------

    def trend_analysis(self, target: str, days: int = 30) -> TrendReport:
        """Bir hedefin N gunluk guvenlik egilimini analiz et."""
        cache_key = _cache_key("trend", target, str(days))
        cached = _cache_get(cache_key)
        if cached is not None:
            return cast(TrendReport, cached)

        report = TrendReport(target=target, days=days)
        conn = self._store._conn

        # Gunluk tarama sayilari
        rows = conn.execute(
            """
            SELECT DATE(scanned_at) as day, COUNT(*) as cnt
            FROM scans
            WHERE target = ? AND scanned_at >= datetime('now', ? || ' days')
            GROUP BY day ORDER BY day
            """,
            (target, f"-{days}"),
        ).fetchall()
        report.daily_scans = [{"date": r[0], "count": r[1]} for r in rows]

        # Gunluk bulgu sayilari
        rows = conn.execute(
            """
            SELECT DATE(s.scanned_at) as day, COUNT(f.id) as cnt
            FROM findings f
            JOIN scans s ON f.scan_id = s.id
            WHERE s.target = ? AND s.scanned_at >= datetime('now', ? || ' days')
            GROUP BY day ORDER BY day
            """,
            (target, f"-{days}"),
        ).fetchall()
        report.daily_findings = [{"date": r[0], "count": r[1]} for r in rows]

        # Egilim yonu: ilk yari ile ikinci yariyi karsilastir
        findings_list = [d["count"] for d in report.daily_findings]
        if len(findings_list) >= 2:
            mid = len(findings_list) // 2
            first_half_avg = sum(findings_list[:mid]) / mid
            second_half_avg = sum(findings_list[mid:]) / (len(findings_list) - mid)

            # Sifira bolmeyi onle
            if first_half_avg > 0:
                change_pct = (second_half_avg - first_half_avg) / first_half_avg
            elif second_half_avg > 0:
                change_pct = 1.0  # sifirdan pozitife gecis = kotulesme
            else:
                change_pct = 0.0

            if change_pct < -0.2:
                report.trend_direction = "improving"
            elif change_pct > 0.2:
                report.trend_direction = "worsening"
            else:
                report.trend_direction = "stable"

        # Onem seviyesi bazinda egilim
        for sev in ("low", "medium", "high", "critical"):
            rows = conn.execute(
                """
                SELECT DATE(s.scanned_at) as day, COUNT(f.id) as cnt
                FROM findings f
                JOIN scans s ON f.scan_id = s.id
                WHERE s.target = ? AND f.severity = ?
                AND s.scanned_at >= datetime('now', ? || ' days')
                GROUP BY day ORDER BY day
                """,
                (target, sev, f"-{days}"),
            ).fetchall()
            sev_counts = [r[1] for r in rows]
            if len(sev_counts) >= 2:
                mid = len(sev_counts) // 2
                first_avg = sum(sev_counts[:mid]) / mid
                second_avg = sum(sev_counts[mid:]) / (len(sev_counts) - mid)
                if first_avg > 0:
                    sev_change = (second_avg - first_avg) / first_avg
                elif second_avg > 0:
                    sev_change = 1.0
                else:
                    sev_change = 0.0

                if sev_change < -0.2:
                    report.severity_trend[sev] = "down"
                elif sev_change > 0.2:
                    report.severity_trend[sev] = "up"
                else:
                    report.severity_trend[sev] = "stable"

        _cache_set(cache_key, report)
        return report
