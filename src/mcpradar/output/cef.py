"""ScanReport -> CEF (Common Event Format) converter for SIEM/SOAR ingestion.

Produces RFC 3164-compatible CEF syslog lines, one per finding.
Compatible with Splunk, QRadar, ArcSight, and Microsoft Sentinel.
"""

from __future__ import annotations

from mcpradar import __version__
from mcpradar.scanner.report import ScanReport, Severity

# Severity to CEF numeric severity (0-10)
_CEF_SEVERITY: dict[Severity, str] = {
    Severity.LOW: "3",
    Severity.MEDIUM: "5",
    Severity.HIGH: "8",
    Severity.CRITICAL: "10",
}

# Characters that must be escaped in CEF extension values
_CEF_ESCAPE_MAP = str.maketrans({
    "\\": "\\\\",
    "=": "\\=",
    "\n": "\\n",
    "\r": "\\r",
    "|": "\\|",
})


def _escape(value: str) -> str:
    """Escape a CEF extension value."""
    return value.translate(_CEF_ESCAPE_MAP)


def _compute_score(finding_count: int, tool_count: int) -> str:
    """Compute approximate AIVSS score for CEF from findings/tools."""
    if tool_count == 0:
        return "0.0"
    raw = min(10.0, finding_count / max(tool_count, 1) * 5)
    return f"{raw:.1f}"


def to_cef(report: ScanReport) -> str:
    """Convert a ScanReport to CEF syslog lines.

    Returns one CEF line per finding, joined by newlines.
    Empty findings returns empty string.

    CEF format:
        CEF:0|deviceVendor|deviceProduct|deviceVersion|signatureId|name|severity|extension
    """
    if not report.findings:
        return ""

    tool_count = len(report.tools) if report.tools else 1
    finding_count = len(report.findings)
    aivss = _compute_score(finding_count, tool_count)
    server_name = _escape(report.target or "unknown")

    lines: list[str] = []
    for f in report.findings:
        sev_str = str(f.severity.value) if hasattr(f.severity, "value") else str(f.severity)
        sev_cef = _CEF_SEVERITY.get(f.severity, "5")  # type: ignore[arg-type]

        title = _escape(f.title or f.rule_id)
        rule_id = _escape(f.rule_id)
        target = _escape(f.target or "")
        desc = _escape(f.description or "")

        extensions = (
            f"suser={target} "
            f"cs1={server_name} "
            f"cs2=scanner "
            f"cs3={_escape(__version__)} "
            f"cn1={aivss} "
            f"cs4={sev_str} "
            f"cs5={desc[:120]} "
            f"cs6={rule_id} "
            f"msg={title}"
        )

        line = (
            f"CEF:0|MCPRadar|mcpradar|{__version__}|"
            f"{rule_id}|{title}|{sev_cef}|{extensions}"
        )
        lines.append(line)

    return "\n".join(lines)


def to_cef_json(report: ScanReport) -> dict:
    """Convert a ScanReport to a JSON payload suitable for webhook POST.

    Returns a dict with CEF lines + metadata for SIEM ingestion.
    """
    return {
        "vendor": "MCPRadar",
        "product": "mcpradar",
        "version": __version__,
        "target": report.target,
        "transport": report.transport,
        "tool_count": len(report.tools) if report.tools else 0,
        "finding_count": len(report.findings),
        "cef_lines": to_cef(report).split("\n") if report.findings else [],
        "timestamp": getattr(report, "scanned_at", ""),
    }
