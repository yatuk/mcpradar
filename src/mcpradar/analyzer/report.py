"""Cross-server contamination analysis data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from mcpradar.scanner.report import ScanReport, Severity


@dataclass
class CrossFinding:
    rule_id: str
    title: str
    description: str
    severity: Severity
    servers: list[str] = field(default_factory=list)
    detail: dict[str, object] = field(default_factory=dict)


@dataclass
class ContextAnalysisReport:
    id: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    server_count: int = 0
    tool_count: int = 0
    scans: list[ScanReport] = field(default_factory=list)
    findings: list[CrossFinding] = field(default_factory=list)
    risk_graph: dict[str, list[str]] = field(default_factory=dict)

    def add_finding(self, f: CrossFinding) -> None:
        self.findings.append(f)

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "server_count": self.server_count,
            "tool_count": self.tool_count,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "servers": f.servers,
                    "detail": f.detail,
                }
                for f in self.findings
            ],
            "risk_graph": self.risk_graph,
        }
