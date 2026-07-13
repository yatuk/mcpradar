"""Scan result data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import uuid4

if TYPE_CHECKING:
    from mcpradar.probe.prober import ProbeResult


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __ge__(self, other: Severity) -> bool:  # type: ignore[override]
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        return order[self.value] >= order[other.value]

    @classmethod
    def from_str(cls, s: str) -> Severity:
        return cls(s.lower())


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: Severity
    target: str
    location: str = ""
    evidence: str = ""
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolInfo:
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] = field(default_factory=dict)


@dataclass
class PromptInfo:
    name: str
    description: str = ""
    arguments: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ResourceInfo:
    uri: str
    name: str = ""
    description: str = ""
    mime_type: str = ""


@dataclass
class ScanReport:
    id: str = field(default_factory=lambda: uuid4().hex[:12])
    target: str = ""
    transport: str = "http"
    scanned_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    server_version: str = ""
    protocol_version: str = ""
    capabilities: dict[str, object] = field(default_factory=dict)
    tools: list[ToolInfo] = field(default_factory=list)
    prompts: list[PromptInfo] = field(default_factory=list)
    resources: list[ResourceInfo] = field(default_factory=list)
    probe_results: list[ProbeResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    # True when tool enumeration did not complete (connection/parse error or a
    # per-tool rule exception). An incomplete scan must not be scored as a clean
    # grade A — the leaderboard renders it as a separate "scan incomplete" state.
    incomplete: bool = False
    incomplete_reason: str = ""
    summary: dict[str, int] = field(
        default_factory=lambda: {
            "total_tools": 0,
            "total_prompts": 0,
            "total_resources": 0,
            "clean": 0,
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0,
        }
    )

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.summary[finding.severity.value] += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "transport": self.transport,
            "scanned_at": self.scanned_at,
            "incomplete": self.incomplete,
            "incomplete_reason": self.incomplete_reason,
            "tools": [
                {
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.input_schema,
                    "output_schema": t.output_schema,
                }
                for t in self.tools
            ],
            "prompts": [
                {"name": p.name, "description": p.description, "arguments": p.arguments}
                for p in self.prompts
            ],
            "resources": [
                {"uri": r.uri, "name": r.name, "description": r.description} for r in self.resources
            ],
            "probe_results": [pr.to_dict() for pr in self.probe_results],
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "target": f.target,
                    "location": f.location,
                    "evidence": f.evidence,
                    "detail": f.detail,
                }
                for f in self.findings
            ],
            "summary": self.summary,
        }
