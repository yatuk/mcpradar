"""Scan result data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import uuid4

if TYPE_CHECKING:
    from mcpradar.probe.prober import ProbeResult
    from mcpradar.scanner.protocol import ReadinessIssue


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

    def to_dict(self) -> dict[str, Any]:
        from mcpradar.scoring.confidence import confidence_for

        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "target": self.target,
            "location": self.location,
            "evidence": self.evidence,
            "detail": self.detail,
            "confidence": confidence_for(self.rule_id),
        }


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
class ResourceTemplateInfo:
    uri_template: str
    name: str = ""
    description: str = ""
    mime_type: str = ""


class SurfaceState(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"
    FAILED = "failed"


@dataclass
class SurfaceStatus:
    state: SurfaceState = SurfaceState.UNSUPPORTED
    count: int = 0
    pages: int = 0
    error: str = ""
    ttl_ms: int | None = None
    cache_scope: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "state": self.state.value,
            "count": self.count,
            "pages": self.pages,
            "error": self.error,
            "ttl_ms": self.ttl_ms,
            "cache_scope": self.cache_scope,
        }


@dataclass
class ScanReport:
    report_schema_version: str = "1.1"
    id: str = field(default_factory=lambda: uuid4().hex[:12])
    target: str = ""
    transport: str = "http"
    scanned_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    server_version: str = ""
    protocol_version: str = ""
    capabilities: dict[str, object] = field(default_factory=dict)
    server_instructions: str = ""
    tools: list[ToolInfo] = field(default_factory=list)
    prompts: list[PromptInfo] = field(default_factory=list)
    resources: list[ResourceInfo] = field(default_factory=list)
    resource_templates: list[ResourceTemplateInfo] = field(default_factory=list)
    surface_status: dict[str, SurfaceStatus] = field(default_factory=dict)
    probe_results: list[ProbeResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    migration_readiness: list[ReadinessIssue] = field(default_factory=list)
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
            "total_resource_templates": 0,
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
            "report_schema_version": self.report_schema_version,
            "id": self.id,
            "target": self.target,
            "transport": self.transport,
            "scanned_at": self.scanned_at,
            "incomplete": self.incomplete,
            "incomplete_reason": self.incomplete_reason,
            "server_version": self.server_version,
            "protocol_version": self.protocol_version,
            "capabilities": self.capabilities,
            "server_instructions": self.server_instructions,
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
            "resource_templates": [
                {
                    "uri_template": template.uri_template,
                    "name": template.name,
                    "description": template.description,
                    "mime_type": template.mime_type,
                }
                for template in self.resource_templates
            ],
            "surface_status": {
                name: status.to_dict() for name, status in self.surface_status.items()
            },
            "probe_results": [pr.to_dict() for pr in self.probe_results],
            "findings": [finding.to_dict() for finding in self.findings],
            "migration_readiness": [issue.to_dict() for issue in self.migration_readiness],
            "summary": self.summary,
        }
