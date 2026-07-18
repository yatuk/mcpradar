"""Standards-compliant SARIF 2.1.0 output."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from mcpradar import __version__
from mcpradar.rules.catalog import RULE_CATALOG, RuleDescriptor
from mcpradar.scanner.report import Finding, ScanReport, Severity
from mcpradar.scoring.confidence import confidence_for

SARIF_SEVERITY: dict[Severity, str] = {
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


def to_sarif(report: ScanReport) -> dict[str, Any]:
    """Convert a scan report to SARIF 2.1.0 JSON."""
    rules = [_sarif_rule(descriptor) for descriptor in RULE_CATALOG.values()]
    results = [_sarif_result(finding) for finding in report.findings]
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "MCPRadar",
                "fullName": "MCPRadar — MCP Server Security Scanner",
                "informationUri": "https://github.com/yatuk/mcpradar",
                "semanticVersion": __version__,
                "rules": rules,
            }
        },
        "automationDetails": {"id": report.id},
        "results": results,
        "invocations": [
            {
                "executionSuccessful": not report.incomplete,
                "endTimeUtc": report.scanned_at,
                "properties": {
                    "incomplete": report.incomplete,
                    "incompleteReason": report.incomplete_reason,
                },
            }
        ],
        "properties": {
            "target": report.target,
            "transport": report.transport,
            "protocolVersion": report.protocol_version,
            "toolsScanned": len(report.tools),
            "promptsScanned": len(report.prompts),
            "resourcesScanned": len(report.resources),
            "resourceTemplatesScanned": len(report.resource_templates),
            "surfaceStatus": {
                name: status.to_dict() for name, status in report.surface_status.items()
            },
        },
    }
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }


def _sarif_rule(descriptor: RuleDescriptor) -> dict[str, Any]:
    return {
        "id": descriptor.id,
        "name": re.sub(r"[^A-Za-z0-9]+", "", descriptor.title),
        "shortDescription": {"text": descriptor.title},
        "fullDescription": {"text": descriptor.help},
        "helpUri": descriptor.help_uri,
        "defaultConfiguration": {"level": SARIF_SEVERITY[Severity.from_str(descriptor.severity)]},
        "properties": {
            "severity": descriptor.severity,
            "confidence": descriptor.confidence,
            "cwe": list(descriptor.cwe),
            "owasp": list(descriptor.owasp),
            "surfaces": list(descriptor.surfaces),
            "status": descriptor.status,
            "protocolProfiles": list(descriptor.protocol_profiles),
            "tags": [*descriptor.cwe, *descriptor.owasp, *descriptor.surfaces],
        },
    }


def _sarif_result(finding: Finding) -> dict[str, Any]:
    location = _location(finding)
    return {
        "ruleId": finding.rule_id,
        "level": SARIF_SEVERITY.get(finding.severity, "warning"),
        "message": {"text": finding.description},
        "locations": [location],
        "properties": {
            "severity": finding.severity.value,
            "confidence": confidence_for(finding.rule_id),
            "title": finding.title,
            "detail": finding.detail,
        },
    }


def _location(finding: Finding) -> dict[str, Any]:
    line = finding.detail.get("line")
    artifact = finding.target
    match = re.match(r"^(.*):(\d+)$", finding.target)
    if match:
        artifact, raw_line = match.groups()
        if not isinstance(line, int):
            line = int(raw_line)
    if finding.location in {"source", "config"} or isinstance(line, int):
        physical: dict[str, Any] = {"artifactLocation": {"uri": Path(artifact).as_posix()}}
        if isinstance(line, int) and line > 0:
            physical["region"] = {"startLine": line}
            if finding.evidence:
                physical["region"]["snippet"] = {"text": finding.evidence}
        return {"physicalLocation": physical}
    return {
        "logicalLocations": [
            {
                "name": finding.target or "server",
                "kind": finding.location or "mcp-server",
                "fullyQualifiedName": f"{finding.location or 'server'}::{finding.target}",
            }
        ]
    }
