"""ScanReport → SARIF v2.1.0 converter."""

from __future__ import annotations

from typing import Any

import sarif_om as sarif

from mcpradar.scanner.report import ScanReport, Severity


def _to_dict(obj: Any) -> Any:
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    if isinstance(obj, list):
        return [_to_dict(i) for i in obj]
    if isinstance(obj, dict):
        return {str(k): _to_dict(v) for k, v in obj.items()}
    # sarif-om object
    return {
        k: _to_dict(v)
        for k, v in obj.__dict__.items()
        if not k.startswith("_")
    }

SARIF_SEVERITY: dict[Severity, str] = {
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}

RULE_HELP: dict[str, str] = {
    "R001": "Tool name matches a dangerous system command (eval, exec, rm, etc.)",
    "R101": "Zero-width Unicode character detected — potential hidden text injection",
    "R102": "Prompt injection pattern found in tool description or schema",
    "R103": "Base64 or hex-encoded blob found in tool description",
    "R104": "Hidden HTML/Markdown content (display:none, font-size:0, etc.)",
    "R105": "Permission scope mismatch — tool name scope differs from description",
}


def to_sarif(report: ScanReport) -> dict[str, Any]:
    driver = sarif.ToolComponent(
        name="MCPRadar",
        full_name="MCPRadar — MCP Server Security Scanner",
        information_uri="https://github.com/yatuk/mcpradar",
        semantic_version="0.1.0",
        rules=[
            sarif.ReportingDescriptor(
                id=rid,
                name=rid,
                short_description=sarif.MultiformatMessageString(
                    text=desc
                ),
                help_uri=f"https://github.com/yatuk/mcpradar/blob/main/docs/detection-rules.md#{rid.lower()}",
            )
            for rid, desc in sorted(RULE_HELP.items())
        ],
    )

    results: list[sarif.Result] = []
    for f in report.findings:
        loc = sarif.Location(
            physical_location=sarif.PhysicalLocation(
                artifact_location=sarif.ArtifactLocation(
                    uri=f.target,
                    uri_base_id=report.target,
                ),
                region=sarif.Region(
                    snippet=sarif.ArtifactContent(text=f.evidence),
                ),
            ),
        )

        results.append(
            sarif.Result(
                rule_id=f.rule_id,
                message=sarif.Message(text=f.description),
                level=SARIF_SEVERITY.get(f.severity, "warning"),
                locations=[loc],
                properties={
                    "severity": f.severity.value,
                    "title": f.title,
                    "detail": f.detail,
                },
            )
        )

    run = sarif.Run(
        tool=sarif.Tool(driver=driver),
        results=results,
        invocations=[
            sarif.Invocation(
                execution_successful=True,
                end_time_utc=report.scanned_at,
            )
        ],
        properties={
            "target": report.target,
            "transport": report.transport,
            "tools_scanned": len(report.tools),
            "prompts_scanned": len(report.prompts),
            "resources_scanned": len(report.resources),
        },
    )

    log = sarif.SarifLog(version="2.1.0", runs=[run])
    result: dict[str, Any] = _to_dict(log)
    return result
