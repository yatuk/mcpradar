"""Deep schema comparison — cosmetic / behavioral / security-impact."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from mcpradar.scanner.report import Finding, ScanReport


class ChangeSeverity(StrEnum):
    COSMETIC = "cosmetic"
    BEHAVIORAL = "behavioral"
    SECURITY = "security"


@dataclass
class SchemaChange:
    field: str
    old: Any
    new: Any
    severity: ChangeSeverity = ChangeSeverity.BEHAVIORAL


@dataclass
class ToolDiff:
    tool_name: str
    changes: list[SchemaChange] = field(default_factory=list)
    added: bool = False
    removed: bool = False

    @property
    def max_severity(self) -> ChangeSeverity:
        if not self.changes:
            return ChangeSeverity.COSMETIC
        order = {"cosmetic": 0, "behavioral": 1, "security": 2}
        worst = ChangeSeverity.COSMETIC
        for c in self.changes:
            if order[c.severity] > order[worst]:
                worst = c.severity
        return worst


@dataclass
class DiffDelta:
    scan_id_a: str = ""
    scan_id_b: str = ""
    scanned_at_a: str = ""
    scanned_at_b: str = ""
    server: str = ""

    tool_diffs: list[ToolDiff] = field(default_factory=list)
    new_findings: list[Finding] = field(default_factory=list)
    resolved_findings: list[str] = field(default_factory=list)

    prompt_added: list[str] = field(default_factory=list)
    prompt_removed: list[str] = field(default_factory=list)
    resource_added: list[str] = field(default_factory=list)
    resource_removed: list[str] = field(default_factory=list)
    resource_template_added: list[str] = field(default_factory=list)
    resource_template_removed: list[str] = field(default_factory=list)
    surface_changes: list[SchemaChange] = field(default_factory=list)

    fingerprint_changes: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(
            self.tool_diffs
            or self.new_findings
            or self.resolved_findings
            or self.prompt_added
            or self.prompt_removed
            or self.resource_added
            or self.resource_removed
            or self.resource_template_added
            or self.resource_template_removed
            or self.surface_changes
            or self.fingerprint_changes
        )

    def summary_counts(self) -> dict[str, int]:
        c = {"added": 0, "removed": 0, "cosmetic": 0, "behavioral": 0, "security": 0}
        for td in self.tool_diffs:
            if td.added:
                c["added"] += 1
            elif td.removed:
                c["removed"] += 1
            else:
                sev = td.max_severity.value
                c[sev] = c.get(sev, 0) + 1
        for change in self.surface_changes:
            severity = change.severity.value
            c[severity] = c.get(severity, 0) + 1
        return c

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id_a": self.scan_id_a,
            "scan_id_b": self.scan_id_b,
            "scanned_at_a": self.scanned_at_a,
            "scanned_at_b": self.scanned_at_b,
            "server": self.server,
            "tool_diffs": [
                {
                    "tool_name": td.tool_name,
                    "added": td.added,
                    "removed": td.removed,
                    "max_severity": td.max_severity.value,
                    "changes": [
                        {
                            "field": c.field,
                            "old": c.old,
                            "new": c.new,
                            "severity": c.severity.value,
                        }
                        for c in td.changes
                    ],
                }
                for td in self.tool_diffs
            ],
            "new_findings": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "target": f.target,
                }
                for f in self.new_findings
            ],
            "resolved_findings": self.resolved_findings,
            "prompt_added": self.prompt_added,
            "prompt_removed": self.prompt_removed,
            "resource_added": self.resource_added,
            "resource_removed": self.resource_removed,
            "resource_template_added": self.resource_template_added,
            "resource_template_removed": self.resource_template_removed,
            "surface_changes": [
                {
                    "field": change.field,
                    "old": change.old,
                    "new": change.new,
                    "severity": change.severity.value,
                }
                for change in self.surface_changes
            ],
            "fingerprint_changes": self.fingerprint_changes,
        }


# ---------------------------------------------------------------------------
# Security-sensitive schema properties
# ---------------------------------------------------------------------------

SECURITY_SENSITIVE_KEYS: set[str] = {
    "command",
    "cmd",
    "script",
    "code",
    "eval",
    "exec",
    "shell",
    "sql",
    "query",
    "expression",
    "template",
    "url",
    "path",
    "file",
    "filename",
    "key",
    "token",
    "password",
    "secret",
    "credential",
    "auth",
}

BEHAVIORAL_KEYS: set[str] = {
    "required",
    "type",
    "format",
    "pattern",
    "minimum",
    "maximum",
    "minLength",
    "maxLength",
    "enum",
    "default",
    "additionalProperties",
}


def _worse(a: ChangeSeverity, b: ChangeSeverity, order: dict[str, int]) -> ChangeSeverity:
    return a if order[a] >= order[b] else b


_SECURITY_OR_BEHAVIORAL = {
    True: ChangeSeverity.SECURITY,
    False: ChangeSeverity.BEHAVIORAL,
}


def _security_or_behavioral(key: str) -> ChangeSeverity:
    return _SECURITY_OR_BEHAVIORAL[key.lower() in SECURITY_SENSITIVE_KEYS]


def _classify_description_change(old_desc: str, new_desc: str) -> ChangeSeverity:
    """Classify description change severity by running security rules on the new text.

    If the new description triggers prompt injection or hidden content rules,
    it's a SECURITY change. Otherwise cosmetic.
    """
    from mcpradar.scanner.report import ToolInfo
    from mcpradar.scanner.rules import HiddenContentDetection, PromptInjectionDetection

    tool = ToolInfo(name="__diff__", description=new_desc)
    for rule_cls in (PromptInjectionDetection, HiddenContentDetection):
        findings = rule_cls().check(tool)
        if findings:
            return ChangeSeverity.SECURITY
    return ChangeSeverity.COSMETIC


def _classify_schema_diff(old: Any, new: Any) -> ChangeSeverity:
    """Classify a bounded JSON Schema 2020-12 change."""
    from mcpradar.schema.walker import SchemaLimitError, iter_schema_properties

    if not isinstance(old, dict) or not isinstance(new, dict):
        return ChangeSeverity.BEHAVIORAL
    try:
        old_walked = dict(iter_schema_properties(old))
        new_walked = dict(iter_schema_properties(new))
    except SchemaLimitError:
        return ChangeSeverity.SECURITY
    worst_walked = ChangeSeverity.COSMETIC
    walked_order = {"cosmetic": 0, "behavioral": 1, "security": 2}
    for property_path in set(old_walked) | set(new_walked):
        old_value = old_walked.get(property_path)
        new_value = new_walked.get(property_path)
        if _semantic_schema(old_value) == _semantic_schema(new_value):
            continue
        leaf = property_path.rsplit(".", 1)[-1].lower()
        worst_walked = _worse(
            worst_walked,
            _security_or_behavioral(leaf),
            walked_order,
        )
    if worst_walked is not ChangeSeverity.COSMETIC:
        return worst_walked
    return (
        ChangeSeverity.BEHAVIORAL
        if _semantic_schema(old) != _semantic_schema(new)
        else ChangeSeverity.COSMETIC
    )


def _semantic_schema(value: object) -> object:
    """Remove presentation-only annotations before schema comparison."""
    if isinstance(value, dict):
        ignored = {"title", "description", "$comment", "examples"}
        return {key: _semantic_schema(child) for key, child in value.items() if key not in ignored}
    if isinstance(value, list):
        return [_semantic_schema(child) for child in value]
    return value


# ---------------------------------------------------------------------------
# Differ
# ---------------------------------------------------------------------------


class Differ:
    def compare(self, report_a: ScanReport, report_b: ScanReport) -> DiffDelta:
        delta = DiffDelta(
            scan_id_a=report_a.id,
            scan_id_b=report_b.id,
            scanned_at_a=report_a.scanned_at,
            scanned_at_b=report_b.scanned_at,
            server=report_a.target,
        )

        tools_a = {t.name: t for t in report_a.tools}
        tools_b = {t.name: t for t in report_b.tools}

        names_a = set(tools_a)
        names_b = set(tools_b)

        # Added tools
        for name in sorted(names_b - names_a):
            t = tools_b[name]
            td = ToolDiff(tool_name=name, added=True)
            td.changes.append(SchemaChange("name", None, t.name, ChangeSeverity.SECURITY))
            td.changes.append(
                SchemaChange("description", None, t.description, ChangeSeverity.COSMETIC)
            )
            td.changes.append(
                SchemaChange("input_schema", {}, t.input_schema, ChangeSeverity.BEHAVIORAL)
            )
            if t.output_schema:
                td.changes.append(
                    SchemaChange("output_schema", {}, t.output_schema, ChangeSeverity.BEHAVIORAL)
                )
            delta.tool_diffs.append(td)

        # Removed tools
        for name in sorted(names_a - names_b):
            t = tools_a[name]
            td = ToolDiff(tool_name=name, removed=True)
            td.changes.append(SchemaChange("name", t.name, None, ChangeSeverity.SECURITY))
            delta.tool_diffs.append(td)

        # Changed tools
        for name in sorted(names_a & names_b):
            t_a = tools_a[name]
            t_b = tools_b[name]
            changes: list[SchemaChange] = []

            # description — run security rules on the new text
            if t_a.description != t_b.description:
                sev = _classify_description_change(t_a.description, t_b.description)
                changes.append(
                    SchemaChange(
                        "description",
                        t_a.description,
                        t_b.description,
                        sev,
                    )
                )

            # input_schema
            if t_a.input_schema != t_b.input_schema:
                sev = _classify_schema_diff(t_a.input_schema, t_b.input_schema)
                changes.append(
                    SchemaChange("input_schema", t_a.input_schema, t_b.input_schema, sev)
                )

            # output_schema
            if t_a.output_schema != t_b.output_schema:
                sev = _classify_schema_diff(t_a.output_schema, t_b.output_schema)
                changes.append(
                    SchemaChange("output_schema", t_a.output_schema, t_b.output_schema, sev)
                )

            if changes:
                delta.tool_diffs.append(ToolDiff(tool_name=name, changes=changes))

        # Findings
        findings_a = {(f.rule_id, f.target): f for f in report_a.findings}
        findings_b = {(f.rule_id, f.target): f for f in report_b.findings}
        delta.new_findings = [f for k, f in findings_b.items() if k not in findings_a]
        delta.resolved_findings = [
            f"{rule_id} ({tool})"
            for (rule_id, tool), f in findings_a.items()
            if (rule_id, tool) not in findings_b
        ]

        # Prompts
        prompts_a = {prompt.name: prompt for prompt in report_a.prompts}
        prompts_b = {prompt.name: prompt for prompt in report_b.prompts}
        pa = set(prompts_a)
        pb = set(prompts_b)
        delta.prompt_added = sorted(pb - pa)
        delta.prompt_removed = sorted(pa - pb)
        _compare_descriptions(
            delta,
            "prompt",
            prompts_a,
            prompts_b,
        )

        # Resources
        resources_a = {resource.uri: resource for resource in report_a.resources}
        resources_b = {resource.uri: resource for resource in report_b.resources}
        ra = set(resources_a)
        rb = set(resources_b)
        delta.resource_added = sorted(rb - ra)
        delta.resource_removed = sorted(ra - rb)
        _compare_descriptions(
            delta,
            "resource",
            resources_a,
            resources_b,
        )

        # Resource templates
        templates_a = {template.uri_template: template for template in report_a.resource_templates}
        templates_b = {template.uri_template: template for template in report_b.resource_templates}
        ta = set(templates_a)
        tb = set(templates_b)
        delta.resource_template_added = sorted(tb - ta)
        delta.resource_template_removed = sorted(ta - tb)
        _compare_descriptions(
            delta,
            "resource_template",
            templates_a,
            templates_b,
        )

        if report_a.server_instructions != report_b.server_instructions:
            delta.surface_changes.append(
                SchemaChange(
                    "server_instructions",
                    report_a.server_instructions,
                    report_b.server_instructions,
                    _classify_description_change(
                        report_a.server_instructions,
                        report_b.server_instructions,
                    ),
                )
            )

        _compare_surface_status(report_a, report_b, delta)

        # Fingerprint comparison
        if report_a.server_version != report_b.server_version:
            a_ver = report_a.server_version or "(yok)"
            b_ver = report_b.server_version or "(yok)"
            delta.fingerprint_changes.append(f"server_version: {a_ver} → {b_ver}")
        if report_a.protocol_version != report_b.protocol_version:
            a_proto = report_a.protocol_version or "(none)"
            b_proto = report_b.protocol_version or "(none)"
            delta.fingerprint_changes.append(f"protocol_version: {a_proto} → {b_proto}")
        if report_a.capabilities != report_b.capabilities:
            delta.fingerprint_changes.append("capabilities: changed")
        tool_count_a = len(report_a.tools)
        tool_count_b = len(report_b.tools)
        if tool_count_a != tool_count_b:
            delta.fingerprint_changes.append(f"tool_count: {tool_count_a} → {tool_count_b}")

        return delta


def _compare_descriptions(
    delta: DiffDelta,
    surface: str,
    old_items: Mapping[str, object],
    new_items: Mapping[str, object],
) -> None:
    for identity in sorted(set(old_items) & set(new_items)):
        old_description = str(getattr(old_items[identity], "description", "") or "")
        new_description = str(getattr(new_items[identity], "description", "") or "")
        if old_description == new_description:
            continue
        delta.surface_changes.append(
            SchemaChange(
                f"{surface}.{identity}.description",
                old_description,
                new_description,
                _classify_description_change(old_description, new_description),
            )
        )


def _compare_surface_status(
    old_report: ScanReport,
    new_report: ScanReport,
    delta: DiffDelta,
) -> None:
    from mcpradar.scanner.report import SurfaceState

    for surface in sorted(set(old_report.surface_status) | set(new_report.surface_status)):
        old_status = old_report.surface_status.get(surface)
        new_status = new_report.surface_status.get(surface)
        old_value = old_status.to_dict() if old_status else None
        new_value = new_status.to_dict() if new_status else None
        if old_value == new_value:
            continue
        degraded = (
            old_status is not None
            and old_status.state is SurfaceState.COMPLETE
            and (new_status is None or new_status.state is not SurfaceState.COMPLETE)
        )
        delta.surface_changes.append(
            SchemaChange(
                f"surface_status.{surface}",
                old_value,
                new_value,
                ChangeSeverity.SECURITY if degraded else ChangeSeverity.BEHAVIORAL,
            )
        )

    if old_report.incomplete != new_report.incomplete:
        delta.surface_changes.append(
            SchemaChange(
                "scan.incomplete",
                old_report.incomplete,
                new_report.incomplete,
                ChangeSeverity.SECURITY if new_report.incomplete else ChangeSeverity.BEHAVIORAL,
            )
        )
