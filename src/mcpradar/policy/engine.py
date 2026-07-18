"""Strict YAML policy-as-code for scan findings and expiring suppressions."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import yaml

from mcpradar.rules.catalog import RULE_CATALOG
from mcpradar.scanner.report import Finding, ScanReport, Severity, ToolInfo
from mcpradar.scoring.engine import compute_mrs_capability


class PolicyError(ValueError):
    """A policy is malformed or unsafe to evaluate."""


@dataclass(frozen=True)
class Suppression:
    rule_id: str
    target: str
    expires: date
    owner: str
    justification: str

    def matches(self, finding: Finding, today: date) -> bool:
        return (
            today <= self.expires
            and self.rule_id == finding.rule_id
            and fnmatch(finding.target, self.target)
        )


@dataclass(frozen=True)
class Policy:
    version: str = "1"
    fail_on: Severity = Severity.HIGH
    deny_rules: frozenset[str] = field(default_factory=frozenset)
    max_risk_score: float = 10.0
    require_complete_scan: bool = True
    suppressions: tuple[Suppression, ...] = ()


@dataclass(frozen=True)
class PolicyViolation:
    code: str
    message: str
    finding: Finding | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.finding is not None:
            result["finding"] = self.finding.to_dict()
        return result


@dataclass(frozen=True)
class PolicyDecision:
    passed: bool
    risk_score: float
    violations: tuple[PolicyViolation, ...]
    suppressed: tuple[Finding, ...]
    expired_suppressions: tuple[Suppression, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "risk_score": self.risk_score,
            "violations": [violation.to_dict() for violation in self.violations],
            "suppressed": [finding.to_dict() for finding in self.suppressed],
            "expired_suppressions": [
                {
                    "rule_id": item.rule_id,
                    "target": item.target,
                    "expires": item.expires.isoformat(),
                    "owner": item.owner,
                    "justification": item.justification,
                }
                for item in self.expired_suppressions
            ],
        }


def load_policy(path: Path) -> Policy:
    """Load a policy with closed-world field validation."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise PolicyError(f"cannot load policy: {exc}") from None
    if not isinstance(raw, dict):
        raise PolicyError("policy root must be an object")
    allowed = {
        "version",
        "fail_on",
        "deny_rules",
        "max_risk_score",
        "require_complete_scan",
        "suppressions",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise PolicyError(f"unknown policy fields: {', '.join(unknown)}")
    version = str(raw.get("version", "1"))
    if version != "1":
        raise PolicyError(f"unsupported policy version: {version}")
    try:
        fail_on = Severity.from_str(str(raw.get("fail_on", "high")))
    except ValueError:
        raise PolicyError("fail_on must be low, medium, high, or critical") from None
    deny_rules = _rule_ids(raw.get("deny_rules", []), "deny_rules")
    max_risk_score = raw.get("max_risk_score", 10.0)
    if not isinstance(max_risk_score, (int, float)) or isinstance(max_risk_score, bool):
        raise PolicyError("max_risk_score must be a number")
    if not 0 <= float(max_risk_score) <= 10:
        raise PolicyError("max_risk_score must be between 0 and 10")
    require_complete = raw.get("require_complete_scan", True)
    if not isinstance(require_complete, bool):
        raise PolicyError("require_complete_scan must be true or false")
    suppressions = _suppressions(raw.get("suppressions", []))
    return Policy(
        version=version,
        fail_on=fail_on,
        deny_rules=frozenset(deny_rules),
        max_risk_score=float(max_risk_score),
        require_complete_scan=require_complete,
        suppressions=tuple(suppressions),
    )


def evaluate_policy(
    report: ScanReport,
    policy: Policy,
    *,
    now: datetime | None = None,
) -> PolicyDecision:
    """Evaluate a report; expired exceptions never suppress a finding."""
    today = (now or datetime.now(UTC)).date()
    expired = tuple(item for item in policy.suppressions if item.expires < today)
    active_findings: list[Finding] = []
    suppressed: list[Finding] = []
    for finding in report.findings:
        if any(item.matches(finding, today) for item in policy.suppressions):
            suppressed.append(finding)
        else:
            active_findings.append(finding)

    violations: list[PolicyViolation] = []
    if policy.require_complete_scan and report.incomplete:
        violations.append(
            PolicyViolation("incomplete-scan", report.incomplete_reason or "scan is incomplete")
        )
    for finding in active_findings:
        if finding.rule_id in policy.deny_rules:
            violations.append(
                PolicyViolation(
                    "denied-rule",
                    f"{finding.rule_id} is denied by policy for {finding.target}",
                    finding,
                )
            )
        elif finding.severity >= policy.fail_on:
            violations.append(
                PolicyViolation(
                    "severity-threshold",
                    f"{finding.severity.value} finding meets {policy.fail_on.value} threshold",
                    finding,
                )
            )
    risk_score = compute_mrs_capability(active_findings, list(report.tools))
    if risk_score > policy.max_risk_score:
        violations.append(
            PolicyViolation(
                "risk-threshold",
                f"MRS {risk_score:.1f} exceeds maximum {policy.max_risk_score:.1f}",
            )
        )
    for item in expired:
        violations.append(
            PolicyViolation(
                "expired-suppression",
                f"suppression for {item.rule_id} ({item.target}) expired {item.expires}",
            )
        )
    return PolicyDecision(
        passed=not violations,
        risk_score=risk_score,
        violations=tuple(violations),
        suppressed=tuple(suppressed),
        expired_suppressions=expired,
    )


def report_from_dict(value: dict[str, Any]) -> ScanReport:
    """Build the policy-relevant portion of a report from exported JSON."""
    report = ScanReport(
        target=str(value.get("target", "")),
        transport=str(value.get("transport", "")),
    )
    report.incomplete = bool(value.get("incomplete", False))
    report.incomplete_reason = str(value.get("incomplete_reason", ""))
    for tool in value.get("tools", []):
        if isinstance(tool, dict):
            report.tools.append(
                ToolInfo(
                    name=str(tool.get("name", "")),
                    description=str(tool.get("description", "")),
                    input_schema=tool.get("input_schema", {})
                    if isinstance(tool.get("input_schema"), dict)
                    else {},
                    output_schema=tool.get("output_schema", {})
                    if isinstance(tool.get("output_schema"), dict)
                    else {},
                )
            )
    for finding in value.get("findings", []):
        if not isinstance(finding, dict):
            continue
        try:
            severity = Severity.from_str(str(finding.get("severity", "")))
        except ValueError as exc:
            raise PolicyError(f"invalid finding severity: {finding.get('severity')}") from exc
        report.findings.append(
            Finding(
                rule_id=str(finding.get("rule_id", "")),
                title=str(finding.get("title", "")),
                description=str(finding.get("description", "")),
                severity=severity,
                target=str(finding.get("target", "")),
                location=str(finding.get("location", "")),
                evidence=str(finding.get("evidence", "")),
                detail=finding.get("detail", {}) if isinstance(finding.get("detail"), dict) else {},
            )
        )
    return report


def _rule_ids(value: object, field_name: str) -> set[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise PolicyError(f"{field_name} must be a list of rule IDs")
    rule_ids = set(value)
    unknown = sorted(rule_ids - set(RULE_CATALOG))
    if unknown:
        raise PolicyError(f"unknown rule IDs in {field_name}: {', '.join(unknown)}")
    return rule_ids


def _suppressions(value: object) -> list[Suppression]:
    if not isinstance(value, list):
        raise PolicyError("suppressions must be a list")
    output: list[Suppression] = []
    required = {"rule_id", "target", "expires", "owner", "justification"}
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise PolicyError(f"suppression {index} must be an object")
        missing = sorted(required - set(item))
        unknown = sorted(set(item) - required)
        if missing or unknown:
            detail = []
            if missing:
                detail.append(f"missing {', '.join(missing)}")
            if unknown:
                detail.append(f"unknown {', '.join(unknown)}")
            raise PolicyError(f"suppression {index}: {'; '.join(detail)}")
        rule_id = str(item["rule_id"])
        _rule_ids([rule_id], f"suppression {index}")
        owner = str(item["owner"]).strip()
        justification = str(item["justification"]).strip()
        target = str(item["target"]).strip()
        if not owner or not justification or not target:
            raise PolicyError(f"suppression {index}: owner, justification, and target are required")
        try:
            expires = date.fromisoformat(str(item["expires"]))
        except ValueError:
            raise PolicyError(f"suppression {index}: expires must use YYYY-MM-DD") from None
        output.append(Suppression(rule_id, target, expires, owner, justification))
    return output
