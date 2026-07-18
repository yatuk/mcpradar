"""Policy-as-code loading, suppression, and CLI tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcpradar.cli import app
from mcpradar.policy import PolicyError, evaluate_policy, load_policy, report_from_dict
from mcpradar.scanner.report import Finding, ScanReport, Severity, ToolInfo


def _write_policy(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


def _report() -> ScanReport:
    report = ScanReport(target="demo", transport="stdio")
    report.tools.append(ToolInfo(name="shell", description="Run a command"))
    report.findings.append(
        Finding(
            rule_id="R001",
            title="Dangerous tool",
            description="dangerous",
            severity=Severity.CRITICAL,
            target="shell",
            location="tool",
        )
    )
    return report


def test_active_suppression_requires_owner_justification_and_expiry(tmp_path: Path) -> None:
    policy = load_policy(
        _write_policy(
            tmp_path / "policy.yml",
            """
version: "1"
fail_on: high
max_risk_score: 10
suppressions:
  - rule_id: R001
    target: shell
    expires: 2026-12-31
    owner: security@example.com
    justification: Accepted in an isolated build worker.
""",
        )
    )
    decision = evaluate_policy(_report(), policy, now=datetime(2026, 7, 18, tzinfo=UTC))
    assert decision.passed
    assert len(decision.suppressed) == 1


def test_expired_suppression_is_a_violation_and_does_not_hide_finding(tmp_path: Path) -> None:
    policy = load_policy(
        _write_policy(
            tmp_path / "policy.yml",
            """
version: "1"
fail_on: critical
suppressions:
  - rule_id: R001
    target: "*"
    expires: 2025-01-01
    owner: security
    justification: Temporary exception.
""",
        )
    )
    decision = evaluate_policy(_report(), policy, now=datetime(2026, 7, 18, tzinfo=UTC))
    assert not decision.passed
    assert {item.code for item in decision.violations} == {
        "severity-threshold",
        "expired-suppression",
    }


@pytest.mark.parametrize(
    "body",
    [
        "version: '2'",
        "version: '1'\nunknown: true",
        "version: '1'\ndeny_rules: [R999]",
        "version: '1'\nmax_risk_score: 11",
        "version: '1'\nsuppressions: [{rule_id: R001}]",
    ],
)
def test_invalid_policy_is_rejected(tmp_path: Path, body: str) -> None:
    with pytest.raises(PolicyError):
        load_policy(_write_policy(tmp_path / "policy.yml", body))


def test_incomplete_scan_denied_rule_and_risk_threshold() -> None:
    report = _report()
    report.incomplete = True
    report.incomplete_reason = "tools pagination failed"
    from mcpradar.policy.engine import Policy

    policy = Policy(
        fail_on=Severity.CRITICAL,
        deny_rules=frozenset({"R001"}),
        max_risk_score=1.0,
    )
    codes = {item.code for item in evaluate_policy(report, policy).violations}
    assert codes == {"incomplete-scan", "denied-rule", "risk-threshold"}


def test_report_json_and_cli_policy_check(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(_report().to_dict()), encoding="utf-8")
    assert report_from_dict(json.loads(report_path.read_text(encoding="utf-8"))).findings
    policy_path = _write_policy(
        tmp_path / "policy.yml",
        "version: '1'\nfail_on: high\nrequire_complete_scan: true\n",
    )
    result = CliRunner().invoke(
        app,
        ["policy", "check", str(policy_path), "--report", str(report_path)],
    )
    assert result.exit_code == 1
    assert json.loads(result.output)["passed"] is False
