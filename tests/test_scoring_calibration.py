"""Scoring calibration gate — positive, negative, and intermediate controls.

Runs the real leaderboard scoring pipeline (MRS-v1) on crafted
result files and on the committed fixtures, asserting the scale is anchored:
malicious → F, benign → A, and a powerful-but-clean server is never A. This gate
must stay green before the leaderboard is published. Offline — no server launch,
no network.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from mcpradar.cli import app
from mcpradar.scanner.report import Severity, ToolInfo
from mcpradar.scanner.rules import RuleEngine

runner = CliRunner()


def _grade_of(results_dir: Path, files: dict[str, dict], server: str) -> dict:
    for fname, payload in files.items():
        (results_dir / fname).write_text(json.dumps(payload), encoding="utf-8")
    out = results_dir / "data.json"
    r = runner.invoke(
        app, ["leaderboard", "generate", "-o", str(out), "--results-dir", str(results_dir)]
    )
    assert r.exit_code == 0, r.output
    rows = json.loads(out.read_text(encoding="utf-8"))
    return next(x for x in rows if x["server"] == server)


def _scanned(name: str, tools: list[dict], findings: list[dict]) -> dict:
    return {
        "name": name,
        "id": "x",
        "target": f"npx -y {name}",
        "scanned_at": "2026-07-12T00:00:00+00:00",
        "tools": tools,
        "summary": {"total_tools": len(tools)},
        "findings": findings,
    }


class TestCalibrationGate:
    def test_positive_control_malicious_is_worst(self, tmp_path: Path) -> None:
        """Critical findings + exec capability → grade F."""
        row = _grade_of(
            tmp_path,
            {
                "m.json": _scanned(
                    "evil",
                    [{"name": "run_command", "description": "Run a shell command"}],
                    [
                        {"rule_id": "R001", "severity": "critical", "title": "danger"},
                        {"rule_id": "R106", "severity": "critical", "title": "secret"},
                        {"rule_id": "R102", "severity": "high", "title": "inj"},
                    ],
                )
            },
            "evil",
        )
        assert row["grade"] == "F"

    def test_negative_control_benign_is_clean(self, tmp_path: Path) -> None:
        """No findings + pure-compute tool → grade A, 0 critical."""
        row = _grade_of(
            tmp_path,
            {
                "b.json": _scanned(
                    "benign",
                    [{"name": "echo", "description": "Return the message unchanged"}],
                    [],
                )
            },
            "benign",
        )
        assert row["grade"] == "A"
        assert row["by_severity"]["critical"] == 0

    def test_intermediate_exec_only_not_grade_a(self, tmp_path: Path) -> None:
        """Arbitrary execution with no CVE and a clean schema is still not A."""
        row = _grade_of(
            tmp_path,
            {
                "s.json": _scanned(
                    "shelly",
                    [{"name": "run_command", "description": "Run a shell command"}],
                    [],
                )
            },
            "shelly",
        )
        assert row["grade"] != "A"
        assert row["risk_score"] > 0.9

    def test_capability_cannot_lower_a_real_finding(self, tmp_path: Path) -> None:
        """A critical on a pure-compute server keeps its base floor (not halved)."""
        row = _grade_of(
            tmp_path,
            {
                "c.json": _scanned(
                    "calc",
                    [{"name": "calculate", "description": "Evaluates math"}],
                    [{"rule_id": "R106", "severity": "critical", "title": "secret"}],
                )
            },
            "calc",
        )
        assert row["risk_score"] >= 5.0  # critical floor survives


class TestBenignFixture:
    def test_benign_fixture_schema_is_clean(self) -> None:
        """The negative-control fixture's tool schema yields no critical/high."""
        echo = ToolInfo(
            name="echo",
            description="Return the provided message unchanged.",
            input_schema={
                "type": "object",
                "properties": {
                    "message": {"type": "string", "maxLength": 4096},
                },
                "required": ["message"],
                "additionalProperties": False,
            },
        )
        findings = RuleEngine(min_severity=Severity.LOW).analyze(echo)
        assert not [f for f in findings if f.severity >= Severity.HIGH]
