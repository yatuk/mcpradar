"""Coverage gate regression tests."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.check_coverage import CRITICAL_THRESHOLDS, check_coverage


def _write_report(path: Path, overall: float, module_percent: float) -> None:
    files = {
        f"src/mcpradar/{name}": {"summary": {"percent_covered": module_percent}}
        for name in CRITICAL_THRESHOLDS
    }
    path.write_text(
        json.dumps({"totals": {"percent_covered": overall}, "files": files}),
        encoding="utf-8",
    )


def test_coverage_gate_accepts_thresholds(tmp_path: Path) -> None:
    report = tmp_path / "coverage.json"
    _write_report(report, 80.0, 90.0)
    assert check_coverage(report) == []


def test_coverage_gate_reports_overall_module_and_missing(tmp_path: Path) -> None:
    report = tmp_path / "coverage.json"
    _write_report(report, 79.9, 89.9)
    payload = json.loads(report.read_text(encoding="utf-8"))
    payload["files"].pop("src/mcpradar/network/safe_http.py")
    report.write_text(json.dumps(payload), encoding="utf-8")
    errors = check_coverage(report)
    assert any("overall" in error for error in errors)
    assert any("missing" in error for error in errors)
    assert any("below" in error and "oauth" in error for error in errors)
