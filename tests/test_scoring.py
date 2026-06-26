"""Unit tests for scoring/engine.py — AIVSS score, grade, confidence."""

from __future__ import annotations

import pytest

from mcpradar.scanner.report import Finding, Severity
from mcpradar.scoring.engine import (
    CONFIDENCE_MAP,
    compute_aivss,
    compute_confidence,
    compute_grade,
    score_server,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _f(rule_id: str = "R109", severity: str = "medium") -> Finding:
    """Create a minimal Finding for test purposes."""
    return Finding(
        rule_id=rule_id,
        title="test",
        description="test finding",
        severity=Severity.from_str(severity),
        location="tool",
        target="test_tool",
        evidence="",
        detail={},
    )


def _findings(*specs: tuple[str, str]) -> list[Finding]:
    """Shorthand: _findings(("R109","medium"), ("R113","high"))."""
    return [_f(rid, sev) for rid, sev in specs]


# ---------------------------------------------------------------------------
# compute_aivss
# ---------------------------------------------------------------------------


class TestComputeAivss:
    def test_empty_findings_returns_zero(self) -> None:
        assert compute_aivss([], tool_count=5) == 0.0

    def test_single_low_on_many_tools(self) -> None:
        score = compute_aivss(_findings(("R114", "low")), tool_count=100)
        # density = 1/100 = 0.01, density_factor = max(0.5, 0.01*5) = 0.5
        # raw = 1/100 * 0.5 = 0.005, capped at 10.0, rounded to 0.0
        assert score == 0.0

    def test_single_critical_on_one_tool(self) -> None:
        score = compute_aivss(_findings(("R107", "critical")), tool_count=1)
        # density = 1/1 = 1.0, density_factor = min(2.0, 1.0*5) = 2.0
        # raw = 10/1 * 2.0 = 20.0, capped at 10.0
        assert score == 10.0

    def test_mixed_severity(self) -> None:
        findings = _findings(
            ("R107", "critical"),
            ("R113", "high"),
            ("R113", "high"),
            ("R109", "medium"),
            ("R114", "low"),
        )
        # 5 findings on 10 tools
        # weighted = 1*10 + 2*7 + 1*4 + 1*1 = 29
        # density = 5/10 = 0.5, density_factor = max(0.5, 0.5*5) = 2.0
        # raw = 29/10 * 2.0 = 5.8
        score = compute_aivss(findings, tool_count=10)
        assert round(score, 1) == 5.8

    def test_zero_tools_falls_back_to_one(self) -> None:
        score = compute_aivss(_findings(("R109", "medium")), tool_count=0)
        # density = 1/1 = 1.0, density_factor = 2.0
        # raw = 4/1 * 2.0 = 8.0
        assert score == 8.0

    def test_density_capped_at_max(self) -> None:
        # 100 findings on 1 tool → density = 100/1 = 100, factor = min(2, 100*5) = 2
        findings = _findings(*[("R114", "low")] * 100)
        score = compute_aivss(findings, tool_count=1)
        # weighted = 100*1 = 100, raw = 100/1 * 2.0 = 200, capped at 10.0
        assert score == 10.0

    def test_many_tools_dilutes_score(self) -> None:
        findings = _findings(("R107", "critical"), ("R113", "high"))
        score_1_tool = compute_aivss(findings, tool_count=1)
        score_10_tools = compute_aivss(findings, tool_count=10)
        assert score_10_tools < score_1_tool


# ---------------------------------------------------------------------------
# compute_grade
# ---------------------------------------------------------------------------


class TestComputeGrade:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (0.0, "A"),
            (0.5, "A"),
            (0.9, "A"),
            (1.0, "B"),
            (2.0, "B"),
            (2.9, "B"),
            (3.0, "C"),
            (4.0, "C"),
            (4.9, "C"),
            (5.0, "D"),
            (6.0, "D"),
            (6.9, "D"),
            (7.0, "F"),
            (8.5, "F"),
            (10.0, "F"),
        ],
    )
    def test_grade_boundaries(self, score: float, expected: str) -> None:
        assert compute_grade(score) == expected

    def test_grade_is_single_char(self) -> None:
        for score in (0.0, 1.5, 3.7, 5.9, 9.9):
            assert len(compute_grade(score)) == 1
            assert compute_grade(score) in "ABCDF"


# ---------------------------------------------------------------------------
# compute_confidence
# ---------------------------------------------------------------------------


class TestComputeConfidence:
    def test_empty_findings_returns_one(self) -> None:
        assert compute_confidence([]) == 1.0

    def test_high_confidence_rules(self) -> None:
        findings = _findings(("R001", "critical"), ("R101", "high"), ("R106", "high"))
        conf = compute_confidence(findings)
        # R001=0.9, R101=0.9, R106=0.9 → avg = 0.9
        assert conf == 0.9

    def test_mixed_confidence_rules(self) -> None:
        findings = _findings(
            ("R001", "critical"),  # 0.9
            ("R109", "medium"),  # 0.7
            ("R114", "low"),  # unknown → 0.5
        )
        conf = compute_confidence(findings)
        # (0.9 + 0.7 + 0.5) / 3 = 0.7
        assert conf == pytest.approx(0.7)

    def test_unknown_rule_defaults_to_half(self) -> None:
        findings = _findings(("R999", "low"))
        conf = compute_confidence(findings)
        assert conf == 0.5

    def test_all_confidence_values_in_range(self) -> None:
        # Every rule in the confidence map should have value in [0.0, 1.0]
        for rule_id, conf in CONFIDENCE_MAP.items():
            assert 0.0 <= conf <= 1.0, f"{rule_id} confidence {conf} out of range"


# ---------------------------------------------------------------------------
# score_server (convenience)
# ---------------------------------------------------------------------------


class TestScoreServer:
    def test_returns_all_keys(self) -> None:
        result = score_server(_findings(("R107", "critical")), tool_count=1)
        expected_keys = {
            "aivss_score",
            "grade",
            "confidence",
            "findings_by_severity",
            "total_findings",
            "tools",
        }
        assert set(result.keys()) == expected_keys

    def test_no_findings_grade_a(self) -> None:
        result = score_server([], tool_count=10)
        assert result["aivss_score"] == 0.0
        assert result["grade"] == "A"
        assert result["confidence"] == 1.0
        assert result["total_findings"] == 0

    def test_severity_counts_correct(self) -> None:
        findings = _findings(
            ("R107", "critical"),
            ("R107", "critical"),
            ("R113", "high"),
            ("R114", "low"),
            ("R114", "low"),
            ("R114", "low"),
        )
        result = score_server(findings, tool_count=3)
        assert result["findings_by_severity"] == {
            "critical": 2,
            "high": 1,
            "medium": 0,
            "low": 3,
        }
        assert result["total_findings"] == 6
        assert result["tools"] == 3
