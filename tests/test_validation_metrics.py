"""Instance-level benchmark metrics and coverage-gap tests."""

from __future__ import annotations

from mcpradar.validation.metrics import compute_benchmark_metrics, validate_labels


def _finding(rule_id: str, target: str, location: str = "tool") -> dict[str, str]:
    return {
        "rule_id": rule_id,
        "target": target,
        "location": location,
        "severity": "high",
    }


def test_duplicate_findings_are_counted_as_instances() -> None:
    targets = {
        "demo": {
            "command": "demo",
            "expected_findings": [{"rule_id": "R001", "target": "danger*", "surface": "tool"}],
        }
    }
    results = {
        "demo": {
            "status": "success",
            "findings": [_finding("R001", "danger-one"), _finding("R001", "danger-two")],
        }
    }
    metrics = compute_benchmark_metrics(targets, results)
    assert metrics["per_rule"]["R001"]["tp"] == 1
    assert metrics["per_rule"]["R001"]["fp"] == 1
    assert metrics["overall"]["precision"] == 0.5


def test_missing_or_failed_scan_counts_expected_instances_as_false_negatives() -> None:
    targets = {
        "missing": {
            "command": "missing",
            "expected_findings": [
                {"rule_id": "S001", "target": "src/server.py:*", "surface": "source"}
            ],
        }
    }
    metrics = compute_benchmark_metrics(targets, {})
    assert metrics["per_rule"]["S001"]["fn"] == 1
    assert metrics["per_surface"]["source"]["fn"] == 1


def test_negative_controls_and_gaps_cover_the_complete_catalog() -> None:
    targets = {
        "clean": {
            "command": "clean",
            "negative_control": True,
            "surfaces": ["tool"],
            "expected_rules": [],
        }
    }
    results = {"clean": {"status": "success", "findings": []}}
    metrics = compute_benchmark_metrics(targets, results)
    assert metrics["coverage"]["catalog_rules"] == 42
    assert len(metrics["per_rule"]) == 42
    assert metrics["coverage"]["gaps"]
    assert metrics["per_rule"]["R001"]["hard_negative_instances"] == 1


def test_label_validation_rejects_unknown_rules() -> None:
    errors = validate_labels(
        {
            "targets": {
                "bad": {"command": "bad", "expected_rules": ["R999"]},
            }
        }
    )
    assert errors == ["bad: unknown rule_id R999"]
