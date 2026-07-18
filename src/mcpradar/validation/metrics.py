"""Instance-level precision/recall metrics with explicit corpus coverage gaps."""

from __future__ import annotations

from collections import defaultdict
from fnmatch import fnmatch
from typing import Any

from mcpradar.rules.catalog import RULE_CATALOG, descriptor_for

_MIN_EVIDENCE = 3


def validate_labels(labels: dict[str, Any]) -> list[str]:
    """Return validation errors without mutating or silently dropping labels."""
    errors: list[str] = []
    targets = labels.get("targets")
    if not isinstance(targets, dict):
        return ["labels.targets must be an object"]
    for name, target in targets.items():
        if not isinstance(target, dict):
            errors.append(f"{name}: target definition must be an object")
            continue
        if not isinstance(target.get("command"), str) or not target.get("command"):
            errors.append(f"{name}: command is required")
        for item in _expected_instances(target):
            rule_id = item["rule_id"]
            if rule_id not in RULE_CATALOG:
                errors.append(f"{name}: unknown rule_id {rule_id}")
        hard_negatives = target.get("hard_negative_rules", [])
        if not isinstance(hard_negatives, list):
            errors.append(f"{name}: hard_negative_rules must be a list")
        else:
            for rule_id in hard_negatives:
                if rule_id not in RULE_CATALOG:
                    errors.append(f"{name}: unknown hard-negative rule_id {rule_id}")
    return errors


def compute_benchmark_metrics(
    targets: dict[str, dict[str, Any]],
    results: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Compute finding-instance metrics, per-surface metrics, and evidence coverage."""
    rule_stats = {rule_id: _empty_stats() for rule_id in RULE_CATALOG}
    surface_stats: dict[str, dict[str, int]] = defaultdict(_empty_stats)
    positive_evidence = dict.fromkeys(RULE_CATALOG, 0)
    negative_evidence = dict.fromkeys(RULE_CATALOG, 0)

    for name, target in targets.items():
        expected = _expected_instances(target)
        for item in expected:
            positive_evidence[item["rule_id"]] += 1
        _count_negative_evidence(target, negative_evidence)

        result = results.get(name)
        if result is None or result.get("status") != "success":
            for item in expected:
                _increment(rule_stats, surface_stats, item, "fn")
            continue

        detected = _detected_instances(result)
        unmatched = set(range(len(detected)))
        for expected_item in expected:
            match_index = next(
                (index for index in sorted(unmatched) if _matches(expected_item, detected[index])),
                None,
            )
            if match_index is None:
                _increment(rule_stats, surface_stats, expected_item, "fn")
            else:
                unmatched.remove(match_index)
                _increment(rule_stats, surface_stats, detected[match_index], "tp")
        for index in unmatched:
            _increment(rule_stats, surface_stats, detected[index], "fp")

    per_rule = {
        rule_id: _metric(stats, positive_evidence[rule_id], negative_evidence[rule_id])
        for rule_id, stats in rule_stats.items()
    }
    per_surface = {surface: _metric(stats) for surface, stats in sorted(surface_stats.items())}
    total = _empty_stats()
    for stats in rule_stats.values():
        for key in total:
            total[key] += stats[key]
    gaps = [
        {
            "rule_id": rule_id,
            "positive_instances": positive_evidence[rule_id],
            "hard_negative_instances": negative_evidence[rule_id],
            "needs_positive": max(0, _MIN_EVIDENCE - positive_evidence[rule_id]),
            "needs_hard_negative": max(0, _MIN_EVIDENCE - negative_evidence[rule_id]),
        }
        for rule_id in RULE_CATALOG
        if positive_evidence[rule_id] < _MIN_EVIDENCE or negative_evidence[rule_id] < _MIN_EVIDENCE
    ]
    return {
        "schema_version": "2.0",
        "per_rule": per_rule,
        "per_surface": per_surface,
        "overall": _metric(total),
        "coverage": {
            "minimum_positive_instances": _MIN_EVIDENCE,
            "minimum_hard_negative_instances": _MIN_EVIDENCE,
            "calibrated_rules": len(RULE_CATALOG) - len(gaps),
            "catalog_rules": len(RULE_CATALOG),
            "gaps": gaps,
        },
        "targets_scanned": len(results),
        "targets_with_labels": len(targets),
        "scan_errors": sorted(name for name, result in results.items() if result.get("error")),
    }


def _expected_instances(target: dict[str, Any]) -> list[dict[str, str]]:
    raw = target.get("expected_findings")
    if isinstance(raw, list):
        output: list[dict[str, str]] = []
        for item in raw:
            if isinstance(item, dict) and isinstance(item.get("rule_id"), str):
                output.append(
                    {
                        "rule_id": item["rule_id"],
                        "target": str(item.get("target", "*")),
                        "surface": str(item.get("surface", "")),
                    }
                )
        return output
    expected_rules = target.get("expected_rules", [])
    if not isinstance(expected_rules, list):
        return []
    return [
        {"rule_id": str(rule_id), "target": "*", "surface": ""}
        for rule_id in expected_rules
        if isinstance(rule_id, str)
    ]


def _detected_instances(result: dict[str, Any]) -> list[dict[str, str]]:
    output: list[dict[str, str]] = []
    findings = result.get("findings", [])
    if not isinstance(findings, list):
        return output
    for finding in findings:
        if not isinstance(finding, dict) or finding.get("severity") == "low":
            continue
        rule_id = finding.get("rule_id")
        if not isinstance(rule_id, str) or rule_id not in RULE_CATALOG:
            continue
        output.append(
            {
                "rule_id": rule_id,
                "target": str(finding.get("target", "")),
                "surface": str(finding.get("location", "")),
            }
        )
    return output


def _matches(expected: dict[str, str], detected: dict[str, str]) -> bool:
    if expected["rule_id"] != detected["rule_id"]:
        return False
    target_pattern = expected.get("target", "*") or "*"
    if not fnmatch(detected.get("target", ""), target_pattern):
        return False
    surface = expected.get("surface", "")
    return not surface or surface == _surface(detected)


def _surface(item: dict[str, str]) -> str:
    explicit = item.get("surface", "")
    if explicit:
        return explicit
    descriptor = descriptor_for(item["rule_id"])
    return descriptor.surfaces[0] if descriptor and descriptor.surfaces else "unknown"


def _empty_stats() -> dict[str, int]:
    return {"tp": 0, "fp": 0, "fn": 0}


def _increment(
    rule_stats: dict[str, dict[str, int]],
    surface_stats: dict[str, dict[str, int]],
    item: dict[str, str],
    classification: str,
) -> None:
    rule_id = item["rule_id"]
    if rule_id not in rule_stats:
        return
    rule_stats[rule_id][classification] += 1
    surface_stats[_surface(item)][classification] += 1


def _metric(
    stats: dict[str, int],
    positive_evidence: int | None = None,
    negative_evidence: int | None = None,
) -> dict[str, Any]:
    tp, fp, fn = stats["tp"], stats["fp"], stats["fn"]
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    result: dict[str, Any] = {
        **stats,
        "precision": round(precision, 3) if precision is not None else None,
        "recall": round(recall, 3) if recall is not None else None,
        "f1": round(f1, 3) if f1 is not None else None,
        "total_findings": tp + fp,
        "total_expected": tp + fn,
    }
    if positive_evidence is not None and negative_evidence is not None:
        result["positive_instances"] = positive_evidence
        result["hard_negative_instances"] = negative_evidence
        result["calibrated"] = (
            positive_evidence >= _MIN_EVIDENCE and negative_evidence >= _MIN_EVIDENCE
        )
    return result


def _count_negative_evidence(target: dict[str, Any], negative_evidence: dict[str, int]) -> None:
    explicit = target.get("hard_negative_rules", [])
    if isinstance(explicit, list):
        for rule_id in explicit:
            if rule_id in negative_evidence:
                negative_evidence[rule_id] += 1
    if not target.get("negative_control"):
        return
    target_surfaces = set(target.get("surfaces", []))
    for rule_id, descriptor in RULE_CATALOG.items():
        if not target_surfaces or target_surfaces.intersection(descriptor.surfaces):
            negative_evidence[rule_id] += 1
