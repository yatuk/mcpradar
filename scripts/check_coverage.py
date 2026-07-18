"""Enforce focused coverage gates for security-critical scanner modules."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

CRITICAL_THRESHOLDS = {
    "network/safe_http.py": 90.0,
    "probe/oauth.py": 90.0,
    "sandbox/container.py": 90.0,
    "scanner/protocol_adapter.py": 90.0,
    "scanner/rules.py": 90.0,
    "schema/walker.py": 90.0,
    "source/analyzer.py": 90.0,
    "source/javascript.py": 90.0,
}


def check_coverage(report_path: Path, *, overall_minimum: float = 80.0) -> list[str]:
    """Return every failed threshold from a coverage.py JSON report."""
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    errors: list[str] = []
    overall = float(payload["totals"]["percent_covered"])
    if overall < overall_minimum:
        errors.append(f"overall coverage {overall:.2f}% is below {overall_minimum:.2f}%")

    normalized = {name.replace("\\", "/"): data for name, data in payload.get("files", {}).items()}
    for suffix, minimum in CRITICAL_THRESHOLDS.items():
        matches = [data for name, data in normalized.items() if name.endswith(suffix)]
        if not matches:
            errors.append(f"critical module missing from report: {suffix}")
            continue
        covered = float(matches[0]["summary"]["percent_covered"])
        if covered < minimum:
            errors.append(f"{suffix} coverage {covered:.2f}% is below {minimum:.2f}%")
    return errors


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, nargs="?", default=Path("coverage.json"))
    args = parser.parse_args()
    errors = check_coverage(args.report)
    if errors:
        raise SystemExit("Coverage gate failed:\n- " + "\n- ".join(errors))
    print("Coverage gate passed: overall >= 80%, security-critical modules >= 90%")


if __name__ == "__main__":
    main()
