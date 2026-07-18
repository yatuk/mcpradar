"""Precision/Recall benchmark runner for MCPRadar.

Usage: python validation/run_benchmark.py [--target NAME] [--timeout 120]

Reads validation/labels.json for ground-truth expected rules per server.
Scans each server, computes per-rule precision/recall/F1, and writes
validation/BENCHMARK.md with a complete breakdown.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from mcpradar.validation.metrics import compute_benchmark_metrics, validate_labels

VALIDATION_DIR = Path(__file__).parent


def load_labels() -> dict:
    """Load ground-truth labels."""
    labels_path = VALIDATION_DIR / "labels.json"
    if not labels_path.exists():
        print("labels.json not found. Run validation/setup_corpus.py first.")
        return {"targets": {}}
    return json.loads(labels_path.read_text(encoding="utf-8"))


def scan_target(name: str, command: str, transport: str, timeout: int = 120) -> dict:
    """Scan a single target and return findings grouped by rule_id."""
    result = {
        "name": name,
        "status": "error",
        "detected_rules": set(),
        "findings": [],
        "error": None,
        "duration_ms": 0,
        "tools": 0,
    }

    start = time.time()
    try:
        # Use a temp file to avoid Rich ANSI codes mixing with stdout
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "mcpradar",
                "scan",
                command,
                "-t",
                transport,
                "--json",
                "-s",
                "low",
                "--no-save",
                "--allow-host-exec",
                "-o",
                tmp_path,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=timeout,
            cwd=str(VALIDATION_DIR.parent),
        )
        result["duration_ms"] = int((time.time() - start) * 1000)

        if proc.returncode != 0:
            result["error"] = proc.stderr[:500] if proc.stderr else f"Exit code {proc.returncode}"

        # Read JSON from temp file (clean, no ANSI codes)
        try:
            data = json.loads(Path(tmp_path).read_text(encoding="utf-8"))
        except (json.JSONDecodeError, FileNotFoundError):
            result["error"] = f"JSON parse failed (exit {proc.returncode})"
            Path(tmp_path).unlink(missing_ok=True)
            return result

        Path(tmp_path).unlink(missing_ok=True)
        result["tools"] = data.get("summary", {}).get("total_tools", 0)
        for f in data.get("findings", []):
            rule_id = f.get("rule_id", "unknown")
            severity = f.get("severity", "")
            # LOW findings are informational lint (e.g. R114 unconstrained
            # strings) and excluded from precision/recall metrics.
            if severity == "low":
                result["low_findings"] = result.get("low_findings", 0) + 1
            else:
                result["detected_rules"].add(rule_id)
            result["findings"].append(
                {
                    "rule_id": rule_id,
                    "severity": severity,
                    "title": f.get("title", ""),
                    "target": f.get("target", ""),
                    "location": f.get("location", ""),
                }
            )
        result["status"] = "success"
    except subprocess.TimeoutExpired:
        result["error"] = f"Timeout after {timeout}s"
    except json.JSONDecodeError as e:
        result["error"] = f"JSON parse error: {e}"
    except Exception as e:
        result["error"] = str(e)[:500]

    return result


def compute_metrics(targets: dict, results: dict) -> dict:
    """Backward-compatible wrapper for the instance-level metrics engine."""
    return compute_benchmark_metrics(targets, results)


def generate_report(targets: dict, results: dict, metrics: dict) -> str:
    """Generate BENCHMARK.md with full precision/recall breakdown."""
    lines = [
        "# MCPRadar Precision/Recall Benchmark",
        "",
        f"**Generated:** {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Scanner version:** {_get_version()}",
        "",
        "## Methodology",
        "",
        "Each target has ground-truth finding instances in `validation/labels.json`. "
        "Every detected finding can match at most one expected instance, so duplicate "
        "alerts are counted instead of being collapsed to a set of rule IDs.",
        "",
        "- **True Positive (TP):** Rule fired AND was expected",
        "- **False Positive (FP):** Rule fired but was NOT expected",
        "- **False Negative (FN):** Rule was expected but did NOT fire",
        "",
        "Metrics use MEDIUM+ findings. The complete catalog remains in the report: a "
        "rule is calibrated only after at least three positive and three hard-negative "
        "instances, and missing evidence is listed as a coverage gap.",
        "",
        "## Overall Results",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Precision | {_pct(metrics['overall']['precision'])} |",
        f"| Recall | {_pct(metrics['overall']['recall'])} |",
        f"| F1 Score | {_pct(metrics['overall']['f1'])} |",
        f"| Targets scanned | {metrics['targets_scanned']} |",
        f"| Total findings | {metrics['overall']['total_findings']} |",
        "",
        "## Per-Rule Metrics",
        "",
        "| Rule | TP | FP | FN | Precision | Recall | F1 | Pos/Neg | Calibrated |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ]

    for rule_id, m in metrics["per_rule"].items():
        lines.append(
            f"| {rule_id} | {m['tp']} | {m['fp']} | {m['fn']} | "
            f"{_pct(m['precision'])} | {_pct(m['recall'])} | {_pct(m['f1'])} | "
            f"{m['positive_instances']}/{m['hard_negative_instances']} | "
            f"{'yes' if m['calibrated'] else 'no'} |"
        )

    lines.extend(
        [
            "",
            "## Per-Surface Metrics",
            "",
            "| Surface | TP | FP | FN | Precision | Recall | F1 |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for surface, m in metrics["per_surface"].items():
        lines.append(
            f"| {surface} | {m['tp']} | {m['fp']} | {m['fn']} | "
            f"{_pct(m['precision'])} | {_pct(m['recall'])} | {_pct(m['f1'])} |"
        )

    lines.extend(
        [
            "",
            "## Corpus Coverage Gaps",
            "",
            f"Calibrated rules: {metrics['coverage']['calibrated_rules']}/"
            f"{metrics['coverage']['catalog_rules']}.",
            "",
            "| Rule | Positives | Hard negatives | Still needed |",
            "|---|---:|---:|---|",
        ]
    )
    for gap in metrics["coverage"]["gaps"]:
        lines.append(
            f"| {gap['rule_id']} | {gap['positive_instances']} | "
            f"{gap['hard_negative_instances']} | +{gap['needs_positive']} positive, "
            f"+{gap['needs_hard_negative']} negative |"
        )

    lines.extend(
        [
            "",
            "## Per-Target Results",
            "",
            "| Target | Status | Tools | Findings | Low (info) "
            "| Expected Rules | Detected (medium+) |",
            "|--------|--------|-------|----------|-----------|---------------|-----------------|",
        ]
    )

    for name in sorted(targets.keys()):
        if name not in results:
            continue
        r = results[name]
        t = targets[name]
        status_icon = "✅" if r["status"] == "success" else "❌"
        expected_str = ", ".join(sorted(t.get("expected_rules", []))) or "(clean)"
        detected_str = ", ".join(sorted(r["detected_rules"])) or "(none)"
        lines.append(
            f"| {name[:50]} | {status_icon} | {r['tools']} | {len(r['findings'])} | "
            f"{r.get('low_findings', 0)} | {expected_str} | {detected_str} |"
        )

    if any(r["error"] for r in results.values()):
        lines.extend(["", "## Errors", ""])
        for name, r in results.items():
            if r["error"]:
                lines.append(f"- **{name}:** {r['error']}")

    lines.extend(
        [
            "",
            "## Test Corpus",
            "",
            "### Demo Malicious Server (`demo/malicious_server.py`)",
            "Intentionally vulnerable MCP server with 9 tools covering rules R001-R109.",
            "",
            "### Appsecco Vulnerable MCP Servers Lab",
            "External corpus: intentionally vulnerable MCP servers covering path traversal, "
            "prompt injection, RCE, typosquatting, secrets exposure, and outdated packages. "
            "Several of these vulnerability classes live in runtime behavior or "
            "implementation code and are statically undetectable by design; those targets "
            "are labeled as clean-for-static-scan with KNOWN LIMITATION notes.",
            "Repository: https://github.com/appsecco/vulnerable-mcp-servers-lab",
            "",
            "### Official MCP Reference Servers",
            "Clean negative controls from https://github.com/modelcontextprotocol/servers. "
            "Expected to produce zero MEDIUM+ findings — any detection is a false positive.",
            "",
        ]
    )

    return "\n".join(lines)


def _get_version() -> str:
    try:
        from mcpradar import __version__

        return __version__
    except ImportError:
        return "unknown"


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.1%}"


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="MCPRadar Precision/Recall Benchmark")
    parser.add_argument("--target", help="Run only a specific target")
    parser.add_argument("--timeout", type=int, default=120, help="Per-target timeout (seconds)")
    args = parser.parse_args()

    labels = load_labels()
    label_errors = validate_labels(labels)
    if label_errors:
        raise SystemExit("Invalid benchmark labels:\n- " + "\n- ".join(label_errors))
    targets = labels.get("targets", {})

    if args.target:
        targets = {args.target: targets[args.target]} if args.target in targets else {}

    if not targets:
        print("No targets found in labels.json")
        return

    results = {}
    for name, info in targets.items():
        print(f"Scanning: {name}")
        results[name] = scan_target(
            name,
            info.get("command", ""),
            info.get("transport", "stdio"),
            timeout=args.timeout,
        )
        status = results[name]["status"]
        detected = len(results[name]["detected_rules"])
        print(f"  {status}: {detected} rules detected, {len(results[name]['findings'])} findings")

    metrics = compute_metrics(targets, results)
    report = generate_report(targets, results, metrics)

    report_path = VALIDATION_DIR / "BENCHMARK.md"
    report_path.write_text(report, encoding="utf-8")
    print(f"\nBenchmark report: {report_path}")
    print(f"Precision: {_pct(metrics['overall']['precision'])}")
    print(f"Recall: {_pct(metrics['overall']['recall'])}")
    print(f"F1: {_pct(metrics['overall']['f1'])}")


if __name__ == "__main__":
    main()
