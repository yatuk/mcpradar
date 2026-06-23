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
            result["detected_rules"].add(rule_id)
            result["findings"].append(
                {
                    "rule_id": rule_id,
                    "severity": f.get("severity", ""),
                    "title": f.get("title", ""),
                    "target": f.get("target", ""),
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
    """Compute per-rule and overall precision/recall/F1."""
    rule_stats: dict[str, dict] = {}  # rule_id -> {tp, fp, fn}

    for name, target_info in targets.items():
        if name not in results:
            continue
        result = results[name]
        expected = set(target_info.get("expected_rules", []))
        detected = result["detected_rules"]

        for rule_id in expected | detected:
            if rule_id not in rule_stats:
                rule_stats[rule_id] = {"tp": 0, "fp": 0, "fn": 0}

        # TP: detected AND expected
        for rule_id in expected & detected:
            rule_stats[rule_id]["tp"] += 1

        # FP: detected but NOT expected
        for rule_id in detected - expected:
            rule_stats[rule_id]["fp"] += 1

        # FN: expected but NOT detected
        for rule_id in expected - detected:
            rule_stats[rule_id]["fn"] += 1

    # Per-rule metrics
    per_rule = {}
    total_tp = total_fp = total_fn = 0
    for rule_id, stats in sorted(rule_stats.items()):
        tp, fp, fn = stats["tp"], stats["fp"], stats["fn"]
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        per_rule[rule_id] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
        }
        total_tp += tp
        total_fp += fp
        total_fn += fn

    overall_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
    overall_f1 = (
        2 * overall_precision * overall_recall / (overall_precision + overall_recall)
        if (overall_precision + overall_recall) > 0
        else 0.0
    )

    return {
        "per_rule": per_rule,
        "overall": {
            "precision": round(overall_precision, 3),
            "recall": round(overall_recall, 3),
            "f1": round(overall_f1, 3),
            "total_findings": total_tp + total_fp,
            "total_expected": total_tp + total_fn,
        },
        "targets_scanned": len(results),
        "targets_with_labels": len(targets),
    }


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
        "Each target server has a ground-truth label in `validation/labels.json` "
        "specifying which MCPRadar rules *should* fire (`expected_rules`). The scanner "
        "runs against each target, and detected rules are compared to expected rules.",
        "",
        "- **True Positive (TP):** Rule fired AND was expected",
        "- **False Positive (FP):** Rule fired but was NOT expected",
        "- **False Negative (FN):** Rule was expected but did NOT fire",
        "",
        "## Overall Results",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Precision | {metrics['overall']['precision']:.1%} |",
        f"| Recall | {metrics['overall']['recall']:.1%} |",
        f"| F1 Score | {metrics['overall']['f1']:.1%} |",
        f"| Targets scanned | {metrics['targets_scanned']} |",
        f"| Total findings | {metrics['overall']['total_findings']} |",
        "",
        "## Per-Rule Metrics",
        "",
        "| Rule ID | TP | FP | FN | Precision | Recall | F1 |",
        "|---|---|---|---|---|---|---|",
    ]

    for rule_id, m in metrics["per_rule"].items():
        lines.append(
            f"| {rule_id} | {m['tp']} | {m['fp']} | {m['fn']} | "
            f"{m['precision']:.1%} | {m['recall']:.1%} | {m['f1']:.1%} |"
        )

    lines.extend(
        [
            "",
            "## Per-Target Results",
            "",
            "| Target | Status | Tools | Findings | Expected Rules | Detected |",
            "|--------|--------|-------|----------|---------------|----------|",
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
            f"{expected_str} | {detected_str} |"
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
            "External corpus: 9 intentionally vulnerable MCP servers covering path traversal, "
            "prompt injection, RCE, typosquatting, secrets exposure, and outdated packages.",
            "Repository: https://github.com/appsecco/vulnerable-mcp-servers-lab",
            "",
            "### Official MCP Reference Servers",
            "Clean negative controls from https://github.com/modelcontextprotocol/servers. "
            "Expected to produce zero findings — any detection is a false positive.",
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


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="MCPRadar Precision/Recall Benchmark")
    parser.add_argument("--target", help="Run only a specific target")
    parser.add_argument("--timeout", type=int, default=120, help="Per-target timeout (seconds)")
    args = parser.parse_args()

    labels = load_labels()
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
    print(f"Precision: {metrics['overall']['precision']:.1%}")
    print(f"Recall: {metrics['overall']['recall']:.1%}")
    print(f"F1: {metrics['overall']['f1']:.1%}")


if __name__ == "__main__":
    main()
