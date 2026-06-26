"""MCPRadar validation pipeline.

Scans all servers in targets.yaml sequentially,
saves results to the validation/ folder as JSON,
and generates an aggregate REPORT.md.

Usage:
    python validation/run_validation.py [--server NAME] [--timeout 60]
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

VALIDATION_DIR = Path(__file__).parent
RESULTS_DIR = VALIDATION_DIR / "results"


def load_targets() -> list[dict[str, Any]]:
    targets_file = VALIDATION_DIR / "targets.yaml"
    with open(targets_file, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data.get("servers", [])


def scan_server(target: dict[str, Any], timeout: int = 60) -> dict[str, Any]:
    """Scan a single server using mcpradar CLI. Returns result dict."""
    cmd = target["scan"]
    transport = target.get("transport", "stdio")

    result: dict[str, Any] = {
        "name": target["name"],
        "command": cmd,
        "transport": transport,
        "status": "not_run",
        "tools": 0,
        "findings": 0,
        "findings_by_severity": {},
        "findings_by_rule": {},
        "error": None,
        "scan_id": None,
        "duration_ms": 0,
        "notes": target.get("notes", ""),
        "triage": [],
    }

    start = time.time()
    try:
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "mcpradar",
                "scan",
                cmd,
                "-t",
                transport,
                "--json",
                "-s",
                "low",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(VALIDATION_DIR.parent),
        )

        result["duration_ms"] = int((time.time() - start) * 1000)

        if proc.returncode != 0:
            result["status"] = "error"
            result["error"] = proc.stderr[:500] if proc.stderr else f"Exit code {proc.returncode}"
            return result

        # Parse JSON output
        raw = proc.stdout.strip()
        if raw:
            try:
                data = json.loads(raw)
                result["scan_id"] = data.get("id", "")
                result["tools"] = data.get("summary", {}).get("total_tools", 0)
                result["findings"] = len(data.get("findings", []))

                for f in data.get("findings", []):
                    sev = f.get("severity", "unknown")
                    rule = f.get("rule_id", "unknown")
                    result["findings_by_severity"][sev] = (
                        result["findings_by_severity"].get(sev, 0) + 1
                    )
                    result["findings_by_rule"][rule] = result["findings_by_rule"].get(rule, 0) + 1

                    # Per-finding triage
                    result["triage"].append(
                        {
                            "rule_id": rule,
                            "severity": sev,
                            "title": f.get("title", ""),
                            "target": f.get("target", ""),
                            "description": f.get("description", "")[:200],
                            "classification": "needs_review",
                        }
                    )

                # Auto-classify known patterns
                for t in result["triage"]:
                    _auto_triage(t, target["name"])

                result["status"] = "success"
            except json.JSONDecodeError as e:
                result["status"] = "error"
                result["error"] = f"JSON parse error: {e}"

    except subprocess.TimeoutExpired:
        result["status"] = "error"
        result["error"] = f"Timeout after {timeout}s"
    except FileNotFoundError:
        result["status"] = "error"
        result["error"] = "mcpradar or npm/npx not found"
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)[:500]

    return result


def _auto_triage(t: dict[str, Any], server_name: str) -> None:
    """Auto-classify known false positive patterns."""
    rule = t["rule_id"]

    # R105 on filesystem server's read_file/write_file is expected (FP)
    target = t.get("target", "")
    if (
        rule == "R105"
        and "filesystem" in server_name
        and ("read_file" in target or "write_file" in target)
    ):
        t["classification"] = "false_positive"
        t["reason"] = "Filesystem tools legitimately bridge file+network context"
        return

    # R105 with both file and network in description = likely FP
    if rule == "R105" and "both_in_description" in str(t):
        t["classification"] = "false_positive"
        t["reason"] = "Tool legitimately bridges two scopes (e.g., fetch+save)"
        return

    # ZWSP in description (not name) on known servers = likely emoji/formatting
    if rule == "R101":
        t["classification"] = "needs_review"
        t["reason"] = "Could be legitimate Unicode (emoji ZWJ) or hidden text attack"
        return

    # Dangerous name on puppeteer (page.evaluate → 'eval' tool)
    if rule == "R001" and "puppeteer" in server_name:
        t["classification"] = "true_positive"
        t["reason"] = "Browser eval tool — legitimate but indeed dangerous"
        return


def generate_report(results: list[dict[str, Any]]) -> str:
    """Generate aggregate validation REPORT.md."""
    lines: list[str] = []
    lines.append("# MCPRadar Validation Results\n")
    lines.append(f"> {len(results)} servers tested\n")
    lines.append("")

    # Summary table
    total_findings = sum(r["findings"] for r in results)
    total_success = sum(1 for r in results if r["status"] == "success")
    lines.append("## Summary\n")
    lines.append(f"- Servers tested: {len(results)}")
    lines.append(f"- Successful scans: {total_success}")
    lines.append(f"- Total findings: {total_findings}")
    lines.append("")

    # Per-server breakdown
    lines.append("## Server-by-Server Breakdown\n")
    lines.append("| Server | Status | Tools | Findings | High+Critical | Triage |")
    lines.append("|--------|--------|-------|----------|---------------|--------|")

    for r in results:
        status = r["status"]
        icon = {"success": "✅", "error": "❌", "not_run": "⏳"}.get(status, "❓")
        high = r["findings_by_severity"].get("high", 0)
        crit = r["findings_by_severity"].get("critical", 0)

        tp = sum(1 for t_ in r["triage"] if t_.get("classification") == "true_positive")
        fp = sum(1 for t_ in r["triage"] if t_.get("classification") == "false_positive")
        nr = sum(1 for t_ in r["triage"] if t_.get("classification") == "needs_review")

        lines.append(
            f"| {r['name']} | {icon} | {r['tools']} | {r['findings']} | "
            f"{high + crit} | TP:{tp} FP:{fp} ?:{nr} |"
        )

    lines.append("")

    # Detailed findings per server
    lines.append("## Detailed Findings\n")
    for r in results:
        if not r["triage"]:
            continue
        lines.append(f"### {r['name']}\n")
        lines.append(f"**Notes:** {r['notes']}\n")
        lines.append("| Rule | Severity | Target | Classification | Reason |")
        lines.append("|------|----------|--------|----------------|--------|")
        for t in r["triage"]:
            cls_icon = {
                "true_positive": "🔴 TP",
                "false_positive": "🟢 FP",
                "needs_review": "🟡 ?",
            }.get(t.get("classification", ""), "❓")
            lines.append(
                f"| {t['rule_id']} | {t['severity']} | {t['target']} | "
                f"{cls_icon} | {t.get('reason', '')} |"
            )
        lines.append("")

    # Legend
    lines.append("## Triage Legend\n")
    lines.append("| Icon | Classification | Meaning |")
    lines.append("|------|----------------|---------|")
    lines.append("| 🔴 TP | True Positive | Real security vulnerability |")
    lines.append("| 🟢 FP | False Positive | Legitimate use, false alarm |")
    lines.append("| 🟡 ? | Needs Review | Manual investigation required |")

    lines.append("")
    lines.append(f"*Generated: {time.strftime('%Y-%m-%d %H:%M UTC')}*")
    lines.append("")

    return "\n".join(lines)


class ValidationRunner:
    """Async validation runner that scans servers and computes metrics."""

    def __init__(self, targets_path: Path | None = None) -> None:
        if targets_path is None:
            targets_path = Path(__file__).parent / "targets.yaml"
        with open(targets_path) as f:
            config = yaml.safe_load(f)
        self.servers: list[dict] = config.get("servers", [])
        self.results: list[dict] = []

    async def run_all(self, timeout: int = 60, skip_scan: bool = False) -> None:
        """Run validation against all configured servers.

        Args:
            timeout: Per-server timeout in seconds.
            skip_scan: If True, re-use existing results instead of re-scanning.
        """
        from mcpradar.scanner.engine import ParallelScanner
        from mcpradar.scanner.report import Severity

        if skip_scan:
            self._load_existing_results()
            return

        servers = [
            (
                srv.get("command", ""),
                srv.get("transport", "stdio"),
            )
            for srv in self.servers
        ]

        ps = ParallelScanner(max_concurrency=3)
        scan_results = await ps.scan_all(
            servers,
            min_severity=Severity.LOW,  # collect all findings for validation
        )

        results_dir = Path(__file__).parent / "results"
        results_dir.mkdir(exist_ok=True)

        for i, (srv, result) in enumerate(zip(self.servers, scan_results, strict=True)):
            server_result = {
                "name": srv.get("name", f"server-{i}"),
                "command": srv.get("command", ""),
                "transport": srv.get("transport", "stdio"),
                "expected_rules": srv.get("expected_rules", []),
            }

            if isinstance(result, Exception):
                server_result["error"] = str(result)
                server_result["tools_count"] = 0
                server_result["findings"] = []
            else:
                server_result["scan_id"] = getattr(result, "id", "")
                server_result["tools_count"] = len(result.tools)
                server_result["findings"] = [
                    {
                        "rule_id": f.rule_id,
                        "title": f.title,
                        "severity": f.severity.value,
                        "target": f.target,
                        "description": f.description,
                    }
                    for f in result.findings
                ]

            self.results.append(server_result)

            # Save per-server result
            safe_name = srv.get("name", f"server-{i}").replace("/", "_").replace(" ", "_")
            result_path = results_dir / f"{safe_name}.json"
            with open(result_path, "w", encoding="utf-8") as f:
                json.dump(server_result, f, indent=2, ensure_ascii=False)

    def _load_existing_results(self) -> None:
        """Load previously saved results."""
        results_dir = Path(__file__).parent / "results"
        if not results_dir.exists():
            print("No existing results found.")
            return
        for result_file in sorted(results_dir.glob("*.json")):
            with open(result_file) as f:
                self.results.append(json.load(f))

    def compute_metrics(self) -> dict:
        """Compute precision and recall metrics per rule.

        Precision = TP / (TP + FP)
        Recall = TP / (TP + FN)
        """
        rule_stats: dict[str, dict] = {}

        for result in self.results:
            expected = set(result.get("expected_rules", []))
            detected = {f["rule_id"] for f in result.get("findings", [])}

            for rule_id in expected | detected:
                if rule_id not in rule_stats:
                    rule_stats[rule_id] = {"tp": 0, "fp": 0, "fn": 0}

            # True positives: detected AND expected
            for rule_id in expected & detected:
                rule_stats[rule_id]["tp"] += 1

            # False positives: detected but NOT expected
            for rule_id in detected - expected:
                rule_stats[rule_id]["fp"] += 1

            # False negatives: expected but NOT detected
            for rule_id in expected - detected:
                rule_stats[rule_id]["fn"] += 1

        # Compute per-rule and overall metrics
        total_tp = total_fp = total_fn = 0
        rule_metrics = {}
        for rule_id, stats in sorted(rule_stats.items()):
            tp, fp, fn = stats["tp"], stats["fp"], stats["fn"]
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
            rule_metrics[rule_id] = {
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
            "per_rule": rule_metrics,
            "overall": {
                "precision": round(overall_precision, 3),
                "recall": round(overall_recall, 3),
                "f1": round(overall_f1, 3),
                "total_findings": total_tp + total_fp,
                "total_expected": total_tp + total_fn,
            },
        }

    def generate_report(self) -> str:
        """Generate a Markdown validation report."""
        metrics = self.compute_metrics()
        lines = [
            "# MCPRadar Validation Report",
            "",
            f"**Date:** {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}",
            f"**Servers tested:** {len(self.results)}",
            f"**Total findings:** {metrics['overall']['total_findings']}",
            "",
            "## Overall Metrics",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| Precision | {metrics['overall']['precision']:.1%} |",
            f"| Recall | {metrics['overall']['recall']:.1%} |",
            f"| F1 Score | {metrics['overall']['f1']:.1%} |",
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
                "## Server Results",
                "",
            ]
        )

        for result in self.results:
            name = result.get("name", "unknown")
            error = result.get("error", "")
            tools = result.get("tools_count", 0)
            findings = result.get("findings", [])
            status = "❌ Error" if error else "✅ OK"
            lines.append(f"### {name} — {status}")
            if error:
                lines.append(f"Error: `{error}`")
            lines.append(f"- Tools: {tools}")
            lines.append(f"- Findings: {len(findings)}")
            if findings:
                for f_ in findings[:10]:  # top 10
                    lines.append(f"  - `{f_['rule_id']}` {f_['title']} ({f_['severity']})")
            lines.append("")

        return "\n".join(lines)


def main() -> None:
    """Run the validation pipeline."""
    import argparse

    parser = argparse.ArgumentParser(description="MCPRadar Validation Runner")
    parser.add_argument("--server", help="Run only a specific server by name")
    parser.add_argument("--timeout", type=int, default=60, help="Per-server timeout in seconds")
    parser.add_argument("--skip-scan", action="store_true", help="Re-use existing results")
    parser.add_argument(
        "--report-only", action="store_true", help="Only generate report from existing results"
    )
    args = parser.parse_args()

    runner = ValidationRunner()

    if args.report_only:
        runner._load_existing_results()
    elif args.server:
        # Filter to single server
        runner.servers = [s for s in runner.servers if s.get("name") == args.server]
        if not runner.servers:
            print(f"Server not found: {args.server}")
            sys.exit(1)
        asyncio.run(runner.run_all(timeout=args.timeout, skip_scan=args.skip_scan))
    else:
        asyncio.run(runner.run_all(timeout=args.timeout, skip_scan=args.skip_scan))

    # Generate and save report
    report = runner.generate_report()
    report_path = Path(__file__).parent / "REPORT.md"
    report_path.write_text(report, encoding="utf-8")
    print(f"Report saved to {report_path}")

    # Print summary
    metrics = runner.compute_metrics()
    print(f"\nPrecision: {metrics['overall']['precision']:.1%}")
    print(f"Recall: {metrics['overall']['recall']:.1%}")
    print(f"F1: {metrics['overall']['f1']:.1%}")


if __name__ == "__main__":
    main()
