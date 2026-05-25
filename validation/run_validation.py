"""MCPRadar validation pipeline.

targets.yaml'daki tum server'lari sirayla tarar,
sonuclari validation/ klasorune JSON olarak kaydeder,
ve aggregate REPORT.md olusturur.

Kullanim:
    python validation/run_validation.py [--server NAME] [--timeout 60]
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
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
    lines.append("| 🔴 TP | True Positive | Gerçek güvenlik açığı |")
    lines.append("| 🟢 FP | False Positive | Meşru kullanım, alarm yanlış |")
    lines.append("| 🟡 ? | Needs Review | Manuel inceleme gerekli |")

    lines.append("")
    lines.append(f"*Generated: {time.strftime('%Y-%m-%d %H:%M UTC')}*")
    lines.append("")

    return "\n".join(lines)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="MCPRadar validation runner")
    parser.add_argument("--server", help="Only scan this server name")
    parser.add_argument("--timeout", type=int, default=60, help="Timeout per scan (seconds)")
    parser.add_argument(
        "--skip-scan",
        action="store_true",
        help="Skip scanning, just regenerate report",
    )
    args = parser.parse_args()

    targets = load_targets()
    if args.server:
        targets = [t for t in targets if args.server.lower() in t["name"].lower()]
        if not targets:
            print(f"No server matching '{args.server}'")
            return

    RESULTS_DIR.mkdir(exist_ok=True)
    results: list[dict[str, Any]] = []

    for i, target in enumerate(targets, 1):
        print(f"\n[{i}/{len(targets)}] {target['name']}")
        print(f"  Command: {target['scan']}")

        if args.skip_scan:
            # Load existing result
            safe = target["name"].replace("/", "_").replace("@", "")
            result_file = RESULTS_DIR / f"{safe}.json"
            if result_file.exists():
                result = json.loads(result_file.read_text(encoding="utf-8"))
                results.append(result)
                print(f"  (loaded from {result_file})")
            continue

        result = scan_server(target, timeout=args.timeout)

        # Save individual result
        safe = target["name"].replace("/", "_").replace("@", "")
        result_file = RESULTS_DIR / f"{safe}.json"
        result_file.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

        results.append(result)

        status_icon = "OK" if result["status"] == "success" else "FAIL"
        print(f"  {status_icon} — {result['findings']} findings, {result['duration_ms']}ms")
        if result["error"]:
            print(f"  Error: {result['error'][:120]}")

    # Generate report
    report = generate_report(results)
    report_path = VALIDATION_DIR / "REPORT.md"
    report_path.write_text(report, encoding="utf-8")
    print(f"\nReport: {report_path}")


if __name__ == "__main__":
    main()
