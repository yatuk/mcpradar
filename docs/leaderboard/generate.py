"""Generate data.json for the leaderboard from validation results.

Usage: python docs/leaderboard/generate.py
Reads: validation/results/*.json
Writes: docs/leaderboard/data.json
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from mcpradar import __version__
from mcpradar.scoring.engine import compute_aivss, compute_confidence, compute_grade

_SCRIPT_ROOT = Path(__file__).resolve().parent.parent.parent
RESULTS_DIR = _SCRIPT_ROOT / "validation/results"
OUTPUT = _SCRIPT_ROOT / "docs/leaderboard/data.json"


class _DictFinding:
    """Minimal Finding-compatible object bridging raw dicts to the scoring engine."""

    __slots__ = ("rule_id", "severity")

    def __init__(self, data: dict) -> None:
        self.rule_id: str = data.get("rule_id", "?")
        self.severity = _DictSeverity(data.get("severity", "low"))


class _DictSeverity:
    """Minimal Severity-compatible object with .value attribute."""

    __slots__ = ("value",)

    def __init__(self, value: str) -> None:
        self.value = value


def compute_tool_hash(scan_id: str) -> str:
    """Compute tool_names_hash from the SQLite store for a given scan_id."""
    try:
        from mcpradar.storage.store import Store

        store = Store()
        report = store.load(scan_id)
        store.close()
        if report.tools:
            names = sorted(t.name for t in report.tools)
            return hashlib.sha256(",".join(names).encode()).hexdigest()[:16]
    except Exception:
        pass
    return ""


def main() -> None:
    rows: list[dict] = []

    if RESULTS_DIR.exists():
        for fpath in sorted(RESULTS_DIR.glob("*.json")):
            try:
                data = json.loads(fpath.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue

            name = data.get("name") or ""
            if not name:
                target = data.get("target", "")
                for token in target.split():
                    if token.startswith("@"):
                        name = token
                        break
                if not name:
                    name = fpath.stem

            # Handle both raw to_dict() format and processed validation format
            summary = data.get("summary", {})
            tools = summary.get("total_tools", len(data.get("tools", [])))
            findings_list = data.get("findings", [])
            findings_count = len(findings_list)
            scan_id = data.get("scan_id", "") or data.get("id", "")

            # Compute severity counts from findings array
            sev: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in findings_list:
                s = f.get("severity", "")
                if s in sev:
                    sev[s] += 1

            findings_detail = [
                {
                    "rule_id": f.get("rule_id", "?"),
                    "severity": f.get("severity", "?"),
                    "target": f.get("target", "?") or "—",
                    "title": f.get("title", "")[:80],
                    "description": f.get("description", "")[:120],
                }
                for f in findings_list
            ]

            # Extract tool details: name, description, schemas
            tools_list = data.get("tools", [])
            tools_detail: list[dict] = []
            for t in tools_list:
                td: dict = {
                    "name": t.get("name", "?"),
                    "description": t.get("description", "")[:200],
                }
                # Include schemas but strip empty ones to save space
                input_schema = t.get("input_schema")
                if input_schema and isinstance(input_schema, dict) and input_schema != {}:
                    td["input_schema"] = input_schema
                output_schema = t.get("output_schema")
                if output_schema and isinstance(output_schema, dict) and output_schema != {}:
                    td["output_schema"] = output_schema
                tools_detail.append(td)

            # Convert raw dict findings to scoring-engine-compatible objects
            dict_findings = [_DictFinding(f) for f in findings_list]
            aivss_score = compute_aivss(dict_findings, tools)  # type: ignore[arg-type]
            grade = compute_grade(aivss_score)
            confidence = round(compute_confidence(dict_findings), 2)  # type: ignore[arg-type]
            tool_hash = compute_tool_hash(scan_id) if scan_id else ""

            rows.append(
                {
                    "server": name,
                    "display_name": name.replace("@", "").replace("/", " / "),
                    "version": data.get("version", ""),
                    "aivss_score": aivss_score,
                    "grade": grade,
                    "confidence": confidence,
                    "tools": tools,
                    "findings": findings_count,
                    "by_severity": {
                        "critical": sev.get("critical", 0),
                        "high": sev.get("high", 0),
                        "medium": sev.get("medium", 0),
                        "low": sev.get("low", 0),
                    },
                    "findings_detail": findings_detail,
                    "tools_detail": tools_detail,
                    "tool_hash": tool_hash,
                    "last_scanned": (
                        data.get("scanned_at", "")[:10] if data.get("scanned_at") else "—"
                    ),
                    "scanner_version": __version__,
                    "status": data.get("status", "unknown"),
                }
            )

    # Sort by AIVSS score ascending (best/safest first)
    rows.sort(key=lambda r: (r["aivss_score"], -r["tools"]))

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Generated {OUTPUT} with {len(rows)} entries")
    for r in rows:
        print(f"  {r['grade']} | {r['aivss_score']:4.1f} | {r['server']}")

    # Also generate subregistry-format servers.json with _meta security scores
    servers_output = _SCRIPT_ROOT / "docs/leaderboard/servers.json"
    servers_json = []
    for r in rows:
        entry = {
            "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
            "name": r["server"]
            .replace("@modelcontextprotocol/", "io.modelcontextprotocol/")
            .replace("@anthropic/", "io.anthropic/")
            .replace("@playwright/", "com.microsoft.playwright/")
            .replace("@", "io.github."),
            "version": r.get("version") or "unknown",
            "_meta": {
                "com.github.yatuk.mcpradar/security": {
                    "aivss_score": r["aivss_score"],
                    "grade": r["grade"],
                    "confidence": r["confidence"],
                    "findings": r["findings"],
                    "by_severity": r["by_severity"],
                    "last_scanned": r["last_scanned"],
                    "scanner_version": r["scanner_version"],
                    "tool_hash": r["tool_hash"],
                }
            },
        }
        servers_json.append(entry)
    servers_output.write_text(
        json.dumps(servers_json, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"Generated {servers_output} with {len(servers_json)} entries (subregistry format)")


if __name__ == "__main__":
    main()
