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


# Rule ID to vulnerability type mapping for filtering
RULE_VULN_TYPE: dict[str, str] = {
    "R001": "Command Execution",
    "R101": "Unicode Attack",
    "R102": "Prompt Injection",
    "R103": "Encoded Payload",
    "R104": "Hidden Content",
    "R105": "Scope Mismatch",
    "R106": "Secret Exposure",
    "R107": "Command Injection",
    "R108": "Supply Chain",
    "R109": "Schema Poisoning",
    "R110": "Version Anomaly",
    "R111": "Insecure Transport",
    "R112": "Authorization",
    "R113": "Path Traversal",
    "R114": "Unbounded Input",
    "C001": "Cross-Server Collision",
    "C002": "Cross-Server Shadowing",
    "C003": "Cross-Server Exfiltration",
    "C004": "Cross-Server Overlap",
    "C005": "Cross-Server Gradient",
    "C006": "Cross-Server Attack Path",
    "C007": "Cross-Server Escalation",
}

# Category inference from server name patterns
_SERVER_CATEGORIES: dict[str, str] = {
    "filesystem": "File System",
    "memory": "AI/ML",
    "sequential-thinking": "AI/ML",
    "everything": "Reference",
    "playwright": "Browser",
    "puppeteer": "Browser",
    "sqlite": "Database",
    "postgres": "Database",
    "mysql": "Database",
    "redis": "Database",
    "slack": "Communication",
    "discord": "Communication",
    "github": "DevOps",
    "gitlab": "DevOps",
    "git": "DevOps",
    "docker": "DevOps",
    "kubernetes": "DevOps",
    "aws": "Cloud",
    "gcp": "Cloud",
    "jira": "DevOps",
    "confluence": "DevOps",
    "brave": "Web Search",
    "tavily": "Web Search",
    "exa": "Web Search",
    "serper": "Web Search",
    "fetch": "Web Search",
    "pinecone": "Vector DB",
    "weaviate": "Vector DB",
    "qdrant": "Vector DB",
    "milvus": "Vector DB",
    "shodan": "OSINT",
    "virustotal": "OSINT",
    "email": "Communication",
    "sendgrid": "Communication",
    "teams": "Communication",
    "local-mcp": "Desktop Automation",
    "lmcp": "Desktop Automation",
    "dotmd": "Knowledge/RAG",
    "chrome-devtools": "Browser/DevTools",
    "searxng": "Web Search",
    "duckduckgo": "Web Search",
    "wardn": "Security",
    "ha-mcp": "IoT/Smart Home",
    "frigate": "IoT/Smart Home",
    "untitled-ui": "Component Library",
    "db-mcp": "Database",
    "equibles": "Financial",
    "stripe": "Financial",
    "paypal": "Financial",
    "crypto": "Crypto Wallets",
    "wallet": "Crypto Wallets",
    "bitcoin": "Crypto Wallets",
    "ethereum": "Crypto Wallets",
    "solana": "Crypto Wallets",
    "blockchain": "Crypto Wallets",
    "web3": "Crypto Wallets",
    "ollama": "Local LLM",
    "lm-studio": "Local LLM",
    "lmstudio": "Local LLM",
    "openwebui": "Local LLM",
    "local-ai": "Local LLM",
    "gpt4all": "Local LLM",
    "jan": "Local LLM",
}

# Categories that indicate API-free / local-first operation
_API_FREE_CATEGORIES: frozenset[str] = frozenset({
    "Desktop Automation",
    "Knowledge/RAG",
    "Financial",
    "Browser/DevTools",
    "IoT/Smart Home",
    "Security",
    "Component Library",
})

_API_FREE_KEYWORDS: frozenset[str] = frozenset({
    "local-mcp", "dotmd", "chrome-devtools", "searxng",
    "duckduckgo", "wardn", "ha-mcp", "frigate",
    "untitled-ui", "db-mcp", "equibles",
})

def _is_api_free(server_name: str, category: str) -> bool:
    """Detect API-free / local-first servers."""
    lower = server_name.lower()
    for kw in _API_FREE_KEYWORDS:
        if kw in lower:
            return True
    return category in _API_FREE_CATEGORIES

def _infer_category(server_name: str) -> str:
    """Infer category from server name keywords."""
    lower = server_name.lower()
    for key, cat in _SERVER_CATEGORIES.items():
        if key in lower:
            return cat
    return "Other"

def _compute_vuln_types(findings_list: list[dict]) -> list[str]:
    """Compute unique vulnerability types from findings."""
    types: set[str] = set()
    for f in findings_list:
        vt = RULE_VULN_TYPE.get(f.get("rule_id", ""))
        if vt:
            types.add(vt)
    return sorted(types)


def _compute_history(server_name: str, current_findings: list[dict], tool_count: int) -> list[dict]:
    """Pull scan history from SQLite store for sparkline trend data."""
    try:
        from mcpradar.storage.store import Store

        store = Store()
        # Find scan IDs for this server by matching against target patterns
        scans = store.list_targets()
        matching: list[str] = []
        for t in scans:
            if server_name.lower() in t.lower():
                ids = store.latest_scans(t, limit=12)
                matching.extend(ids)
        if not matching:
            store.close()
            return []

        history: list[dict] = []
        for sid in matching[-12:]:
            try:
                report = store.load(sid)
                df = [_DictFinding({
                    "rule_id": f.rule_id,
                    "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                }) for f in report.findings]
                score = compute_aivss(df, max(report.tools_count or tool_count, 1))  # type: ignore[arg-type]
                history.append({
                    "date": report.scanned_at[:10] if hasattr(report, 'scanned_at') else "",
                    "score": round(score, 1),
                    "grade": compute_grade(score),
                })
            except Exception:
                continue
        store.close()
        return history
    except Exception:
        return []


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
                    "target": f.get("target", "?") or "-",
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
                        data.get("scanned_at", "")[:10] if data.get("scanned_at") else "-"
                    ),
                    "scanner_version": __version__,
                    "status": data.get("status", "unknown"),
                    "category": _infer_category(name),
                    "vuln_types": _compute_vuln_types(findings_list),
                    "history": _compute_history(name, findings_list, tools),
                    "api_free": _is_api_free(name, _infer_category(name)),
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

    # Generate per-server SVG badges
    _generate_badges(rows, OUTPUT.parent)


def _generate_badges(rows: list[dict], output_dir: Path) -> None:
    """Generate per-server SVG security badges for README embedding."""
    badge_dir = output_dir / "badges"
    badge_dir.mkdir(parents=True, exist_ok=True)

    grades: dict[str, str] = {
        "A": "#3fb950", "B": "#56d364", "C": "#d29922", "D": "#db6d28", "F": "#f85149",
    }
    base_url = "https://yatuk.github.io/mcpradar"

    for r in rows:
        safe_name = r["server"].replace("@", "").replace("/", "-")
        grade = r.get("grade", "?")
        color = grades.get(grade, "#8b949e")
        score = f"{r.get('aivss_score', 0):.1f}"
        server_encoded = r["server"].replace("@", "").replace("/", "-")

        svg = (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="140" height="20" role="img" aria-label="MCPRadar Security: {grade} - {score}/10">\n'
            f'  <title>MCPRadar Security Score: {grade} ({score}/10)</title>\n'
            f'  <linearGradient id="bg" x1="0" y1="0" x2="1" y2="0">\n'
            f'    <stop offset="0%" stop-color="#444"/>\n'
            f'    <stop offset="100%" stop-color="#333"/>\n'
            f'  </linearGradient>\n'
            f'  <rect width="140" height="20" rx="3" fill="url(#bg)"/>\n'
            f'  <rect x="68" width="72" height="20" rx="0" fill="{color}" fill-opacity="0.15"/>\n'
            f'  <text x="34" y="14" fill="#c9d1d9" font-size="10" font-family="sans-serif" text-anchor="middle" font-weight="600">MCPRadar</text>\n'
            f'  <text x="104" y="14" fill="{color}" font-size="10" font-family="sans-serif" text-anchor="middle" font-weight="600">{grade} &middot; {score}</text>\n'
            f'</svg>'
        )
        (badge_dir / f"{safe_name}.svg").write_text(svg, encoding="utf-8")

    print(f"Generated {len(rows)} badges in {badge_dir}")


if __name__ == "__main__":
    main()
