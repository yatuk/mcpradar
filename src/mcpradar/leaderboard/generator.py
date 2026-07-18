"""Pure leaderboard generation, independent from the CLI presentation layer."""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcpradar.scoring.capability import compute_aars, dominant_capability, tag_tool
from mcpradar.scoring.confidence import confidence_for
from mcpradar.scoring.engine import compute_grade

_SEVERITIES = ("critical", "high", "medium", "low")
_GRADE_COLORS = {
    "A": "#3fb950",
    "B": "#56d364",
    "C": "#d29922",
    "D": "#db6d28",
    "F": "#f85149",
}
_CATEGORY_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("filesystem", "File System"),
    ("memory", "AI/ML"),
    ("sequential-thinking", "AI/ML"),
    ("everything", "Reference"),
    ("playwright", "Browser"),
    ("puppeteer", "Browser"),
    ("browser", "Browser"),
    ("sqlite", "Database"),
    ("postgres", "Database"),
    ("mysql", "Database"),
    ("redis", "Database"),
    ("neo4j", "Database"),
    ("clickhouse", "Database"),
    ("slack", "Communication"),
    ("discord", "Communication"),
    ("email", "Communication"),
    ("github", "DevOps"),
    ("gitlab", "DevOps"),
    ("docker", "DevOps"),
    ("kubernetes", "DevOps"),
    ("terminal", "DevOps"),
    ("commands", "DevOps"),
    ("brave", "Web Search"),
    ("tavily", "Web Search"),
    ("searxng", "Web Search"),
    ("fetch", "Web Search"),
    ("search", "Web Search"),
    ("wallet", "Crypto Wallets"),
    ("crypto", "Crypto Wallets"),
    ("bitcoin", "Crypto Wallets"),
    ("pdf", "Documents"),
    ("pandoc", "Documents"),
    ("markdown", "Documents"),
    ("blender", "Media"),
    ("youtube", "Media"),
    ("arxiv", "Science"),
    ("bio", "Science"),
    ("context7", "Development"),
)
_API_FREE_CATEGORIES = frozenset(
    {"File System", "Desktop Automation", "Documents", "Development", "Media"}
)
_RULE_TYPES = {
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
    "R114": "Input Bounds",
}
_RULE_FAMILY_TYPES = {
    "C": "Cross-Server Risk",
    "S": "Source-Code Risk",
    "M": "Configuration Risk",
    "D": "Dependency Vulnerability",
    "T": "Package Identity",
}


@dataclass(frozen=True)
class GenerationSummary:
    """Summary returned to presentation adapters after generation."""

    rows: list[dict[str, Any]]
    badge_count: int

    @property
    def scanned(self) -> list[dict[str, Any]]:
        return [
            row
            for row in self.rows
            if row["status"] == "scanned" and row.get("risk_score") is not None
        ]

    @property
    def pending(self) -> list[dict[str, Any]]:
        return [
            row for row in self.rows if row["status"] != "scanned" or row.get("risk_score") is None
        ]


def generate_leaderboard(
    results_dir: Path,
    output: Path,
    *,
    scanner_version: str,
) -> GenerationSummary:
    """Build deterministic leaderboard JSON and matching security badges."""
    rows = _load_rows(results_dir, output, scanner_version)
    rows = _deduplicate(rows)
    rows.sort(
        key=lambda row: (
            row["status"] != "scanned",
            row["risk_score"] if row["risk_score"] is not None else 11.0,
            -row["tools"],
            row["server"],
        )
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    badge_count = _write_badges(output.parent / "badges", rows)
    return GenerationSummary(rows, badge_count)


def _load_rows(results_dir: Path, output: Path, scanner_version: str) -> list[dict[str, Any]]:
    if not results_dir.exists():
        return []
    output_resolved = output.resolve()
    rows: list[dict[str, Any]] = []
    for result_path in sorted(results_dir.glob("*.json")):
        if result_path.resolve() == output_resolved:
            continue
        try:
            data = json.loads(result_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(data, dict):
            continue
        rows.append(_row_from_result(data, result_path.stem, scanner_version))
    return rows


def _row_from_result(
    data: dict[str, Any],
    fallback_name: str,
    scanner_version: str,
) -> dict[str, Any]:
    name = _server_name(data, fallback_name)
    raw_tools = data.get("tools", [])
    tool_objects = raw_tools if isinstance(raw_tools, list) else []
    summary = data.get("summary", {})
    if not isinstance(summary, dict):
        summary = {}
    tools = summary.get("total_tools", len(tool_objects))
    tools = tools if isinstance(tools, int) and tools >= 0 else len(tool_objects)
    raw_findings = data.get("findings", [])
    findings = (
        [item for item in raw_findings if isinstance(item, dict)]
        if isinstance(raw_findings, list)
        else []
    )
    scan_id = str(data.get("scan_id", "") or data.get("id", ""))
    was_scanned = bool(tools or scan_id or data.get("scanned_at"))
    scan_coverage = str(data.get("scan_coverage", "")) or (
        "incomplete" if data.get("incomplete") else "live" if was_scanned else "unscanned"
    )
    category = _category(name)
    common = {
        "server": name,
        "display_name": name.replace("@", "").replace("/", " / "),
        "version": data.get("version", ""),
        "scoring_model": "mrs-v1",
        "tools": tools,
        "scanner_version": scanner_version,
        "scan_coverage": scan_coverage,
        "trending": bool(data.get("trending")),
        "popularity": data.get("popularity"),
        "category": category,
        "vuln_types": _vulnerability_types(findings),
        "history": [],
        "api_free": _is_api_free(name, category),
    }
    if not was_scanned or data.get("incomplete"):
        return {
            **common,
            "risk_score": None,
            "grade": "-",
            "confidence": None,
            "findings": 0,
            "by_severity": dict.fromkeys(_SEVERITIES, 0),
            "findings_detail": [],
            "tool_hash": "",
            "last_scanned": "-",
            "status": "incomplete" if data.get("incomplete") else "pending",
        }

    severity, dependency_severity = _severity_counts(findings)
    meaningful = severity["critical"] + severity["high"] + severity["medium"]
    score, aars, breakdown = _score(severity, dependency_severity, findings, tool_objects, tools)
    detail = _finding_details(findings)
    confidence = (
        round(sum(item["confidence"] for item in detail) / len(detail), 2) if detail else 1.0
    )
    return {
        **common,
        "risk_score": score,
        "grade": compute_grade(score),
        "aars": round(aars, 1),
        "capability": dominant_capability(tool_objects),
        "confidence": confidence,
        "vulnerable_deps": sum(dependency_severity.values()),
        "tools_detail": [_tool_detail(tool) for tool in tool_objects if isinstance(tool, dict)],
        "findings": meaningful,
        "low_findings": severity["low"],
        "by_severity": severity,
        "findings_detail": detail,
        "tool_hash": _tool_hash(tool_objects, scan_id),
        "last_scanned": str(data.get("scanned_at", ""))[:10] or "-",
        "status": "scanned",
        "breakdown": breakdown,
    }


def _server_name(data: dict[str, Any], fallback: str) -> str:
    name = data.get("name")
    if isinstance(name, str) and name:
        return name
    target = str(data.get("target", ""))
    return next((token for token in target.split() if token.startswith("@")), fallback)


def _category(name: str) -> str:
    lowered = name.lower()
    return next(
        (category for keyword, category in _CATEGORY_KEYWORDS if keyword in lowered),
        "Other",
    )


def _is_api_free(name: str, category: str) -> bool:
    lowered = name.lower()
    return category in _API_FREE_CATEGORIES or any(
        keyword in lowered for keyword in ("local", "filesystem", "sqlite", "calculator", "searxng")
    )


def _vulnerability_types(findings: list[dict[str, Any]]) -> list[str]:
    types = {
        _RULE_TYPES.get(rule_id, _RULE_FAMILY_TYPES.get(rule_id[:1], "Security Finding"))
        for finding in findings
        if isinstance((rule_id := finding.get("rule_id")), str) and rule_id
    }
    return sorted(types)


def _severity_counts(
    findings: list[dict[str, Any]],
) -> tuple[dict[str, int], dict[str, int]]:
    severity = dict.fromkeys(_SEVERITIES, 0)
    dependency_severity = dict.fromkeys(_SEVERITIES, 0)
    for finding in findings:
        value = finding.get("severity")
        bucket = dependency_severity if finding.get("rule_id") == "D001" else severity
        if value in bucket:
            bucket[value] += 1
    return severity, dependency_severity


def _score(
    severity: dict[str, int],
    dependency_severity: dict[str, int],
    findings: list[dict[str, Any]],
    tools: list[Any],
    tool_count: int,
) -> tuple[float, float, dict[str, Any]]:
    weighted = severity["critical"] * 10 + severity["high"] * 7 + severity["medium"] * 4
    base = weighted / max(tool_count, 3)
    if severity["critical"]:
        base = max(base, 5.0)
    elif severity["high"]:
        base = max(base, 3.0)
    aars = compute_aars(tools)
    threat_multiplier = 1.15 if any(item.get("rule_id") == "R111" for item in findings) else 1.0
    dependency_risk = min(
        4.9,
        dependency_severity["critical"]
        + dependency_severity["high"] * 0.4
        + dependency_severity["medium"] * 0.15,
    )
    capability_term = round((base + aars) / 2 * threat_multiplier, 2)
    terms = {
        "findings": round(base, 2),
        "capability": capability_term,
        "dependencies": round(dependency_risk, 2),
    }
    score = min(10.0, round(max(terms.values()), 1))
    return (
        score,
        aars,
        {
            "base": round(base, 2),
            "aars": round(aars, 2),
            "capability_term": capability_term,
            "thm": threat_multiplier,
            "dep_risk": round(dependency_risk, 2),
            "weighted_findings": weighted,
            "driver": max(terms, key=terms.__getitem__),
        },
    )


def _finding_details(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "rule_id": finding.get("rule_id", "?"),
            "severity": finding.get("severity", "?"),
            "title": str(finding.get("title", ""))[:80],
            "description": str(finding.get("description", ""))[:120],
            "confidence": finding.get(
                "confidence", confidence_for(str(finding.get("rule_id", "")))
            ),
        }
        for finding in findings
        if finding.get("severity") in ("critical", "high", "medium")
    ]


def _tool_detail(tool: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": tool.get("name", ""),
        "description": str(tool.get("description", ""))[:400],
        "input_schema": tool.get("input_schema", {}),
        "output_schema": tool.get("output_schema", {}),
        "capabilities": sorted(tag_tool(tool)),
    }


def _tool_hash(tools: list[Any], scan_id: str) -> str:
    names = sorted(
        str(tool.get("name", "")) for tool in tools if isinstance(tool, dict) and tool.get("name")
    )
    if not names and scan_id:
        names = _stored_tool_names(scan_id)
    return hashlib.sha256(",".join(names).encode()).hexdigest()[:16] if names else ""


def _stored_tool_names(scan_id: str) -> list[str]:
    try:
        from mcpradar.storage.store import Store

        store = Store()
        try:
            report = store.load(scan_id)
        finally:
            store.close()
        return sorted(tool.name for tool in report.tools) if report else []
    except Exception as exc:
        logging.getLogger("mcpradar").warning(
            "Failed to compute tool hash for %s: %s", scan_id, exc
        )
        return []


def _deduplicate(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_name: dict[str, dict[str, Any]] = {}
    for row in rows:
        existing = by_name.get(row["server"])
        if existing is None:
            by_name[row["server"]] = row
            continue
        winner = max((existing, row), key=lambda item: (item["status"] == "scanned", item["tools"]))
        winner["trending"] = bool(existing.get("trending") or row.get("trending"))
        winner["popularity"] = existing.get("popularity") or row.get("popularity")
        by_name[row["server"]] = winner

    by_hash: dict[str, dict[str, Any]] = {}
    passthrough: list[dict[str, Any]] = []
    for row in by_name.values():
        fingerprint = row.get("tool_hash") or ""
        if row["status"] != "scanned" or not fingerprint:
            passthrough.append(row)
            continue
        existing = by_hash.get(fingerprint)
        if existing is None:
            by_hash[fingerprint] = row
            continue
        winner = min((existing, row), key=_canonical_rank)
        winner["trending"] = bool(existing.get("trending") or row.get("trending"))
        winner["popularity"] = existing.get("popularity") or row.get("popularity")
        by_hash[fingerprint] = winner
    return [*by_hash.values(), *passthrough]


def _canonical_rank(row: dict[str, Any]) -> tuple[bool, int, str]:
    name = row["server"]
    return name.startswith("@anthropic/"), len(name), name


def _write_badges(badges_dir: Path, rows: list[dict[str, Any]]) -> int:
    badges_dir.mkdir(parents=True, exist_ok=True)
    for old in badges_dir.glob("*.svg"):
        try:
            if "MCPRadar Security Score:" in old.read_text(encoding="utf-8"):
                old.unlink()
        except OSError:
            continue
    count = 0
    for row in rows:
        slug = re.sub(r"[^A-Za-z0-9._-]+", "-", row["server"].replace("@", "")).strip(".-")
        if not slug:
            continue
        (badges_dir / f"{slug}.svg").write_text(_badge_svg(row), encoding="utf-8")
        count += 1
    return count


def _badge_svg(row: dict[str, Any]) -> str:
    unscored = row["status"] != "scanned" or row.get("risk_score") is None
    if unscored:
        label = "incomplete" if row["status"] == "incomplete" else "not scanned"
        color, right, aria = "#8b949e", label, label
    else:
        grade = row["grade"]
        color = _GRADE_COLORS.get(grade, "#8b949e")
        right = f"{grade} · {row['risk_score']:.1f}"
        aria = f"{grade} - {row['risk_score']:.1f}/10"
    right_width = 96 if unscored else 72
    total_width = 68 + right_width
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20" '
        f'role="img" aria-label="MCPRadar Security: {aria}">\n'
        f"  <title>MCPRadar Security Score: {aria}</title>\n"
        '  <linearGradient id="bg" x1="0" y1="0" x2="1" y2="0">\n'
        '    <stop offset="0%" stop-color="#444"/>\n'
        '    <stop offset="100%" stop-color="#333"/>\n'
        "  </linearGradient>\n"
        f'  <rect width="{total_width}" height="20" rx="3" fill="url(#bg)"/>\n'
        f'  <rect x="68" width="{right_width}" height="20" fill="{color}" fill-opacity="0.15"/>\n'
        '  <text x="34" y="14" fill="#c9d1d9" font-size="10" font-family="sans-serif" '
        'text-anchor="middle" font-weight="600">MCPRadar</text>\n'
        f'  <text x="{68 + right_width // 2}" y="14" fill="{color}" font-size="10" '
        f'font-family="sans-serif" text-anchor="middle" font-weight="600">{right}</text>\n'
        "</svg>\n"
    )
