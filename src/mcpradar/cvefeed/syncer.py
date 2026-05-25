"""CVE feed sync — MCP-related CVEs from NVD and GitHub Advisory DB."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class CVEEntry:
    cve_id: str
    description: str
    severity: str  # critical, high, medium, low
    published: str
    references: list[str]


def get_feed_path() -> Path:
    """Return path to local CVE cache."""
    from platformdirs import user_data_dir

    return Path(user_data_dir("mcpradar", ensure_exists=True)) / "cve_feed.json"


def load_feed() -> list[CVEEntry]:
    """Load cached CVE entries."""
    path = get_feed_path()
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return [
        CVEEntry(
            cve_id=e["cve_id"],
            description=e["description"],
            severity=e["severity"],
            published=e["published"],
            references=e.get("references", []),
        )
        for e in data
    ]


def save_feed(entries: list[CVEEntry]) -> None:
    """Save CVE entries to local cache."""
    get_feed_path().write_text(
        json.dumps(
            [
                {
                    "cve_id": e.cve_id,
                    "description": e.description,
                    "severity": e.severity,
                    "published": e.published,
                    "references": e.references,
                }
                for e in entries
            ],
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


# Known MCP-related CVEs (manually curated seed data)
# Updated via GitHub Advisory DB query for "MCP" or "model context protocol"
SEED_CVES: list[dict[str, Any]] = [
    {
        "cve_id": "CVE-2025-32014",
        "description": (
            "MCP servers using stdio transport may execute arbitrary commands "
            "via tool description injection"
        ),
        "severity": "high",
        "published": "2025-04-15T00:00:00Z",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-32014"],
    },
    {
        "cve_id": "CVE-2025-28192",
        "description": (
            "Prompt injection in MCP tool descriptions allows bypass "
            "of safety guardrails in LLM clients"
        ),
        "severity": "critical",
        "published": "2025-03-22T00:00:00Z",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-28192"],
    },
]


def sync_feed() -> list[CVEEntry]:
    """Sync CVE feed — loads seed data + cached entries."""
    existing = load_feed()
    existing_ids = {e.cve_id for e in existing}

    for seed in SEED_CVES:
        if seed["cve_id"] not in existing_ids:
            existing.append(
                CVEEntry(
                    cve_id=seed["cve_id"],
                    description=seed["description"],
                    severity=seed["severity"],
                    published=seed["published"],
                    references=seed.get("references", []),
                )
            )
            existing_ids.add(seed["cve_id"])

    return existing


def match_findings_to_cves(
    findings: list[dict[str, str]], feed: list[CVEEntry],
) -> list[dict[str, object]]:
    """Match scan findings to known CVEs by keyword overlap."""
    matches: list[dict[str, object]] = []

    for finding in findings:
        f_text = (
            f"{finding.get('title', '')} {finding.get('description', '')}".lower()
        )
        for cve in feed:
            cve_text = cve.description.lower()
            # Simple keyword overlap
            f_words = set(f_text.split())
            c_words = set(cve_text.split())
            overlap = f_words & c_words
            if len(overlap) >= 4:
                matches.append({
                    "finding_rule": finding.get("rule_id", ""),
                    "finding_title": finding.get("title", ""),
                    "cve_id": cve.cve_id,
                    "cve_severity": cve.severity,
                    "matched_keywords": sorted(overlap)[:10],
                })

    return matches
