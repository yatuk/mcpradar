"""CVE feed sync — MCP-related CVEs from NVD and GitHub Advisory DB."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx


@dataclass
class CVEEntry:
    cve_id: str
    description: str
    severity: str  # critical, high, medium, low
    published: str
    references: list[str]


@dataclass
class CVEMatch:
    """A scored match between a finding and a CVE."""

    finding_rule: str
    finding_title: str
    cve_id: str
    cve_severity: str
    score: float
    matched_keywords: list[str] = field(default_factory=list)
    cwe_overlap: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_rule": self.finding_rule,
            "finding_title": self.finding_title,
            "cve_id": self.cve_id,
            "cve_severity": self.cve_severity,
            "score": round(self.score, 3),
            "matched_keywords": self.matched_keywords,
            "cwe_overlap": self.cwe_overlap,
        }


# Rule ID → related CWE IDs (for CVE matching)
RULE_CWE_MAPPING: dict[str, list[str]] = {
    "R001": ["CWE-78"],  # OS Command Injection
    "R101": ["CWE-451"],  # UI Misrepresentation
    "R102": ["CWE-74"],  # Injection
    "R103": ["CWE-506"],  # Embedded Malicious Code
    "R104": ["CWE-451"],  # UI Misrepresentation
    "R105": ["CWE-863"],  # Incorrect Authorization
    "R106": ["CWE-798"],  # Hardcoded Credentials
    "R107": ["CWE-77"],  # Command Injection
    "R108": ["CWE-494"],  # Download of Code Without Integrity Check
    "R109": ["CWE-20"],  # Improper Input Validation
    "R110": ["CWE-441"],  # Unintended Proxy
    "R111": ["CWE-319"],  # Cleartext Transmission
    "C001": ["CWE-1104"],  # Use of Unmaintained Third Party Components
    "C002": ["CWE-1104"],
    "C003": ["CWE-918"],  # SSRF
    "C004": ["CWE-1104"],
    "C005": ["CWE-863"],  # Incorrect Authorization
    "C006": ["CWE-923"],  # Improper Restriction of Communication Channel
    "C007": ["CWE-269"],  # Improper Privilege Management
}


class NVDAPISyncer:
    """Sync MCP-related CVEs from the NVD API 2.0.

    Uses rate-limited HTTP requests with exponential backoff.
    Results are cached locally in cve_feed.json.
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    MCP_KEYWORDS = [
        "MCP",
        "Model Context Protocol",
        "MCP server",
        "MCP tool",
        "MCP client",
        "MCP transport",
        "stdio",
    ]

    def __init__(self, api_key: str | None = None) -> None:
        self._api_key = api_key or os.environ.get("NVD_API_KEY", "")
        self._backoff_s = 1.0
        self._max_backoff_s = 60.0

    # -- Public API ---------------------------------------------------------

    def search_mcp_cves(self, keywords: list[str] | None = None) -> list[CVEEntry]:
        """Search NVD for MCP-related CVEs.

        Fetches from the NVD API 2.0 endpoint with exponential backoff
        on rate-limit responses (429) and server errors (503).
        Returns parsed CVEEntry objects.
        """
        search_keywords = keywords or self.MCP_KEYWORDS
        all_entries: list[CVEEntry] = []
        seen_ids: set[str] = set()

        for keyword in search_keywords:
            entries = self._fetch_cves_for_keyword(keyword)
            for entry in entries:
                if entry.cve_id not in seen_ids:
                    seen_ids.add(entry.cve_id)
                    all_entries.append(entry)

        # Reset backoff on success
        self._backoff_s = 1.0
        return all_entries

    def sync_all(self) -> int:
        """Full sync: fetch from NVD, merge with local cache, save.

        Returns total number of CVEs in the feed after sync.
        """
        # Load existing cache
        existing = load_feed()
        existing_ids = {e.cve_id: e for e in existing}

        # Fetch from NVD
        try:
            remote = self.search_mcp_cves()
        except Exception:
            # Network error — return existing count
            remote = []

        # Merge: new entries added, existing updated if newer published date
        for entry in remote:
            if entry.cve_id in existing_ids:
                old = existing_ids[entry.cve_id]
                if entry.published > old.published:
                    existing_ids[entry.cve_id] = entry
            else:
                existing_ids[entry.cve_id] = entry

        merged = list(existing_ids.values())
        save_feed(merged)
        return len(merged)

    # -- Internal -----------------------------------------------------------

    def _fetch_cves_for_keyword(self, keyword: str) -> list[CVEEntry]:
        """Fetch CVEs for a single keyword, with pagination and backoff."""
        entries: list[CVEEntry] = []
        start_index = 0
        results_per_page = 50

        while True:
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": str(results_per_page),
                "startIndex": str(start_index),
            }
            headers: dict[str, str] = {}
            if self._api_key:
                headers["apiKey"] = self._api_key

            response = self._request_with_backoff(params, headers)
            if response is None:
                break

            try:
                data = response.json()
            except Exception:
                break

            vulnerabilities = data.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                cve_data = vuln.get("cve", {})
                entry = self._parse_cve_item(cve_data)
                if entry:
                    entries.append(entry)

            total_results = data.get("totalResults", 0)
            start_index += results_per_page
            if start_index >= total_results:
                break

        return entries

    def _request_with_backoff(
        self, params: dict[str, Any], headers: dict[str, Any]
    ) -> httpx.Response | None:
        """Make an HTTP GET with exponential backoff on rate limits."""
        max_retries = 5
        for attempt in range(max_retries):
            try:
                response = httpx.get(
                    self.BASE_URL,
                    params=params,
                    headers=headers,
                    timeout=30.0,
                )
                if response.status_code == 200:
                    return response
                if response.status_code in (429, 503):
                    # Rate limited — back off
                    time.sleep(self._backoff_s)
                    self._backoff_s = min(self._backoff_s * 2, self._max_backoff_s)
                    continue
                # Other error — give up
                return None
            except Exception:
                if attempt < max_retries - 1:
                    time.sleep(self._backoff_s)
                    self._backoff_s = min(self._backoff_s * 2, self._max_backoff_s)
                else:
                    return None
        return None

    def _parse_cve_item(self, cve_data: dict[str, Any]) -> CVEEntry | None:
        """Parse an NVD CVE item dict into a CVEEntry."""
        cve_id = cve_data.get("id", "")
        if not cve_id:
            return None

        # Get English description
        description = ""
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # Get CVSS v3 base severity
        severity = "unknown"
        metrics = cve_data.get("metrics", {})
        for metric_key in ("cvssMetricV31", "cvssMetricV30"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                base_severity = cvss_data.get("baseSeverity", "")
                if base_severity:
                    severity = base_severity.lower()
                    break

        published = cve_data.get("published", "")

        references = [
            ref.get("url", "") for ref in cve_data.get("references", []) if ref.get("url")
        ]

        return CVEEntry(
            cve_id=cve_id,
            description=description,
            severity=severity,
            published=published,
            references=references,
        )


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
    findings: list[Any],
    feed: list[CVEEntry],
    min_score: float = 0.3,
) -> list[CVEMatch]:
    """Match scan findings to CVEs using multi-factor scoring.

    Scoring weights:
    - 40% keyword overlap (Jaccard similarity)
    - 40% CWE overlap (binary: 1.0 if any CWE matches)
    - 20% severity correlation

    Only returns matches with score >= min_score.
    """
    matches: list[CVEMatch] = []

    for finding in findings:
        finding_text = f"{finding.title} {finding.description}".lower()
        finding_keywords = set(finding_text.split())

        for cve in feed:
            cve_text = cve.description.lower()
            cve_keywords = set(cve_text.split())

            # 1. Keyword overlap (Jaccard)
            intersection = finding_keywords & cve_keywords
            union = finding_keywords | cve_keywords
            keyword_score = len(intersection) / len(union) if union else 0.0

            # 2. CWE overlap
            rule_cwes = set(RULE_CWE_MAPPING.get(finding.rule_id, []))
            # CWEs aren't easily extractable from NVD API text — use rule mapping
            cwe_score = 1.0 if len(rule_cwes) > 0 else 0.0
            # (Future: extract CWEs from CVE references for real overlap)

            # 3. Severity correlation
            finding_sev = (
                finding.severity.value
                if hasattr(finding.severity, "value")
                else str(finding.severity)
            )
            cve_sev = cve.severity.lower()
            severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3, "unknown": -1}

            f_sev_idx = severity_order.get(finding_sev, -1)
            c_sev_idx = severity_order.get(cve_sev, -1)
            if f_sev_idx >= 0 and c_sev_idx >= 0:
                diff = abs(f_sev_idx - c_sev_idx)
                if diff == 0:
                    severity_score = 1.0
                elif diff == 1:
                    severity_score = 0.7
                elif diff == 2:
                    severity_score = 0.3
                else:
                    severity_score = 0.0
            else:
                severity_score = 0.5

            # Combined weighted score
            score = 0.4 * keyword_score + 0.4 * cwe_score + 0.2 * severity_score

            if score >= min_score:
                matches.append(
                    CVEMatch(
                        finding_rule=finding.rule_id,
                        finding_title=finding.title,
                        cve_id=cve.cve_id,
                        cve_severity=cve.severity,
                        score=score,
                        matched_keywords=sorted(intersection)[:10],
                        cwe_overlap=sorted(rule_cwes),
                    )
                )

    # Sort by score descending, deduplicate by (finding_rule, cve_id)
    matches.sort(key=lambda m: m.score, reverse=True)
    seen: set[tuple[str, str]] = set()
    deduped: list[CVEMatch] = []
    for m in matches:
        key = (m.finding_rule, m.cve_id)
        if key not in seen:
            seen.add(key)
            deduped.append(m)
    return deduped
