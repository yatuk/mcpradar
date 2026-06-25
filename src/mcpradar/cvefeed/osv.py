"""OSV.dev vulnerability database client — package-level CVE lookup.

OSV aggregates from GitHub Advisory DB, PyPA, RustSec, Go, OSS-Fuzz, etc.
No API key required. https://osv.dev/docs/
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


@dataclass
class OSVVulnerability:
    """A parsed vulnerability entry from OSV."""

    id: str
    summary: str
    details: str
    aliases: list[str]  # CVE IDs
    severity_score: float | None  # CVSS score
    severity_vector: str  # CVSS vector string
    cwe_ids: list[str]
    fixed_version: str | None
    affected_versions: list[str]
    references: list[str]


class OSVClient:
    """Client for the OSV.dev vulnerability database API."""

    BASE_URL = "https://api.osv.dev/v1"

    def __init__(self, cache_ttl: int = 86400) -> None:
        self._cache_ttl = cache_ttl

    def query_package(
        self, ecosystem: str, name: str, version: str | None = None
    ) -> list[OSVVulnerability]:
        """Query OSV for vulnerabilities affecting a package.

        Args:
            ecosystem: Package ecosystem (e.g. "npm", "PyPI").
            name: Package name (e.g. "@modelcontextprotocol/server-filesystem").
            version: Specific version to check, or None for all known vulns.

        Returns:
            List of parsed vulnerability entries.
        """
        body: dict[str, Any] = {
            "package": {"name": name, "ecosystem": ecosystem},
        }
        if version:
            body["version"] = version

        try:
            response = httpx.post(
                f"{self.BASE_URL}/query",
                json=body,
                timeout=30.0,
            )
            response.raise_for_status()
            data = response.json()
        except Exception:
            return []

        return [self._parse_vuln(v) for v in data.get("vulns", [])]

    def query_batch(
        self, queries: list[tuple[str, str, str | None]]
    ) -> dict[str, list[OSVVulnerability]]:
        """Batch query multiple packages.

        Args:
            queries: List of (ecosystem, name, version) tuples.

        Returns:
            Dict mapping package name to list of vulnerabilities.
        """
        body: dict[str, Any] = {
            "queries": [
                {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
                for ecosystem, name, version in queries
            ]
        }
        try:
            response = httpx.post(
                f"{self.BASE_URL}/querybatch",
                json=body,
                timeout=60.0,
            )
            response.raise_for_status()
            data = response.json()
        except Exception:
            return {}

        results: dict[str, list[OSVVulnerability]] = {}
        for i, result in enumerate(data.get("results", [])):
            if i < len(queries):
                name = queries[i][1]
                results[name] = [self._parse_vuln(v) for v in result.get("vulns", [])]
        return results

    def _parse_vuln(self, raw: dict[str, Any]) -> OSVVulnerability:
        """Parse a raw OSV vulnerability dict."""
        # Extract CVSS score
        severity_score = None
        severity_vector = ""
        for sev in raw.get("severity", []):
            if sev.get("type") == "CVSS_V3":
                score_str = sev.get("score", "")
                if isinstance(score_str, str) and "CVSS:3" in score_str:
                    severity_vector = score_str
                # Try numeric score (may be separate or same entry)
                numeric = sev.get("score")
                if isinstance(numeric, (int, float)):
                    severity_score = float(numeric)

        # Extract CWE IDs
        db_specific = raw.get("database_specific", {})
        cwe_ids = db_specific.get("cwe_ids", [])
        if isinstance(cwe_ids, str):
            cwe_ids = [cwe_ids]

        # Extract fixed version from first SEMVER range
        fixed_version = None
        affected_versions: list[str] = []
        for affected in raw.get("affected", []):
            for rng in affected.get("ranges", []):
                if rng.get("type") == "SEMVER":
                    for event in rng.get("events", []):
                        if "fixed" in event:
                            fixed_version = event["fixed"]
                        if "introduced" in event:
                            affected_versions.append(event["introduced"])
            # Also collect explicit versions
            for ver in affected.get("versions", []):
                affected_versions.append(ver)

        return OSVVulnerability(
            id=raw.get("id", ""),
            summary=raw.get("summary", ""),
            details=raw.get("details", ""),
            aliases=raw.get("aliases", []),
            severity_score=severity_score,
            severity_vector=severity_vector,
            cwe_ids=list(cwe_ids),
            fixed_version=fixed_version,
            affected_versions=affected_versions,
            references=[ref.get("url", "") for ref in raw.get("references", [])],
        )


def enrich_scan_with_osv(
    findings: list[Any],
    package_ecosystem: str,
    package_name: str,
    package_version: str,
) -> list[dict[str, Any]]:
    """Enrich scan findings with OSV vulnerability data.

    Queries OSV for the given package+version and returns a list of
    CVE match dicts that can be merged into leaderboard/server.json output.

    Args:
        findings: List of Finding objects from a scan.
        package_ecosystem: "npm", "PyPI", etc.
        package_name: Package identifier.
        package_version: Version string.

    Returns:
        List of dicts with cve_id, severity, cwe_ids, summary, fixed_version.
    """
    client = OSVClient()
    vulns = client.query_package(package_ecosystem, package_name, package_version)

    matches: list[dict[str, Any]] = []
    for v in vulns:
        matches.append(
            {
                "id": v.id,
                "aliases": v.aliases,
                "summary": v.summary,
                "severity_score": v.severity_score,
                "severity_vector": v.severity_vector,
                "cwe_ids": v.cwe_ids,
                "fixed_version": v.fixed_version,
                "affected_versions": v.affected_versions[:5],
                "references": v.references[:5],
            }
        )

    return matches
