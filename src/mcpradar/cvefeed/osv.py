"""OSV.dev vulnerability database client — package-level CVE lookup.

OSV aggregates from GitHub Advisory DB, PyPA, RustSec, Go, OSS-Fuzz, etc.
No API key required. https://osv.dev/docs/
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


def _cvss_base_score(vector: str) -> float | None:
    """Compute the CVSS v3.x base score from a vector string.

    Returns None if the vector is not a parseable CVSS:3.x vector.
    """
    if "CVSS:3" not in vector:
        return None
    metrics = {}
    for part in vector.split("/"):
        if ":" in part:
            k, _, v = part.partition(":")
            metrics[k] = v
    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
        ac = {"L": 0.77, "H": 0.44}[metrics["AC"]]
        ui = {"N": 0.85, "R": 0.62}[metrics["UI"]]
        scope_changed = metrics["S"] == "C"
        pr_map = (
            {"N": 0.85, "L": 0.68, "H": 0.50}
            if scope_changed
            else {"N": 0.85, "L": 0.62, "H": 0.27}
        )
        pr = pr_map[metrics["PR"]]
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        c, i, a = cia[metrics["C"]], cia[metrics["I"]], cia[metrics["A"]]
    except KeyError:
        return None

    isc_base = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = (1.08 * (impact + exploitability)) if scope_changed else (impact + exploitability)
    import math

    return min(math.ceil(raw * 10) / 10, 10.0)


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
        self._detail_cache: dict[str, OSVVulnerability | None] = {}

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

    def get_vuln(self, vuln_id: str) -> OSVVulnerability | None:
        """Fetch a single vulnerability's full record by OSV/GHSA id.

        The ``/querybatch`` endpoint returns only ids; severity, summary, and
        fix data must be hydrated from ``/vulns/{id}``.
        """
        if vuln_id in self._detail_cache:
            return self._detail_cache[vuln_id]
        try:
            response = httpx.get(f"{self.BASE_URL}/vulns/{vuln_id}", timeout=30.0)
            response.raise_for_status()
            parsed = self._parse_vuln(response.json())
        except Exception:
            parsed = None
        self._detail_cache[vuln_id] = parsed
        return parsed

    def _parse_vuln(self, raw: dict[str, Any]) -> OSVVulnerability:
        """Parse a raw OSV vulnerability dict."""
        # Extract CVSS score
        severity_score = None
        severity_vector = ""
        for sev in raw.get("severity", []):
            if sev.get("type", "").startswith("CVSS"):
                score_str = sev.get("score", "")
                if isinstance(score_str, str) and "CVSS:" in score_str:
                    severity_vector = score_str
                    severity_score = _cvss_base_score(score_str)
                elif isinstance(score_str, (int, float)):
                    severity_score = float(score_str)

        db_specific = raw.get("database_specific", {})
        # OSV rarely carries a numeric score; the GitHub Advisory label
        # (CRITICAL/HIGH/MODERATE/LOW) is the reliable fallback.
        if severity_score is None:
            label = str(db_specific.get("severity", "")).upper()
            severity_score = {
                "CRITICAL": 9.5,
                "HIGH": 7.5,
                "MODERATE": 5.0,
                "MEDIUM": 5.0,
                "LOW": 2.0,
            }.get(label)

        # Extract CWE IDs
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
