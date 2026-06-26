"""Unit tests for cvefeed/osv.py — OSV.dev API client."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from mcpradar.cvefeed.osv import (
    OSVClient,
    OSVVulnerability,
    enrich_scan_with_osv,
)

# ---------------------------------------------------------------------------
# Mock responses
# ---------------------------------------------------------------------------


def _mock_vuln_response() -> dict:
    """A realistic OSV query response with one vulnerability."""
    return {
        "vulns": [
            {
                "id": "GHSA-hc55-p739-j48w",
                "summary": "Path traversal in MCP filesystem server",
                "details": "The filesystem server does not properly validate paths...",
                "aliases": ["CVE-2025-53110"],
                "severity": [
                    {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                    {"type": "CVSS_V3", "score": 9.8},
                ],
                "database_specific": {"cwe_ids": ["CWE-22"]},
                "affected": [
                    {
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [
                                    {"introduced": "0.1.0"},
                                    {"fixed": "2025.7.1"},
                                ],
                            }
                        ],
                        "versions": ["2025.6.5"],
                    }
                ],
                "references": [
                    {
                        "url": "https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-hc55-p739-j48w"
                    }
                ],
            }
        ]
    }


def _mock_empty_response() -> dict:
    return {"vulns": []}


def _mock_batch_response() -> dict:
    return {
        "results": [
            {
                "vulns": [
                    {
                        "id": "GHSA-hc55-p739-j48w",
                        "summary": "Path traversal",
                        "details": "...",
                        "aliases": ["CVE-2025-53110"],
                        "severity": [{"type": "CVSS_V3", "score": 9.8}],
                        "database_specific": {"cwe_ids": ["CWE-22"]},
                        "affected": [
                            {"ranges": [{"type": "SEMVER", "events": [{"fixed": "2025.7.1"}]}]}
                        ],
                        "references": [],
                    }
                ]
            },
            {"vulns": []},
        ]
    }


# ---------------------------------------------------------------------------
# OSVClient.query_package
# ---------------------------------------------------------------------------


class TestQueryPackage:
    def test_returns_parsed_vulnerability(self) -> None:
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = _mock_vuln_response()

        with patch("httpx.post", return_value=mock_response) as mock_post:
            client = OSVClient()
            vulns = client.query_package(
                "npm", "@modelcontextprotocol/server-filesystem", "2025.6.5"
            )

        assert len(vulns) == 1
        v = vulns[0]
        assert isinstance(v, OSVVulnerability)
        assert v.id == "GHSA-hc55-p739-j48w"
        assert v.summary == "Path traversal in MCP filesystem server"
        assert v.aliases == ["CVE-2025-53110"]
        assert v.cwe_ids == ["CWE-22"]
        assert v.fixed_version == "2025.7.1"
        assert v.severity_score == 9.8
        assert "CVSS:3" in v.severity_vector
        assert "2025.6.5" in v.affected_versions

        # Verify request body
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        body = call_args[1]["json"]
        assert body["package"]["name"] == "@modelcontextprotocol/server-filesystem"
        assert body["package"]["ecosystem"] == "npm"
        assert body["version"] == "2025.6.5"

    def test_no_vulns_returns_empty_list(self) -> None:
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = _mock_empty_response()

        with patch("httpx.post", return_value=mock_response):
            client = OSVClient()
            vulns = client.query_package("npm", "safe-package", "1.0.0")

        assert len(vulns) == 0

    def test_http_error_returns_empty_list(self) -> None:
        with patch("httpx.post", side_effect=Exception("Connection refused")):
            client = OSVClient()
            vulns = client.query_package("npm", "any", "1.0.0")

        assert len(vulns) == 0

    def test_version_optional(self) -> None:
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = _mock_empty_response()

        with patch("httpx.post", return_value=mock_response) as mock_post:
            client = OSVClient()
            client.query_package("PyPI", "requests")

        body = mock_post.call_args[1]["json"]
        assert "version" not in body

    def test_cwe_ids_as_string_converted_to_list(self) -> None:
        data = _mock_vuln_response()
        data["vulns"][0]["database_specific"]["cwe_ids"] = "CWE-22"

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = data

        with patch("httpx.post", return_value=mock_response):
            client = OSVClient()
            vulns = client.query_package("npm", "test", "1.0")

        assert isinstance(vulns[0].cwe_ids, list)
        assert vulns[0].cwe_ids == ["CWE-22"]


# ---------------------------------------------------------------------------
# OSVClient.query_batch
# ---------------------------------------------------------------------------


class TestQueryBatch:
    def test_batch_query_returns_mapped_results(self) -> None:
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = _mock_batch_response()

        with patch("httpx.post", return_value=mock_response):
            client = OSVClient()
            results = client.query_batch(
                [
                    ("npm", "pkg-a", "1.0"),
                    ("npm", "pkg-b", "2.0"),
                ]
            )

        assert len(results) == 2
        assert len(results["pkg-a"]) == 1
        assert results["pkg-a"][0].id == "GHSA-hc55-p739-j48w"
        assert len(results["pkg-b"]) == 0

    def test_batch_error_returns_empty_dict(self) -> None:
        with patch("httpx.post", side_effect=Exception("Timeout")):
            client = OSVClient()
            results = client.query_batch([("npm", "test", "1.0")])

        assert results == {}


# ---------------------------------------------------------------------------
# OSVVulnerability dataclass
# ---------------------------------------------------------------------------


class TestOSVVulnerability:
    def test_fields_all_populated(self) -> None:
        v = OSVVulnerability(
            id="GHSA-1234",
            summary="Test vuln",
            details="Test details",
            aliases=["CVE-2025-9999"],
            severity_score=7.5,
            severity_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe_ids=["CWE-22"],
            fixed_version="2.0.0",
            affected_versions=["1.0.0", "1.5.0"],
            references=["https://example.com/advisory"],
        )
        assert v.id == "GHSA-1234"
        assert v.severity_score == 7.5
        assert v.fixed_version == "2.0.0"

    def test_optional_fields_can_be_none(self) -> None:
        v = OSVVulnerability(
            id="GHSA-1234",
            summary="",
            details="",
            aliases=[],
            severity_score=None,
            severity_vector="",
            cwe_ids=[],
            fixed_version=None,
            affected_versions=[],
            references=[],
        )
        assert v.severity_score is None
        assert v.fixed_version is None


# ---------------------------------------------------------------------------
# enrich_scan_with_osv
# ---------------------------------------------------------------------------


class TestEnrichScanWithOsv:
    def test_returns_cve_matches(self) -> None:
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = _mock_vuln_response()

        with patch("httpx.post", return_value=mock_response):
            matches = enrich_scan_with_osv(
                findings=[],
                package_ecosystem="npm",
                package_name="@modelcontextprotocol/server-filesystem",
                package_version="2025.6.5",
            )

        assert len(matches) == 1
        assert matches[0]["id"] == "GHSA-hc55-p739-j48w"
        assert matches[0]["aliases"] == ["CVE-2025-53110"]
        assert matches[0]["severity_score"] == 9.8
        assert matches[0]["cwe_ids"] == ["CWE-22"]
        assert matches[0]["fixed_version"] == "2025.7.1"

    def test_no_vulns_returns_empty_list(self) -> None:
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = _mock_empty_response()

        with patch("httpx.post", return_value=mock_response):
            matches = enrich_scan_with_osv([], "npm", "safe", "1.0")

        assert matches == []
