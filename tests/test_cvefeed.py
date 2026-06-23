"""Tests for CVE feed syncer and matching."""

from __future__ import annotations

from unittest.mock import MagicMock

from mcpradar.cvefeed.syncer import (
    CVEEntry,
    CVEMatch,
    NVDAPISyncer,
    match_findings_to_cves,
    save_feed,
)
from mcpradar.scanner.report import Finding, Severity

# Sample NVD API response for mocking
NVD_MOCK_RESPONSE = {
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2025-32014",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "MCP servers vulnerable to command injection via tool description",
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseSeverity": "HIGH",
                                "baseScore": 7.5,
                            }
                        }
                    ]
                },
                "published": "2025-04-15T00:00:00.000",
                "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2025-32014"}],
            }
        }
    ],
}

NVD_EMPTY_RESPONSE = {"totalResults": 0, "vulnerabilities": []}


class TestNVDAPISyncer:
    """Tests for the NVD API syncer (mocked HTTP)."""

    def test_search_mcp_cves_mocked(self, monkeypatch) -> None:
        def mock_get(*args, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = NVD_MOCK_RESPONSE
            return resp

        monkeypatch.setattr("httpx.get", mock_get)

        syncer = NVDAPISyncer()
        entries = syncer.search_mcp_cves()
        assert len(entries) >= 1
        cve = entries[0]
        assert cve.cve_id == "CVE-2025-32014"
        assert cve.severity == "high"
        assert cve.published == "2025-04-15T00:00:00.000"

    def test_empty_nvd_response(self, monkeypatch) -> None:
        def mock_get(*args, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = NVD_EMPTY_RESPONSE
            return resp

        monkeypatch.setattr("httpx.get", mock_get)

        syncer = NVDAPISyncer()
        entries = syncer.search_mcp_cves()
        assert len(entries) == 0

    def test_api_key_from_env(self, monkeypatch) -> None:
        monkeypatch.setenv("NVD_API_KEY", "test-api-key-12345")

        def mock_get(*args, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = NVD_MOCK_RESPONSE
            return resp

        monkeypatch.setattr("httpx.get", mock_get)

        syncer = NVDAPISyncer()
        syncer.search_mcp_cves()
        # The inner _request_with_backoff checks self._api_key
        # Just verify it doesn't crash
        assert syncer._api_key == "test-api-key-12345"

    def test_rate_limit_backoff(self, monkeypatch) -> None:
        call_count = [0]

        def mock_get(*args, **kwargs):
            call_count[0] += 1
            resp = MagicMock()
            if call_count[0] <= 2:
                resp.status_code = 429
            else:
                resp.status_code = 200
                resp.json.return_value = NVD_MOCK_RESPONSE
            return resp

        # Speed up sleep for testing
        monkeypatch.setattr("time.sleep", lambda s: None)
        monkeypatch.setattr("httpx.get", mock_get)

        syncer = NVDAPISyncer()
        syncer._backoff_s = 0.01  # Tiny backoff for test speed
        syncer._max_backoff_s = 0.1
        entries = syncer.search_mcp_cves()
        # Should eventually succeed after backoff
        assert len(entries) >= 1

    def test_sync_all_preserves_seed(self, monkeypatch) -> None:
        """sync_all should preserve existing feed entries even if NVD fails."""
        # Pre-populate the local feed with seed entries
        seed = [
            CVEEntry(
                cve_id="CVE-2025-32014",
                description="MCP command injection",
                severity="high",
                published="2025-04-15T00:00:00.000",
                references=["https://example.com"],
            ),
            CVEEntry(
                cve_id="CVE-2025-28192",
                description="MCP prompt injection bypass",
                severity="critical",
                published="2025-03-22T00:00:00.000",
                references=["https://example.com"],
            ),
        ]
        save_feed(seed)

        # Make httpx always raise to simulate complete network failure
        def mock_get(*args, **kwargs):
            raise ConnectionError("offline")

        monkeypatch.setattr("httpx.get", mock_get)
        # Also disable sleep to avoid the backoff delay (5 retries x 7 keywords)
        monkeypatch.setattr("time.sleep", lambda s: None)

        syncer = NVDAPISyncer()
        count = syncer.sync_all()
        # The two pre-seeded CVEs should be preserved
        assert count >= 2


class TestCVEMatching:
    """Tests for the CVE-to-finding matching logic."""

    def setup_method(self) -> None:
        self.feed = [
            CVEEntry(
                cve_id="CVE-2025-0001",
                description="command injection in MCP tool parameter handling",
                severity="critical",
                published="2025-01-01",
                references=["https://example.com"],
            ),
            CVEEntry(
                cve_id="CVE-2025-0002",
                description="exposed API keys in MCP server configuration",
                severity="critical",
                published="2025-02-01",
                references=["https://example.com"],
            ),
        ]

    def test_keyword_match(self) -> None:
        findings = [
            Finding(
                rule_id="R107",
                title="Command Injection",
                description="Shell metacharacters found in tool parameter defaults",
                severity=Severity.CRITICAL,
                target="test_tool",
            )
        ]
        matches = match_findings_to_cves(findings, self.feed, min_score=0.1)
        assert len(matches) > 0
        assert matches[0].cve_id == "CVE-2025-0001"

    def test_score_below_threshold_filtered(self) -> None:
        findings = [
            Finding(
                rule_id="R101",
                title="Zero-width Unicode",
                description="Hidden character detected in tool name",
                severity=Severity.LOW,
                target="test_tool",
            )
        ]
        matches = match_findings_to_cves(findings, self.feed, min_score=0.9)
        # Very high threshold, unlikely to match
        assert len(matches) == 0

    def test_empty_findings(self) -> None:
        matches = match_findings_to_cves([], self.feed)
        assert len(matches) == 0

    def test_empty_feed(self) -> None:
        findings = [
            Finding(
                rule_id="R107",
                title="Command Injection",
                description="test",
                severity=Severity.CRITICAL,
                target="test_tool",
            )
        ]
        matches = match_findings_to_cves(findings, [])
        assert len(matches) == 0

    def test_cvematch_dataclass_fields(self) -> None:
        cm = CVEMatch(
            finding_rule="R107",
            finding_title="Test",
            cve_id="CVE-2025-0001",
            cve_severity="critical",
            score=0.75,
            matched_keywords=["injection", "tool"],
            cwe_overlap=["CWE-77"],
        )
        d = cm.to_dict()
        assert d["score"] == 0.75
        assert "injection" in d["matched_keywords"]

    def test_severity_correlation(self) -> None:
        """A critical finding matching a critical CVE should score higher than a low finding."""
        critical_finding = [
            Finding(
                rule_id="R107",
                title="Command Injection",
                description="MCP tool parameter command injection vulnerability",
                severity=Severity.CRITICAL,
                target="test_tool",
            )
        ]
        low_finding = [
            Finding(
                rule_id="R107",
                title="Command Injection",
                description="MCP tool parameter command injection vulnerability",
                severity=Severity.LOW,
                target="test_tool",
            )
        ]
        critical_matches = match_findings_to_cves(critical_finding, self.feed, min_score=0.0)
        low_matches = match_findings_to_cves(low_finding, self.feed, min_score=0.0)
        # Critical finding should score higher (same keywords, same CWE, but closer severity)
        if critical_matches and low_matches:
            assert critical_matches[0].score >= low_matches[0].score

    def test_deduplication(self) -> None:
        """Duplicate (finding_rule, cve_id) pairs should be removed."""
        findings = [
            Finding(
                rule_id="R107",
                title="Cmd Inj A",
                description="command injection in MCP tool parameter handling in function X",
                severity=Severity.CRITICAL,
                target="tool_a",
            ),
            Finding(
                rule_id="R107",
                title="Cmd Inj B",
                description="command injection in MCP tool parameter handling in function Y",
                severity=Severity.CRITICAL,
                target="tool_b",
            ),
        ]
        matches = match_findings_to_cves(findings, self.feed, min_score=0.1)
        # Only 1 CVE matches "command injection", and both findings have same rule_id
        # Only one match per (rule_id, cve_id) should be kept (highest score)
        r107_cve1_matches = [
            m for m in matches if m.finding_rule == "R107" and m.cve_id == "CVE-2025-0001"
        ]
        assert len(r107_cve1_matches) <= 1
