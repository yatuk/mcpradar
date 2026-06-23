"""Fingerprint ve transport check testleri."""

from __future__ import annotations

from unittest.mock import patch

from mcpradar.fingerprint.fingerprinter import Fingerprinter, _tls_version_order
from mcpradar.fingerprint.models import ServerFingerprint, TLSInfo
from mcpradar.fingerprint.transport_check import TransportChecker
from mcpradar.scanner.report import ScanReport, ToolInfo


class TestTLSVersionOrder:
    def test_tls13_higher_than_tls12(self) -> None:
        assert _tls_version_order("TLSv1.3") > _tls_version_order("TLSv1.2")

    def test_tls12_higher_than_tls11(self) -> None:
        assert _tls_version_order("TLSv1.2") > _tls_version_order("TLSv1.1")

    def test_plain_is_lowest(self) -> None:
        assert _tls_version_order("plain") < _tls_version_order("TLSv1.0")

    def test_unknown_defaults_low(self) -> None:
        assert _tls_version_order("Unknown") == -1


class TestServerFingerprint:
    def test_create_from_report(self) -> None:
        report = ScanReport(
            target="http://test.local",
            transport="http",
            server_version="1.0.0",
            protocol_version="2025-03-26",
        )
        report.tools.append(ToolInfo(name="get_weather", description="Weather"))
        report.tools.append(ToolInfo(name="search", description="Search"))

        tls = TLSInfo(
            version="TLSv1.3",
            cert_issuer="Test CA",
            cert_subject="test.local",
            cert_expiry="2027-01-01T00:00:00",
            cert_valid=True,
            self_signed=False,
        )
        fp = Fingerprinter.create(report, tls)

        assert fp.tool_count == 2
        assert fp.server_version == "1.0.0"
        assert fp.protocol_version == "2025-03-26"
        assert len(fp.server_id) == 16
        assert len(fp.tool_names_hash) == 64  # SHA256 hex
        assert fp.tls_info is not None
        assert fp.tls_info.version == "TLSv1.3"

    def test_tool_names_hash_deterministic(self) -> None:
        report1 = ScanReport(target="http://x", transport="http")
        report1.tools.append(ToolInfo(name="b_tool", description="B"))
        report1.tools.append(ToolInfo(name="a_tool", description="A"))

        report2 = ScanReport(target="http://x", transport="http")
        report2.tools.append(ToolInfo(name="a_tool", description="A"))
        report2.tools.append(ToolInfo(name="b_tool", description="B"))

        fp1 = Fingerprinter.create(report1)
        fp2 = Fingerprinter.create(report2)
        # Sorted names should produce same hash regardless of insertion order
        assert fp1.tool_names_hash == fp2.tool_names_hash

    def test_server_id_changes_with_different_tools(self) -> None:
        report1 = ScanReport(target="http://x", transport="http")
        report1.tools.append(ToolInfo(name="search", description="Search"))
        report2 = ScanReport(target="http://x", transport="http")
        report2.tools.append(ToolInfo(name="eval", description="Eval"))

        fp1 = Fingerprinter.create(report1)
        fp2 = Fingerprinter.create(report2)
        assert fp1.server_id != fp2.server_id

    def test_no_tls_for_stdio(self) -> None:
        report = ScanReport(target="npx my-server", transport="stdio")
        fp = Fingerprinter.create(report, None)
        assert fp.tls_info is None


class TestFingerprinterCompare:
    def test_first_scan_no_baseline(self) -> None:
        current = _make_fp(version="1.0.0")
        diff = Fingerprinter.compare(None, current)
        assert diff.is_first_scan

    def test_same_fingerprint_no_changes(self) -> None:
        baseline = _make_fp(version="1.0.0")
        current = _make_fp(version="1.0.0")
        diff = Fingerprinter.compare(baseline, current)
        assert diff.version_change is None
        assert not diff.tool_names_changed
        assert not diff.protocol_changed

    def test_rollback_detected(self) -> None:
        baseline = _make_fp(version="2.0.0")
        current = _make_fp(version="1.0.0")
        diff = Fingerprinter.compare(baseline, current)
        assert diff.version_change == "rollback"

    def test_major_upgrade_detected(self) -> None:
        baseline = _make_fp(version="1.0.0")
        current = _make_fp(version="2.0.0")
        diff = Fingerprinter.compare(baseline, current)
        assert diff.version_change == "major_upgrade"

    def test_minor_version_change(self) -> None:
        baseline = _make_fp(version="1.0.0")
        current = _make_fp(version="1.1.0")
        diff = Fingerprinter.compare(baseline, current)
        assert diff.version_change == "minor_upgrade"

    def test_tls_downgrade_detected(self) -> None:
        tls_old = TLSInfo("TLSv1.3", "CA", "srv", "", True, False)
        tls_new = TLSInfo("TLSv1.1", "CA", "srv", "", True, False)
        baseline = _make_fp(version="1.0.0", tls=tls_old)
        current = _make_fp(version="1.0.0", tls=tls_new)
        diff = Fingerprinter.compare(baseline, current)
        assert diff.tls_downgrade


class TestTransportChecker:
    def test_stdio_returns_none(self) -> None:
        checker = TransportChecker()
        result = checker.check("npx my-server", "stdio")
        assert result is None

    def test_plain_http_detected(self) -> None:
        checker = TransportChecker()
        result = checker.check("http://example.com", "http")
        assert result is not None
        assert result.version == "plain"

    def test_no_findings_for_stdio(self) -> None:
        checker = TransportChecker()
        findings = checker.generate_findings("npx x", "stdio", None)
        assert len(findings) == 0

    def test_findings_for_plain_http(self) -> None:
        checker = TransportChecker()
        tls_info = TLSInfo(
            version="plain",
            cert_issuer="",
            cert_subject="",
            cert_expiry="",
            cert_valid=False,
            self_signed=False,
        )
        findings = checker.generate_findings("http://example.com", "http", tls_info)
        assert len(findings) >= 1
        assert any("Plain HTTP" in f.description for f in findings)

    def test_findings_for_old_tls(self) -> None:
        checker = TransportChecker()
        tls_info = TLSInfo(
            version="TLSv1.0",
            cert_issuer="CA",
            cert_subject="srv",
            cert_expiry="2027-01-01T00:00:00",
            cert_valid=True,
            self_signed=False,
        )
        findings = checker.generate_findings("https://example.com", "http", tls_info)
        assert len(findings) >= 1
        assert any("TLS" in f.title for f in findings)
        assert any(f.severity.value == "critical" for f in findings)

    def test_findings_for_expired_cert(self) -> None:
        checker = TransportChecker()
        tls_info = TLSInfo(
            version="TLSv1.3",
            cert_issuer="CA",
            cert_subject="srv",
            cert_expiry="2020-01-01T00:00:00",
            cert_valid=False,
            self_signed=False,
        )
        findings = checker.generate_findings("https://example.com", "http", tls_info)
        assert any("suresi dolmus" in f.description for f in findings)

    def test_findings_for_self_signed(self) -> None:
        checker = TransportChecker()
        tls_info = TLSInfo(
            version="TLSv1.3",
            cert_issuer="My CA",
            cert_subject="My CA",
            cert_expiry="2027-01-01T00:00:00",
            cert_valid=True,
            self_signed=True,
        )
        findings = checker.generate_findings("https://example.com", "http", tls_info)
        assert any("Self-signed" in f.title for f in findings)

    def test_clean_tls_no_findings(self) -> None:
        checker = TransportChecker()
        tls_info = TLSInfo(
            version="TLSv1.3",
            cert_issuer="Trusted CA",
            cert_subject="example.com",
            cert_expiry="2027-06-01T00:00:00",
            cert_valid=True,
            self_signed=False,
        )
        # Mock HSTS check to return True
        # Mock HEAD request to return Mcp-Method/Mcp-Name headers (2026-07-28 spec)
        from unittest.mock import MagicMock

        mock_head = MagicMock()
        mock_head.headers = {"mcp-method": "tools/list", "mcp-name": "search"}
        with (
            patch.object(checker, "check_hsts", return_value=True),
            patch("httpx.head", return_value=mock_head),
        ):
            findings = checker.generate_findings("https://example.com", "http", tls_info)
        assert len(findings) == 0


def _make_fp(
    version: str = "1.0.0",
    endpoint: str = "http://test.local",
    transport: str = "http",
    tls: TLSInfo | None = None,
) -> ServerFingerprint:
    """Helper to create a test fingerprint quickly."""
    import hashlib

    return ServerFingerprint(
        server_id=hashlib.sha256(endpoint.encode()).hexdigest()[:16],
        endpoint=endpoint,
        transport=transport,
        server_version=version,
        protocol_version="2025-03-26",
        capabilities={},
        tool_names_hash=hashlib.sha256(b"search,get_weather").hexdigest(),
        tool_count=2,
        first_seen="2026-01-01T00:00:00",
        last_seen="2026-06-01T00:00:00",
        tls_info=tls,
    )
