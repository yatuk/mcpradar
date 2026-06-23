"""Fingerprinter — creates and compares MCP server fingerprints."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from mcpradar.fingerprint.models import FingerprintDiff, ServerFingerprint, TLSInfo
from mcpradar.scanner.report import ScanReport


class Fingerprinter:
    """Creates and compares server fingerprints for identity tracking."""

    @staticmethod
    def create(report: ScanReport, tls_info: TLSInfo | None = None) -> ServerFingerprint:
        """Create a ServerFingerprint from a ScanReport."""
        sorted_names = ",".join(sorted(t.name for t in report.tools))
        tool_names_hash = hashlib.sha256(sorted_names.encode()).hexdigest()
        server_id = hashlib.sha256(
            f"{report.target}|{report.transport}|{tool_names_hash}".encode()
        ).hexdigest()[:16]

        now = datetime.now(UTC).isoformat()

        return ServerFingerprint(
            server_id=server_id,
            endpoint=report.target,
            transport=report.transport,
            server_version=report.server_version,
            protocol_version=report.protocol_version,
            capabilities=report.capabilities,
            tool_names_hash=tool_names_hash,
            tool_count=len(report.tools),
            first_seen=now,
            last_seen=now,
            tls_info=tls_info,
        )

    @staticmethod
    def compare(baseline: ServerFingerprint | None, current: ServerFingerprint) -> FingerprintDiff:
        """Compare two fingerprints. baseline=None means first scan."""
        diff = FingerprintDiff()

        if baseline is None:
            diff.is_first_scan = True
            return diff

        diff.previous_version = baseline.server_version
        diff.current_version = current.server_version

        # Tool names changed
        diff.tool_names_changed = baseline.tool_names_hash != current.tool_names_hash

        # Version change analysis
        if baseline.server_version != current.server_version:
            diff.version_change = Fingerprinter._classify_version_change(
                baseline.server_version, current.server_version
            )

        # Protocol changed
        diff.protocol_changed = baseline.protocol_version != current.protocol_version

        # Capabilities changed
        diff.capabilities_changed = baseline.capabilities != current.capabilities

        # Endpoint changed
        diff.endpoint_changed = baseline.endpoint != current.endpoint

        # TLS info changed
        if baseline.tls_info and current.tls_info:
            bt = baseline.tls_info
            ct = current.tls_info
            diff.tls_changed = (
                bt.version != ct.version
                or bt.cert_issuer != ct.cert_issuer
                or bt.self_signed != ct.self_signed
            )
            # Downgrade: TLS version went down
            diff.tls_downgrade = _tls_version_order(ct.version) < _tls_version_order(bt.version)

        return diff

    @staticmethod
    def _classify_version_change(old_ver: str, new_ver: str) -> str:
        """Classify version change as rollback, major_upgrade, or minor_upgrade."""
        try:
            old_parts = [int(x) for x in old_ver.split(".")]
            new_parts = [int(x) for x in new_ver.split(".")]
        except ValueError:
            return "minor_upgrade"

        if new_parts < old_parts:
            return "rollback"
        if len(old_parts) > 0 and len(new_parts) > 0 and new_parts[0] > old_parts[0]:
            return "major_upgrade"
        return "minor_upgrade"


def _tls_version_order(version: str) -> int:
    """Return numeric order for TLS version string (higher = newer)."""
    order = {
        "TLSv1.3": 5,
        "TLSv1.2": 4,
        "TLSv1.1": 3,
        "TLSv1.0": 2,
        "SSLv3": 1,
        "plain": 0,
        "N/A": -1,
    }
    return order.get(version, -1)
