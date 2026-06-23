"""Fingerprint data models."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TLSInfo:
    """TLS/transport security information for an MCP endpoint."""

    version: str  # "TLSv1.3", "N/A" (stdio), "plain" (HTTP)
    cert_issuer: str  # certificate issuer organizationName or CN
    cert_subject: str  # certificate subject organizationName or CN
    cert_expiry: str  # ISO datetime string
    cert_valid: bool  # True if not expired
    self_signed: bool  # True if issuer == subject


@dataclass
class ServerFingerprint:
    """Cryptographic identity fingerprint for an MCP server."""

    server_id: str  # SHA256(endpoint|transport|tool_names_hash)[:16]
    endpoint: str
    transport: str
    server_version: str  # from initialize() serverVersion
    protocol_version: str  # from initialize() protocolVersion
    capabilities: dict[str, object]  # from initialize() capabilities
    tool_names_hash: str  # SHA256(sorted tool names joined by comma)
    tool_count: int
    first_seen: str  # ISO timestamp
    last_seen: str  # ISO timestamp
    tls_info: TLSInfo | None = None  # None for stdio transport


@dataclass
class FingerprintDiff:
    """Result of comparing two ServerFingerprint objects."""

    tool_names_changed: bool = False
    tools_added: list[str] = field(default_factory=list)
    tools_removed: list[str] = field(default_factory=list)
    version_change: str | None = None  # "rollback", "major_upgrade", "minor_upgrade", None
    previous_version: str = ""
    current_version: str = ""
    protocol_changed: bool = False
    capabilities_changed: bool = False
    tls_changed: bool = False
    tls_downgrade: bool = False
    endpoint_changed: bool = False
    is_first_scan: bool = False  # True when baseline is None
