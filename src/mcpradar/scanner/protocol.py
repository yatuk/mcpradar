"""MCP protocol profiles and forward-compatibility readiness checks."""

from __future__ import annotations

from dataclasses import dataclass, field

MCP_V2_PROFILE = "2026-07-28"


@dataclass(frozen=True)
class ReadinessIssue:
    code: str
    title: str
    description: str
    target_profile: str = MCP_V2_PROFILE
    detail: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "title": self.title,
            "description": self.description,
            "target_profile": self.target_profile,
            "detail": self.detail,
        }


def is_v2_profile(protocol_version: str) -> bool:
    """Whether a negotiated protocol uses the stateless 2026 profile."""
    return protocol_version.startswith(MCP_V2_PROFILE)


def assess_migration_readiness(
    protocol_version: str, *, uses_session_id: bool
) -> list[ReadinessIssue]:
    """Return migration observations, kept separate from vulnerabilities."""
    if not uses_session_id or is_v2_profile(protocol_version):
        return []
    return [
        ReadinessIssue(
            code="MCP2026_SESSION_STATE",
            title="Session-based transport requires MCP 2026 migration",
            description=(
                "The negotiated MCP profile still uses Mcp-Session-Id. This is valid "
                "for current v1 profiles, but the 2026-07-28 stateless profile removes "
                "protocol-level sessions."
            ),
            detail={"negotiated_profile": protocol_version or "unknown"},
        )
    ]
