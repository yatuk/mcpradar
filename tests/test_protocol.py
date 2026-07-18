"""Protocol-profile and migration-readiness tests."""

from mcpradar.scanner.protocol import assess_migration_readiness, is_v2_profile


def test_v2_profile_detection_accepts_rc_suffix() -> None:
    assert is_v2_profile("2026-07-28")
    assert is_v2_profile("2026-07-28-rc1")
    assert not is_v2_profile("2025-11-25")


def test_v1_session_is_readiness_issue_not_vulnerability() -> None:
    issues = assess_migration_readiness("2025-11-25", uses_session_id=True)
    assert [issue.code for issue in issues] == ["MCP2026_SESSION_STATE"]


def test_stateless_or_sessionless_profiles_are_ready() -> None:
    assert assess_migration_readiness("2026-07-28", uses_session_id=False) == []
    assert assess_migration_readiness("2025-11-25", uses_session_id=False) == []
