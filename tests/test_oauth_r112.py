"""R112 OAuth hardening: metadata probe + finding generation."""

from __future__ import annotations

import httpx
import pytest

from mcpradar.probe.oauth import OAuthMetadata, probe_oauth_metadata
from mcpradar.scanner.rules import check_server_auth


def _mock_httpx(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    """Route every httpx.Client built by the prober through a MockTransport."""
    real_client = httpx.Client

    def factory(**kwargs: object) -> httpx.Client:
        kwargs.pop("transport", None)
        return real_client(transport=httpx.MockTransport(handler), **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(httpx, "Client", factory)


# ---------------------------------------------------------------------------
# check_server_auth — pure finding logic (no network)
# ---------------------------------------------------------------------------


class TestCheckServerAuth:
    def test_missing_pkce_is_high(self) -> None:
        findings = check_server_auth("https://x/mcp", "http", has_pkce_s256=False)
        assert [f.rule_id for f in findings] == ["R112"]
        assert findings[0].severity.value == "high"
        assert "PKCE" in findings[0].title

    def test_missing_iss_flagged(self) -> None:
        findings = check_server_auth("https://x/mcp", "http", has_iss=False)
        assert any("iss" in f.title.lower() for f in findings)

    def test_session_id_flagged(self) -> None:
        findings = check_server_auth("https://x/mcp", "http", uses_session_id=True)
        assert any("session" in f.title.lower() for f in findings)

    def test_none_means_not_checked_no_findings(self) -> None:
        # A non-OAuth server: nothing observed, nothing flagged.
        assert check_server_auth("https://x/mcp", "http") == []

    def test_healthy_oauth_no_findings(self) -> None:
        findings = check_server_auth("https://x/mcp", "http", has_iss=True, has_pkce_s256=True)
        assert findings == []


# ---------------------------------------------------------------------------
# probe_oauth_metadata — discovery
# ---------------------------------------------------------------------------


class TestProbeOAuthMetadata:
    def test_non_http_target_returns_none(self) -> None:
        assert probe_oauth_metadata("stdio://foo") is None

    def test_no_oauth_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _mock_httpx(monkeypatch, lambda req: httpx.Response(404))
        assert probe_oauth_metadata("https://host/mcp") is None

    def test_full_discovery_healthy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            if req.url.path.endswith("oauth-protected-resource"):
                return httpx.Response(
                    200, json={"authorization_servers": ["https://as.example.com"]}
                )
            if req.url.path.endswith("oauth-authorization-server"):
                return httpx.Response(
                    200,
                    json={
                        "authorization_response_iss_parameter_supported": True,
                        "code_challenge_methods_supported": ["S256"],
                        "registration_endpoint": "https://as.example.com/register",
                    },
                )
            return httpx.Response(404)

        _mock_httpx(monkeypatch, handler)
        meta = probe_oauth_metadata("https://host/mcp")
        assert isinstance(meta, OAuthMetadata)
        assert meta.uses_oauth
        assert meta.has_iss is True
        assert meta.has_pkce_s256 is True
        assert meta.supports_dcr is True

    def test_discovery_missing_pkce_and_iss(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            if req.url.path.endswith("oauth-protected-resource"):
                return httpx.Response(
                    200, json={"authorization_servers": ["https://as.example.com"]}
                )
            if req.url.path.endswith("oauth-authorization-server"):
                return httpx.Response(200, json={"code_challenge_methods_supported": ["plain"]})
            return httpx.Response(404)

        _mock_httpx(monkeypatch, handler)
        meta = probe_oauth_metadata("https://host/mcp")
        assert meta is not None
        assert meta.has_iss is False
        assert meta.has_pkce_s256 is False

        findings = check_server_auth(
            "https://host/mcp",
            "http",
            has_iss=meta.has_iss,
            has_pkce_s256=meta.has_pkce_s256,
        )
        rule_titles = [f.title for f in findings]
        assert any("PKCE" in t for t in rule_titles)
        assert any("iss" in t.lower() for t in rule_titles)

    def test_401_challenge_marks_oauth_unknown(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            if "well-known" in req.url.path:
                return httpx.Response(404)
            return httpx.Response(401, headers={"WWW-Authenticate": 'Bearer realm="mcp"'})

        _mock_httpx(monkeypatch, handler)
        meta = probe_oauth_metadata("https://host/mcp")
        assert meta is not None
        assert meta.uses_oauth
        # No AS reachable → hardening signals stay "unknown", not "absent".
        assert meta.has_iss is None
        assert meta.has_pkce_s256 is None
