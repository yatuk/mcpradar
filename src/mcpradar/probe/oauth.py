"""OAuth 2.1 metadata discovery for MCP authorization hardening (R112).

The R112 rule can only fire if the server's OAuth posture is actually observed.
This module performs the discovery the MCP auth spec defines, read-only:

  1. RFC 9728 — Protected Resource Metadata at
     ``{origin}/.well-known/oauth-protected-resource`` (also tried with the
     resource path suffixed). Yields the ``authorization_servers`` list.
  2. RFC 8414 — Authorization Server Metadata at
     ``{as}/.well-known/oauth-authorization-server`` (falling back to
     ``/.well-known/openid-configuration``). From it we read the two
     hardening signals the spec cares about:
       - ``authorization_response_iss_parameter_supported`` (RFC 9207) — the
         ``iss`` mix-up defence.
       - ``code_challenge_methods_supported`` containing ``S256`` — PKCE.
       - ``registration_endpoint`` — Dynamic Client Registration support.

Everything is best-effort: a server that speaks no OAuth (no protected-resource
metadata, no ``WWW-Authenticate: Bearer``) yields ``None`` so R112 stays silent
rather than flagging a non-OAuth server. All network/parse errors are swallowed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    import httpx

_WELL_KNOWN_PR = "/.well-known/oauth-protected-resource"
_WELL_KNOWN_AS = "/.well-known/oauth-authorization-server"
_WELL_KNOWN_OIDC = "/.well-known/openid-configuration"


@dataclass
class OAuthMetadata:
    """Observed OAuth posture. ``None`` fields mean "could not be determined"."""

    uses_oauth: bool = False
    authorization_servers: list[str] = field(default_factory=list)
    as_metadata_present: bool = False
    # RFC 9207 iss support; None when no AS metadata was reachable.
    has_iss: bool | None = None
    # PKCE S256 offered; None when unknown.
    has_pkce_s256: bool | None = None
    # Dynamic Client Registration endpoint advertised; None when unknown.
    supports_dcr: bool | None = None


def _origin(target: str) -> tuple[str, str] | None:
    """Return (origin, resource_path) for an http(s)/sse target, else None."""
    url = target
    if url.startswith("sse://"):
        url = "http://" + url[len("sse://") :]
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    port = f":{parsed.port}" if parsed.port else ""
    origin = f"{parsed.scheme}://{parsed.hostname}{port}"
    return origin, parsed.path.rstrip("/")


def probe_oauth_metadata(target: str, timeout: float = 5.0) -> OAuthMetadata | None:
    """Discover a server's OAuth metadata. Returns None if it speaks no OAuth."""
    parts = _origin(target)
    if parts is None:
        return None
    origin, resource_path = parts

    try:
        import httpx
    except Exception:  # pragma: no cover - httpx is a hard dependency
        return None

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        pr = _fetch_protected_resource(client, origin, resource_path, target)
        if pr is None:
            return None  # no OAuth in play — leave R112 silent

        meta = OAuthMetadata(uses_oauth=True)
        servers = pr.get("authorization_servers")
        if isinstance(servers, list):
            meta.authorization_servers = [s for s in servers if isinstance(s, str)]

        as_url = meta.authorization_servers[0] if meta.authorization_servers else None
        if as_url:
            as_meta = _fetch_as_metadata(client, as_url)
            if as_meta is not None:
                meta.as_metadata_present = True
                iss = as_meta.get("authorization_response_iss_parameter_supported")
                meta.has_iss = bool(iss) if isinstance(iss, bool) else False
                methods = as_meta.get("code_challenge_methods_supported")
                if isinstance(methods, list):
                    meta.has_pkce_s256 = "S256" in methods
                else:
                    meta.has_pkce_s256 = False
                meta.supports_dcr = bool(as_meta.get("registration_endpoint"))
        return meta


def _fetch_protected_resource(
    client: httpx.Client, origin: str, resource_path: str, target: str
) -> dict[str, object] | None:
    """Try RFC 9728 discovery: well-known paths, then a 401 challenge hint."""
    candidates = [origin + _WELL_KNOWN_PR]
    if resource_path:
        # RFC 9728 §3.1: the resource path is appended to the well-known path.
        candidates.append(origin + _WELL_KNOWN_PR + resource_path)

    for url in candidates:
        doc = _get_json(client, url)
        if doc is not None:
            return doc

    # No metadata document — probe the resource itself. An OAuth-protected MCP
    # server answers an unauthenticated request with 401 + WWW-Authenticate.
    try:
        resp = client.get(target)
    except Exception:
        return None
    if resp.status_code == 401 and "www-authenticate" in resp.headers:
        challenge = resp.headers["www-authenticate"]
        if "bearer" in challenge.lower():
            # OAuth is required but metadata isn't discoverable — record the
            # fact so has_iss/PKCE come back as "unknown", not "absent".
            return {"authorization_servers": []}
    return None


def _fetch_as_metadata(client: httpx.Client, as_url: str) -> dict[str, object] | None:
    base = as_url.rstrip("/")
    for suffix in (_WELL_KNOWN_AS, _WELL_KNOWN_OIDC):
        doc = _get_json(client, base + suffix)
        if doc is not None:
            return doc
    return None


def _get_json(client: httpx.Client, url: str) -> dict[str, object] | None:
    try:
        resp = client.get(url)
    except Exception:
        return None
    if resp.status_code != 200:
        return None
    try:
        data = resp.json()
    except Exception:
        return None
    return data if isinstance(data, dict) else None
