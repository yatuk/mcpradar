"""SSRF-resistant HTTP helpers for URLs learned from an MCP server.

The scanner may contact the target the user explicitly selected. URLs learned
from that target cross a trust boundary: they must use HTTPS, resolve only to
public addresses, and are revalidated after every redirect.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_BLOCKED_HOSTNAMES = frozenset({"localhost", "localhost.localdomain"})


class SafeHttpError(ValueError):
    """The URL violates the scanner's outbound-network policy."""


@dataclass(frozen=True)
class SafeUrlPolicy:
    """Outbound policy with an explicit user-selected origin allowlist."""

    trusted_origins: frozenset[str] = field(default_factory=frozenset)
    max_redirects: int = 5
    max_response_bytes: int = 1_048_576

    @classmethod
    def for_target(cls, target: str) -> SafeUrlPolicy:
        origin = canonical_origin(target)
        return cls(trusted_origins=frozenset({origin}) if origin else frozenset())

    def validate(self, url: str, *, resolve_dns: bool = True) -> str:
        """Validate an outbound URL and return its normalized origin."""
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"}:
            raise SafeHttpError(f"unsupported URL scheme: {parsed.scheme or '<missing>'}")
        if not parsed.hostname:
            raise SafeHttpError("URL has no hostname")
        if parsed.username is not None or parsed.password is not None:
            raise SafeHttpError("credentials in URLs are not allowed")

        origin = canonical_origin(url)
        trusted = origin in self.trusted_origins
        if not trusted and parsed.scheme != "https":
            raise SafeHttpError("discovered URLs must use HTTPS")

        host = parsed.hostname.rstrip(".").lower()
        if not trusted and host in _BLOCKED_HOSTNAMES:
            raise SafeHttpError(f"blocked local hostname: {host}")

        literal = _ip_literal(host)
        if literal is not None:
            if not trusted and not _is_public_address(literal):
                raise SafeHttpError(f"blocked non-public address: {literal}")
            return origin

        if resolve_dns and not trusted:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            addresses = _resolve_addresses(host, port)
            if not addresses:
                raise SafeHttpError(f"hostname did not resolve: {host}")
            blocked = [str(address) for address in addresses if not _is_public_address(address)]
            if blocked:
                blocked_text = ", ".join(blocked)
                raise SafeHttpError(f"hostname resolves to non-public address: {blocked_text}")
        return origin


def canonical_origin(url: str) -> str:
    """Return a normalized scheme/host/port origin, or an empty string."""
    if url.startswith("sse://"):
        url = "http://" + url[len("sse://") :]
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    host = parsed.hostname.rstrip(".").lower()
    if ":" in host:
        host = f"[{host}]"
    default_port = 443 if parsed.scheme == "https" else 80
    port = f":{parsed.port}" if parsed.port and parsed.port != default_port else ""
    return f"{parsed.scheme}://{host}{port}"


def safe_get(client: httpx.Client, url: str, policy: SafeUrlPolicy) -> httpx.Response:
    """GET with per-hop validation and bounded redirects/body size."""
    current = url
    # MockTransport never opens a socket. Skipping DNS for it keeps unit tests
    # deterministic without weakening real transports.
    resolve_dns = client._transport.__class__.__name__ != "MockTransport"

    for hop in range(policy.max_redirects + 1):
        policy.validate(current, resolve_dns=resolve_dns)
        with client.stream("GET", current, follow_redirects=False) as streamed:
            if streamed.status_code in _REDIRECT_STATUSES:
                location = streamed.headers.get("location")
                if not location:
                    return _bounded_response(streamed, policy.max_response_bytes)
                if hop == policy.max_redirects:
                    raise SafeHttpError("too many redirects")
                current = urljoin(current, location)
                continue
            return _bounded_response(streamed, policy.max_response_bytes)

    raise SafeHttpError("too many redirects")  # pragma: no cover


def _bounded_response(response: httpx.Response, max_bytes: int) -> httpx.Response:
    """Read a streaming response without buffering beyond the policy limit."""
    content_length = response.headers.get("content-length")
    if content_length:
        try:
            declared_size = int(content_length)
        except ValueError:
            declared_size = 0
        if declared_size > max_bytes:
            raise SafeHttpError("response exceeds configured size limit")

    body = bytearray()
    for chunk in response.iter_bytes():
        body.extend(chunk)
        if len(body) > max_bytes:
            raise SafeHttpError("response exceeds configured size limit")
    # ``iter_bytes`` returns decoded content. Reusing the upstream
    # content-encoding/content-length headers makes the new Response attempt a
    # second gzip/brotli decode (or advertise the compressed byte length).
    headers = response.headers.copy()
    headers.pop("content-encoding", None)
    headers.pop("content-length", None)
    return httpx.Response(
        status_code=response.status_code,
        headers=headers,
        content=bytes(body),
        request=response.request,
        extensions=response.extensions,
    )


def _ip_literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _resolve_addresses(host: str, port: int) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return set()
    addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for answer in answers:
        try:
            addresses.add(ipaddress.ip_address(answer[4][0]))
        except (ValueError, IndexError):
            continue
    return addresses


def _is_public_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped.is_global
    return address.is_global
