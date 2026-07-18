"""Outbound-network policy regression tests."""

from __future__ import annotations

import gzip
import ipaddress

import httpx
import pytest

from mcpradar.network.safe_http import (
    SafeHttpError,
    SafeUrlPolicy,
    _resolve_addresses,
    canonical_origin,
    safe_get,
)


def test_explicit_local_target_is_allowed() -> None:
    policy = SafeUrlPolicy.for_target("http://127.0.0.1:8000/mcp")
    assert policy.validate("http://127.0.0.1:8000/.well-known/test")


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data",
        "https://127.0.0.1/admin",
        "https://[::1]/admin",
        "https://[::ffff:127.0.0.1]/admin",
        "https://localhost/admin",
        "file:///etc/passwd",
        "https://user:password@example.com/metadata",
    ],
)
def test_untrusted_local_or_unsafe_urls_are_blocked(url: str) -> None:
    with pytest.raises(SafeHttpError):
        SafeUrlPolicy().validate(url, resolve_dns=False)


def test_dns_answer_is_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "mcpradar.network.safe_http._resolve_addresses",
        lambda _host, _port: {ipaddress.ip_address("10.0.0.8")},
    )
    with pytest.raises(SafeHttpError, match="non-public"):
        SafeUrlPolicy().validate("https://metadata.attacker.example/data")


def test_redirect_target_is_revalidated() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "public.example":
            return httpx.Response(302, headers={"location": "http://127.0.0.1/private"})
        raise AssertionError("blocked redirect must not be requested")

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as client,
        pytest.raises(SafeHttpError),
    ):
        safe_get(client, "https://public.example/start", SafeUrlPolicy())


def test_response_size_is_bounded() -> None:
    policy = SafeUrlPolicy(max_response_bytes=4)
    transport = httpx.MockTransport(lambda _request: httpx.Response(200, content=b"12345"))
    with (
        httpx.Client(transport=transport) as client,
        pytest.raises(SafeHttpError, match="size"),
    ):
        safe_get(client, "https://public.example/data", policy)


def test_decoded_response_drops_compression_headers() -> None:
    payload = b'{"ok": true}'
    compressed = gzip.compress(payload)
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(
            200,
            headers={
                "content-type": "application/json",
                "content-encoding": "gzip",
                "content-length": str(len(compressed)),
            },
            stream=httpx.ByteStream(compressed),
        )
    )
    with httpx.Client(transport=transport) as client:
        response = safe_get(client, "https://public.example/data", SafeUrlPolicy())
    assert response.json() == {"ok": True}
    assert "content-encoding" not in response.headers
    assert response.headers["content-length"] == str(len(payload))


@pytest.mark.parametrize(
    ("url", "origin"),
    [
        ("sse://Example.COM:80/events", "http://example.com"),
        ("https://Example.COM:443/mcp", "https://example.com"),
        ("https://[2001:4860:4860::8888]:8443/mcp", "https://[2001:4860:4860::8888]:8443"),
        ("stdio://server", ""),
    ],
)
def test_canonical_origin_normalizes_urls(url: str, origin: str) -> None:
    assert canonical_origin(url) == origin


def test_discovered_plain_http_and_unresolved_dns_are_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(SafeHttpError, match="HTTPS"):
        SafeUrlPolicy().validate("http://public.example/data", resolve_dns=False)
    monkeypatch.setattr("mcpradar.network.safe_http._resolve_addresses", lambda *_args: set())
    with pytest.raises(SafeHttpError, match="did not resolve"):
        SafeUrlPolicy().validate("https://missing.example/data")


def test_public_dns_answer_and_trusted_origin_are_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "mcpradar.network.safe_http._resolve_addresses",
        lambda *_args: {ipaddress.ip_address("8.8.8.8")},
    )
    assert SafeUrlPolicy().validate("https://dns.google/data") == "https://dns.google"
    policy = SafeUrlPolicy.for_target("http://localhost:9000/mcp")
    assert policy.validate("http://localhost:9000/private") == "http://localhost:9000"


def test_content_length_limit_invalid_length_and_redirect_limits() -> None:
    oversized = httpx.MockTransport(
        lambda _request: httpx.Response(
            200,
            headers={"content-length": "10"},
            stream=httpx.ByteStream(b"x"),
        )
    )
    with httpx.Client(transport=oversized) as client, pytest.raises(SafeHttpError, match="size"):
        safe_get(client, "https://public.example/data", SafeUrlPolicy(max_response_bytes=4))

    invalid = httpx.MockTransport(
        lambda _request: httpx.Response(200, headers={"content-length": "invalid"}, content=b"x")
    )
    with httpx.Client(transport=invalid) as client:
        assert safe_get(client, "https://public.example/data", SafeUrlPolicy()).status_code == 200

    redirect = httpx.MockTransport(
        lambda _request: httpx.Response(302, headers={"location": "/again"})
    )
    with httpx.Client(transport=redirect) as client, pytest.raises(SafeHttpError, match="redirect"):
        safe_get(client, "https://public.example/start", SafeUrlPolicy(max_redirects=1))


def test_redirect_without_location_is_returned() -> None:
    transport = httpx.MockTransport(lambda _request: httpx.Response(302))
    with httpx.Client(transport=transport) as client:
        assert safe_get(client, "https://public.example/data", SafeUrlPolicy()).status_code == 302


def test_dns_resolution_filters_bad_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "mcpradar.network.safe_http.socket.getaddrinfo",
        lambda *_args, **_kwargs: [
            (None, None, None, None, ("8.8.8.8", 443)),
            (None, None, None, None, ("not-an-ip", 443)),
            (None, None, None, None, ()),
        ],
    )
    assert _resolve_addresses("dns.google", 443) == {ipaddress.ip_address("8.8.8.8")}
    monkeypatch.setattr(
        "mcpradar.network.safe_http.socket.getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("dns failed")),
    )
    assert _resolve_addresses("missing.example", 443) == set()
