"""Transport security checker — TLS version, certificate validation, HSTS."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone  # noqa: F401
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from mcpradar.fingerprint.models import TLSInfo

if TYPE_CHECKING:
    from mcpradar.scanner.report import Finding


class TransportChecker:
    """Checks transport-layer security for MCP endpoints."""

    def __init__(self, timeout: float = 5.0) -> None:
        self._timeout = timeout

    def check(self, target: str, transport: str) -> TLSInfo | None:
        """Check transport security. Returns TLSInfo or None for stdio."""
        if transport == "stdio":
            return None

        # Detect plain HTTP
        if target.startswith("http://"):
            return TLSInfo(
                version="plain",
                cert_issuer="",
                cert_subject="",
                cert_expiry="",
                cert_valid=False,
                self_signed=False,
            )

        # HTTPS — do TLS handshake and cert check
        if target.startswith("https://"):
            return self._check_https(target)

        # SSE over HTTP — check if the underlying URL is https
        if target.startswith("sse://"):
            http_target = target.replace("sse://", "http://")
            if http_target.startswith("https://"):
                return self._check_https(http_target)
            return TLSInfo(
                version="plain",
                cert_issuer="",
                cert_subject="",
                cert_expiry="",
                cert_valid=False,
                self_signed=False,
            )

        # Unknown — assume plain
        return TLSInfo(
            version="plain",
            cert_issuer="",
            cert_subject="",
            cert_expiry="",
            cert_valid=False,
            self_signed=False,
        )

    def _check_https(self, url: str) -> TLSInfo:
        """Perform TLS handshake and extract certificate info."""
        parsed = urlparse(url)
        host = parsed.hostname or "localhost"
        port = parsed.port or 443

        try:
            ctx = ssl.create_default_context()
            with (
                socket.create_connection((host, port), timeout=self._timeout) as sock,
                ctx.wrap_socket(sock, server_hostname=host) as tls_sock,
            ):
                tls_version = tls_sock.version() or "Unknown"
                cert = tls_sock.getpeercert()

            if cert is None:
                return TLSInfo(
                    version=tls_version,
                    cert_issuer="",
                    cert_subject="",
                    cert_expiry="",
                    cert_valid=False,
                    self_signed=False,
                )

            # Extract subject/issuer
            subject_raw: object = cert.get("subject", [])
            issuer_raw: object = cert.get("issuer", [])
            subject = self._cert_name(subject_raw)
            issuer = self._cert_name(issuer_raw)

            # Check expiry
            not_after_raw: object = cert.get("notAfter", "")
            not_after = str(not_after_raw) if isinstance(not_after_raw, str) else ""
            cert_valid = True
            try:
                from datetime import datetime as dt

                expiry = dt.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                cert_valid = expiry > dt.now()
            except (ValueError, TypeError):
                cert_valid = False
                not_after = ""

            # Self-signed check
            self_signed = (subject == issuer) if subject and issuer else False

            expiry_iso = ""
            if not_after:
                try:
                    expiry_iso = dt.strptime(not_after, "%b %d %H:%M:%S %Y %Z").isoformat()
                except (ValueError, TypeError):
                    expiry_iso = not_after

            return TLSInfo(
                version=tls_version,
                cert_issuer=issuer,
                cert_subject=subject,
                cert_expiry=expiry_iso,
                cert_valid=cert_valid,
                self_signed=self_signed,
            )

        except OSError:
            return TLSInfo(
                version="error",
                cert_issuer="",
                cert_subject="",
                cert_expiry="",
                cert_valid=False,
                self_signed=False,
            )

    @staticmethod
    def _cert_name(entries: object) -> str:
        """Extract CN or organizationName from certificate name entries."""
        if not isinstance(entries, list):
            return ""
        for entry in entries:
            if not isinstance(entry, (tuple, list)):
                continue
            for item in entry:
                if isinstance(item, (tuple, list)) and len(item) >= 2:
                    k, v = item[0], item[1]
                    if k == "organizationName":
                        return str(v)
        for entry in entries:
            if not isinstance(entry, (tuple, list)):
                continue
            for item in entry:
                if isinstance(item, (tuple, list)) and len(item) >= 2:
                    k, v = item[0], item[1]
                    if k == "commonName":
                        return str(v)
        return ""

    def check_hsts(self, url: str) -> bool:
        """Check if the server sends Strict-Transport-Security header."""
        try:
            import httpx

            parsed = urlparse(url)
            hsts_url = f"{parsed.scheme}://{parsed.hostname}:{parsed.port or 443}/"
            response = httpx.get(hsts_url, timeout=self._timeout, follow_redirects=False)
            return "strict-transport-security" in response.headers
        except Exception:
            return False

    def generate_findings(
        self, target: str, transport: str, tls_info: TLSInfo | None
    ) -> list[Finding]:
        """Generate R111 findings from transport check results."""
        from mcpradar.scanner.report import Finding, Severity

        findings: list[Finding] = []

        if transport == "stdio":
            return findings  # No transport security concerns for stdio

        if tls_info is None:
            # No TLS info — assume plain
            findings.append(
                Finding(
                    rule_id="R111",
                    title="Guvenli olmayan transport",
                    description="Plain HTTP kullaniliyor — trafik sifrelenmemis",
                    severity=Severity.HIGH,
                    target=target,
                    location="transport",
                )
            )
            return findings

        if tls_info.version == "plain":
            findings.append(
                Finding(
                    rule_id="R111",
                    title="Guvenli olmayan transport",
                    description="Plain HTTP kullaniliyor — trafik sifrelenmemis",
                    severity=Severity.HIGH,
                    target=target,
                    location="transport",
                )
            )

        elif tls_info.version == "error":
            findings.append(
                Finding(
                    rule_id="R111",
                    title="TLS baglanti hatasi",
                    description="TLS handshake basarisiz — sunucuya guvenli baglanilamadi",
                    severity=Severity.HIGH,
                    target=target,
                    location="transport",
                )
            )

        else:
            # Check TLS version
            if tls_info.version in ("TLSv1.0", "TLSv1.1", "SSLv3"):
                findings.append(
                    Finding(
                        rule_id="R111",
                        title="Eski TLS surumu",
                        description=f"{tls_info.version} kullaniliyor — TLS >= 1.2 gerekli",
                        severity=Severity.CRITICAL,
                        target=target,
                        location="transport",
                        detail={"tls_version": tls_info.version},
                    )
                )

            # Check certificate
            if not tls_info.cert_valid:
                findings.append(
                    Finding(
                        rule_id="R111",
                        title="Sertifika suresi dolmus",
                        description="Sunucu sertifikasi gecersiz veya suresi dolmus",
                        severity=Severity.HIGH,
                        target=target,
                        location="transport",
                        detail={"cert_expiry": tls_info.cert_expiry},
                    )
                )

            if tls_info.self_signed:
                findings.append(
                    Finding(
                        rule_id="R111",
                        title="Self-signed sertifika",
                        description="Sunucu self-signed sertifika kullaniyor",
                        severity=Severity.MEDIUM,
                        target=target,
                        location="transport",
                    )
                )

            # Check HSTS
            if not self.check_hsts(target):
                findings.append(
                    Finding(
                        rule_id="R111",
                        title="HSTS header eksik",
                        description="Strict-Transport-Security header'i gonderilmemis",
                        severity=Severity.MEDIUM,
                        target=target,
                        location="transport",
                    )
                )

        return findings
