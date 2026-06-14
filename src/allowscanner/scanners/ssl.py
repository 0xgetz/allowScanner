"""SSL/TLS certificate scanner with robust error handling."""

from __future__ import annotations

import builtins
import contextlib
import socket
import ssl
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from ..core.exceptions import NetworkError, SSLError
from ..core.logging import get_logger
from ..core.models import CertificateInfo, Severity, Vulnerability

logger = get_logger()


class SSLScanner:
    """Check SSL/TLS configuration and certificate health."""

    async def scan(self, url: str) -> tuple[CertificateInfo | None, list[Vulnerability]]:
        """Scan URL for SSL/TLS configuration.

        Args:
            url: URL to scan (must be HTTPS)

        Returns:
            Tuple of (certificate info, list of vulnerabilities)
        """
        # Parse URL and extract hostname
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                logger.warning(f"Could not extract hostname from URL: {url}")
                return None, []

            # Only scan HTTPS URLs
            scheme = parsed.scheme
            if scheme != "https":
                logger.debug(f"Skipping SSL scan for non-HTTPS URL: {url}")
                return None, []
        except Exception as e:
            logger.error(f"Failed to parse URL {url}: {e}")
            return None, []

        vulns: list[Vulnerability] = []
        cert_info = CertificateInfo()

        try:
            # Create SSL context with proper verification
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED

            # Connect and get certificate
            sock = None
            ssock = None
            try:
                # Create connection with timeout
                sock = socket.create_connection((hostname, 443), timeout=10)
                ssock = ctx.wrap_socket(sock, server_hostname=hostname)
                sock = None  # Ownership transferred to ssock

                # Get certificate
                cert: dict[str, Any] | None = ssock.getpeercert()
                if not cert:
                    logger.warning(f"No certificate received from {hostname}")
                    return None, vulns

                # Get cipher information
                cipher: tuple[str, str, int] | None = ssock.cipher()

                # Extract issuer and subject safely
                issuer_list: list[list[tuple[str, str]]] = cert.get("issuer", [])
                subject_list: list[list[tuple[str, str]]] = cert.get("subject", [])

                issuer: dict[str, str] = {}
                subject: dict[str, str] = {}

                if issuer_list:
                    with contextlib.suppress(ValueError, IndexError):
                        issuer = dict(x[0] for x in issuer_list if x and x[0])

                if subject_list:
                    with contextlib.suppress(ValueError, IndexError):
                        subject = dict(x[0] for x in subject_list if x and x[0])

                # Populate certificate info
                cert_info.issuer = issuer.get("organizationName", "Unknown") if issuer else "Unknown"
                cert_info.subject = subject.get("commonName", "Unknown") if subject else "Unknown"
                cert_info.protocol = ssock.version() or "Unknown"
                cert_info.cipher = cipher[0] if cipher else "Unknown"

                # Extract dates
                not_before: str | None = cert.get("notBefore")
                not_after: str | None = cert.get("notAfter")

                if not_before:
                    cert_info.not_before = not_before

                if not_after:
                    cert_info.not_after = not_after
                    try:
                        # Try parsing with timezone first, then without
                        not_after_date = None
                        for fmt in ["%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"]:
                            try:
                                not_after_date = datetime.strptime(not_after.strip(), fmt)
                                break
                            except ValueError:
                                continue
                        if not_after_date is None:
                            raise ValueError(f"Unable to parse date: {not_after}")
                        days_left = (not_after_date - datetime.now()).days
                        cert_info.days_remaining = days_left

                        if days_left < 0:
                            vulns.append(
                                Vulnerability(
                                    name="Expired SSL Certificate",
                                    severity=Severity.CRITICAL,
                                    url=url,
                                    description=f"Certificate expired {abs(days_left)} days ago",
                                    recommendation="Renew the SSL certificate immediately",
                                    cwe="CWE-295",
                                )
                            )
                        elif days_left < 30:
                            vulns.append(
                                Vulnerability(
                                    name="SSL Certificate Expiring Soon",
                                    severity=Severity.MEDIUM,
                                    url=url,
                                    description=f"Certificate expires in {days_left} days",
                                    recommendation="Schedule certificate renewal",
                                    cwe="CWE-295",
                                )
                            )
                    except ValueError as e:
                        logger.warning(f"Failed to parse certificate date: {e}")

                # Extract Subject Alternative Names
                san_list: list[tuple[str, str]] | None = cert.get("subjectAltName")
                if san_list:
                    cert_info.san = [v for _, v in san_list if v]

                # Check for weak ciphers
                if cipher:
                    weak = ["DES", "RC4", "NULL", "MD5", "EXPORT", "anon"]
                    if any(w in cipher[0] for w in weak):
                        vulns.append(
                            Vulnerability(
                                name="Weak SSL Cipher",
                                severity=Severity.HIGH,
                                url=url,
                                description=f"Weak cipher suite: {cipher[0]}",
                                recommendation="Disable weak cipher suites on the server",
                                cwe="CWE-326",
                            )
                        )

                # Actively probe which TLS protocol versions the server accepts
                supported = self._supported_protocols(hostname)
                cert_info.supported_protocols = supported
                for weak_proto in ("TLSv1", "TLSv1.1"):
                    if weak_proto in supported:
                        vulns.append(
                            Vulnerability(
                                name=f"Deprecated TLS Protocol Supported: {weak_proto}",
                                severity=Severity.HIGH,
                                url=url,
                                description=(
                                    f"Server still accepts {weak_proto} connections "
                                    "(deprecated; disallowed by PCI-DSS and modern browsers)"
                                ),
                                recommendation="Disable TLS 1.0/1.1 and require TLS 1.2 or higher",
                                cwe="CWE-326",
                            )
                        )
                if supported and "TLSv1.3" not in supported:
                    vulns.append(
                        Vulnerability(
                            name="TLS 1.3 Not Supported",
                            severity=Severity.LOW,
                            url=url,
                            description="Server does not negotiate TLS 1.3",
                            recommendation="Enable TLS 1.3 for stronger security and better performance",
                            cwe="CWE-326",
                        )
                    )

                logger.debug(f"SSL scan completed for {hostname}")

            finally:
                # Clean up sockets
                if ssock:
                    with contextlib.suppress(Exception):
                        ssock.close()
                elif sock:
                    with contextlib.suppress(Exception):
                        sock.close()

        except ssl.SSLCertVerificationError as e:
            logger.warning(f"SSL certificate verification failed for {hostname}: {e}")
            vulns.append(
                Vulnerability(
                    name="SSL Certificate Verification Failed",
                    severity=Severity.HIGH,
                    url=url,
                    description=str(e),
                    recommendation="Fix certificate chain or install valid certificate",
                    cwe="CWE-295",
                )
            )
        except ssl.SSLError as e:
            logger.error(f"SSL error for {hostname}: {e}")
            raise SSLError(
                f"SSL/TLS error for {hostname}",
                host=hostname,
                port=443,
                original_error=e,
                suggestion="Check SSL/TLS configuration on the server",
            ) from e
        except builtins.TimeoutError as e:
            logger.warning(f"Connection timeout for {hostname}: {e}")
            # Return None gracefully like ConnectionRefusedError
        except ConnectionRefusedError as e:
            logger.debug(f"Connection refused for {hostname}: {e}")
            # HTTPS not available - not critical for HTTP sites
        except OSError as e:
            logger.warning(f"Network error for {hostname}: {e}")
            raise NetworkError(
                "Network error during SSL scan",
                host=hostname,
                port=443,
                original_error=e,
                suggestion="Check network connectivity",
            ) from e
        except Exception as e:
            logger.error(f"Unexpected error during SSL scan for {hostname}: {e}")
            raise SSLError("Unexpected error during SSL scan", host=hostname, original_error=e) from e

        return cert_info if cert_info.issuer else None, vulns

    def _supported_protocols(self, hostname: str) -> list[str]:
        """Actively probe which TLS versions the server will negotiate."""
        versions = [
            ("TLSv1", ssl.TLSVersion.TLSv1),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
        ]
        supported: list[str] = []
        for label, version in versions:
            if self._probe_protocol(hostname, version):
                supported.append(label)
        return supported

    def _probe_protocol(self, hostname: str, version: ssl.TLSVersion) -> bool:
        """Return True if the server completes a handshake pinned to ``version``.

        Note: the local OpenSSL build must support the version to test it; if it
        was compiled without TLS 1.0/1.1 those probes silently return False.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = version
            ctx.maximum_version = version
        except (ValueError, OSError):
            return False
        try:
            with (
                socket.create_connection((hostname, 443), timeout=8) as raw,
                ctx.wrap_socket(raw, server_hostname=hostname) as tls,
            ):
                return tls.version() is not None
        except (OSError, ssl.SSLError, ValueError):
            return False
