"""SSL/TLS certificate scanner."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime

from ..core.models import Vulnerability, Severity, CertificateInfo


class SSLScanner:
    """Check SSL/TLS configuration and certificate health."""

    async def scan(self, url: str) -> tuple[CertificateInfo | None, list[Vulnerability]]:
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname
        if not hostname:
            return None, []

        vulns: list[Vulnerability] = []
        cert_info = CertificateInfo()

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED

            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()

                    # Basic info
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    subject = dict(x[0] for x in cert.get("subject", []))
                    cert_info.issuer = issuer.get("organizationName", "Unknown")
                    cert_info.subject = subject.get("commonName", "Unknown")
                    cert_info.protocol = ssock.version() or "Unknown"
                    cert_info.cipher = cipher[0] if cipher else "Unknown"

                    # Dates
                    if "notBefore" in cert:
                        cert_info.not_before = cert["notBefore"]
                    if "notAfter" in cert:
                        cert_info.not_after = cert["notAfter"]
                        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                        days_left = (not_after - datetime.now()).days
                        cert_info.days_remaining = days_left

                        if days_left < 0:
                            vulns.append(Vulnerability(
                                name="Expired SSL Certificate",
                                severity=Severity.CRITICAL,
                                url=url,
                                description=f"Certificate expired {abs(days_left)} days ago",
                                recommendation="Renew the SSL certificate immediately",
                                cwe="CWE-295",
                            ))
                        elif days_left < 30:
                            vulns.append(Vulnerability(
                                name="SSL Certificate Expiring Soon",
                                severity=Severity.MEDIUM,
                                url=url,
                                description=f"Certificate expires in {days_left} days",
                                recommendation="Schedule certificate renewal",
                                cwe="CWE-295",
                            ))

                    # SAN
                    if "subjectAltName" in cert:
                        cert_info.san = [v for _, v in cert["subjectAltName"]]

                    # Weak ciphers
                    if cipher:
                        weak = ["DES", "RC4", "NULL", "MD5", "EXPORT", "anon"]
                        if any(w in cipher[0] for w in weak):
                            vulns.append(Vulnerability(
                                name="Weak SSL Cipher",
                                severity=Severity.HIGH,
                                url=url,
                                description=f"Weak cipher suite: {cipher[0]}",
                                recommendation="Disable weak cipher suites on the server",
                                cwe="CWE-326",
                            ))

                    # Weak protocols
                    proto = ssock.version() or ""
                    if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                        vulns.append(Vulnerability(
                            name=f"Weak TLS Protocol: {proto}",
                            severity=Severity.HIGH,
                            url=url,
                            description=f"Server supports deprecated protocol {proto}",
                            recommendation="Disable TLS 1.0/1.1, only allow TLS 1.2+",
                            cwe="CWE-326",
                        ))

                    # HSTS check is done in header scanner

        except ssl.SSLCertVerificationError as e:
            vulns.append(Vulnerability(
                name="SSL Certificate Verification Failed",
                severity=Severity.HIGH,
                url=url,
                description=str(e),
                recommendation="Fix certificate chain or install valid certificate",
                cwe="CWE-295",
            ))
        except ssl.SSLError as e:
            vulns.append(Vulnerability(
                name="SSL/TLS Error",
                severity=Severity.HIGH,
                url=url,
                description=str(e),
                recommendation="Check SSL/TLS configuration on the server",
            ))
        except (socket.timeout, ConnectionRefusedError, OSError):
            # HTTPS not available or connection issues - not critical for HTTP sites
            pass

        return cert_info if cert_info.issuer else None, vulns
