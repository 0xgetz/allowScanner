"""Comprehensive tests for SSLScanner."""

from __future__ import annotations

import ssl
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from allowscanner.core.models import Severity
from allowscanner.scanners.ssl import SSLScanner


class MockSSLSocket:
    """Mock SSL socket for testing."""

    def __init__(
        self,
        cert: dict | None = None,
        cipher: tuple | None = None,
        version: str = "TLSv1.3",
    ) -> None:
        self._cert = cert
        self._cipher = cipher
        self._version = version

    def getpeercert(self) -> dict | None:
        return self._cert

    def cipher(self) -> tuple | None:
        return self._cipher

    def version(self) -> str | None:
        return self._version

    def __enter__(self) -> MockSSLSocket:
        return self

    def __exit__(self, *args) -> None:
        pass


class MockSocket:
    """Mock socket for testing."""

    def __init__(self, ssl_socket: MockSSLSocket | None = None) -> None:
        self.ssl_socket = ssl_socket

    def __enter__(self) -> MockSocket:
        return self

    def __exit__(self, *args) -> None:
        pass


def create_mock_cert(
    days_until_expiry: int = 365,
    issuer_org: str = "Test CA",
    subject_cn: str = "example.com",
    san: list | None = None,
) -> dict:
    """Create a mock certificate dictionary."""
    not_after = datetime.now() + timedelta(days=days_until_expiry)
    not_before = datetime.now() - timedelta(days=1)

    return {
        "issuer": ((("organizationName", issuer_org),),),
        "subject": ((("commonName", subject_cn),),),
        "notBefore": not_before.strftime("%b %d %H:%M:%S %Y %Z"),
        "notAfter": not_after.strftime("%b %d %H:%M:%S %Y %Z"),
        "subjectAltName": tuple((f"DNS:{s}", s) for s in (san or [subject_cn])),
    }


@pytest.fixture
def scanner() -> SSLScanner:
    """Create an SSLScanner instance."""
    return SSLScanner()


class TestCertificateParsing:
    """Test SSL certificate parsing."""

    @pytest.mark.asyncio
    async def test_valid_certificate_parsed(
        self, scanner: SSLScanner
    ) -> None:
        """Test that a valid certificate is parsed correctly."""
        cert = create_mock_cert()
        cipher = ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.3", 256)
        ssl_socket = MockSSLSocket(cert=cert, cipher=cipher, version="TLSv1.3")

        with patch("socket.create_connection") as mock_create:
            mock_create.return_value = MockSocket(ssl_socket)

            with patch.object(ssl.SSLContext, "wrap_socket", return_value=ssl_socket):
                cert_info, vulns = await scanner.scan("https://example.com")

        assert cert_info is not None
        assert cert_info.issuer == "Test CA"
        assert cert_info.subject == "example.com"
        assert cert_info.protocol == "TLSv1.3"
        assert cert_info.cipher == "ECDHE-RSA-AES256-GCM-SHA384"
        assert cert_info.days_remaining is not None
        assert cert_info.days_remaining > 0

    @pytest.mark.asyncio
    async def test_certificate_san_parsed(
        self, scanner: SSLScanner
    ) -> None:
        """Test that SAN entries are parsed correctly."""
        cert = create_mock_cert(san=["example.com", "www.example.com", "api.example.com"])
        ssl_socket = MockSSLSocket(cert=cert, version="TLSv1.3")

        with patch("socket.create_connection") as mock_create:
            mock_create.return_value = MockSocket(ssl_socket)

            with patch.object(ssl.SSLContext, "wrap_socket", return_value=ssl_socket):
                cert_info, vulns = await scanner.scan("https://example.com")

        assert cert_info is not None
        assert "www.example.com" in cert_info.san
        assert "api.example.com" in cert_info.san


class TestExpiryDetection:
    """Test SSL certificate expiry detection."""

    @pytest.mark.asyncio
    async def test_expired_certificate_detected(
        self, scanner: SSLScanner
    ) -> None:
        """Test that an expired certificate is detected."""
        cert = create_mock_cert(days_until_expiry=-10)  # Expired 10 days ago
        ssl_socket = MockSSLSocket(cert=cert, version="TLSv1.3")

        with patch("socket.create_connection") as mock_create:
            mock_create.return_value = MockSocket(ssl_socket)

            with patch.object(ssl.SSLContext, "wrap_socket", return_value=ssl_socket):
                cert_info, vulns = await scanner.scan("https://example.com")

        expired_vulns = [v for v in vulns if "Expired SSL Certificate" in v.name]
        assert len(expired_vulns) > 0
        assert expired_vulns[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_expiring_soon_certificate_detected(
        self, scanner: SSLScanner
    ) -> None:
        """Test that a certificate expiring soon is detected."""
        cert = create_mock_cert(days_until_expiry=15)  # Expires in 15 days
        ssl_socket = MockSSLSocket(cert=cert, version="TLSv1.3")

        with patch("socket.create_connection") as mock_create:
            mock_create.return_value = MockSocket(ssl_socket)

            with patch.object(ssl.SSLContext, "wrap_socket", return_value=ssl_socket):
                cert_info, vulns = await scanner.scan("https://example.com")

        expiring_vulns = [v for v in vulns if "expiring" in v.name.lower()]
        assert len(expiring_vulns) > 0
        assert expiring_vulns[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_valid_certificate_no_expiry_vuln(
        self, scanner: SSLScanner
    ) -> None:
        """Test that a valid certificate with no expiry issues has no vulns."""
        cert = create_mock_cert(days_until_expiry=365)
        ssl_socket = MockSSLSocket(cert=cert, version="TLSv1.3")

        with patch("socket.create_connection") as mock_create:
            mock_create.return_value = MockSocket(ssl_socket)

            with patch.object(ssl.SSLContext, "wrap_socket", return_value=ssl_socket):
                cert_info, vulns = await scanner.scan("https://example.com")

        expiry_vulns = [v for v in vulns if "expir" in v.name.lower()]
        assert len(expiry_vulns) == 0


class TestWeakCipherDetection:
    """Test weak cipher suite detection."""

    @pytest.mark.asyncio
    async def test_weak_cipher_des_detected(
        self, scanner: SSLScanner
    ) -> None:
        """Test that DES cipher is detected as weak."""
        cert = create_mock_cert()
        cipher = ("DES-CBC3-SHA", "TLSv1.2", 168)
        ssl_socket = MockSSLSocket(cert=cert, cipher=cipher, version="TLSv1.2")

        with patch("socket.create_connection") as mock_create:
            mock_create.return_value = MockSocket(ssl_socket)

            with patch.object(ssl.SSLContext, "wrap_socket", return_value=ssl_socket):
                cert_info, vulns = await scanner.scan("https://example.com")

        weak_vulns = [v for v in vulns if "Weak SSL Cipher" in v.name]
        assert len(weak_vulns) > 0
        assert weak_vulns[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_weak_cipher_rc4_detected(
        self, scanner: SSLScanner
    ) -> None:
        """Test that RC4 cipher is detected as weak."""
        cert = create_mock_cert()
        cipher = ("RC4-SHA", "TLSv1.2", 128)
        ssl_socket = MockSSLSocket(cert=cert, cipher=cipher, version="TLSv1.2")

        with patch("socket.create_connection") as mock_create:
            mock_create.return_value = MockSocket(ssl_socket)

            with patch.object(ssl.SSLContext, "wrap_socket", return_value=ssl_socket):
                cert_info, vulns = await scanner.scan("https://example.com")

        weak_vulns = [v for v in vulns if "Weak SSL Cipher" in v.name]
        assert len(weak_vulns) > 0

    @pytest.mark.asyncio
    async def test_strong_cipher_no_vuln(
        self, scanner: SSLScanner
    ) -> None:
        """Test that strong cipher does not trigger vulnerability."""
        cert = create_mock_cert()
        cipher = ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.3", 256)
        ssl_socket = MockSSLSocket(cert=cert, cipher=cipher, version="TLSv1.3")

        with patch("socket.create_connection") as mock_create:
            mock_create.return_value = MockSocket(ssl_socket)

            with patch.object(ssl.SSLContext, "wrap_socket", return_value=ssl_socket):
                cert_info, vulns = await scanner.scan("https://example.com")

        weak_vulns = [v for v in vulns if "Weak SSL Cipher" in v.name]
        assert len(weak_vulns) == 0


class TestDeprecatedProtocolDetection:
    """Test deprecated protocol detection."""

    @pytest.mark.asyncio
    async def test_tls_1_0_detected(
        self, scanner: SSLScanner
    ) -> None:
        """Test that TLS 1.0 is detected as deprecated."""
        cert = create_mock_cert()
        ssl_socket = MockSSLSocket(cert=cert, version="TLSv1")

        with patch("socket.create_connection") as mock_create:
            mock_create.return_value = MockSocket(ssl_socket)

            with patch.object(ssl.SSLContext, "wrap_socket", return_value=ssl_socket):
                cert_info, vulns = await scanner.scan("https://example.com")

        proto_vulns = [v for v in vulns if "Weak TLS Protocol" in v.name]
        assert len(proto_vulns) > 0
        assert proto_vulns[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_tls_1_1_detected(
        self, scanner: SSLScanner
    ) -> None:
        """Test that TLS 1.1 is detected as deprecated."""
        cert = create_mock_cert()
        ssl_socket = MockSSLSocket(cert=cert, version="TLSv1.1")

        with patch("socket.create_connection") as mock_create:
            mock_create.return_value = MockSocket(ssl_socket)

            with patch.object(ssl.SSLContext, "wrap_socket", return_value=ssl_socket):
                cert_info, vulns = await scanner.scan("https://example.com")

        proto_vulns = [v for v in vulns if "Weak TLS Protocol" in v.name]
        assert len(proto_vulns) > 0

    @pytest.mark.asyncio
    async def test_tls_1_2_accepted(
        self, scanner: SSLScanner
    ) -> None:
        """Test that TLS 1.2 is accepted and not flagged."""
        cert = create_mock_cert()
        ssl_socket = MockSSLSocket(cert=cert, version="TLSv1.2")

        with patch("socket.create_connection") as mock_create:
            mock_create.return_value = MockSocket(ssl_socket)

            with patch.object(ssl.SSLContext, "wrap_socket", return_value=ssl_socket):
                cert_info, vulns = await scanner.scan("https://example.com")

        proto_vulns = [v for v in vulns if "Weak TLS Protocol" in v.name]
        assert len(proto_vulns) == 0

    @pytest.mark.asyncio
    async def test_tls_1_3_accepted(
        self, scanner: SSLScanner
    ) -> None:
        """Test that TLS 1.3 is accepted and not flagged."""
        cert = create_mock_cert()
        ssl_socket = MockSSLSocket(cert=cert, version="TLSv1.3")

        with patch("socket.create_connection") as mock_create:
            mock_create.return_value = MockSocket(ssl_socket)

            with patch.object(ssl.SSLContext, "wrap_socket", return_value=ssl_socket):
                cert_info, vulns = await scanner.scan("https://example.com")

        proto_vulns = [v for v in vulns if "Weak TLS Protocol" in v.name]
        assert len(proto_vulns) == 0


class TestSSLErrorHandling:
    """Test SSL scanner error handling."""

    @pytest.mark.asyncio
    async def test_ssl_verification_error(
        self, scanner: SSLScanner
    ) -> None:
        """Test that SSL verification errors are handled."""
        with patch("socket.create_connection") as mock_create:
            mock_socket = MagicMock()
            mock_create.return_value = mock_socket

            mock_socket.__enter__ = MagicMock(return_value=mock_socket)
            mock_socket.__exit__ = MagicMock(return_value=False)

            with patch.object(ssl.SSLContext, "wrap_socket", side_effect=ssl.SSLCertVerificationError("certificate verify failed")):
                cert_info, vulns = await scanner.scan("https://self-signed.example.com")

        verification_vulns = [v for v in vulns if "SSL Certificate Verification Failed" in v.name]
        assert len(verification_vulns) > 0
        assert verification_vulns[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_connection_refused(
        self, scanner: SSLScanner
    ) -> None:
        """Test that connection refused is handled gracefully."""
        with patch("socket.create_connection", side_effect=ConnectionRefusedError):
            cert_info, vulns = await scanner.scan("https://example.com")

        assert cert_info is None
        assert len(vulns) == 0

    @pytest.mark.asyncio
    async def test_timeout(
        self, scanner: SSLScanner
    ) -> None:
        """Test that timeout is handled gracefully."""
        with patch("socket.create_connection", side_effect=TimeoutError):
            cert_info, vulns = await scanner.scan("https://example.com")

        assert cert_info is None
        assert len(vulns) == 0

    @pytest.mark.asyncio
    async def test_invalid_url(
        self, scanner: SSLScanner
    ) -> None:
        """Test that invalid URL is handled."""
        cert_info, vulns = await scanner.scan("not-a-valid-url")

        assert cert_info is None
        assert len(vulns) == 0

    @pytest.mark.asyncio
    async def test_http_url(
        self, scanner: SSLScanner
    ) -> None:
        """Test that HTTP URL returns None certificate."""
        cert_info, vulns = await scanner.scan("http://example.com")

        assert cert_info is None
        assert len(vulns) == 0


class TestCertificateNone:
    """Test handling when no certificate is returned."""

    @pytest.mark.asyncio
    async def test_no_certificate_returned(
        self, scanner: SSLScanner
    ) -> None:
        """Test that None certificate is handled."""
        ssl_socket = MockSSLSocket(cert=None, version="TLSv1.3")

        with patch("socket.create_connection") as mock_create:
            mock_create.return_value = MockSocket(ssl_socket)

            with patch.object(ssl.SSLContext, "wrap_socket", return_value=ssl_socket):
                cert_info, vulns = await scanner.scan("https://example.com")

        assert cert_info is None
        assert len(vulns) == 0
