"""Comprehensive tests for HeaderScanner."""

from __future__ import annotations

import pytest

from allowscanner.core.models import Severity
from allowscanner.scanners.headers import HeaderScanner


class MockResponse:
    """Mock aiohttp ClientResponse for headers testing."""

    def __init__(self, headers: dict | None = None, cookies: dict | None = None) -> None:
        self._headers = headers or {}
        self._cookies = cookies or {}

    @property
    def headers(self) -> dict:
        return self._headers

    @property
    def cookies(self) -> dict:
        return self._cookies


class MockSession:
    """Mock aiohttp ClientSession for headers testing."""

    def __init__(self, response: MockResponse | None = None) -> None:
        self.response = response

    async def get(self, url: str, **kwargs) -> tuple:
        if self.response:
            return self.response, ""
        return None, ""


@pytest.fixture
def scanner() -> HeaderScanner:
    """Create a HeaderScanner instance."""
    return HeaderScanner()


class TestCSPDetection:
    """Test Content-Security-Policy header detection."""

    @pytest.mark.asyncio
    async def test_csp_header_present(
        self, scanner: HeaderScanner
    ) -> None:
        """Test that CSP header is detected when present."""
        response = MockResponse(headers={"Content-Security-Policy": "default-src 'self'"})
        session = MockSession(response=response)

        headers_found, vulns = await scanner.scan("https://example.com", session)

        csp_headers = [h for h in headers_found if h.name == "Content-Security-Policy"]
        assert len(csp_headers) > 0
        assert csp_headers[0].present is True
        assert csp_headers[0].value == "default-src 'self'"

    @pytest.mark.asyncio
    async def test_csp_header_missing(
        self, scanner: HeaderScanner
    ) -> None:
        """Test that missing CSP header is detected."""
        response = MockResponse(headers={})
        session = MockSession(response=response)

        headers_found, vulns = await scanner.scan("https://example.com", session)

        csp_headers = [h for h in headers_found if h.name == "Content-Security-Policy"]
        assert len(csp_headers) > 0
        assert csp_headers[0].present is False

        csp_vulns = [v for v in vulns if "Missing Content-Security-Policy" in v.name]
        assert len(csp_vulns) > 0
        assert csp_vulns[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_csp_insecure_unsafe_inline(
        self, scanner: HeaderScanner
    ) -> None:
        """Test that CSP with unsafe-inline is flagged."""
        response = MockResponse(headers={"Content-Security-Policy": "default-src 'unsafe-inline'"})
        session = MockSession(response=response)

        headers_found, vulns = await scanner.scan("https://example.com", session)

        insecure_vulns = [v for v in vulns if "Insecure CSP" in v.name]
        assert len(insecure_vulns) > 0
        assert insecure_vulns[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_csp_insecure_unsafe_eval(
        self, scanner: HeaderScanner
    ) -> None:
        """Test that CSP with unsafe-eval is flagged."""
        response = MockResponse(headers={"Content-Security-Policy": "script-src 'unsafe-eval'"})
        session = MockSession(response=response)

        headers_found, vulns = await scanner.scan("https://example.com", session)

        insecure_vulns = [v for v in vulns if "Insecure CSP" in v.name]
        assert len(insecure_vulns) > 0

    @pytest.mark.asyncio
    async def test_csp_overly_permissive_wildcard(
        self, scanner: HeaderScanner
    ) -> None:
        """Test that CSP with wildcard is flagged."""
        response = MockResponse(headers={"Content-Security-Policy": "default-src *"})
        session = MockSession(response=response)

        headers_found, vulns = await scanner.scan("https://example.com", session)

        permissive_vulns = [v for v in vulns if "Overly Permissive CSP" in v.name]
        assert len(permissive_vulns) > 0
        assert permissive_vulns[0].severity == Severity.MEDIUM


class TestHSTSDetection:
    """Test Strict-Transport-Security header detection."""

    @pytest.mark.asyncio
    async def test_hsts_header_present(
        self, scanner: HeaderScanner
    ) -> None:
        """Test that HSTS header is detected when present."""
        response = MockResponse(headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains"})
        session = MockSession(response=response)

        headers_found, vulns = await scanner.scan("https://example.com", session)

        hsts_headers = [h for h in headers_found if h.name == "Strict-Transport-Security"]
        assert len(hsts_headers) > 0
        assert hsts_headers[0].present is True

    @pytest.mark.asyncio
    async def test_hsts_header_missing(
        self, scanner: HeaderScanner
    ) -> None:
        """Test that missing HSTS header is detected."""
        response = MockResponse(headers={})
        session = MockSession(response=response)

        headers_found, vulns = await scanner.scan("https://example.com", session)

        hsts_vulns = [v for v in vulns if "Missing Strict-Transport-Security" in v.name]
        assert len(hsts_vulns) > 0
        assert hsts_vulns[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_hsts_weak_max_age(
        self, scanner: HeaderScanner
    ) -> None:
        """Test that HSTS with weak max-age is flagged."""
        response = MockResponse(headers={"Strict-Transport-Security": "max-age=86400"})
        session = MockSession(response=response)

        headers_found, vulns = await scanner.scan("https://example.com", session)

        weak_vulns = [v for v in vulns if "Weak HSTS max-age" in v.name]
        assert len(weak_vulns) > 0
        assert weak_vulns[0].severity == Severity.LOW

    @pytest.mark.asyncio
    async def test_hsts_strong_max_age(
        self, scanner: HeaderScanner
    ) -> None:
        """Test that HSTS with strong max-age is not flagged."""
        response = MockResponse(headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains"})
        session = MockSession(response=response)

        headers_found, vulns = await scanner.scan("https://example.com", session)

        weak_vulns = [v for v in vulns if "Weak HSTS max-age" in v.name]
        assert len(weak_vulns) == 0


class TestXFrameOptionsDetection:
    """Test X-Frame-Options header detection."""

    @pytest.mark.asyncio
    async def test_x_frame_options_deny(
        self, scanner: HeaderScanner
    ) -> None:
        """Test that X-Frame-Options: DENY is accepted."""
        response = MockResponse(headers={"X-Frame-Options": "DENY"})
        session = MockSession(response=response)

        headers_found, vulns = await scanner.scan("https://example.com", session)

        xfo_headers = [h for h in headers_found if h.name == "X-Frame-Options"]
        assert len(xfo_headers) > 0
        assert xfo_headers[0].present is True

        insecure_vulns = [v for v in vulns if "Insecure X-Frame-Options" in v.name]
        assert len(insecure_vulns) == 0

    @pytest.mark.asyncio
    async def test_x_frame_options_sameorigin(
        self, scanner: HeaderScanner
    ) -> None:
        """Test that X-Frame-Options: SAMEORIGIN is accepted."""
        response = MockResponse(headers={"X-Frame-Options": "SAMEORIGIN"})
        session = MockSession(response=response)

        headers_found, vulns = await scanner.scan("https://example.com", session)

        xfo_headers = [h for h in headers_found if h.name == "X-Frame-Options"]
        assert len(xfo_headers) > 0

        insecure_vulns = [v for v in vulns if "Insecure X-Frame-Options" in v.name]
        assert len(insecure_vulns) == 0

    @pytest.mark.asyncio
    async def test_x_frame_options_missing(
        self, scanner: HeaderScanner
    ) -> None:
        """Test that missing X-Frame-Options is detected."""
        response = MockResponse(headers={})
        session = MockSession(response=response)

        headers_found, vulns = await scanner.scan("https://example.com", session)

        xfo_vulns = [v for v in vulns if "Missing X-Frame-Options" in v.name]
        assert len(xfo_vulns) > 0
        assert xfo_vulns[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_x_frame_options_insecure_value(
        self, scanner: HeaderScanner
    ) -> None:
        """Test that X-Frame-Options with insecure value is flagged."""
        response = MockResponse(headers={"X-Frame-Options": "ALLOW-FROM https://example.com"})
        session = MockSession(response=response)

        headers_found, vulns = await scanner.scan("https://example.com", session)

        insecure_vulns = [v for v in vulns if "Insecure X-Frame-Options" in v.name]
        assert len(insecure_vulns) > 0


class TestXContentTypeOptionsDetection:
    """Test X-Content-Type-Options header detection."""

    @pytest.mark.asyncio
    async def test_x_content_type_options_present(
        self, scanner: HeaderScanner
    ) -> None:
        """Test that X-Content-Type-Options header is detected."""
        response = MockResponse(headers={"X-Content-Type-Options": "nosniff"})
        session = MockSession(response=response)

        headers_found, vulns = await scanner.scan("https://example.com", session)

        xcto_headers = [h for h in headers_found if h.name == "X-Content-Type-Options"]
        assert len(xcto_headers) > 0
        assert xcto_headers[0].present is True

    @pytest.mark.asyncio
    async def test_x_content_type_options_missing(
        self, scanner: HeaderScanner
    ) -> None:
        """Test that missing X-Content-Type-Options is detected."""
        response = MockResponse(headers={})
        session = MockSession(response=response)

        headers_found, vulns = await scanner.scan("https://example.com", session)

        xcto_vulns = [v for v in vulns if "Missing X-Content-Type-Options" in v.name]
        assert len(xcto_vulns) > 0
        assert xcto_vulns[0].severity == Severity.LOW


class TestReferrerPolicyDetection:
    """Test Referrer-Policy header detection."""

    @pytest.mark.asyncio
    async def test_referrer_policy_present(
        self, scanner: HeaderScanner
    ) -> None:
        """Test that Referrer-Policy header is detected."""
        response = MockResponse(headers={"Referrer-Policy": "strict-origin-when-cross-origin"})
        session = MockSession(response=response)

        headers_found, vulns = await scanner.scan("https://example.com", session)

        rp_headers = [h for h in headers_found if h.name == "Referrer-Policy"]
        assert len(rp_headers) > 0
        assert rp_headers[0].present is True

    @pytest.mark.asyncio
    async def test_referrer_policy_missing(
        self, scanner: HeaderScanner
    ) -> None:
        """Test that missing Referrer-Policy is detected."""
        response = MockResponse(headers={})
        session = MockSession(response=response)

        headers_found, vulns = await scanner.scan("https://example.com", session)

        rp_vulns = [v for v in vulns if "Missing Referrer-Policy" in v.name]
        assert len(rp_vulns) > 0


class TestPermissionsPolicyDetection:
    """Test Permissions-Policy header detection."""

    @pytest.mark.asyncio
    async def test_permissions_policy_present(
        self, scanner: HeaderScanner
    ) -> None:
        """Test that Permissions-Policy header is detected."""
        response = MockResponse(headers={"Permissions-Policy": "camera=(), microphone=()"})
        session = MockSession(response=response)

        headers_found, vulns = await scanner.scan("https://example.com", session)

        pp_headers = [h for h in headers_found if h.name == "Permissions-Policy"]
        assert len(pp_headers) > 0
        assert pp_headers[0].present is True

    @pytest.mark.asyncio
    async def test_permissions_policy_missing(
        self, scanner: HeaderScanner
    ) -> None:
        """Test that missing Permissions-Policy is detected."""
        response = MockResponse(headers={})
        session = MockSession(response=response)

        headers_found, vulns = await scanner.scan("https://example.com", session)

        pp_vulns = [v for v in vulns if "Missing Permissions-Policy" in v.name]
        assert len(pp_vulns) > 0


class TestInformationDisclosure:
    """Test information disclosure header detection."""

    @pytest.mark.asyncio
    async def test_server_header_detected(
        self, scanner: HeaderScanner
    ) -> None:
        """Test that Server header is flagged as information disclosure."""
        response = MockResponse(headers={"Server": "Apache/2.4.41 (Ubuntu)"})
        session = MockSession(response=response)

        headers_found, vulns = await scanner.scan("https://example.com", session)

        disclosure_vulns = [v for v in vulns if "Information Disclosure: Server" in v.name]
        assert len(disclosure_vulns) > 0
        assert disclosure_vulns[0].severity == Severity.LOW

    @pytest.mark.asyncio
    async def test_x_powered_by_detected(
        self, scanner: HeaderScanner
    ) -> None:
        """Test that X-Powered-By header is flagged."""
        response = MockResponse(headers={"X-Powered-By": "PHP/7.4.3"})
        session = MockSession(response=response)

        headers_found, vulns = await scanner.scan("https://example.com", session)

        disclosure_vulns = [v for v in vulns if "Information Disclosure: X-Powered-By" in v.name]
        assert len(disclosure_vulns) > 0

    @pytest.mark.asyncio
    async def test_no_information_disclosure(
        self, scanner: HeaderScanner
    ) -> None:
        """Test that no information disclosure when headers absent."""
        response = MockResponse(headers={
            "Content-Type": "text/html",
            "Strict-Transport-Security": "max-age=31536000",
        })
        session = MockSession(response=response)

        headers_found, vulns = await scanner.scan("https://example.com", session)

        disclosure_vulns = [v for v in vulns if "Information Disclosure" in v.name]
        assert len(disclosure_vulns) == 0


class TestNoneResponse:
    """Test handling when response is None."""

    @pytest.mark.asyncio
    async def test_none_response_handled(
        self, scanner: HeaderScanner
    ) -> None:
        """Test that None response is handled gracefully."""
        session = MockSession(response=None)

        headers_found, vulns = await scanner.scan("https://example.com", session)

        assert isinstance(headers_found, list)
        assert isinstance(vulns, list)
        assert len(headers_found) == 0


class TestCompleteHeadersScan:
    """Test complete header security scan."""

    @pytest.mark.asyncio
    async def test_all_security_headers_present(
        self, scanner: HeaderScanner
    ) -> None:
        """Test when all security headers are present."""
        response = MockResponse(headers={
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=()",
        })
        session = MockSession(response=response)

        headers_found, vulns = await scanner.scan("https://example.com", session)

        # All security headers should be found
        assert len(headers_found) >= 6

        # No missing header vulnerabilities
        missing_vulns = [v for v in vulns if "Missing" in v.name]
        assert len(missing_vulns) == 0

    @pytest.mark.asyncio
    async def test_no_security_headers(
        self, scanner: HeaderScanner
    ) -> None:
        """Test when no security headers are present."""
        response = MockResponse(headers={
            "Content-Type": "text/html",
            "Server": "nginx",
        })
        session = MockSession(response=response)

        headers_found, vulns = await scanner.scan("https://example.com", session)

        # All security headers should be marked as missing
        missing_vulns = [v for v in vulns if "Missing" in v.name]
        assert len(missing_vulns) >= 6  # At least 6 expected headers

        # Information disclosure vulns
        disclosure_vulns = [v for v in vulns if "Information Disclosure" in v.name]
        assert len(disclosure_vulns) >= 1
