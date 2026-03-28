"""Comprehensive tests for CookieScanner."""

from __future__ import annotations

import pytest

from allowscanner.core.models import Severity
from allowscanner.scanners.cookies import CookieScanner


class MockCookie:
    """Mock aiohttp Cookie."""

    def __init__(self, key: str, value: str = "", attributes: dict | None = None) -> None:
        self.key = key
        self.value = value
        self._attributes = attributes or {}

    def get(self, attr: str) -> bool | None:
        return self._attributes.get(attr.lower())


class MockResponse:
    """Mock aiohttp ClientResponse for cookie testing."""

    def __init__(self, cookies: dict | None = None, headers: dict | None = None) -> None:
        self._cookies = cookies or {}
        self._headers = headers or {}

    @property
    def cookies(self) -> dict:
        return self._cookies

    @property
    def headers(self) -> dict:
        return self._headers


class MockSession:
    """Mock aiohttp ClientSession for cookie testing."""

    def __init__(self, response: MockResponse | None = None) -> None:
        self.response = response

    async def get(self, url: str, **kwargs) -> tuple:
        if self.response:
            return self.response, ""
        return None, ""


@pytest.fixture
def scanner() -> CookieScanner:
    """Create a CookieScanner instance."""
    return CookieScanner()


class TestSecureFlag:
    """Test Secure flag detection."""

    @pytest.mark.asyncio
    async def test_cookie_missing_secure_flag(
        self, scanner: CookieScanner
    ) -> None:
        """Test that cookie without Secure flag is detected."""
        cookies = {"session": MockCookie("session", "abc123", {"httponly": True})}
        response = MockResponse(cookies=cookies)
        session = MockSession(response=response)

        vulns = await scanner.scan("https://example.com", session)

        insecure_vulns = [v for v in vulns if "Insecure Cookie" in v.name]
        assert len(insecure_vulns) > 0
        assert insecure_vulns[0].severity == Severity.MEDIUM
        assert insecure_vulns[0].cwe == "CWE-614"

    @pytest.mark.asyncio
    async def test_cookie_with_secure_flag(
        self, scanner: CookieScanner
    ) -> None:
        """Test that cookie with Secure flag is not flagged."""
        cookies = {"session": MockCookie("session", "abc123", {"secure": True, "httponly": True})}
        response = MockResponse(cookies=cookies)
        session = MockSession(response=response)

        vulns = await scanner.scan("https://example.com", session)

        insecure_vulns = [v for v in vulns if "Insecure Cookie" in v.name]
        assert len(insecure_vulns) == 0


class TestHttpOnlyFlag:
    """Test HttpOnly flag detection."""

    @pytest.mark.asyncio
    async def test_cookie_missing_httponly_flag(
        self, scanner: CookieScanner
    ) -> None:
        """Test that cookie without HttpOnly flag is detected."""
        cookies = {"session": MockCookie("session", "abc123", {"secure": True})}
        response = MockResponse(cookies=cookies)
        session = MockSession(response=response)

        vulns = await scanner.scan("https://example.com", session)

        httponly_vulns = [v for v in vulns if "Missing HttpOnly" in v.name]
        assert len(httponly_vulns) > 0
        assert httponly_vulns[0].severity == Severity.MEDIUM
        assert httponly_vulns[0].cwe == "CWE-1004"

    @pytest.mark.asyncio
    async def test_cookie_with_httponly_flag(
        self, scanner: CookieScanner
    ) -> None:
        """Test that cookie with HttpOnly flag is not flagged."""
        cookies = {"session": MockCookie("session", "abc123", {"secure": True, "httponly": True})}
        response = MockResponse(cookies=cookies)
        session = MockSession(response=response)

        vulns = await scanner.scan("https://example.com", session)

        httponly_vulns = [v for v in vulns if "Missing HttpOnly" in v.name]
        assert len(httponly_vulns) == 0


class TestSameSiteAttribute:
    """Test SameSite attribute detection."""

    @pytest.mark.asyncio
    async def test_cookie_missing_samesite(
        self, scanner: CookieScanner
    ) -> None:
        """Test that cookie without SameSite is detected via raw header."""
        raw_cookie = "session=abc123; Secure; HttpOnly"
        response = MockResponse(headers={"Set-Cookie": raw_cookie})
        session = MockSession(response=response)

        vulns = await scanner.scan("https://example.com", session)

        samesite_vulns = [v for v in vulns if "Missing SameSite" in v.name]
        assert len(samesite_vulns) > 0
        assert samesite_vulns[0].severity == Severity.LOW
        assert samesite_vulns[0].cwe == "CWE-1275"

    @pytest.mark.asyncio
    async def test_cookie_with_samesite(
        self, scanner: CookieScanner
    ) -> None:
        """Test that cookie with SameSite is not flagged."""
        raw_cookie = "session=abc123; Secure; HttpOnly; SameSite=Lax"
        response = MockResponse(headers={"Set-Cookie": raw_cookie})
        session = MockSession(response=response)

        vulns = await scanner.scan("https://example.com", session)

        samesite_vulns = [v for v in vulns if "Missing SameSite" in v.name]
        assert len(samesite_vulns) == 0


class TestRawCookieHeader:
    """Test raw Set-Cookie header parsing."""

    @pytest.mark.asyncio
    async def test_raw_cookie_multiple_issues(
        self, scanner: CookieScanner
    ) -> None:
        """Test that raw cookie header with multiple issues is detected."""
        raw_cookie = "session=abc123"
        response = MockResponse(headers={"Set-Cookie": raw_cookie})
        session = MockSession(response=response)

        vulns = await scanner.scan("https://example.com", session)

        # Should detect missing Secure, HttpOnly, and SameSite
        assert len(vulns) >= 3

        secure_vulns = [v for v in vulns if "Insecure Cookie" in v.name]
        httponly_vulns = [v for v in vulns if "Missing HttpOnly" in v.name]
        samesite_vulns = [v for v in vulns if "Missing SameSite" in v.name]

        assert len(secure_vulns) > 0
        assert len(httponly_vulns) > 0
        assert len(samesite_vulns) > 0

    @pytest.mark.asyncio
    async def test_raw_cookie_secure_httponly_samesite(
        self, scanner: CookieScanner
    ) -> None:
        """Test that raw cookie with all security attributes is not flagged."""
        raw_cookie = "session=abc123; Secure; HttpOnly; SameSite=Strict"
        response = MockResponse(headers={"Set-Cookie": raw_cookie})
        session = MockSession(response=response)

        vulns = await scanner.scan("https://example.com", session)

        assert len(vulns) == 0


class TestNoCookies:
    """Test when no cookies are present."""

    @pytest.mark.asyncio
    async def test_no_cookies_returns_empty(
        self, scanner: CookieScanner
    ) -> None:
        """Test that no cookies means no vulnerabilities."""
        response = MockResponse(cookies={}, headers={})
        session = MockSession(response=response)

        vulns = await scanner.scan("https://example.com", session)

        assert len(vulns) == 0

    @pytest.mark.asyncio
    async def test_none_response_returns_empty(
        self, scanner: CookieScanner
    ) -> None:
        """Test that None response is handled gracefully."""
        session = MockSession(response=None)

        vulns = await scanner.scan("https://example.com", session)

        assert isinstance(vulns, list)
        assert len(vulns) == 0


class TestMultipleCookies:
    """Test multiple cookies scanning."""

    @pytest.mark.asyncio
    async def test_multiple_cookies_scanned(
        self, scanner: CookieScanner
    ) -> None:
        """Test that all cookies are scanned for security issues."""
        cookies = {
            "session": MockCookie("session", "abc123", {"secure": True, "httponly": True}),
            "tracking": MockCookie("tracking", "xyz789", {}),  # No security flags
        }
        response = MockResponse(cookies=cookies)
        session = MockSession(response=response)

        vulns = await scanner.scan("https://example.com", session)

        # tracking cookie should have 2 vulns (missing secure, missing httponly)
        tracking_vulns = [v for v in vulns if "tracking" in v.name.lower()]
        assert len(tracking_vulns) >= 2
