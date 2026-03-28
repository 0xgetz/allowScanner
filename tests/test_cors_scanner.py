"""Comprehensive tests for CORSScanner."""

from __future__ import annotations

import pytest

from allowscanner.core.models import Severity
from allowscanner.scanners.cors import CORSScanner


class MockResponse:
    """Mock aiohttp ClientResponse for CORS testing."""

    def __init__(self, headers: dict | None = None) -> None:
        self._headers = headers or {}

    @property
    def headers(self) -> dict:
        return self._headers


class MockSession:
    """Mock aiohttp ClientSession for CORS testing."""

    def __init__(self, response: MockResponse | None = None) -> None:
        self.response = response
        self.request_count = 0
        self.last_origin = None

    async def get(self, url: str, **kwargs) -> tuple:
        self.request_count += 1
        self.last_origin = kwargs.get("headers", {}).get("Origin")
        if self.response:
            return self.response, ""
        return None, ""


@pytest.fixture
def scanner() -> CORSScanner:
    """Create a CORSScanner instance."""
    return CORSScanner()


class TestWildcardOrigin:
    """Test wildcard origin CORS misconfiguration."""

    @pytest.mark.asyncio
    async def test_wildcard_with_credentials_critical(
        self, scanner: CORSScanner
    ) -> None:
        """Test that wildcard origin with credentials is critical."""
        response = MockResponse(headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        })
        session = MockSession(response=response)

        vulns = await scanner.scan("https://example.com", session)

        wildcard_vulns = [v for v in vulns if "Wildcard + Credentials" in v.name]
        assert len(wildcard_vulns) > 0
        assert wildcard_vulns[0].severity == Severity.CRITICAL
        assert wildcard_vulns[0].cwe == "CWE-942"

    @pytest.mark.asyncio
    async def test_wildcard_without_credentials_info(
        self, scanner: CORSScanner
    ) -> None:
        """Test that wildcard origin without credentials is informational."""
        response = MockResponse(headers={
            "Access-Control-Allow-Origin": "*",
        })
        session = MockSession(response=response)

        vulns = await scanner.scan("https://example.com", session)

        public_vulns = [v for v in vulns if "Public API (Wildcard)" in v.name]
        assert len(public_vulns) > 0
        assert public_vulns[0].severity == Severity.INFO


class TestReflectedOrigin:
    """Test reflected origin CORS misconfiguration."""

    @pytest.mark.asyncio
    async def test_reflected_origin_with_credentials_high(
        self, scanner: CORSScanner
    ) -> None:
        """Test that reflected origin with credentials is high severity."""
        response = MockResponse(headers={
            "Access-Control-Allow-Origin": "https://evil.com",
            "Access-Control-Allow-Credentials": "true",
        })
        session = MockSession(response=response)

        vulns = await scanner.scan("https://example.com", session)

        reflected_vulns = [v for v in vulns if "Reflected Origin with Credentials" in v.name]
        assert len(reflected_vulns) > 0
        assert reflected_vulns[0].severity == Severity.HIGH
        assert reflected_vulns[0].cwe == "CWE-942"

    @pytest.mark.asyncio
    async def test_reflected_origin_without_credentials_low(
        self, scanner: CORSScanner
    ) -> None:
        """Test that reflected origin without credentials is low severity."""
        response = MockResponse(headers={
            "Access-Control-Allow-Origin": "https://evil.com",
        })
        session = MockSession(response=response)

        vulns = await scanner.scan("https://example.com", session)

        reflected_vulns = [v for v in vulns if "Reflected Origin" in v.name and "Credentials" not in v.name]
        assert len(reflected_vulns) > 0
        assert reflected_vulns[0].severity == Severity.LOW


class TestNullOrigin:
    """Test null origin CORS misconfiguration."""

    @pytest.mark.asyncio
    async def test_null_origin_allowed(
        self, scanner: CORSScanner
    ) -> None:
        """Test that allowing null origin is medium severity."""
        response = MockResponse(headers={
            "Access-Control-Allow-Origin": "null",
        })
        session = MockSession(response=response)

        vulns = await scanner.scan("https://example.com", session)

        null_vulns = [v for v in vulns if "Null Origin Allowed" in v.name]
        assert len(null_vulns) > 0
        assert null_vulns[0].severity == Severity.MEDIUM
        assert null_vulns[0].cwe == "CWE-942"


class TestNoCORSHeaders:
    """Test when no CORS headers are present."""

    @pytest.mark.asyncio
    async def test_no_cors_headers(
        self, scanner: CORSScanner
    ) -> None:
        """Test that no CORS headers means no vulnerabilities."""
        response = MockResponse(headers={})
        session = MockSession(response=response)

        vulns = await scanner.scan("https://example.com", session)

        cors_vulns = [v for v in vulns if "CORS" in v.name]
        assert len(cors_vulns) == 0


class TestDeduplication:
    """Test vulnerability deduplication."""

    @pytest.mark.asyncio
    async def test_vulnerabilities_deduplicated(
        self, scanner: CORSScanner
    ) -> None:
        """Test that duplicate vulnerabilities are removed."""
        response = MockResponse(headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        })
        session = MockSession(response=response)

        vulns = await scanner.scan("https://example.com", session)

        # Should only have one critical wildcard vuln, not multiple
        wildcard_vulns = [v for v in vulns if "Wildcard + Credentials" in v.name]
        assert len(wildcard_vulns) == 1


class TestNoneResponse:
    """Test handling when response is None."""

    @pytest.mark.asyncio
    async def test_none_response_handled(
        self, scanner: CORSScanner
    ) -> None:
        """Test that None response is handled gracefully."""
        session = MockSession(response=None)

        vulns = await scanner.scan("https://example.com", session)

        assert isinstance(vulns, list)
        assert len(vulns) == 0
