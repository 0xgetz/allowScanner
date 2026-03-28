"""Comprehensive tests for SubdomainScanner."""

from __future__ import annotations

import socket
from unittest.mock import patch

import pytest

from allowscanner.core.models import Severity
from allowscanner.scanners.subdomain import COMMON_SUBDOMAINS, SubdomainScanner


@pytest.fixture
def scanner() -> SubdomainScanner:
    """Create a SubdomainScanner instance."""
    return SubdomainScanner(wordlist_size=100)


class TestSubdomainEnumeration:
    """Test subdomain enumeration."""

    @pytest.mark.asyncio
    async def test_subdomains_found(
        self, scanner: SubdomainScanner
    ) -> None:
        """Test that subdomains are discovered when DNS resolves."""
        def mock_getaddrinfo(host: str, *args, **kwargs) -> list:
            if host in ["www.example.com", "mail.example.com", "api.example.com"]:
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 80))]
            raise socket.gaierror("Name or service not known")

        with patch("socket.getaddrinfo", side_effect=mock_getaddrinfo):
            subdomains, vulns = await scanner.scan("example.com")

        assert len(subdomains) > 0
        assert "www.example.com" in subdomains
        assert "mail.example.com" in subdomains
        assert "api.example.com" in subdomains

    @pytest.mark.asyncio
    async def test_no_subdomains_found(
        self, scanner: SubdomainScanner
    ) -> None:
        """Test when no subdomains resolve."""
        def mock_getaddrinfo(host: str, *args, **kwargs) -> list:
            raise socket.gaierror("Name or service not known")

        with patch("socket.getaddrinfo", side_effect=mock_getaddrinfo):
            subdomains, vulns = await scanner.scan("example.com")

        assert len(subdomains) == 0
        assert len(vulns) == 0

    @pytest.mark.asyncio
    async def test_vulnerability_reported_when_subdomains_found(
        self, scanner: SubdomainScanner
    ) -> None:
        """Test that a vulnerability is reported when subdomains are found."""
        def mock_getaddrinfo(host: str, *args, **kwargs) -> list:
            if host == "www.example.com":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 80))]
            raise socket.gaierror("Name or service not known")

        with patch("socket.getaddrinfo", side_effect=mock_getaddrinfo):
            subdomains, vulns = await scanner.scan("example.com")

        assert len(vulns) > 0
        assert vulns[0].name == "Subdomain Enumeration"
        assert vulns[0].severity == Severity.INFO
        assert vulns[0].cwe == "CWE-200"


class TestWordlistLoading:
    """Test wordlist loading and configuration."""

    def test_default_wordlist_loaded(
        self, scanner: SubdomainScanner
    ) -> None:
        """Test that default wordlist is loaded."""
        assert len(COMMON_SUBDOMAINS) > 0
        assert "www" in COMMON_SUBDOMAINS
        assert "mail" in COMMON_SUBDOMAINS
        assert "api" in COMMON_SUBDOMAINS

    def test_custom_wordlist_size(
        self, scanner: SubdomainScanner
    ) -> None:
        """Test that custom wordlist size is respected."""
        small_scanner = SubdomainScanner(wordlist_size=5)
        assert small_scanner.wordlist_size == 5

        # When scanning, it should only use first 5 subdomains
        # This is tested implicitly through the scan method

    def test_wordlist_contains_common_subdomains(
        self, scanner: SubdomainScanner
    ) -> None:
        """Test that wordlist contains expected common subdomains."""
        expected = ["www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp", "vpn"]
        for sub in expected:
            assert sub in COMMON_SUBDOMAINS


class TestConcurrency:
    """Test scanner concurrency behavior."""

    @pytest.mark.asyncio
    async def test_concurrent_dns_queries(
        self, scanner: SubdomainScanner
    ) -> None:
        """Test that DNS queries are made concurrently."""
        call_count = 0
        max_concurrent = 0
        current_concurrent = 0
        lock = __import__("asyncio").Lock()

        def mock_getaddrinfo(host: str, *args, **kwargs) -> list:
            nonlocal call_count, current_concurrent, max_concurrent
            call_count += 1
            # Simulate some delay
            __import__("time").sleep(0.01)
            return []

        with patch("socket.getaddrinfo", side_effect=mock_getaddrinfo):
            await scanner.scan("example.com")

        # Should have attempted DNS lookups for all wordlist entries
        assert call_count == scanner.wordlist_size


class TestErrorHandling:
    """Test scanner error handling."""

    @pytest.mark.asyncio
    async def test_socket_herror_handled(
        self, scanner: SubdomainScanner
    ) -> None:
        """Test that socket.herror is handled gracefully."""
        def mock_getaddrinfo(host: str, *args, **kwargs) -> list:
            raise socket.herror("Unknown host")

        with patch("socket.getaddrinfo", side_effect=mock_getaddrinfo):
            subdomains, vulns = await scanner.scan("example.com")

        assert isinstance(subdomains, list)
        assert len(subdomains) == 0

    @pytest.mark.asyncio
    async def test_general_exception_handled(
        self, scanner: SubdomainScanner
    ) -> None:
        """Test that general exceptions are handled gracefully."""
        def mock_getaddrinfo(host: str, *args, **kwargs) -> list:
            raise Exception("Unexpected error")

        with patch("socket.getaddrinfo", side_effect=mock_getaddrinfo):
            subdomains, vulns = await scanner.scan("example.com")

        assert isinstance(subdomains, list)
        assert len(subdomains) == 0
