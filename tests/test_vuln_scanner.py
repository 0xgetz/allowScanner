"""Comprehensive tests for VulnerabilityScanner."""

from __future__ import annotations

import asyncio

import pytest

from allowscanner.core.config import ScanConfig
from allowscanner.core.models import Severity
from allowscanner.scanners.vuln import VulnerabilityScanner


# Fixtures
@pytest.fixture
def config() -> ScanConfig:
    """Create a test configuration."""
    return ScanConfig(concurrency=10, timeout=5)


@pytest.fixture
def scanner(config: ScanConfig) -> VulnerabilityScanner:
    """Create a VulnerabilityScanner instance."""
    return VulnerabilityScanner(config)


class MockResponse:
    """Mock aiohttp ClientResponse."""

    def __init__(
        self,
        status: int = 200,
        headers: dict | None = None,
        cookies: dict | None = None,
    ) -> None:
        self.status = status
        self._headers = headers or {}
        self._cookies = cookies or {}

    @property
    def headers(self) -> dict:
        return self._headers

    @property
    def cookies(self) -> dict:
        return self._cookies


class MockSession:
    """Mock aiohttp ClientSession for testing."""

    def __init__(self, responses: list | None = None) -> None:
        self.responses = responses or []
        self.call_count = 0

    async def get(self, url: str, **kwargs) -> tuple:
        """Mock GET request."""
        if self.responses and self.call_count < len(self.responses):
            resp = self.responses[self.call_count]
            self.call_count += 1
            return resp, "mock content"
        return None, ""

    async def request(self, method: str, url: str, **kwargs) -> tuple:
        """Mock any request method."""
        if self.responses and self.call_count < len(self.responses):
            resp = self.responses[self.call_count]
            self.call_count += 1
            return resp, "mock content"
        return None, ""


# SQL Injection Tests
class TestSQLInjectionDetection:
    """Test SQL injection vulnerability detection."""

    @pytest.mark.asyncio
    async def test_sql_injection_detected_with_error_message(
        self, scanner: VulnerabilityScanner
    ) -> None:
        """Test that SQL injection is detected when error message is present."""
        mock_response = MockResponse(status=200, headers={})
        session = MockSession(responses=[mock_response] * 20)

        async def mock_get(url: str, **kwargs) -> tuple:
            content = "You have an error in your SQL syntax near ' at line 1"
            return mock_response, content

        session.get = mock_get  # type: ignore

        vulns = await scanner.scan("https://example.com", session)
        sql_vulns = [v for v in vulns if "SQL Injection" in v.name]

        assert len(sql_vulns) > 0
        assert sql_vulns[0].severity == Severity.CRITICAL
        assert sql_vulns[0].cwe == "CWE-89"

    @pytest.mark.asyncio
    async def test_sql_injection_not_detected_without_indicators(
        self, scanner: VulnerabilityScanner
    ) -> None:
        """Test that SQL injection is not detected when no indicators present."""
        mock_response = MockResponse(status=200, headers={})
        session = MockSession(responses=[mock_response] * 20)

        async def mock_get(url: str, **kwargs) -> tuple:
            content = "Normal page content without SQL errors"
            return mock_response, content

        session.get = mock_get  # type: ignore

        vulns = await scanner.scan("https://example.com", session)
        sql_vulns = [v for v in vulns if "SQL Injection" in v.name]

        assert len(sql_vulns) == 0


# XSS Detection Tests
class TestXSSDetection:
    """Test XSS vulnerability detection."""

    @pytest.mark.asyncio
    async def test_xss_detected_with_reflected_payload(
        self, scanner: VulnerabilityScanner
    ) -> None:
        """Test that XSS is detected when payload is reflected."""
        mock_response = MockResponse(status=200, headers={})
        session = MockSession(responses=[mock_response] * 20)

        async def mock_get(url: str, **kwargs) -> tuple:
            content = "<script>alert('XSS')</script>"
            return mock_response, content

        session.get = mock_get  # type: ignore

        vulns = await scanner.scan("https://example.com", session)
        xss_vulns = [v for v in vulns if "XSS" in v.name]

        assert len(xss_vulns) > 0
        assert xss_vulns[0].severity == Severity.HIGH
        assert xss_vulns[0].cwe == "CWE-79"

    @pytest.mark.asyncio
    async def test_xss_not_detected_when_sanitized(
        self, scanner: VulnerabilityScanner
    ) -> None:
        """Test that XSS is not detected when content is sanitized."""
        mock_response = MockResponse(status=200, headers={})
        session = MockSession(responses=[mock_response] * 20)

        async def mock_get(url: str, **kwargs) -> tuple:
            content = "Search results for: &lt;script&gt;alert(1)&lt;/script&gt;"
            return mock_response, content

        session.get = mock_get  # type: ignore

        vulns = await scanner.scan("https://example.com", session)
        xss_vulns = [v for v in vulns if "XSS" in v.name]

        assert len(xss_vulns) == 0


# Directory Traversal Tests
class TestDirectoryTraversalDetection:
    """Test directory traversal vulnerability detection."""

    @pytest.mark.asyncio
    async def test_directory_traversal_detected_with_passwd(
        self, scanner: VulnerabilityScanner
    ) -> None:
        """Test that directory traversal is detected when /etc/passwd content is present."""
        mock_response = MockResponse(status=200, headers={})
        session = MockSession(responses=[mock_response] * 20)

        async def mock_get(url: str, **kwargs) -> tuple:
            content = "root:x:0:0:root:/root:/bin/bash"
            return mock_response, content

        session.get = mock_get  # type: ignore

        vulns = await scanner.scan("https://example.com", session)
        traversal_vulns = [v for v in vulns if "Directory Traversal" in v.name]

        assert len(traversal_vulns) > 0
        assert traversal_vulns[0].severity == Severity.HIGH
        assert traversal_vulns[0].cwe == "CWE-22"


# Command Injection Tests
class TestCommandInjectionDetection:
    """Test command injection vulnerability detection."""

    @pytest.mark.asyncio
    async def test_command_injection_detected_with_id_output(
        self, scanner: VulnerabilityScanner
    ) -> None:
        """Test that command injection is detected when id output is present."""
        mock_response = MockResponse(status=200, headers={})
        session = MockSession(responses=[mock_response] * 20)

        async def mock_get(url: str, **kwargs) -> tuple:
            content = "uid=0(root) gid=0(root) groups=0(root)"
            return mock_response, content

        session.get = mock_get  # type: ignore

        vulns = await scanner.scan("https://example.com", session)
        cmdi_vulns = [v for v in vulns if "Command Injection" in v.name]

        assert len(cmdi_vulns) > 0
        assert cmdi_vulns[0].severity == Severity.CRITICAL
        assert cmdi_vulns[0].cwe == "CWE-78"


# Sensitive File Exposure Tests
class TestSensitiveFileExposure:
    """Test sensitive file exposure detection."""

    @pytest.mark.asyncio
    async def test_env_file_exposed_with_credentials(
        self, scanner: VulnerabilityScanner
    ) -> None:
        """Test that .env file with credentials is detected as critical."""
        mock_response = MockResponse(status=200, headers={})
        session = MockSession(responses=[mock_response] * 100)

        async def mock_get(url: str, **kwargs) -> tuple:
            if "/.env" in url:
                content = "DB_PASSWORD=secret123\nAPI_KEY=abc123"
            else:
                content = "Not found"
            return mock_response, content

        session.get = mock_get  # type: ignore

        vulns = await scanner.scan("https://example.com", session)
        env_vulns = [v for v in vulns if "Sensitive File" in v.name and "/.env" in v.url]

        assert len(env_vulns) > 0
        assert env_vulns[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_git_exposed_detected(
        self, scanner: VulnerabilityScanner
    ) -> None:
        """Test that .git/config exposure is detected as high severity."""
        mock_response = MockResponse(status=200, headers={})
        session = MockSession(responses=[mock_response] * 100)

        async def mock_get(url: str, **kwargs) -> tuple:
            if "/.git/config" in url:
                content = "[core]\nrepositoryformatversion = 0"
            else:
                content = "Not found"
            return mock_response, content

        session.get = mock_get  # type: ignore

        vulns = await scanner.scan("https://example.com", session)
        git_vulns = [v for v in vulns if "Sensitive File" in v.name and ".git" in v.url]

        assert len(git_vulns) > 0
        assert git_vulns[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_sensitive_file_not_detected_when_404(
        self, scanner: VulnerabilityScanner
    ) -> None:
        """Test that sensitive files are not detected when returning 404."""
        mock_response = MockResponse(status=404, headers={})
        session = MockSession(responses=[mock_response] * 100)

        async def mock_get(url: str, **kwargs) -> tuple:
            return mock_response, "Not Found"

        session.get = mock_get  # type: ignore

        vulns = await scanner.scan("https://example.com", session)
        sensitive_vulns = [v for v in vulns if "Sensitive File" in v.name]

        assert len(sensitive_vulns) == 0


# Admin Panel Detection Tests
class TestAdminPanelDetection:
    """Test admin panel discovery."""

    @pytest.mark.asyncio
    async def test_admin_panel_detected(
        self, scanner: VulnerabilityScanner
    ) -> None:
        """Test that admin panel is detected when login indicators present."""
        mock_response = MockResponse(status=200, headers={})
        session = MockSession(responses=[mock_response] * 100)

        async def mock_get(url: str, **kwargs) -> tuple:
            if "/admin" in url:
                content = "<html><form><input name='username'><input name='password'></form></html>"
            else:
                content = "Not found"
            return mock_response, content

        session.get = mock_get  # type: ignore

        vulns = await scanner.scan("https://example.com", session)
        admin_vulns = [v for v in vulns if "Admin Panel" in v.name]

        assert len(admin_vulns) > 0
        assert admin_vulns[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_admin_panel_not_detected_without_indicators(
        self, scanner: VulnerabilityScanner
    ) -> None:
        """Test that page without admin indicators is not detected."""
        mock_response = MockResponse(status=200, headers={})
        session = MockSession(responses=[mock_response] * 100)

        async def mock_get(url: str, **kwargs) -> tuple:
            content = "<html><body>Just a regular page</body></html>"
            return mock_response, content

        session.get = mock_get  # type: ignore

        vulns = await scanner.scan("https://example.com", session)
        admin_vulns = [v for v in vulns if "Admin Panel" in v.name]

        assert len(admin_vulns) == 0


# Backup File Exposure Tests
class TestBackupFileExposure:
    """Test backup file exposure detection."""

    @pytest.mark.asyncio
    async def test_backup_file_detected(
        self, scanner: VulnerabilityScanner
    ) -> None:
        """Test that backup files are detected when accessible."""
        mock_response = MockResponse(status=200, headers={})
        session = MockSession(responses=[mock_response] * 100)

        async def mock_get(url: str, **kwargs) -> tuple:
            if "/config.bak" in url:
                content = "config data " * 20  # >100 chars
            else:
                content = "Not found"
            return mock_response, content

        session.get = mock_get  # type: ignore

        vulns = await scanner.scan("https://example.com", session)
        backup_vulns = [v for v in vulns if "Backup File" in v.name]

        assert len(backup_vulns) > 0
        assert backup_vulns[0].severity == Severity.MEDIUM


# Error Handling Tests
class TestErrorHandling:
    """Test scanner error handling."""

    @pytest.mark.asyncio
    async def test_scanner_handles_none_response(
        self, scanner: VulnerabilityScanner
    ) -> None:
        """Test that scanner handles None response gracefully."""
        session = MockSession()

        async def mock_get(url: str, **kwargs) -> tuple:
            return None, ""

        session.get = mock_get  # type: ignore

        vulns = await scanner.scan("https://example.com", session)
        assert isinstance(vulns, list)

    @pytest.mark.asyncio
    async def test_scanner_handles_connection_error(
        self, scanner: VulnerabilityScanner
    ) -> None:
        """Test that scanner handles connection errors gracefully."""
        session = MockSession()

        async def mock_get(url: str, **kwargs) -> tuple:
            raise ConnectionError("Connection refused")

        session.get = mock_get  # type: ignore

        vulns = await scanner.scan("https://example.com", session)
        assert isinstance(vulns, list)

    @pytest.mark.asyncio
    async def test_scanner_handles_timeout(
        self, scanner: VulnerabilityScanner
    ) -> None:
        """Test that scanner handles timeouts gracefully."""
        session = MockSession()

        async def mock_get(url: str, **kwargs) -> tuple:
            raise asyncio.TimeoutError()

        session.get = mock_get  # type: ignore

        vulns = await scanner.scan("https://example.com", session)
        assert isinstance(vulns, list)


# Open Redirect Tests
class TestOpenRedirect:
    """Test open redirect vulnerability detection."""

    @pytest.mark.asyncio
    async def test_open_redirect_detected(
        self, scanner: VulnerabilityScanner
    ) -> None:
        """Test that open redirect is detected when Location header contains attacker URL."""
        mock_response = MockResponse(
            status=302,
            headers={"Location": "https://evil.com"},
        )
        session = MockSession(responses=[mock_response] * 20)

        async def mock_request(method: str, url: str, **kwargs) -> tuple:
            content = ""
            return mock_response, content

        session.request = mock_request  # type: ignore

        vulns = await scanner.scan("https://example.com", session)
        redirect_vulns = [v for v in vulns if "Open Redirect" in v.name]

        assert len(redirect_vulns) > 0
        assert redirect_vulns[0].severity == Severity.MEDIUM
        assert redirect_vulns[0].cwe == "CWE-601"


# Concurrency Tests
class TestConcurrency:
    """Test scanner concurrency behavior."""

    @pytest.mark.asyncio
    async def test_scanner_respects_concurrency_limit(
        self, scanner: VulnerabilityScanner
    ) -> None:
        """Test that scanner respects concurrency limits."""
        lock = asyncio.Lock()
        concurrent_count = 0
        max_concurrent = 0

        mock_response = MockResponse(status=200, headers={})

        async def mock_get(url: str, **kwargs) -> tuple:
            nonlocal concurrent_count, max_concurrent
            async with lock:
                concurrent_count += 1
                max_concurrent = max(max_concurrent, concurrent_count)

            await asyncio.sleep(0.01)  # Simulate network delay

            async with lock:
                concurrent_count -= 1

            return mock_response, "content"

        session = MockSession()
        session.get = mock_get  # type: ignore

        await scanner.scan("https://example.com", session)

        # Should not exceed configured concurrency
        assert max_concurrent <= scanner.config.concurrency
