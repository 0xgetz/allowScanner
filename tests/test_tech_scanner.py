"""Comprehensive tests for TechScanner."""

from __future__ import annotations

import pytest

from allowscanner.scanners.tech import TechScanner


class MockResponse:
    """Mock aiohttp ClientResponse for tech testing."""

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
    """Mock aiohttp ClientSession for tech testing."""

    def __init__(self, response: MockResponse | None = None) -> None:
        self.response = response

    async def get(self, url: str, **kwargs) -> tuple:
        if self.response:
            return self.response, ""
        return None, ""


@pytest.fixture
def scanner() -> TechScanner:
    """Create a TechScanner instance."""
    return TechScanner()


class TestFrameworkDetection:
    """Test web framework detection."""

    @pytest.mark.asyncio
    async def test_wordpress_detected_by_content(
        self, scanner: TechScanner
    ) -> None:
        """Test that WordPress is detected from content patterns."""
        response = MockResponse(headers={})
        session = MockSession(response=response)

        async def mock_get(url: str, **kwargs) -> tuple:
            content = "<link rel='stylesheet' href='/wp-content/themes/twentytwenty/style.css'>"
            return response, content

        session.get = mock_get  # type: ignore

        technologies = await scanner.scan("https://example.com", session)
        wp_tech = [t for t in technologies if t.name == "WordPress"]

        assert len(wp_tech) > 0
        assert wp_tech[0].category == "CMS"

    @pytest.mark.asyncio
    async def test_laravel_detected_by_content(
        self, scanner: TechScanner
    ) -> None:
        """Test that Laravel is detected from content patterns."""
        response = MockResponse(headers={})
        session = MockSession(response=response)

        async def mock_get(url: str, **kwargs) -> tuple:
            content = "<meta name='csrf-token' content='abc123'>"
            return response, content

        session.get = mock_get  # type: ignore

        technologies = await scanner.scan("https://example.com", session)
        laravel_tech = [t for t in technologies if t.name == "Laravel"]

        assert len(laravel_tech) > 0
        assert laravel_tech[0].category == "Framework"

    @pytest.mark.asyncio
    async def test_django_detected_by_content(
        self, scanner: TechScanner
    ) -> None:
        """Test that Django is detected from content patterns."""
        response = MockResponse(headers={})
        session = MockSession(response=response)

        async def mock_get(url: str, **kwargs) -> tuple:
            content = "<input type='hidden' name='csrfmiddlewaretoken' value='xyz'>"
            return response, content

        session.get = mock_get  # type: ignore

        technologies = await scanner.scan("https://example.com", session)
        django_tech = [t for t in technologies if t.name == "Django"]

        assert len(django_tech) > 0
        assert django_tech[0].category == "Framework"

    @pytest.mark.asyncio
    async def test_react_detected_by_content(
        self, scanner: TechScanner
    ) -> None:
        """Test that React is detected from content patterns."""
        response = MockResponse(headers={})
        session = MockSession(response=response)

        async def mock_get(url: str, **kwargs) -> tuple:
            content = "<div id='__reactRootContainer'></div>"
            return response, content

        session.get = mock_get  # type: ignore

        technologies = await scanner.scan("https://example.com", session)
        react_tech = [t for t in technologies if t.name == "React"]

        assert len(react_tech) > 0
        assert react_tech[0].category == "Frontend"


class TestServerDetection:
    """Test web server detection."""

    @pytest.mark.asyncio
    async def test_nginx_detected_by_header(
        self, scanner: TechScanner
    ) -> None:
        """Test that Nginx is detected from Server header."""
        response = MockResponse(headers={"Server": "nginx/1.18.0"})
        session = MockSession(response=response)

        technologies = await scanner.scan("https://example.com", session)
        nginx_tech = [t for t in technologies if t.name == "Nginx"]

        assert len(nginx_tech) > 0
        assert nginx_tech[0].category == "Web Server"

    @pytest.mark.asyncio
    async def test_apache_detected_by_header(
        self, scanner: TechScanner
    ) -> None:
        """Test that Apache is detected from Server header."""
        response = MockResponse(headers={"Server": "Apache/2.4.41 (Ubuntu)"})
        session = MockSession(response=response)

        technologies = await scanner.scan("https://example.com", session)
        apache_tech = [t for t in technologies if t.name == "Apache"]

        assert len(apache_tech) > 0
        assert apache_tech[0].category == "Web Server"

    @pytest.mark.asyncio
    async def test_cloudflare_detected_by_header(
        self, scanner: TechScanner
    ) -> None:
        """Test that Cloudflare is detected from headers."""
        response = MockResponse(headers={"server": "cloudflare", "cf-ray": "6b8f2a1b2c3d4e5f"})
        session = MockSession(response=response)

        technologies = await scanner.scan("https://example.com", session)
        cf_tech = [t for t in technologies if t.name == "Cloudflare"]

        assert len(cf_tech) > 0
        assert cf_tech[0].category == "CDN/WAF"


class TestVersionDetection:
    """Test technology version detection."""

    @pytest.mark.asyncio
    async def test_version_detected_from_meta_generator(
        self, scanner: TechScanner
    ) -> None:
        """Test that version is extracted from meta generator tag."""
        response = MockResponse(headers={})
        session = MockSession(response=response)

        async def mock_get(url: str, **kwargs) -> tuple:
            content = """
            <html>
            <head>
                <meta name="generator" content="WordPress 5.8.1">
                <link rel='stylesheet' href='/wp-content/themes/test/style.css'>
            </head>
            </html>
            """
            return response, content

        session.get = mock_get  # type: ignore

        technologies = await scanner.scan("https://example.com", session)
        wp_tech = [t for t in technologies if t.name == "WordPress"]

        assert len(wp_tech) > 0
        assert wp_tech[0].version == "5.8.1"


class TestMultipleTechnologies:
    """Test detection of multiple technologies."""

    @pytest.mark.asyncio
    async def test_multiple_technologies_detected(
        self, scanner: TechScanner
    ) -> None:
        """Test that multiple technologies are detected in one page."""
        response = MockResponse(headers={"Server": "nginx/1.18.0"})
        session = MockSession(response=response)

        async def mock_get(url: str, **kwargs) -> tuple:
            content = """
            <html>
            <head>
                <link rel='stylesheet' href='/wp-content/themes/test/style.css'>
                <script src='/wp-includes/js/jquery.min.js'></script>
            </head>
            <body>
                <div id='__reactRootContainer'></div>
            </body>
            </html>
            """
            return response, content

        session.get = mock_get  # type: ignore

        technologies = await scanner.scan("https://example.com", session)
        tech_names = [t.name for t in technologies]

        assert "WordPress" in tech_names
        assert "jQuery" in tech_names
        assert "React" in tech_names
        assert "Nginx" in tech_names


class TestNoTechnologiesDetected:
    """Test when no technologies are detected."""

    @pytest.mark.asyncio
    async def test_no_technologies_detected(
        self, scanner: TechScanner
    ) -> None:
        """Test that no technologies are detected when patterns don't match."""
        response = MockResponse(headers={"Server": "CustomServer/1.0"})
        session = MockSession(response=response)

        async def mock_get(url: str, **kwargs) -> tuple:
            content = "<html><body><h1>Hello World</h1></body></html>"
            return response, content

        session.get = mock_get  # type: ignore

        technologies = await scanner.scan("https://example.com", session)

        assert len(technologies) == 0

    @pytest.mark.asyncio
    async def test_none_response_returns_empty(
        self, scanner: TechScanner
    ) -> None:
        """Test that None response returns empty list."""
        session = MockSession(response=None)

        technologies = await scanner.scan("https://example.com", session)

        assert len(technologies) == 0
