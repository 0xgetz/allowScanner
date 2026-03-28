"""Comprehensive tests for HttpClient with new error handling."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from allowscanner.core.config import ScanConfig
from allowscanner.core.exceptions import NetworkError, TimeoutError, SSLError
from allowscanner.scanners.http import HttpClient


@pytest.fixture
def config() -> ScanConfig:
    """Create a test configuration."""
    return ScanConfig(concurrency=10, timeout=5)


@pytest.fixture
def client(config: ScanConfig) -> HttpClient:
    """Create an HttpClient instance."""
    return HttpClient(config)


class MockClientResponse:
    """Mock aiohttp ClientResponse."""

    def __init__(
        self,
        status: int = 200,
        headers: dict | None = None,
        cookies: dict | None = None,
        text_content: str = "OK",
    ) -> None:
        self.status = status
        self._headers = headers or {}
        self._cookies = cookies or {}
        self._text_content = text_content

    @property
    def headers(self) -> dict:
        return self._headers

    @property
    def cookies(self) -> dict:
        return self._cookies

    async def text(self, errors: str = "strict") -> str:
        return self._text_content

    async def __aenter__(self) -> MockClientResponse:
        return self

    async def __aexit__(self, *args) -> None:
        pass


class TestHttpClientCreation:
    """Test HttpClient creation and initialization."""

    def test_client_created_with_config(
        self, config: ScanConfig
    ) -> None:
        """Test that HttpClient is created with config."""
        client = HttpClient(config)
        assert client.config == config
        assert client._session is None

    def test_client_default_user_agent(
        self, config: ScanConfig
    ) -> None:
        """Test that default user agent is set."""
        client = HttpClient(config)
        assert "AllowScanner" in client.config.user_agent


class TestHttpClientStart:
    """Test HttpClient start method."""

    @pytest.mark.asyncio
    async def test_start_creates_session(
        self, client: HttpClient
    ) -> None:
        """Test that start() creates an aiohttp session."""
        with patch("aiohttp.ClientSession") as mock_session:
            await client.start()
            assert client._session is not None
            mock_session.assert_called_once()

    @pytest.mark.asyncio
    async def test_start_creates_ssl_context(
        self, client: HttpClient
    ) -> None:
        """Test that start() creates proper SSL context."""
        with patch("aiohttp.ClientSession") as mock_session:
            await client.start()
            # Check that session was called with SSL context
            call_kwargs = mock_session.call_args[1]
            assert "connector" in call_kwargs

    @pytest.mark.asyncio
    async def test_start_sets_timeout(
        self, client: HttpClient
    ) -> None:
        """Test that start() sets proper timeout."""
        client.config.timeout = 30
        with patch("aiohttp.ClientSession") as mock_session:
            await client.start()
            call_kwargs = mock_session.call_args[1]
            assert "timeout" in call_kwargs


class TestHttpGet:
    """Test HttpClient GET method."""

    @pytest.mark.asyncio
    async def test_get_returns_response_and_content(
        self, client: HttpClient
    ) -> None:
        """Test that get() returns response and content."""
        mock_response = MockClientResponse(
            status=200,
            headers={"Content-Type": "text/html"},
            text_content="<html>Hello</html>",
        )

        client._session = MagicMock()
        client._session.get = AsyncMock(return_value=mock_response)

        resp, content = await client.get("https://example.com")

        assert resp is not None
        assert resp.status == 200
        assert content == "<html>Hello</html>"

    @pytest.mark.asyncio
    async def test_get_with_headers(
        self, client: HttpClient
    ) -> None:
        """Test that get() passes headers correctly."""
        mock_response = MockClientResponse(status=200)

        client._session = MagicMock()
        client._session.get = AsyncMock(return_value=mock_response)

        headers = {"Authorization": "Bearer token123"}
        await client.get("https://example.com", headers=headers)

        client._session.get.assert_called_once_with(
            "https://example.com", headers=headers
        )

    @pytest.mark.asyncio
    async def test_get_raises_network_error_on_exception(
        self, client: HttpClient
    ) -> None:
        """Test that get() raises NetworkError on exception."""
        client._session = MagicMock()
        client._session.get = AsyncMock(side_effect=Exception("Network error"))

        with pytest.raises(NetworkError):
            await client.get("https://example.com")


class TestHttpRequest:
    """Test HttpClient request method."""

    @pytest.mark.asyncio
    async def test_request_post_returns_response(
        self, client: HttpClient
    ) -> None:
        """Test that request() with POST returns response."""
        mock_response = MockClientResponse(
            status=201,
            text_content='{"status": "created"}',
        )

        client._session = MagicMock()
        client._session.request = AsyncMock(return_value=mock_response)

        resp, content = await client.request("POST", "https://example.com/api", data="test")

        assert resp is not None
        assert resp.status == 201
        assert content == '{"status": "created"}'

    @pytest.mark.asyncio
    async def test_request_passes_method_correctly(
        self, client: HttpClient
    ) -> None:
        """Test that request() passes method correctly."""
        mock_response = MockClientResponse(status=200)

        client._session = MagicMock()
        client._session.request = AsyncMock(return_value=mock_response)

        await client.request("DELETE", "https://example.com/resource")

        client._session.request.assert_called_once_with(
            "DELETE", "https://example.com/resource"
        )

    @pytest.mark.asyncio
    async def test_request_raises_network_error_on_exception(
        self, client: HttpClient
    ) -> None:
        """Test that request() raises NetworkError on exception."""
        client._session = MagicMock()
        client._session.request = AsyncMock(side_effect=Exception("Network error"))

        with pytest.raises(NetworkError):
            await client.request("POST", "https://example.com")


class TestHttpClientClose:
    """Test HttpClient close method."""

    @pytest.mark.asyncio
    async def test_close_closes_session(
        self, client: HttpClient
    ) -> None:
        """Test that close() closes the session."""
        mock_session = MagicMock()
        mock_session.close = AsyncMock()
        client._session = mock_session

        await client.close()

        mock_session.close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_close_handles_none_session(
        self, client: HttpClient
    ) -> None:
        """Test that close() handles None session gracefully."""
        client._session = None

        # Should not raise
        await client.close()


class TestSessionProperty:
    """Test HttpClient session property."""

    def test_session_property_returns_session(
        self, client: HttpClient
    ) -> None:
        """Test that session property returns the session."""
        mock_session = MagicMock()
        client._session = mock_session

        assert client.session is mock_session

    def test_session_property_raises_when_not_started(
        self, client: HttpClient
    ) -> None:
        """Test that session property raises when not started."""
        client._session = None

        with pytest.raises(Exception, match="not started"):
            client.session


class TestSSLVerification:
    """Test SSL verification settings."""

    @pytest.mark.asyncio
    async def test_ssl_verification_enabled_by_default(
        self, client: HttpClient
    ) -> None:
        """Test that SSL verification is enabled by default."""
        with patch("aiohttp.ClientSession") as mock_session, patch("ssl.create_default_context") as mock_ssl:
            mock_ctx = MagicMock()
            mock_ssl.return_value = mock_ctx

            await client.start()

            # SSL context should have verification enabled
            assert mock_ctx.check_hostname is True
            assert mock_ctx.verify_mode is not None


class TestConcurrencyLimit:
    """Test concurrency limit settings."""

    @pytest.mark.asyncio
    async def test_connector_respects_concurrency_limit(
        self, client: HttpClient
    ) -> None:
        """Test that TCP connector respects concurrency limit."""
        client.config.concurrency = 25

        with patch("aiohttp.ClientSession") as mock_session, patch("aiohttp.TCPConnector") as mock_connector:
            await client.start()

            mock_connector.assert_called_once()
            call_kwargs = mock_connector.call_args[1]
            assert call_kwargs["limit"] == 25


class TestUserAgent:
    """Test User-Agent header settings."""

    @pytest.mark.asyncio
    async def test_custom_user_agent(
        self, client: HttpClient
    ) -> None:
        """Test that custom user agent is used."""
        client.config.user_agent = "CustomBot/1.0"

        with patch("aiohttp.ClientSession") as mock_session:
            await client.start()

            call_kwargs = mock_session.call_args[1]
            assert call_kwargs["headers"]["User-Agent"] == "CustomBot/1.0"
