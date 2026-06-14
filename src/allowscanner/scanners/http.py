"""Async HTTP client wrapper with robust error handling."""

from __future__ import annotations

import asyncio
import socket
import ssl
from typing import Any

import aiohttp

from ..core.config import ScanConfig
from ..core.exceptions import AllowScannerError, NetworkError, SSLError, TimeoutError
from ..core.logging import get_logger

logger = get_logger()


class RateLimiter:
    """Async rate limiter with adaptive backoff on HTTP 429."""

    def __init__(self, rate: float = 0.0) -> None:
        self._min_interval = 1.0 / rate if rate > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next = 0.0
        self._pending_pause = 0.0

    async def acquire(self) -> None:
        async with self._lock:
            loop = asyncio.get_event_loop()
            now = loop.time()
            pause = self._pending_pause
            self._pending_pause = 0.0
            wait = (self._next - now) + pause
            if wait > 0:
                await asyncio.sleep(wait)
                now = loop.time()
            self._next = max(now, self._next) + self._min_interval

    def backoff(self, retry_after: float | None = None) -> None:
        """Slow down after a 429: widen spacing and insert a one-off pause."""
        self._min_interval = min(max(self._min_interval * 2, 0.5), 10.0)
        pause = retry_after if (retry_after and retry_after > 0) else self._min_interval
        self._pending_pause = max(self._pending_pause, pause)


def _parse_retry_after(value: str | None) -> float | None:
    """Parse a Retry-After header (delta-seconds form only)."""
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


class HttpClient:
    """Shared async HTTP client for all scanners with robust error handling."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._session: aiohttp.ClientSession | None = None
        self._retry_count = 2  # Number of retries for failed requests
        self._limiter: RateLimiter = RateLimiter(float(config.rate_limit or 0))

    async def start(self) -> None:
        """Initialize the HTTP client session."""
        try:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = self.config.verify_ssl
            ssl_ctx.verify_mode = ssl.CERT_REQUIRED if self.config.verify_ssl else ssl.CERT_NONE

            connector = aiohttp.TCPConnector(
                ssl=ssl_ctx,
                limit=self.config.concurrency,
                enable_cleanup_closed=True,
                family=socket.AF_UNSPEC,  # Both IPv4 and IPv6
            )

            session_headers = {"User-Agent": self.config.user_agent, **self.config.extra_headers}
            self._session = aiohttp.ClientSession(
                connector=connector,
                headers=session_headers,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                raise_for_status=False,  # Don't raise on 4xx/5xx
            )

            logger.debug("HTTP client initialized successfully")
        except ssl.SSLError as e:
            raise SSLError(
                "Failed to initialize SSL context",
                original_error=e,
                suggestion="Check your SSL configuration or disable SSL verification with --no-ssl",
            ) from e
        except Exception as e:
            raise NetworkError(
                "Failed to initialize HTTP client", original_error=e, suggestion="Check your network configuration"
            ) from e

    async def close(self) -> None:
        """Close the HTTP client session."""
        if self._session:
            try:
                await self._session.close()
                logger.debug("HTTP client session closed")
            except Exception as e:
                logger.warning(f"Error closing HTTP session: {e}")

    @property
    def session(self) -> aiohttp.ClientSession:
        """Get the active session or raise an error."""
        if not self._session:
            raise AllowScannerError(
                "HttpClient not started. Call start() first.",
                suggestion="Initialize the HTTP client before making requests",
            )
        return self._session

    async def get(self, url: str, **kwargs: Any) -> tuple[aiohttp.ClientResponse | None, str]:
        """Make a GET request with error handling.

        Args:
            url: URL to fetch
            **kwargs: Additional arguments for aiohttp

        Returns:
            Tuple of (response, response text)

        Raises:
            NetworkError: On network failures
            TimeoutError: On timeout
            SSLError: On SSL errors
        """
        return await self._request_with_retry("GET", url, **kwargs)

    async def request(self, method: str, url: str, **kwargs: Any) -> tuple[aiohttp.ClientResponse | None, str]:
        """Make a request with error handling.

        Args:
            method: HTTP method
            url: URL to fetch
            **kwargs: Additional arguments for aiohttp

        Returns:
            Tuple of (response, response text)

        Raises:
            NetworkError: On network failures
            TimeoutError: On timeout
            SSLError: On SSL errors
        """
        return await self._request_with_retry(method, url, **kwargs)

    async def _request_with_retry(
        self, method: str, url: str, **kwargs: Any
    ) -> tuple[aiohttp.ClientResponse | None, str]:
        """Make a request with retry logic."""

        for attempt in range(self._retry_count + 1):
            try:
                return await self._make_request(method, url, **kwargs)
            except asyncio.TimeoutError as e:
                if attempt < self._retry_count:
                    logger.warning(f"Request timeout (attempt {attempt + 1}/{self._retry_count + 1}): {url}")
                    await asyncio.sleep(1)  # Wait before retry
                else:
                    raise TimeoutError(
                        f"Request timed out after {self._retry_count + 1} attempts",
                        url=url,
                        operation=f"{method} request",
                        timeout_duration=self.config.timeout,
                        original_error=e,
                        suggestion="Increase timeout with -t flag or check target availability",
                    ) from e
            except aiohttp.ClientSSLError as e:
                raise SSLError(
                    f"SSL error during {method} request",
                    context={"url": url},
                    original_error=e,
                    suggestion="Check SSL certificate or use --no-ssl for testing",
                ) from e
            except aiohttp.ClientConnectorError as e:
                raise NetworkError(
                    f"Connection failed for {method} request",
                    url=url,
                    original_error=e,
                    suggestion="Check if the target is accessible and firewall rules",
                ) from e
            except aiohttp.ClientError as e:
                logger.warning(f"HTTP client error (attempt {attempt + 1}): {e}")
                if attempt >= self._retry_count:
                    raise NetworkError(
                        f"HTTP request failed after {self._retry_count + 1} attempts",
                        url=url,
                        original_error=e,
                        suggestion="Check URL and network connectivity",
                    ) from e
            except Exception as e:
                logger.error(f"Unexpected error during {method} request: {e}")
                if attempt >= self._retry_count:
                    raise NetworkError(
                        f"Unexpected error during {method} request",
                        url=url,
                        original_error=e,
                        suggestion="Check logs for details",
                    ) from e

        # Should not reach here, but just in case
        return None, ""

    async def _make_request(self, method: str, url: str, **kwargs: Any) -> tuple[aiohttp.ClientResponse | None, str]:
        """Make the actual HTTP request, pacing via the rate limiter."""
        await self._limiter.acquire()
        async with self.session.request(method, url, **kwargs) as resp:
            text = await resp.text(errors="ignore")
            logger.debug(f"{method} {url} -> {resp.status}")
            if resp.status == 429:
                self._limiter.backoff(_parse_retry_after(resp.headers.get("Retry-After")))
            return resp, text
