"""Async HTTP client wrapper with robust error handling."""

from __future__ import annotations

import ssl
from typing import Any

import aiohttp
import asyncio

from ..core.config import ScanConfig
from ..core.exceptions import NetworkError, TimeoutError, SSLError, AllowScannerError
from ..core.logging import get_logger

logger = get_logger()


class HttpClient:
    """Shared async HTTP client for all scanners with robust error handling."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._session: aiohttp.ClientSession | None = None
        self._retry_count = 2  # Number of retries for failed requests

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
                family=0,  # Both IPv4 and IPv6
            )
            
            self._session = aiohttp.ClientSession(
                connector=connector,
                headers={"User-Agent": self.config.user_agent},
                timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                raise_for_status=False,  # Don't raise on 4xx/5xx
            )
            
            logger.debug("HTTP client initialized successfully")
        except ssl.SSLError as e:
            raise SSLError(
                "Failed to initialize SSL context",
                original_error=e,
                suggestion="Check your SSL configuration or disable SSL verification with --no-ssl"
            )
        except Exception as e:
            raise NetworkError(
                "Failed to initialize HTTP client",
                original_error=e,
                suggestion="Check your network configuration"
            )

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
                suggestion="Initialize the HTTP client before making requests"
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

    async def _request_with_retry(self, method: str, url: str, **kwargs: Any) -> tuple[aiohttp.ClientResponse | None, str]:
        """Make a request with retry logic."""
        last_error: Exception | None = None
        
        for attempt in range(self._retry_count + 1):
            try:
                return await self._make_request(method, url, **kwargs)
            except asyncio.TimeoutError as e:
                last_error = e
                if attempt < self._retry_count:
                    logger.warning(f"Request timeout (attempt {attempt + 1}/{self._retry_count + 1}): {url}")
                    await asyncio.sleep(1)  # Wait before retry
                else:
                    raise TimeoutError(
                        f"Request timed out after {self._retry_count + 1} attempts",
                        url=url,
                        operation=f"{method} request",
                        timeout_seconds=self.config.timeout,
                        original_error=e,
                        suggestion="Increase timeout with -t flag or check target availability"
                    )
            except aiohttp.ClientSSLError as e:
                last_error = e
                raise SSLError(
                    f"SSL error during {method} request",
                    url=url,
                    original_error=e,
                    suggestion="Check SSL certificate or use --no-ssl for testing"
                )
            except aiohttp.ClientConnectorError as e:
                last_error = e
                raise NetworkError(
                    f"Connection failed for {method} request",
                    url=url,
                    original_error=e,
                    suggestion="Check if the target is accessible and firewall rules"
                )
            except aiohttp.ClientError as e:
                last_error = e
                logger.warning(f"HTTP client error (attempt {attempt + 1}): {e}")
                if attempt >= self._retry_count:
                    raise NetworkError(
                        f"HTTP request failed after {self._retry_count + 1} attempts",
                        url=url,
                        original_error=e,
                        suggestion="Check URL and network connectivity"
                    )
            except Exception as e:
                last_error = e
                logger.error(f"Unexpected error during {method} request: {e}")
                if attempt >= self._retry_count:
                    raise NetworkError(
                        f"Unexpected error during {method} request",
                        url=url,
                        original_error=e,
                        suggestion="Check logs for details"
                    )
        
        # Should not reach here, but just in case
        return None, ""

    async def _make_request(self, method: str, url: str, **kwargs: Any) -> tuple[aiohttp.ClientResponse | None, str]:
        """Make the actual HTTP request."""
        # Use the appropriate method on the session
        method_func = getattr(self.session, method.lower(), None)
        if method_func is None:
            # Fallback to request() for standard methods
            async with self.session.request(method, url, **kwargs) as resp:
                text = await resp.text(errors="ignore")
                logger.debug(f"{method} {url} -> {resp.status}")
                return resp, text
        else:
            async with method_func(url, **kwargs) as resp:
                text = await resp.text(errors="ignore")
                logger.debug(f"{method} {url} -> {resp.status}")
                return resp, text
