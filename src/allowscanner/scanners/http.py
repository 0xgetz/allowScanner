"""Async HTTP client wrapper."""

from __future__ import annotations

import ssl
from typing import Optional

import aiohttp

from ..core.config import ScanConfig


class HttpClient:
    """Shared async HTTP client for all scanners."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._session: Optional[aiohttp.ClientSession] = None

    async def start(self) -> None:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(
            ssl=ssl_ctx,
            limit=self.config.concurrency,
            enable_cleanup_closed=True,
        )
        self._session = aiohttp.ClientSession(
            connector=connector,
            headers={"User-Agent": self.config.user_agent},
            timeout=aiohttp.ClientTimeout(total=self.config.timeout),
        )

    async def close(self) -> None:
        if self._session:
            await self._session.close()

    @property
    def session(self) -> aiohttp.ClientSession:
        if not self._session:
            raise RuntimeError("HttpClient not started. Call start() first.")
        return self._session

    async def get(self, url: str, **kwargs) -> tuple[Optional[aiohttp.ClientResponse], str]:
        try:
            async with self.session.get(url, **kwargs) as resp:
                text = await resp.text(errors="ignore")
                return resp, text
        except Exception:
            return None, ""

    async def request(self, method: str, url: str, **kwargs) -> tuple[Optional[aiohttp.ClientResponse], str]:
        try:
            async with self.session.request(method, url, **kwargs) as resp:
                text = await resp.text(errors="ignore")
                return resp, text
        except Exception:
            return None, ""
