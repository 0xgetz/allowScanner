"""Same-host crawler / attack-surface mapper.

Breadth-first crawl from the target, scope-aware, extracting links, forms, and
parameter names. Maps the real surface so other modules and the operator know
what exists, instead of only testing a single URL.
"""

from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING
from urllib.parse import urldefrag, urljoin, urlparse

from ..core.logging import get_logger
from ..core.models import Severity, Vulnerability
from ..core.scope import Scope

if TYPE_CHECKING:
    from .http import HttpClient

logger = get_logger()

_HREF = re.compile(r"<a\s[^>]*href=[\"']([^\"'#]+)[\"']", re.IGNORECASE)
_FORM = re.compile(r"<form\s[^>]*action=[\"']([^\"']*)[\"']", re.IGNORECASE)
_INPUT_NAME = re.compile(r"<(?:input|textarea|select)\s[^>]*name=[\"']([^\"']+)[\"']", re.IGNORECASE)

_PageResult = tuple[str, int, list[str], set[str], list[str]]


class Crawler:
    """Discover the in-scope surface of a web app."""

    def __init__(self, scope: Scope, max_pages: int = 100, max_depth: int = 2, concurrency: int = 20) -> None:
        self.scope = scope
        self.max_pages = max_pages
        self.max_depth = max_depth
        self._sem = asyncio.Semaphore(max(1, concurrency))

    async def scan(self, start_url: str, session: HttpClient) -> tuple[list[str], list[Vulnerability]]:
        start = start_url.rstrip("/")
        seen: set[str] = {start}
        discovered: list[str] = []
        params: set[str] = set()
        forms: list[str] = []
        frontier: list[tuple[str, int]] = [(start, 0)]

        while frontier and len(discovered) < self.max_pages:
            batch, frontier = frontier, []
            results = await asyncio.gather(
                *(self._fetch(url, depth, session) for url, depth in batch),
                return_exceptions=True,
            )
            for res in results:
                if isinstance(res, BaseException) or res is None:
                    continue
                url, depth, links, page_params, page_forms = res
                discovered.append(url)
                params.update(page_params)
                forms.extend(page_forms)
                if len(discovered) >= self.max_pages or depth >= self.max_depth:
                    continue
                for link in links:
                    norm = urldefrag(link)[0].rstrip("/")
                    if norm and norm not in seen and self.scope.in_scope(norm):
                        seen.add(norm)
                        frontier.append((norm, depth + 1))

        vulns: list[Vulnerability] = []
        if discovered:
            param_note = f". Parameters: {', '.join(sorted(params)[:20])}" if params else ""
            vulns.append(
                Vulnerability(
                    name="Crawl Surface Mapped",
                    severity=Severity.INFO,
                    url=start_url,
                    description=(
                        f"Crawled {len(discovered)} page(s); found {len(params)} unique parameter(s) "
                        f"and {len(forms)} form(s){param_note}"
                    ),
                    recommendation="Review the discovered surface and feed parameters into targeted tests",
                    cwe="CWE-200",
                )
            )
        logger.debug(f"Crawl of {start_url}: {len(discovered)} pages, {len(params)} params")
        return discovered, vulns

    async def _fetch(self, url: str, depth: int, session: HttpClient) -> _PageResult | None:
        async with self._sem:
            try:
                resp, body = await session.get(url)
            except Exception:
                return None
            if not resp or not body:
                return None
            ctype = ""
            try:
                ctype = resp.headers.get("Content-Type", "")
            except Exception:
                ctype = ""
            if "html" not in ctype.lower() and "<html" not in body[:512].lower():
                return (url, depth, [], self._query_params(url), [])
            links = [urljoin(url, m.group(1)) for m in _HREF.finditer(body)]
            forms = [urljoin(url, m.group(1) or url) for m in _FORM.finditer(body)]
            page_params = self._query_params(url) | set(_INPUT_NAME.findall(body))
            return (url, depth, links, page_params, forms)

    def _query_params(self, url: str) -> set[str]:
        query = urlparse(url).query
        return {kv.split("=")[0] for kv in query.split("&") if kv}
