"""Hidden HTTP parameter discovery (Arjun-style).

Probes a URL with candidate parameter names and keeps the ones the application
actually reacts to. Two signals are used, both confirmed by isolating a single
name before reporting:

- **Reflection** — a unique canary value sent as ``?name=<canary>`` shows up in
  the response body (and was not already there).
- **Status change** — the parameter consistently flips the response status code
  versus the baseline (re-checked once to rule out flaky endpoints).

Names are sent in chunks and bisected, so confirming N real params out of a
large wordlist costs far fewer requests than one-per-name.
"""

from __future__ import annotations

import secrets as _secrets
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..core.logging import get_logger
from ..core.models import Severity, Vulnerability

if TYPE_CHECKING:
    from .http import HttpClient

logger = get_logger()

DEFAULT_PARAMS: list[str] = [
    "id",
    "page",
    "p",
    "q",
    "query",
    "search",
    "s",
    "keyword",
    "lang",
    "locale",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "url",
    "uri",
    "next",
    "return",
    "return_url",
    "returnto",
    "continue",
    "dest",
    "destination",
    "callback",
    "jsonp",
    "debug",
    "test",
    "admin",
    "edit",
    "preview",
    "draft",
    "user",
    "user_id",
    "uid",
    "username",
    "account",
    "email",
    "token",
    "access_token",
    "auth",
    "key",
    "api_key",
    "apikey",
    "secret",
    "session",
    "sid",
    "file",
    "filename",
    "path",
    "dir",
    "folder",
    "download",
    "doc",
    "document",
    "image",
    "img",
    "src",
    "format",
    "type",
    "view",
    "mode",
    "action",
    "do",
    "cmd",
    "exec",
    "func",
    "method",
    "step",
    "order",
    "sort",
    "filter",
    "category",
    "cat",
    "tag",
    "limit",
    "offset",
    "start",
    "count",
    "from",
    "to",
    "date",
    "year",
    "month",
    "status",
    "state",
    "ref",
    "source",
    "campaign",
    "code",
    "hash",
    "sig",
    "signature",
]


class ParamFinder:
    """Discover undeclared query parameters a target reacts to."""

    def __init__(
        self,
        wordlist: list[str] | None = None,
        chunk_size: int = 25,
        max_params: int = 512,
    ) -> None:
        names = wordlist if wordlist else DEFAULT_PARAMS
        self.names = [n for n in dict.fromkeys(n.strip() for n in names) if n][:max_params]
        self.chunk_size = max(1, chunk_size)

    def _build(self, url: str, extra: dict[str, str]) -> str:
        parts = urlsplit(url)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        query.update(extra)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))

    async def _get(self, url: str, session: HttpClient) -> tuple[int, str]:
        try:
            resp, body = await session.get(url)
        except Exception:
            return 0, ""
        if not resp:
            return 0, ""
        return resp.status, body or ""

    async def scan(self, url: str, session: HttpClient) -> tuple[list[str], list[Vulnerability]]:
        if not self.names:
            return [], []

        canary = "az" + _secrets.token_hex(5)
        base_status, base_body = await self._get(url, session)
        canary_in_base = canary in base_body

        found: list[str] = []
        for i in range(0, len(self.names), self.chunk_size):
            chunk = self.names[i : i + self.chunk_size]
            found.extend(
                await self._probe(url, chunk, canary, canary_in_base, base_status, session),
            )

        found = sorted(set(found))
        vulns: list[Vulnerability] = []
        if found:
            shown = ", ".join(found[:30])
            vulns.append(
                Vulnerability(
                    name="Hidden Parameters Discovered",
                    severity=Severity.INFO,
                    url=url,
                    description=f"Server reacts to {len(found)} undeclared parameter(s): {shown}",
                    recommendation=(
                        "Probe these parameters for injection, IDOR/access-control, open redirect, "
                        "and mass-assignment issues"
                    ),
                    cwe="CWE-200",
                )
            )
        logger.debug(f"Param discovery on {url}: {len(found)} found")
        return found, vulns

    async def _probe(
        self,
        url: str,
        chunk: list[str],
        canary: str,
        canary_in_base: bool,
        base_status: int,
        session: HttpClient,
    ) -> list[str]:
        status, body = await self._get(self._build(url, dict.fromkeys(chunk, canary)), session)
        reflected = (canary in body) and not canary_in_base
        status_changed = status != 0 and base_status != 0 and status != base_status
        if not (reflected or status_changed):
            return []

        if len(chunk) == 1:
            return await self._confirm(url, chunk[0], canary, canary_in_base, base_status, session)

        mid = len(chunk) // 2
        left = await self._probe(url, chunk[:mid], canary, canary_in_base, base_status, session)
        right = await self._probe(url, chunk[mid:], canary, canary_in_base, base_status, session)
        return left + right

    async def _confirm(
        self,
        url: str,
        name: str,
        canary: str,
        canary_in_base: bool,
        base_status: int,
        session: HttpClient,
    ) -> list[str]:
        status, body = await self._get(self._build(url, {name: canary}), session)
        if (canary in body) and not canary_in_base:
            return [name]
        if status != 0 and base_status != 0 and status != base_status:
            recheck, _ = await self._get(self._build(url, {name: canary}), session)
            if recheck == status:
                return [name]
        return []
