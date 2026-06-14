"""Context-aware injection verification (XSS + blind SQLi).

Higher-signal than substring matching: instead of only grepping for error
strings, this module confirms behaviour.

- **Reflected XSS** — a unique canary is injected and the response is checked for
  the canary appearing *unescaped* in HTML (vs HTML-entity-encoded, which is
  reported only as an informational reflection).
- **Boolean-based blind SQLi** — a TRUE condition reproduces the baseline body
  while a FALSE condition diverges; the pair is re-confirmed before reporting.
- **Time-based blind SQLi** — a sleep payload makes the response noticeably
  slower than baseline, re-confirmed with a second slow request and a fast
  control so a generally-slow server doesn't trip a false positive.

Parameters to test come from earlier discovery (crawler / paramfind); a small
default set is used when none were found.
"""

from __future__ import annotations

import asyncio
import secrets as _secrets
import time
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..core.logging import get_logger
from ..core.models import Severity, Vulnerability

if TYPE_CHECKING:
    from .http import HttpClient

logger = get_logger()

DEFAULT_TEST_PARAMS = ["id", "q", "search", "page", "name", "user", "category", "sort", "file", "url"]

_BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    (" AND 1=1", " AND 1=2"),
    ("' OR '1'='1", "' AND '1'='2"),
]

_TIME_PAYLOADS = [
    "' AND SLEEP({d})-- -",
    "'||(SELECT pg_sleep({d}))||'",
    "1)) OR SLEEP({d})-- -",
    "' OR SLEEP({d})-- -",
]


class InjectionScanner:
    """Verify XSS and blind SQLi on a target's parameters by behaviour."""

    def __init__(
        self,
        params: list[str] | None = None,
        concurrency: int = 10,
        max_params: int = 15,
        sleep_seconds: int = 5,
        time_threshold: float = 4.0,
    ) -> None:
        names = params if params else DEFAULT_TEST_PARAMS
        self.params = [n for n in dict.fromkeys(n.strip() for n in names) if n][:max_params]
        self._sem = asyncio.Semaphore(max(1, concurrency))
        self.sleep_seconds = sleep_seconds
        self.time_threshold = time_threshold

    def _build(self, url: str, name: str, value: str) -> str:
        parts = urlsplit(url)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        query[name] = value
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))

    async def _get(self, url: str, session: HttpClient) -> tuple[int, str, float]:
        async with self._sem:
            start = time.monotonic()
            try:
                resp, body = await session.get(url)
            except Exception:
                return 0, "", time.monotonic() - start
            elapsed = time.monotonic() - start
            if not resp:
                return 0, "", elapsed
            return resp.status, body or "", elapsed

    async def scan(self, url: str, session: HttpClient) -> list[Vulnerability]:
        if not self.params:
            return []

        _base_status, base_body, base_time = await self._get(url, session)
        vulns: list[Vulnerability] = []
        for name in self.params:
            xss = await self._check_xss(url, name, session)
            if xss:
                vulns.append(xss)
            sqli = await self._check_boolean_sqli(url, name, base_body, session)
            if sqli:
                vulns.append(sqli)
                continue
            timed = await self._check_time_sqli(url, name, base_time, session)
            if timed:
                vulns.append(timed)
        logger.debug(f"Injection verification on {url}: {len(vulns)} confirmed")
        return vulns

    async def _check_xss(self, url: str, name: str, session: HttpClient) -> Vulnerability | None:
        canary = "xq" + _secrets.token_hex(4)
        marker = f"<{canary}>"
        _, body, _ = await self._get(self._build(url, name, f'"{marker}'), session)
        if marker in body:
            return Vulnerability(
                name="Reflected XSS",
                severity=Severity.HIGH,
                url=self._build(url, name, marker),
                description=f"Parameter '{name}' reflects input unescaped into HTML, enabling script injection",
                payload=marker,
                recommendation="Context-encode output and apply a strict Content-Security-Policy",
                cwe="CWE-79",
            )
        if f"&lt;{canary}&gt;" in body:
            return Vulnerability(
                name="Parameter Reflection (encoded)",
                severity=Severity.INFO,
                url=url,
                description=f"Parameter '{name}' is reflected but HTML-encoded; review other sinks/contexts",
                recommendation="Confirm encoding holds in attribute, JS, and URL contexts",
                cwe="CWE-79",
            )
        return None

    async def _check_boolean_sqli(
        self, url: str, name: str, base_body: str, session: HttpClient
    ) -> Vulnerability | None:
        seed = _secrets.token_hex(3)
        for true_suffix, false_suffix in _BOOLEAN_PAIRS:
            _, true_body, _ = await self._get(self._build(url, name, seed + true_suffix), session)
            _, false_body, _ = await self._get(self._build(url, name, seed + false_suffix), session)
            if not true_body and not false_body:
                continue
            true_like_base = self._similar(true_body, base_body)
            diverges = not self._similar(true_body, false_body)
            if true_like_base and diverges:
                _, t2, _ = await self._get(self._build(url, name, seed + true_suffix), session)
                _, f2, _ = await self._get(self._build(url, name, seed + false_suffix), session)
                if self._similar(t2, true_body) and not self._similar(t2, f2):
                    return Vulnerability(
                        name="SQL Injection (boolean-based blind)",
                        severity=Severity.CRITICAL,
                        url=self._build(url, name, seed + true_suffix),
                        description=(
                            f"Parameter '{name}' alters the response for TRUE vs FALSE SQL conditions, "
                            "indicating blind SQL injection"
                        ),
                        payload=f"{true_suffix} / {false_suffix}",
                        recommendation="Use parameterized queries / prepared statements; never concatenate input",
                        cwe="CWE-89",
                    )
        return None

    async def _check_time_sqli(
        self, url: str, name: str, base_time: float, session: HttpClient
    ) -> Vulnerability | None:
        for template in _TIME_PAYLOADS:
            payload = template.format(d=self.sleep_seconds)
            _, _, elapsed = await self._get(self._build(url, name, payload), session)
            if elapsed < max(self.time_threshold, base_time + self.time_threshold):
                continue
            control = template.format(d=0)
            _, _, control_time = await self._get(self._build(url, name, control), session)
            if control_time >= self.time_threshold:
                continue
            _, _, confirm = await self._get(self._build(url, name, payload), session)
            if confirm >= self.time_threshold:
                return Vulnerability(
                    name="SQL Injection (time-based blind)",
                    severity=Severity.CRITICAL,
                    url=self._build(url, name, payload),
                    description=(
                        f"Parameter '{name}' delays the response by ~{self.sleep_seconds}s on a sleep payload, "
                        "indicating time-based blind SQL injection"
                    ),
                    payload=payload,
                    recommendation="Use parameterized queries / prepared statements; never concatenate input",
                    cwe="CWE-89",
                )
        return None

    @staticmethod
    def _similar(a: str, b: str, tolerance: float = 0.05) -> bool:
        la, lb = len(a), len(b)
        if la == 0 and lb == 0:
            return True
        longest = max(la, lb)
        return abs(la - lb) <= max(8, int(longest * tolerance))
