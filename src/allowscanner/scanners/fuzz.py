"""Content discovery (path fuzzing) scanner.

Probes a wordlist of paths against the target and reports endpoints that exist
or are access-controlled. Calibrates against a random baseline path first so
catch-all/soft-404 responses don't drown the output in false positives.
"""

from __future__ import annotations

import asyncio
import secrets
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from ..core.logging import get_logger
from ..core.models import Severity, Vulnerability

if TYPE_CHECKING:
    from .http import HttpClient

logger = get_logger()

# Built-in list of generally interesting paths, distinct from the targeted
# sensitive-file / admin-panel lists in the vulnerability scanner.
DEFAULT_WORDLIST: list[str] = [
    "backup",
    "backups",
    "old",
    "new",
    "test",
    "tests",
    "tmp",
    "temp",
    "dev",
    "staging",
    "private",
    "internal",
    "secret",
    "secrets",
    "config",
    "configs",
    "settings",
    "uploads",
    "upload",
    "files",
    "download",
    "downloads",
    "logs",
    "log",
    "data",
    "db",
    "database",
    "dump",
    "export",
    "import",
    "api",
    "api/v1",
    "api/v2",
    "v1",
    "v2",
    "graphql",
    "rest",
    "swagger",
    "swagger-ui",
    "openapi.json",
    "docs",
    "documentation",
    "redoc",
    "health",
    "healthz",
    "status",
    "metrics",
    "debug",
    "trace",
    "actuator",
    "console",
    "admin",
    "administrator",
    "login",
    "logout",
    "register",
    "signup",
    "dashboard",
    "panel",
    "cms",
    "wp-admin",
    "phpmyadmin",
    "adminer",
    "user",
    "users",
    "account",
    "accounts",
    "profile",
    "billing",
    "invoices",
    "payment",
    "cart",
    "checkout",
    "search",
    "static",
    "assets",
    "media",
    "images",
    "img",
    "css",
    "js",
    ".well-known/security.txt",
    ".well-known/openid-configuration",
    "robots.txt",
    "sitemap.xml",
    "crossdomain.xml",
    "server-status",
]

# Response codes worth surfacing. 404/410 are explicitly excluded as "not found".
INTERESTING_STATUS = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}


class FuzzScanner:
    """Discover reachable or protected endpoints from a wordlist."""

    def __init__(self, wordlist: list[str] | None = None, concurrency: int = 50) -> None:
        self.wordlist = wordlist if wordlist else list(DEFAULT_WORDLIST)
        self._sem = asyncio.Semaphore(max(1, concurrency))

    async def scan(self, url: str, session: HttpClient) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        base = url.rstrip("/") + "/"
        baseline_status, baseline_len = await self._baseline(base, session)
        seen: set[str] = set()

        async def probe(path: str) -> None:
            async with self._sem:
                target = urljoin(base, path.lstrip("/"))
                try:
                    resp, content = await session.get(target, allow_redirects=False)
                except Exception:
                    return
                if not resp:
                    return
                status = resp.status
                if status not in INTERESTING_STATUS:
                    return
                # Soft-404 filter: if the random baseline also returned 200 with a
                # similar body length, this is probably a catch-all, not a real hit.
                if status == 200 and baseline_status == 200 and abs(len(content) - baseline_len) < 48:
                    return

                key = f"{status}:{target}"
                if key in seen:
                    return
                seen.add(key)

                if status in (401, 403):
                    severity = Severity.INFO
                    desc = f"Protected endpoint exists (HTTP {status}): /{path}"
                    rec = "Confirm the access control is intentional and not bypassable"
                elif status >= 500:
                    severity = Severity.LOW
                    desc = f"Endpoint returns server error (HTTP {status}): /{path}"
                    rec = "Server errors can leak stack traces — review error handling"
                else:
                    severity = Severity.LOW
                    desc = f"Discovered endpoint (HTTP {status}): /{path}"
                    rec = "Confirm whether this endpoint should be publicly reachable"

                vulns.append(
                    Vulnerability(
                        name=f"Content Discovery: /{path}",
                        severity=severity,
                        url=target,
                        description=desc,
                        recommendation=rec,
                        cwe="CWE-538",
                    )
                )

        await asyncio.gather(*(probe(p) for p in self.wordlist), return_exceptions=True)
        logger.debug(f"Fuzzing for {url}: {len(vulns)} interesting paths from {len(self.wordlist)} words")
        return vulns

    async def _baseline(self, base: str, session: HttpClient) -> tuple[int | None, int]:
        """Probe a random path to learn how the server answers a guaranteed miss."""
        target = urljoin(base, f"{secrets.token_hex(8)}-allowscanner-nope")
        try:
            resp, content = await session.get(target, allow_redirects=False)
        except Exception:
            return None, 0
        if not resp:
            return None, 0
        return resp.status, len(content)
