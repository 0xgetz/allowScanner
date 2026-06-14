"""Subdomain takeover detection.

For each host, resolves the CNAME and, when it points at a third-party
service, fetches the page and looks for that service's "unclaimed resource"
fingerprint. A dangling CNAME plus a matching fingerprint is a classic
takeover primitive.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING

import dns.asyncresolver
import dns.exception
import dns.resolver

from ..core.logging import get_logger
from ..core.models import Severity, Vulnerability

if TYPE_CHECKING:
    from .http import HttpClient

logger = get_logger()

# service -> (CNAME substrings, response-body fingerprints)
FINGERPRINTS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "GitHub Pages": (("github.io",), ("There isn't a GitHub Pages site here",)),
    "Amazon S3": (("s3.amazonaws.com", "s3-website"), ("NoSuchBucket", "The specified bucket does not exist")),
    "Heroku": (("herokuapp.com", "herokudns.com"), ("No such app", "no-such-app.html")),
    "Shopify": (("myshopify.com",), ("Sorry, this shop is currently unavailable",)),
    "Fastly": (("fastly.net",), ("Fastly error: unknown domain",)),
    "Surge.sh": (("surge.sh",), ("project not found",)),
    "Bitbucket": (("bitbucket.io",), ("Repository not found",)),
    "Tumblr": (("domains.tumblr.com",), ("Whatever you were looking for doesn't currently exist",)),
    "Pantheon": (("pantheonsite.io",), ("The gods are wise, but do not know of the site",)),
    "Zendesk": (("zendesk.com",), ("Help Center Closed",)),
    "Webflow": (("proxy-ssl.webflow.com", "proxy.webflow.com"), ("The page you are looking for doesn't exist",)),
    "Ghost": (("ghost.io",), ("The thing you were looking for is no longer here",)),
}


class TakeoverScanner:
    """Detect dangling CNAMEs vulnerable to subdomain takeover."""

    def __init__(self, concurrency: int = 30) -> None:
        self._sem = asyncio.Semaphore(max(1, concurrency))

    async def scan(self, hosts: list[str], session: HttpClient) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        seen: set[str] = set()

        async def check(host: str) -> None:
            async with self._sem:
                cname = await self._cname(host)
                if not cname:
                    return
                for service, (patterns, signatures) in FINGERPRINTS.items():
                    if not any(p in cname for p in patterns):
                        continue
                    body = await self._body(host, session)
                    if body and any(sig in body for sig in signatures) and host not in seen:
                        seen.add(host)
                        vulns.append(
                            Vulnerability(
                                name=f"Possible Subdomain Takeover: {service}",
                                severity=Severity.HIGH,
                                url=host,
                                description=(
                                    f"{host} has a dangling CNAME to {cname} ({service}) and the response "
                                    "matches the provider's unclaimed-resource page"
                                ),
                                recommendation=f"Remove the dangling DNS record or reclaim the {service} resource",
                                cwe="CWE-350",
                            )
                        )
                    return

        await asyncio.gather(*(check(h) for h in hosts), return_exceptions=True)
        logger.debug(f"Takeover scan: {len(vulns)} findings across {len(hosts)} hosts")
        return vulns

    async def _cname(self, host: str) -> str:
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = 5
            answers = await resolver.resolve(host, "CNAME")
            return str(answers[0].target).rstrip(".").lower()
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            return ""
        except Exception:
            return ""

    async def _body(self, host: str, session: HttpClient) -> str:
        for scheme in ("https", "http"):
            with contextlib.suppress(Exception):
                resp, body = await session.get(f"{scheme}://{host}")
                if resp is not None:
                    return body
        return ""
