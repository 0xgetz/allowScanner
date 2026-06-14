"""Secret and endpoint discovery from HTML and linked JavaScript.

Fetches the page and its same-origin scripts, then greps for leaked
credentials (API keys, tokens, private keys) and hidden API endpoints that
attackers routinely mine from client-side code.
"""

from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse

from ..core.logging import get_logger
from ..core.models import Severity, Vulnerability

if TYPE_CHECKING:
    from .http import HttpClient

logger = get_logger()

# (label, pattern, severity)
SECRET_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), Severity.CRITICAL),
    (
        "AWS Secret Access Key",
        re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"),
        Severity.CRITICAL,
    ),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), Severity.HIGH),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), Severity.CRITICAL),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), Severity.CRITICAL),
    ("Stripe Live Secret Key", re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b"), Severity.CRITICAL),
    ("Stripe Live Publishable Key", re.compile(r"\bpk_live_[0-9A-Za-z]{24,}\b"), Severity.LOW),
    ("Twilio API Key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), Severity.HIGH),
    (
        "SendGrid API Key",
        re.compile(r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b"),
        Severity.CRITICAL,
    ),
    ("Mailgun API Key", re.compile(r"\bkey-[0-9a-f]{32}\b"), Severity.HIGH),
    (
        "JSON Web Token",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
        Severity.MEDIUM,
    ),
    (
        "Private Key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        Severity.CRITICAL,
    ),
    ("Firebase Database URL", re.compile(r"\b[a-z0-9-]+\.firebaseio\.com\b"), Severity.LOW),
    (
        "Generic Secret Assignment",
        re.compile(r"(?i)(?:api[_-]?key|secret|token|password)\s*[=:]\s*['\"]([0-9A-Za-z_\-]{16,})['\"]"),
        Severity.MEDIUM,
    ),
]

_SCRIPT_SRC = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.IGNORECASE)
_ENDPOINT = re.compile(r"[\"'](/(?:api|v\d|graphql|rest|internal|admin|user|auth|account)[A-Za-z0-9_\-/.]*)[\"']")


def _redact(token: str) -> str:
    if len(token) <= 8:
        return token[0] + "***"
    return f"{token[:4]}…{token[-4:]}"


class SecretScanner:
    """Mine HTML and linked JavaScript for leaked secrets and hidden endpoints."""

    def __init__(self, max_scripts: int = 20, concurrency: int = 20) -> None:
        self.max_scripts = max_scripts
        self._sem = asyncio.Semaphore(max(1, concurrency))

    async def scan(self, url: str, session: HttpClient) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        try:
            resp, html = await session.get(url)
        except Exception:
            return vulns
        if not resp:
            return vulns

        documents: list[tuple[str, str]] = [(url, html)]

        base_host = urlparse(url).hostname or ""
        srcs: list[str] = []
        for match in _SCRIPT_SRC.finditer(html):
            full = urljoin(url, match.group(1))
            if urlparse(full).hostname == base_host:
                srcs.append(full)
        srcs = list(dict.fromkeys(srcs))[: self.max_scripts]

        async def fetch_js(src: str) -> None:
            async with self._sem:
                try:
                    r, body = await session.get(src)
                except Exception:
                    return
                if r and body:
                    documents.append((src, body))

        await asyncio.gather(*(fetch_js(s) for s in srcs), return_exceptions=True)

        seen_secrets: set[str] = set()
        endpoints: set[str] = set()
        for location, body in documents:
            for label, pattern, severity in SECRET_PATTERNS:
                for match in pattern.finditer(body):
                    token = match.group(0)
                    key = f"{label}:{token[:48]}"
                    if key in seen_secrets:
                        continue
                    seen_secrets.add(key)
                    vulns.append(
                        Vulnerability(
                            name=f"Exposed Secret: {label}",
                            severity=severity,
                            url=location,
                            description=f"Possible {label} found in client-side code: {_redact(token)}",
                            recommendation="Rotate the credential immediately and keep secrets server-side",
                            cwe="CWE-798",
                        )
                    )
            for match in _ENDPOINT.finditer(body):
                endpoints.add(match.group(1))

        if endpoints:
            sample = ", ".join(sorted(endpoints)[:15])
            vulns.append(
                Vulnerability(
                    name="Endpoints Exposed in JavaScript",
                    severity=Severity.INFO,
                    url=url,
                    description=f"Discovered {len(endpoints)} endpoint path(s) in client-side code: {sample}",
                    recommendation="Review these endpoints for missing authorization or hidden functionality",
                    cwe="CWE-200",
                )
            )

        logger.debug(f"Secret scan for {url}: {len(seen_secrets)} secrets, {len(endpoints)} endpoints")
        return vulns
