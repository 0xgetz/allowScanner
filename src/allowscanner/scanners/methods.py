"""HTTP method / verb audit.

Asks the server which methods it advertises (OPTIONS) and actively probes
dangerous verbs. Enabled PUT/DELETE/TRACE/PATCH/CONNECT are classic
misconfigurations (arbitrary writes, Cross-Site Tracing, proxy abuse).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..core.logging import get_logger
from ..core.models import Severity, Vulnerability

if TYPE_CHECKING:
    from .http import HttpClient

logger = get_logger()

# method -> (severity, explanation, cwe)
DANGEROUS_METHODS: dict[str, tuple[Severity, str, str]] = {
    "PUT": (Severity.HIGH, "Arbitrary file upload or resource creation may be possible", "CWE-650"),
    "DELETE": (Severity.HIGH, "Arbitrary resource deletion may be possible", "CWE-650"),
    "TRACE": (Severity.MEDIUM, "TRACE enables Cross-Site Tracing (XST) and can echo headers/cookies", "CWE-693"),
    "PATCH": (Severity.MEDIUM, "Resource modification may be possible", "CWE-650"),
    "CONNECT": (Severity.MEDIUM, "The server may be usable as a forward proxy", "CWE-441"),
}


class HttpMethodScanner:
    """Audit which HTTP methods a target accepts."""

    async def scan(self, url: str, session: HttpClient) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []

        advertised: set[str] = set()
        try:
            resp, _ = await session.request("OPTIONS", url)
        except Exception:
            resp = None
        if resp is not None:
            allow = resp.headers.get("Allow", "") or resp.headers.get("Access-Control-Allow-Methods", "")
            advertised = {m.strip().upper() for m in allow.split(",") if m.strip()}
            if allow:
                vulns.append(
                    Vulnerability(
                        name="HTTP Methods Advertised",
                        severity=Severity.INFO,
                        url=url,
                        description=f"Server advertises methods via OPTIONS: {allow}",
                        recommendation="Restrict each endpoint to the methods it actually needs",
                        cwe="CWE-200",
                    )
                )

        for method, (severity, note, cwe) in DANGEROUS_METHODS.items():
            try:
                resp, _ = await session.request(method, url, allow_redirects=False)
            except Exception:
                continue
            if resp is None:
                continue
            accepted = resp.status < 400 or method in advertised
            if accepted:
                vulns.append(
                    Vulnerability(
                        name=f"Dangerous HTTP Method Enabled: {method}",
                        severity=severity,
                        url=url,
                        description=f"{method} returned HTTP {resp.status}. {note}",
                        recommendation=f"Disable {method} unless it is explicitly required",
                        cwe=cwe,
                    )
                )

        logger.debug(f"Method audit for {url}: {len(vulns)} findings")
        return vulns
