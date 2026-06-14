"""GraphQL endpoint discovery and introspection check.

Probes common GraphQL routes and tries an introspection query. Exposed
introspection hands an attacker the full schema, so it's a frequent bug
bounty finding.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from ..core.logging import get_logger
from ..core.models import Severity, Vulnerability

if TYPE_CHECKING:
    from .http import HttpClient

logger = get_logger()

GRAPHQL_PATHS = [
    "graphql",
    "api/graphql",
    "v1/graphql",
    "v2/graphql",
    "query",
    "graphql/console",
    "graphiql",
    "api",
]

INTROSPECTION_QUERY = '{"query":"{__schema{queryType{name}}}"}'


class GraphQLScanner:
    """Detect GraphQL endpoints and whether introspection is enabled."""

    def __init__(self, concurrency: int = 10) -> None:
        self._sem = asyncio.Semaphore(max(1, concurrency))

    async def scan(self, url: str, session: HttpClient) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        base = url.rstrip("/") + "/"
        seen: set[str] = set()

        async def probe(path: str) -> None:
            async with self._sem:
                target = urljoin(base, path)
                try:
                    resp, body = await session.request(
                        "POST",
                        target,
                        data=INTROSPECTION_QUERY,
                        headers={"Content-Type": "application/json"},
                    )
                except Exception:
                    return
                if not resp or target in seen:
                    return

                low = body.lower()
                if '"__schema"' in body or '"querytype"' in low:
                    seen.add(target)
                    vulns.append(
                        Vulnerability(
                            name="GraphQL Introspection Enabled",
                            severity=Severity.MEDIUM,
                            url=target,
                            description="The GraphQL endpoint exposes its full schema via introspection",
                            recommendation="Disable introspection in production to shrink the attack surface",
                            cwe="CWE-200",
                        )
                    )
                elif "graphql" in low and ("errors" in low or "must provide query" in low):
                    seen.add(target)
                    vulns.append(
                        Vulnerability(
                            name="GraphQL Endpoint Detected",
                            severity=Severity.INFO,
                            url=target,
                            description="A GraphQL endpoint is reachable (introspection appears disabled)",
                            recommendation="Ensure authorization, depth limiting, and rate limiting are enforced",
                            cwe="CWE-200",
                        )
                    )

        await asyncio.gather(*(probe(p) for p in GRAPHQL_PATHS), return_exceptions=True)
        logger.debug(f"GraphQL scan for {url}: {len(vulns)} findings")
        return vulns
