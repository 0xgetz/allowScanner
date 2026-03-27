"""CORS misconfiguration scanner."""

from __future__ import annotations

from ..core.models import Vulnerability, Severity


class CORSScanner:
    """Check for CORS misconfigurations."""

    async def scan(self, url: str, session) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []

        # Test with various Origin headers
        test_origins = [
            "https://evil.com",
            "null",
            f"https://evil.{url.split('//')[1].split('/')[0] if '//' in url else 'example.com'}",
            "https://attacker.com",
            url.rstrip("/"),  # Same origin (should be allowed)
        ]

        for origin in test_origins:
            resp, _ = await session.get(url, headers={"Origin": origin})
            if not resp:
                continue

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

            if not acao:
                continue

            # Wildcard with credentials = critical
            if acao == "*" and acac == "true":
                vulns.append(Vulnerability(
                    name="CORS Misconfiguration: Wildcard + Credentials",
                    severity=Severity.CRITICAL,
                    url=url,
                    description="Access-Control-Allow-Origin: * with Allow-Credentials: true",
                    payload=f"Origin: {origin}",
                    recommendation="Never use wildcard origin with credentials. Validate origins strictly.",
                    cwe="CWE-942",
                ))
                return vulns

            # Reflected origin (attacker origin accepted)
            if acao == origin and origin not in (url.rstrip("/"),):
                if acac == "true":
                    vulns.append(Vulnerability(
                        name="CORS Misconfiguration: Reflected Origin with Credentials",
                        severity=Severity.HIGH,
                        url=url,
                        description=f"Server reflects attacker origin and allows credentials",
                        payload=f"Origin: {origin} → ACAO: {acao}",
                        recommendation="Validate origins against a strict allowlist",
                        cwe="CWE-942",
                    ))
                else:
                    vulns.append(Vulnerability(
                        name="CORS: Reflected Origin",
                        severity=Severity.LOW,
                        url=url,
                        description=f"Server reflects arbitrary origin: {origin}",
                        payload=f"Origin: {origin} → ACAO: {acao}",
                        recommendation="Validate origins against a strict allowlist",
                        cwe="CWE-942",
                    ))

            # Null origin
            if acao == "null":
                vulns.append(Vulnerability(
                    name="CORS Misconfiguration: Null Origin Allowed",
                    severity=Severity.MEDIUM,
                    url=url,
                    description="Server allows 'null' origin, exploitable via sandboxed iframes",
                    recommendation="Do not allow null origin",
                    cwe="CWE-942",
                ))

            # Wildcard without credentials (informational)
            if acao == "*" and acac != "true":
                vulns.append(Vulnerability(
                    name="CORS: Public API (Wildcard)",
                    severity=Severity.INFO,
                    url=url,
                    description="API allows all origins (no credentials) — may be intentional for public APIs",
                    recommendation="Verify this is intentional for a public API",
                ))

        # Deduplicate
        seen = set()
        unique = []
        for v in vulns:
            key = (v.name, v.url)
            if key not in seen:
                seen.add(key)
                unique.append(v)

        return unique
