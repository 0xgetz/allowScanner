"""Cookie security scanner."""

from __future__ import annotations

from ..core.models import Severity, Vulnerability


class CookieScanner:
    """Check cookie security attributes."""

    async def scan(self, url: str, session: object) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []

        resp, _ = await session.get(url)
        if not resp:
            return vulns

        # Check Set-Cookie headers
        cookies = resp.cookies
        if not cookies:
            # Also check raw headers
            raw_cookies = resp.headers.getall("Set-Cookie", []) if hasattr(resp.headers, 'getall') else []
            if not raw_cookies:
                return vulns
            for raw in raw_cookies:
                vulns.extend(self._check_cookie_string(raw, url))
        else:
            for cookie in cookies.values():
                vulns.extend(self._check_cookie(cookie, url))

        return vulns

    def _check_cookie(self, cookie, url: str) -> list[Vulnerability]:
        vulns = []
        name = cookie.key

        if not cookie.get("secure"):
            vulns.append(Vulnerability(
                name=f"Insecure Cookie: {name}",
                severity=Severity.MEDIUM,
                url=url,
                description=f"Cookie '{name}' missing Secure flag — can be sent over HTTP",
                recommendation="Set the Secure flag on all cookies",
                cwe="CWE-614",
            ))

        if not cookie.get("httponly"):
            vulns.append(Vulnerability(
                name=f"Cookie Missing HttpOnly: {name}",
                severity=Severity.MEDIUM,
                url=url,
                description=f"Cookie '{name}' missing HttpOnly flag — accessible via JavaScript",
                recommendation="Set the HttpOnly flag on session cookies",
                cwe="CWE-1004",
            ))

        return vulns

    def _check_cookie_string(self, raw: str, url: str) -> list[Vulnerability]:
        vulns = []
        parts = [p.strip().lower() for p in raw.split(";")]
        cookie_name = parts[0].split("=")[0].strip() if parts else "unknown"

        if "secure" not in parts:
            vulns.append(Vulnerability(
                name=f"Insecure Cookie: {cookie_name}",
                severity=Severity.MEDIUM,
                url=url,
                description=f"Cookie '{cookie_name}' missing Secure flag",
                recommendation="Set the Secure flag on all cookies",
                cwe="CWE-614",
            ))

        if "httponly" not in parts:
            vulns.append(Vulnerability(
                name=f"Cookie Missing HttpOnly: {cookie_name}",
                severity=Severity.MEDIUM,
                url=url,
                description=f"Cookie '{cookie_name}' missing HttpOnly flag",
                recommendation="Set the HttpOnly flag on session cookies",
                cwe="CWE-1004",
            ))

        if "samesite" not in parts:
            vulns.append(Vulnerability(
                name=f"Cookie Missing SameSite: {cookie_name}",
                severity=Severity.LOW,
                url=url,
                description=f"Cookie '{cookie_name}' missing SameSite attribute",
                recommendation="Set SameSite=Lax or SameSite=Strict on cookies",
                cwe="CWE-1275",
            ))

        return vulns
