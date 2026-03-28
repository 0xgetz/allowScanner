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
        # Parse cookie string into parts, keeping original case for attribute detection
        raw_parts = [p.strip() for p in raw.split(";")]
        parts_lower = [p.lower() for p in raw_parts]
        cookie_name = raw_parts[0].split("=")[0].strip() if raw_parts else "unknown"

        # Helper function to check if an attribute exists (case-insensitive)
        def has_attribute(attr: str) -> bool:
            return any(p.lower() == attr for p in parts_lower)

        # Helper function to get attribute value (case-insensitive)
        def get_attribute_value(attr: str) -> str | None:
            for p in raw_parts:
                if "=" in p:
                    key, _, value = p.partition("=")
                    if key.strip().lower() == attr.lower():
                        return value.strip().lower()
            return None

        if not has_attribute("secure"):
            vulns.append(Vulnerability(
                name=f"Insecure Cookie: {cookie_name}",
                severity=Severity.MEDIUM,
                url=url,
                description=f"Cookie '{cookie_name}' missing Secure flag",
                recommendation="Set the Secure flag on all cookies",
                cwe="CWE-614",
            ))

        if not has_attribute("httponly"):
            vulns.append(Vulnerability(
                name=f"Cookie Missing HttpOnly: {cookie_name}",
                severity=Severity.MEDIUM,
                url=url,
                description=f"Cookie '{cookie_name}' missing HttpOnly flag",
                recommendation="Set the HttpOnly flag on session cookies",
                cwe="CWE-1004",
            ))

        # Check for SameSite attribute (with or without value)
        samesite_value = get_attribute_value("samesite")
        if samesite_value is None:
            vulns.append(Vulnerability(
                name=f"Cookie Missing SameSite: {cookie_name}",
                severity=Severity.LOW,
                url=url,
                description=f"Cookie '{cookie_name}' missing SameSite attribute",
                recommendation="Set SameSite=Lax or SameSite=Strict on cookies",
                cwe="CWE-1275",
            ))

        return vulns
