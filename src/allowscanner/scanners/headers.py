"""Security header scanner."""

from __future__ import annotations

from typing import TYPE_CHECKING, TypedDict

from ..core.models import SecurityHeader, Severity, Vulnerability

if TYPE_CHECKING:
    from .http import HttpClient


class HeaderInfo(TypedDict, total=False):
    severity: Severity
    desc: str
    fix: str
    cwe: str


EXPECTED_HEADERS: dict[str, HeaderInfo] = {
    "Strict-Transport-Security": {
        "severity": Severity.MEDIUM,
        "desc": "HSTS header missing. Site is vulnerable to SSL stripping attacks.",
        "fix": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "cwe": "CWE-319",
    },
    "Content-Security-Policy": {
        "severity": Severity.MEDIUM,
        "desc": "CSP header missing. Site is more vulnerable to XSS and injection attacks.",
        "fix": "Add a Content-Security-Policy header with restrictive directives",
        "cwe": "CWE-693",
    },
    "X-Content-Type-Options": {
        "severity": Severity.LOW,
        "desc": "X-Content-Type-Options header missing. Browser may MIME-sniff responses.",
        "fix": "Add: X-Content-Type-Options: nosniff",
        "cwe": "CWE-693",
    },
    "X-Frame-Options": {
        "severity": Severity.MEDIUM,
        "desc": "X-Frame-Options header missing. Site may be vulnerable to clickjacking.",
        "fix": "Add: X-Frame-Options: DENY (or SAMEORIGIN)",
        "cwe": "CWE-1021",
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "desc": "Referrer-Policy header missing. URLs may leak to third parties.",
        "fix": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "cwe": "CWE-200",
    },
    "Permissions-Policy": {
        "severity": Severity.LOW,
        "desc": "Permissions-Policy header missing. Browser features not restricted.",
        "fix": "Add Permissions-Policy to restrict camera, microphone, geolocation, etc.",
        "cwe": "CWE-693",
    },
    "X-XSS-Protection": {
        "severity": Severity.INFO,
        "desc": "X-XSS-Protection header missing (deprecated but still useful for older browsers).",
        "fix": "Add: X-XSS-Protection: 0 (disabling is preferred over '1; mode=block')",
    },
}


class HeaderScanner:
    """Analyze HTTP security headers."""

    async def scan(self, url: str, session: HttpClient) -> tuple[list[SecurityHeader], list[Vulnerability]]:

        vulns: list[Vulnerability] = []
        headers_found: list[SecurityHeader] = []

        resp, _ = await session.get(url)
        if not resp:
            return headers_found, vulns

        response_headers = resp.headers

        for header_name, info in EXPECTED_HEADERS.items():  # info: dict[str, Any]
            value = response_headers.get(header_name)
            if value:
                sh = SecurityHeader(name=header_name, present=True, value=value)
                headers_found.append(sh)

                # Check for insecure values
                if header_name == "Content-Security-Policy":
                    if "'unsafe-inline'" in value or "'unsafe-eval'" in value:
                        vulns.append(
                            Vulnerability(
                                name="Insecure CSP Policy",
                                severity=Severity.MEDIUM,
                                url=url,
                                description="CSP contains 'unsafe-inline' or 'unsafe-eval'",
                                payload=value,
                                recommendation="Remove unsafe-inline/unsafe-eval, use nonces or hashes",
                                cwe="CWE-693",
                            )
                        )
                    if "*" in value:
                        vulns.append(
                            Vulnerability(
                                name="Overly Permissive CSP",
                                severity=Severity.MEDIUM,
                                url=url,
                                description="CSP uses wildcard (*) source",
                                payload=value,
                                recommendation="Specify explicit domains instead of wildcards",
                                cwe="CWE-693",
                            )
                        )

                elif header_name == "X-Frame-Options":
                    if value.upper() not in ("DENY", "SAMEORIGIN"):
                        vulns.append(
                            Vulnerability(
                                name="Insecure X-Frame-Options",
                                severity=Severity.MEDIUM,
                                url=url,
                                description=f"X-Frame-Options set to '{value}' (should be DENY or SAMEORIGIN)",
                                recommendation="Set X-Frame-Options to DENY or SAMEORIGIN",
                                cwe="CWE-1021",
                            )
                        )

                elif header_name == "Strict-Transport-Security":
                    if "max-age=" in value:
                        try:
                            max_age = int(value.split("max-age=")[1].split(";")[0].strip())
                            if max_age < 31536000:
                                vulns.append(
                                    Vulnerability(
                                        name="Weak HSTS max-age",
                                        severity=Severity.LOW,
                                        url=url,
                                        description=f"HSTS max-age is {max_age}s (recommended: ≥31536000)",
                                        recommendation="Set max-age to at least 31536000 (1 year)",
                                        cwe="CWE-319",
                                    )
                                )
                        except (ValueError, IndexError):
                            pass
            else:
                sh = SecurityHeader(
                    name=header_name,
                    present=False,
                    recommendation=info["fix"],
                )
                headers_found.append(sh)
                vulns.append(
                    Vulnerability(
                        name=f"Missing {header_name}",
                        severity=info["severity"],
                        url=url,
                        description=info["desc"],
                        recommendation=info["fix"],
                        cwe=info.get("cwe"),
                    )
                )

        # Check for information disclosure headers
        info_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
        for h in info_headers:
            val = response_headers.get(h)
            if val:
                vulns.append(
                    Vulnerability(
                        name=f"Information Disclosure: {h}",
                        severity=Severity.LOW,
                        url=url,
                        description=f"Server reveals: {h}: {val}",
                        payload=val,
                        recommendation=f"Remove or obfuscate the {h} header",
                        cwe="CWE-200",
                    )
                )

        return headers_found, vulns
