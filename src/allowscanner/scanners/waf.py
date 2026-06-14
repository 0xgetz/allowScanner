"""WAF / CDN detection.

Fingerprints common web application firewalls and CDNs from response headers
and cookies, then fires a benign attack-shaped probe to see whether traffic
gets actively blocked. Knowing a WAF is in front changes how the rest of an
engagement is approached, so this is reported as informational context.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..core.logging import get_logger
from ..core.models import Severity, Vulnerability

if TYPE_CHECKING:
    from .http import HttpClient

logger = get_logger()

# name -> {"headers": {header: (substrings,)}, "cookies": (substrings,), "server": (substrings,)}
SIGNATURES: dict[str, dict[str, object]] = {
    "Cloudflare": {
        "headers": {"server": ("cloudflare",), "cf-ray": (), "cf-cache-status": ()},
        "cookies": ("__cfduid", "cf_clearance", "__cf_bm"),
    },
    "Akamai": {
        "headers": {"server": ("akamaighost",), "x-akamai-transformed": (), "akamai-grn": ()},
        "cookies": ("akamai",),
    },
    "AWS CloudFront / WAF": {
        "headers": {"server": ("cloudfront",), "x-amz-cf-id": (), "x-amzn-requestid": ()},
        "cookies": ("awsalb", "awsalbcors"),
    },
    "Imperva / Incapsula": {
        "headers": {"x-iinfo": (), "x-cdn": ("incapsula",)},
        "cookies": ("incap_ses", "visid_incap", "nlbi_"),
    },
    "Sucuri": {
        "headers": {"server": ("sucuri",), "x-sucuri-id": (), "x-sucuri-cache": ()},
        "cookies": (),
    },
    "F5 BIG-IP ASM": {
        "headers": {"server": ("big-ip", "bigip")},
        "cookies": ("ts", "bigipserver", "f5_cspm"),
    },
    "Fastly": {
        "headers": {"x-served-by": ("cache-",), "x-fastly-request-id": (), "fastly-io-info": ()},
        "cookies": (),
    },
    "Barracuda": {
        "headers": {"server": ("barracuda",)},
        "cookies": ("barra_counter_session", "bnes_"),
    },
    "Wordfence": {
        "headers": {},
        "cookies": ("wordfence_verifiedhuman", "wfvt_"),
    },
    "Azure Front Door": {
        "headers": {"x-azure-ref": (), "server": ("azure",)},
        "cookies": (),
    },
}

# Body / status signatures that indicate active blocking when a probe is sent.
BLOCK_SIGNATURES = (
    "attention required",
    "access denied",
    "request blocked",
    "web application firewall",
    "this request has been blocked",
    "you have been blocked",
    "incident id",
    "not acceptable",
    "mod_security",
    "blocked by",
)
BLOCK_STATUS = {403, 406, 429, 501, 503}

# A harmless but attack-shaped query string to trip signature-based WAFs.
_PROBE_QS = "?allowscanner_test=%3Cscript%3Ealert(1)%3C/script%3E%27%20OR%20%271%27=%271"


class WafScanner:
    """Detect WAFs/CDNs from fingerprints and an active blocking probe."""

    async def scan(self, url: str, session: HttpClient) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        try:
            resp, _ = await session.get(url)
        except Exception:
            return vulns
        if not resp:
            return vulns

        headers = {k.lower(): str(v).lower() for k, v in resp.headers.items()}
        cookies = headers.get("set-cookie", "")

        detected: list[str] = []
        for name, sig in SIGNATURES.items():
            if self._matches(sig, headers, cookies):
                detected.append(name)

        for name in detected:
            vulns.append(
                Vulnerability(
                    name=f"WAF/CDN Detected: {name}",
                    severity=Severity.INFO,
                    url=url,
                    description=f"Responses carry {name} fingerprints",
                    recommendation="Account for the WAF/CDN when testing; some findings may be filtered or rate-limited",
                    cwe="CWE-200",
                )
            )

        # Active probe: does an attack-shaped request get blocked?
        blocked = await self._probe_blocking(url, session)
        if blocked and not detected:
            vulns.append(
                Vulnerability(
                    name="WAF/IPS Blocking Detected",
                    severity=Severity.INFO,
                    url=url,
                    description="An attack-shaped request was actively blocked, indicating a WAF or IPS is present",
                    recommendation="Account for the filtering layer when testing this target",
                    cwe="CWE-200",
                )
            )

        logger.debug(f"WAF scan for {url}: detected={detected or 'none'} blocked={blocked}")
        return vulns

    def _matches(self, sig: dict[str, object], headers: dict[str, str], cookies: str) -> bool:
        header_sigs = sig.get("headers", {})
        if isinstance(header_sigs, dict):
            for header, substrings in header_sigs.items():
                if header not in headers:
                    continue
                subs = substrings if isinstance(substrings, tuple) else ()
                if not subs or any(s in headers[header] for s in subs):
                    return True
        cookie_sigs = sig.get("cookies", ())
        return isinstance(cookie_sigs, tuple) and any(c in cookies for c in cookie_sigs)

    async def _probe_blocking(self, url: str, session: HttpClient) -> bool:
        target = url.rstrip("/") + "/" + _PROBE_QS
        try:
            resp, body = await session.get(target, allow_redirects=False)
        except Exception:
            return False
        if not resp:
            return False
        if resp.status in BLOCK_STATUS:
            return True
        low = body.lower()
        return any(sig in low for sig in BLOCK_SIGNATURES)
