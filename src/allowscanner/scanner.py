"""Main scanner orchestrator."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime
from urllib.parse import urlparse

from .core.config import ScanConfig
from .core.models import ScanResult
from .scanners.http import HttpClient
from .scanners import (
    SSLScanner, DNSScanner, VulnerabilityScanner, HeaderScanner,
    SubdomainScanner, TechScanner, CORSScanner, CookieScanner,
)


class AllowScanner:
    """Advanced web security scanner."""

    def __init__(self, target_url: str, config: ScanConfig | None = None) -> None:
        self.target_url = target_url.rstrip("/")
        self.base_domain = urlparse(target_url).hostname or target_url
        self.config = config or ScanConfig()
        self.result = ScanResult(
            target_url=self.target_url,
            base_domain=self.base_domain,
        )

    async def run(self) -> ScanResult:
        """Execute all scan modules and return results."""
        self.result.scan_start = datetime.now()
        start = time.monotonic()

        http = HttpClient(self.config)
        await http.start()

        try:
            tasks: list = []

            if self.config.check_technologies:
                tasks.append(self._run_tech(http))
            if self.config.check_headers:
                tasks.append(self._run_headers(http))
            if self.config.check_vulnerabilities:
                tasks.append(self._run_vulns(http))
            if self.config.check_ssl:
                tasks.append(self._run_ssl())
            if self.config.check_dns:
                tasks.append(self._run_dns())
            if self.config.check_subdomains:
                tasks.append(self._run_subdomains())
            if self.config.check_cors:
                tasks.append(self._run_cors(http))
            if self.config.check_cookies:
                tasks.append(self._run_cookies(http))

            await asyncio.gather(*tasks, return_exceptions=True)

        finally:
            await http.close()

        self.result.scan_end = datetime.now()
        self.result.duration_seconds = time.monotonic() - start

        return self.result

    async def _run_tech(self, http: HttpClient) -> None:
        scanner = TechScanner()
        self.result.technologies = await scanner.scan(self.target_url, http)

    async def _run_headers(self, http: HttpClient) -> None:
        scanner = HeaderScanner()
        headers, vulns = await scanner.scan(self.target_url, http)
        self.result.security_headers = headers
        self.result.vulnerabilities.extend(vulns)

    async def _run_vulns(self, http: HttpClient) -> None:
        scanner = VulnerabilityScanner(self.config)
        vulns = await scanner.scan(self.target_url, http)
        self.result.vulnerabilities.extend(vulns)

    async def _run_ssl(self) -> None:
        scanner = SSLScanner()
        cert, vulns = await scanner.scan(self.target_url)
        if cert:
            self.result.certificate = cert
        self.result.vulnerabilities.extend(vulns)

    async def _run_dns(self) -> None:
        scanner = DNSScanner()
        records, vulns = await scanner.scan(self.base_domain)
        self.result.dns_records = records
        self.result.vulnerabilities.extend(vulns)

    async def _run_subdomains(self) -> None:
        scanner = SubdomainScanner(self.config.subdomain_wordlist_size)
        subs, vulns = await scanner.scan(self.base_domain)
        self.result.subdomains = subs
        self.result.vulnerabilities.extend(vulns)

    async def _run_cors(self, http: HttpClient) -> None:
        scanner = CORSScanner()
        vulns = await scanner.scan(self.target_url, http)
        self.result.vulnerabilities.extend(vulns)

    async def _run_cookies(self, http: HttpClient) -> None:
        scanner = CookieScanner()
        vulns = await scanner.scan(self.target_url, http)
        self.result.vulnerabilities.extend(vulns)
