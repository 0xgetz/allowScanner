"""Main scanner orchestrator with robust error handling."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from .core.config import ScanConfig
from .core.exceptions import AllowScannerError, ValidationError
from .core.logging import get_logger, log_scan_session
from .core.models import ScanResult, Vulnerability
from .core.scope import Scope
from .core.suppress import apply_suppressions, load_suppressions
from .scanners import (
    CookieScanner,
    CORSScanner,
    Crawler,
    DNSScanner,
    FuzzScanner,
    GraphQLScanner,
    HeaderScanner,
    HttpMethodScanner,
    PortScanner,
    SecretScanner,
    SSLScanner,
    SubdomainScanner,
    TakeoverScanner,
    TechScanner,
    VulnerabilityScanner,
    WafScanner,
)
from .scanners.http import HttpClient

logger = get_logger()


class AllowScanner:
    """Advanced web security scanner with error recovery."""

    def __init__(self, target_url: str, config: ScanConfig | None = None) -> None:
        # Validate and sanitize URL
        self.target_url = self._validate_url(target_url)
        self.base_domain = self._extract_domain(target_url)
        self.config = config or ScanConfig()
        self.result = ScanResult(
            target_url=self.target_url,
            base_domain=self.base_domain,
        )
        logger.info(f"Scanner initialized for target: {self.target_url}")

    def _validate_url(self, url: str) -> str:
        """Validate and sanitize the target URL.

        Args:
            url: Target URL to validate

        Returns:
            Sanitized URL

        Raises:
            ValidationError: If URL is invalid
        """
        if not url or not isinstance(url, str):
            raise ValidationError(
                "Target URL cannot be empty",
                field="url",
                suggestion="Provide a valid URL starting with http:// or https://",
            )

        # Strip trailing slashes and whitespace
        url = url.strip().rstrip("/")

        # Check if URL has a scheme
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        # Validate URL structure
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise ValidationError(
                f"Invalid URL format: {url}",
                field="url",
                value=url,
                suggestion="URL must have a valid scheme (http/https) and domain",
            )

        if parsed.scheme not in ("http", "https"):
            raise ValidationError(
                f"Unsupported URL scheme: {parsed.scheme}",
                field="url",
                value=parsed.scheme,
                suggestion="Only http:// and https:// schemes are supported",
            )

        return url

    def _extract_domain(self, url: str) -> str:
        """Extract the base domain from URL.

        Args:
            url: URL to extract domain from

        Returns:
            Base domain string
        """
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            raise ValidationError(
                "Could not extract hostname from URL",
                field="url",
                value=url,
                suggestion="Provide a URL with a valid hostname",
            )
        return hostname

    @log_scan_session
    async def run(self) -> ScanResult:
        """Execute all scan modules and return results.

        Returns:
            ScanResult with all findings

        Raises:
            AllowScannerError: If scan fails completely
        """
        self.result.scan_start = datetime.now()
        start = time.monotonic()

        http = HttpClient(self.config)
        await http.start()

        try:
            tasks: list[Any] = []

            if self.config.check_crawl:
                await self._run_crawl(http)

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
            if self.config.check_ports:
                tasks.append(self._run_ports())
            if self.config.check_fuzz:
                tasks.append(self._run_fuzz(http))
            if self.config.check_secrets:
                tasks.append(self._run_secrets(http))
            if self.config.check_graphql:
                tasks.append(self._run_graphql(http))
            if self.config.check_methods:
                tasks.append(self._run_methods(http))
            if self.config.check_waf:
                tasks.append(self._run_waf(http))

            # Run all tasks with error recovery
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results and handle errors
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(f"Scanner task {i} failed: {result}")
                    # Add error as vulnerability for visibility
                    self.result.vulnerabilities.append(self._create_error_vulnerability(result, tasks[i].__name__))

            if self.config.check_takeover:
                await self._run_takeover(http)

            patterns = load_suppressions(self.config.suppress_file)
            if patterns:
                before = len(self.result.vulnerabilities)
                self.result.vulnerabilities = apply_suppressions(self.result.vulnerabilities, patterns)
                suppressed = before - len(self.result.vulnerabilities)
                if suppressed:
                    logger.info(f"Suppressed {suppressed} finding(s) via suppression rules")

        except Exception as e:
            logger.error(f"Critical error during scan: {e}")
            raise AllowScannerError(
                f"Scan failed: {e}", suggestion="Check logs for details or try with --verbose flag"
            ) from e
        finally:
            await http.close()

        self.result.scan_end = datetime.now()
        self.result.duration_seconds = time.monotonic() - start

        logger.info(f"Scan completed in {self.result.duration_seconds:.2f}s")
        return self.result

    def _create_error_vulnerability(self, error: Exception, scanner_name: str) -> Vulnerability:
        """Create a vulnerability entry from an error.

        Args:
            error: Exception that occurred
            scanner_name: Name of the scanner that failed

        Returns:
            Vulnerability object representing the error
        """
        from .core.models import Severity, Vulnerability

        return Vulnerability(
            name=f"Scanner Error: {scanner_name}",
            severity=Severity.MEDIUM,
            url=self.target_url,
            description=f"Scanner encountered an error: {error!s}",
            recommendation="Review scanner logs and try again",
            cwe="CWE-unknown",
        )

    async def _run_tech(self, http: HttpClient) -> None:
        """Run technology detection scanner."""
        try:
            scanner = TechScanner()
            self.result.technologies = await scanner.scan(self.target_url, http)
            logger.debug(f"Technology scan completed: {len(self.result.technologies)} found")
        except Exception as e:
            logger.error(f"Technology scanner failed: {e}")
            raise

    async def _run_headers(self, http: HttpClient) -> None:
        """Run security header scanner."""
        try:
            scanner = HeaderScanner()
            headers, vulns = await scanner.scan(self.target_url, http)
            self.result.security_headers = headers
            self.result.vulnerabilities.extend(vulns)
            logger.debug(f"Header scan completed: {len(vulns)} issues found")
        except Exception as e:
            logger.error(f"Header scanner failed: {e}")
            raise

    async def _run_vulns(self, http: HttpClient) -> None:
        """Run vulnerability scanner."""
        try:
            scanner = VulnerabilityScanner(self.config)
            vulns = await scanner.scan(self.target_url, http)
            self.result.vulnerabilities.extend(vulns)
            logger.debug(f"Vulnerability scan completed: {len(vulns)} found")
        except Exception as e:
            logger.error(f"Vulnerability scanner failed: {e}")
            raise

    async def _run_ssl(self) -> None:
        """Run SSL/TLS scanner."""
        try:
            scanner = SSLScanner()
            cert, vulns = await scanner.scan(self.target_url)
            if cert:
                self.result.certificate = cert
            self.result.vulnerabilities.extend(vulns)
            logger.debug(f"SSL scan completed: {len(vulns)} issues found")
        except Exception as e:
            logger.error(f"SSL scanner failed: {e}")
            raise

    async def _run_dns(self) -> None:
        """Run DNS security scanner."""
        try:
            scanner = DNSScanner()
            records, vulns = await scanner.scan(self.base_domain)
            self.result.dns_records = records
            self.result.vulnerabilities.extend(vulns)
            logger.debug(f"DNS scan completed: {len(vulns)} issues found")
        except Exception as e:
            logger.error(f"DNS scanner failed: {e}")
            raise

    async def _run_subdomains(self) -> None:
        """Run subdomain enumeration scanner."""
        try:
            scanner = SubdomainScanner(self.config.subdomain_wordlist_size)
            subs, vulns = await scanner.scan(self.base_domain)
            self.result.subdomains = subs
            self.result.vulnerabilities.extend(vulns)
            logger.debug(f"Subdomain scan completed: {len(subs)} found")
        except Exception as e:
            logger.error(f"Subdomain scanner failed: {e}")
            raise

    async def _run_cors(self, http: HttpClient) -> None:
        """Run CORS scanner."""
        try:
            scanner = CORSScanner()
            vulns = await scanner.scan(self.target_url, http)
            self.result.vulnerabilities.extend(vulns)
            logger.debug(f"CORS scan completed: {len(vulns)} issues found")
        except Exception as e:
            logger.error(f"CORS scanner failed: {e}")
            raise

    async def _run_cookies(self, http: HttpClient) -> None:
        """Run cookie security scanner."""
        try:
            scanner = CookieScanner()
            vulns = await scanner.scan(self.target_url, http)
            self.result.vulnerabilities.extend(vulns)
            logger.debug(f"Cookie scan completed: {len(vulns)} issues found")
        except Exception as e:
            logger.error(f"Cookie scanner failed: {e}")
            raise

    async def _run_ports(self) -> None:
        """Run TCP port scanner."""
        try:
            scanner = PortScanner(ports=self.config.port_list, concurrency=self.config.concurrency)
            open_ports, vulns = await scanner.scan(self.base_domain)
            self.result.open_ports = open_ports
            self.result.vulnerabilities.extend(vulns)
            logger.debug(f"Port scan completed: {len(open_ports)} open ports")
        except Exception as e:
            logger.error(f"Port scanner failed: {e}")
            raise

    async def _run_fuzz(self, http: HttpClient) -> None:
        """Run content discovery / fuzzing scanner."""
        try:
            scanner = FuzzScanner(wordlist=self.config.fuzz_wordlist, concurrency=self.config.concurrency)
            vulns = await scanner.scan(self.target_url, http)
            self.result.vulnerabilities.extend(vulns)
            logger.debug(f"Fuzzing completed: {len(vulns)} findings")
        except Exception as e:
            logger.error(f"Fuzz scanner failed: {e}")
            raise

    async def _run_secrets(self, http: HttpClient) -> None:
        """Run secret / endpoint discovery scanner."""
        try:
            scanner = SecretScanner(concurrency=self.config.concurrency)
            vulns = await scanner.scan(self.target_url, http)
            self.result.vulnerabilities.extend(vulns)
            logger.debug(f"Secret scan completed: {len(vulns)} findings")
        except Exception as e:
            logger.error(f"Secret scanner failed: {e}")
            raise

    async def _run_graphql(self, http: HttpClient) -> None:
        """Run GraphQL introspection scanner."""
        try:
            scanner = GraphQLScanner()
            vulns = await scanner.scan(self.target_url, http)
            self.result.vulnerabilities.extend(vulns)
            logger.debug(f"GraphQL scan completed: {len(vulns)} findings")
        except Exception as e:
            logger.error(f"GraphQL scanner failed: {e}")
            raise

    async def _run_methods(self, http: HttpClient) -> None:
        """Run HTTP method audit."""
        try:
            scanner = HttpMethodScanner()
            vulns = await scanner.scan(self.target_url, http)
            self.result.vulnerabilities.extend(vulns)
            logger.debug(f"Method audit completed: {len(vulns)} findings")
        except Exception as e:
            logger.error(f"Method scanner failed: {e}")
            raise

    async def _run_takeover(self, http: HttpClient) -> None:
        """Run subdomain takeover detection over the base domain and discovered subdomains."""
        try:
            hosts = [self.base_domain, *self.result.subdomains]
            scanner = TakeoverScanner(concurrency=self.config.concurrency)
            vulns = await scanner.scan(hosts, http)
            self.result.vulnerabilities.extend(vulns)
            logger.debug(f"Takeover scan completed: {len(vulns)} findings")
        except Exception as e:
            logger.error(f"Takeover scanner failed: {e}")

    async def _run_waf(self, http: HttpClient) -> None:
        """Run WAF/CDN detection."""
        try:
            scanner = WafScanner()
            vulns = await scanner.scan(self.target_url, http)
            self.result.vulnerabilities.extend(vulns)
            logger.debug(f"WAF scan completed: {len(vulns)} findings")
        except Exception as e:
            logger.error(f"WAF scanner failed: {e}")
            raise

    async def _run_crawl(self, http: HttpClient) -> None:
        """Crawl the in-scope surface and record discovered URLs."""
        try:
            scope = Scope(
                hosts=self.config.scope_hosts or [self.base_domain],
                exclude_patterns=self.config.exclude_patterns,
            )
            crawler = Crawler(
                scope,
                max_pages=self.config.crawl_max_pages,
                max_depth=self.config.crawl_max_depth,
                concurrency=self.config.concurrency,
            )
            discovered, vulns = await crawler.scan(self.target_url, http)
            self.result.discovered_urls = discovered
            self.result.vulnerabilities.extend(vulns)
            logger.debug(f"Crawl completed: {len(discovered)} URLs discovered")
        except Exception as e:
            logger.error(f"Crawler failed: {e}")
