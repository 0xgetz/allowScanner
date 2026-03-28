"""Main scanner orchestrator with robust error handling."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime
from urllib.parse import urlparse

from .core.config import ScanConfig
from .core.exceptions import AllowScannerError, ValidationError
from .core.logging import get_logger, log_scan_session
from .core.models import ScanResult
from .scanners import (
    CookieScanner,
    CORSScanner,
    DNSScanner,
    HeaderScanner,
    SSLScanner,
    SubdomainScanner,
    TechScanner,
    VulnerabilityScanner,
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
                suggestion="Provide a valid URL starting with http:// or https://"
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
                suggestion="URL must have a valid scheme (http/https) and domain"
            )

        if parsed.scheme not in ("http", "https"):
            raise ValidationError(
                f"Unsupported URL scheme: {parsed.scheme}",
                field="url",
                value=parsed.scheme,
                suggestion="Only http:// and https:// schemes are supported"
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
                suggestion="Provide a URL with a valid hostname"
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

            # Run all tasks with error recovery
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results and handle errors
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(f"Scanner task {i} failed: {result}")
                    # Add error as vulnerability for visibility
                    self.result.vulnerabilities.append(
                        self._create_error_vulnerability(result, tasks[i].__name__)
                    )

        except Exception as e:
            logger.error(f"Critical error during scan: {e}")
            raise AllowScannerError(
                f"Scan failed: {e}",
                suggestion="Check logs for details or try with --verbose flag"
            )
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


# Import Vulnerability for type hints
from .core.models import Vulnerability
