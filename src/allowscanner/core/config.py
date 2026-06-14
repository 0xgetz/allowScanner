"""Configuration for AllowScanner with validation."""

from __future__ import annotations

from dataclasses import dataclass, field

from .exceptions import ConfigurationError
from .logging import get_logger

logger = get_logger()


@dataclass
class ScanConfig:
    """Scanner configuration with validation."""

    # Connection
    concurrency: int = 50
    timeout: int = 15
    max_redirects: int = 10
    user_agent: str = "AllowScanner/2.0 (Security Audit)"
    verify_ssl: bool = True  # Enable/disable SSL verification

    # Scan modules (all enabled by default)
    check_ssl: bool = True
    check_dns: bool = True
    check_headers: bool = True
    check_vulnerabilities: bool = True
    check_admin_panels: bool = True
    check_sensitive_files: bool = True
    check_technologies: bool = True
    check_subdomains: bool = True
    check_ports: bool = True
    check_cors: bool = True
    check_cookies: bool = True
    check_fuzz: bool = True
    check_secrets: bool = True
    check_graphql: bool = True
    check_methods: bool = True
    check_takeover: bool = True
    check_waf: bool = True
    check_crawl: bool = True

    # Subdomain wordlist size
    subdomain_wordlist_size: int = 500
    fuzz_wordlist: list[str] | None = None
    port_list: list[int] | None = None
    extra_headers: dict[str, str] = field(default_factory=dict)
    scope_hosts: list[str] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=list)
    crawl_max_pages: int = 100
    crawl_max_depth: int = 2
    suppress_file: str | None = None
    baseline_file: str | None = None

    # Port scan range
    port_range: tuple[int, int] = field(default_factory=lambda: (1, 1024))

    # Output
    output_format: str = "terminal"  # terminal | json | html | markdown
    output_file: str | None = None
    verbose: bool = False
    no_color: bool = False

    # Rate limiting
    rate_limit: int | None = None  # requests per second

    # Proxy
    proxy: str | None = None

    def __post_init__(self) -> None:
        """Validate configuration after initialization."""
        self._validate()

    def _validate(self) -> None:
        """Validate all configuration values.

        Raises:
            ConfigurationError: If any configuration value is invalid
        """
        # Validate concurrency
        if not isinstance(self.concurrency, int) or self.concurrency < 1:
            raise ConfigurationError(
                "Concurrency must be a positive integer",
                config_key="concurrency",
                config_value=str(self.concurrency),
                suggestion="Set concurrency to a value >= 1",
            )

        if self.concurrency > 1000:
            raise ConfigurationError(
                "Concurrency too high (max 1000)",
                config_key="concurrency",
                config_value=str(self.concurrency),
                allowed_values=["1-1000"],
                suggestion="Reduce concurrency to avoid overwhelming the target",
            )

        # Validate timeout
        if not isinstance(self.timeout, (int, float)) or self.timeout < 1:
            raise ConfigurationError(
                "Timeout must be a positive number",
                config_key="timeout",
                config_value=str(self.timeout),
                suggestion="Set timeout to a value >= 1 second",
            )

        if self.timeout > 300:
            raise ConfigurationError(
                "Timeout too high (max 300 seconds)",
                config_key="timeout",
                config_value=str(self.timeout),
                allowed_values=["1-300"],
                suggestion="Reduce timeout to avoid excessively long scans",
            )

        # Validate max redirects
        if not isinstance(self.max_redirects, int) or self.max_redirects < 0:
            raise ConfigurationError(
                "Max redirects must be a non-negative integer",
                config_key="max_redirects",
                config_value=str(self.max_redirects),
                suggestion="Set max_redirects to 0 or higher",
            )

        # Validate subdomain wordlist size
        if not isinstance(self.subdomain_wordlist_size, int) or self.subdomain_wordlist_size < 1:
            raise ConfigurationError(
                "Subdomain wordlist size must be a positive integer",
                config_key="subdomain_wordlist_size",
                config_value=str(self.subdomain_wordlist_size),
                suggestion="Set wordlist size to a value >= 1",
            )

        # Validate port range
        if not isinstance(self.port_range, (list, tuple)) or len(self.port_range) != 2:
            raise ConfigurationError(
                "Port range must be a tuple of two integers",
                config_key="port_range",
                config_value=str(self.port_range),
                suggestion="Set port_range to (start, end) format",
            )

        start_port, end_port = self.port_range
        if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
            raise ConfigurationError(
                "Port numbers must be between 1 and 65535",
                config_key="port_range",
                config_value=str(self.port_range),
                allowed_values=["1-65535"],
                suggestion="Use valid port numbers",
            )

        if start_port > end_port:
            raise ConfigurationError(
                "Start port must be <= end port",
                config_key="port_range",
                config_value=str(self.port_range),
                suggestion="Swap the port numbers",
            )

        # Validate output format
        valid_formats = {"terminal", "json", "html", "markdown", "sarif"}
        if self.output_format not in valid_formats:
            raise ConfigurationError(
                f"Invalid output format: {self.output_format}",
                config_key="output_format",
                config_value=self.output_format,
                allowed_values=list(valid_formats),
                suggestion="Use one of: terminal, json, html, markdown",
            )

        # Validate rate limit
        if self.rate_limit is not None and (not isinstance(self.rate_limit, (int, float)) or self.rate_limit < 1):
            raise ConfigurationError(
                "Rate limit must be a positive number",
                config_key="rate_limit",
                config_value=str(self.rate_limit),
                suggestion="Set rate_limit to a value >= 1 or None",
            )

        logger.debug("Configuration validated successfully")
