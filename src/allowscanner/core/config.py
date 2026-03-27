"""Configuration for AllowScanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ScanConfig:
    """Scanner configuration."""

    # Connection
    concurrency: int = 50
    timeout: int = 15
    max_redirects: int = 10
    user_agent: str = "AllowScanner/2.0 (Security Audit)"

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

    # Subdomain wordlist size
    subdomain_wordlist_size: int = 500

    # Port scan range
    port_range: tuple[int, int] = (1, 1024)

    # Output
    output_format: str = "terminal"  # terminal | json | html | markdown
    output_file: Optional[str] = None
    verbose: bool = False
    no_color: bool = False

    # Rate limiting
    rate_limit: Optional[int] = None  # requests per second

    # Proxy
    proxy: Optional[str] = None
