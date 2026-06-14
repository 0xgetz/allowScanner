"""Subdomain enumeration scanner with robust error handling."""

from __future__ import annotations

import asyncio
import socket
from typing import TYPE_CHECKING, Any

from ..core.exceptions import DNSError, ScannerError
from ..core.logging import get_logger
from ..core.models import Severity, Vulnerability

if TYPE_CHECKING:
    pass

logger = get_logger()

COMMON_SUBDOMAINS = [
    "www",
    "mail",
    "remote",
    "blog",
    "webmail",
    "server",
    "ns1",
    "ns2",
    "smtp",
    "secure",
    "vpn",
    "m",
    "shop",
    "ftp",
    "mail2",
    "test",
    "portal",
    "ns",
    "ww1",
    "host",
    "support",
    "dev",
    "web",
    "bbs",
    "ww42",
    "mx",
    "email",
    "cloud",
    "1",
    "mail1",
    "2",
    "forum",
    "owa",
    "www2",
    "gw",
    "admin",
    "store",
    "mx1",
    "cdn",
    "api",
    "exchange",
    "office",
    "mx2",
    "docs",
    "beta",
    "news",
    "help",
    "apps",
    "mail3",
    "search",
    "vpn2",
    "my",
    "login",
    "viewer",
    "cms",
    "stage",
    "db",
    "vpn1",
    "mx3",
    "forum2",
    "www3",
    "mail4",
    "admin2",
    "server2",
    "mx4",
    "sip",
    "proxy",
    "dashboard",
    "staging",
    "media",
    "api2",
    "webmail2",
    "mail5",
    "git",
    "ci",
    "jenkins",
    "gitlab",
    "grafana",
    "prometheus",
    "kibana",
    "elastic",
    "redis",
    "mongo",
    "postgres",
    "mysql",
    "rabbitmq",
    "kafka",
    "registry",
    "docker",
    "k8s",
    "kube",
    "argocd",
    "vault",
    "consul",
    "nomad",
    "traefik",
    "nginx",
    "haproxy",
    "monitoring",
    "analytics",
    "metrics",
    "status",
    "health",
    "uptime",
    "debug",
    "trace",
    "log",
    "logs",
    "sentry",
    "errors",
]


class SubdomainScanner:
    """Discover subdomains via DNS resolution with proper error handling."""

    def __init__(self, wordlist_size: int = 500) -> None:
        self.wordlist_size = wordlist_size

    async def scan(self, domain: str) -> tuple[list[str], list[Vulnerability]]:
        """Scan for subdomains.

        Args:
            domain: Domain to scan for subdomains

        Returns:
            Tuple of (list of found subdomains, list of vulnerabilities)

        Raises:
            DNSError: If domain is invalid
            ScannerError: If scanning fails
        """
        # Validate domain
        if not domain or not isinstance(domain, str):
            raise DNSError(
                "Invalid domain name for subdomain scan", domain=domain, suggestion="Provide a valid domain name"
            )

        subdomains: list[str] = []
        vulns: list[Vulnerability] = []
        sem = asyncio.Semaphore(100)  # Limit concurrent DNS queries

        wordlist = COMMON_SUBDOMAINS[: self.wordlist_size]
        logger.debug(f"Starting subdomain scan for {domain} with {len(wordlist)} words")

        async def check_subdomain(sub: str) -> None:
            async with sem:
                full = f"{sub}.{domain}"
                try:
                    loop = asyncio.get_event_loop()
                    # Use run_in_executor to avoid blocking the event loop
                    await loop.run_in_executor(None, self._resolve_host, full)
                    subdomains.append(full)
                except socket.gaierror as e:
                    # DNS resolution failed - subdomain doesn't exist
                    logger.debug(f"Subdomain {full} not found: {e}")
                except socket.herror as e:
                    # DNS resolution error
                    logger.debug(f"DNS error for {full}: {e}")
                except TimeoutError as e:
                    logger.warning(f"DNS timeout for {full}: {e}")
                except OSError as e:
                    logger.warning(f"Network error resolving {full}: {e}")
                except Exception as e:
                    logger.warning(f"Unexpected error resolving {full}: {e}")

        tasks = [check_subdomain(s) for s in wordlist]

        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as e:
            raise ScannerError(
                "Subdomain scan failed", scanner_name="SubdomainScanner", target=domain, original_error=e
            ) from e

        if subdomains:
            # Log found subdomains (limit to first 10 for readability)
            logger.info(f"Found {len(subdomains)} subdomains for {domain}")

            vulns.append(
                Vulnerability(
                    name="Subdomain Enumeration",
                    severity=Severity.INFO,
                    url=domain,
                    description=f"Found {len(subdomains)} subdomains: {', '.join(subdomains[:10])}{'...' if len(subdomains) > 10 else ''}",
                    recommendation="Review subdomains and ensure only intended ones are accessible",
                    cwe="CWE-200",
                )
            )

        return subdomains, vulns

    def _resolve_host(self, hostname: str) -> list[Any] | None:
        """Resolve hostname to IP addresses.

        This method runs in an executor to avoid blocking the event loop.

        Args:
            hostname: Hostname to resolve

        Returns:
            List of address info tuples, or None if resolution fails

        Raises:
            socket.gaierror: If hostname cannot be resolved
            socket.herror: If DNS error occurs
        """
        try:
            # Use getaddrinfo for both IPv4 and IPv6
            return socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror:
            raise
        except socket.herror:
            raise
        except TimeoutError:
            raise
        except OSError:
            raise
