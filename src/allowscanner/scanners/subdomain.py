"""Subdomain enumeration scanner."""

from __future__ import annotations

import asyncio
import socket

from ..core.models import Vulnerability, Severity


COMMON_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test",
    "portal", "ns", "ww1", "host", "support", "dev", "web", "bbs",
    "ww42", "mx", "email", "cloud", "1", "mail1", "2", "forum",
    "owa", "www2", "gw", "admin", "store", "mx1", "cdn", "api",
    "exchange", "office", "mx2", "docs", "beta", "news", "help",
    "apps", "mail3", "search", "vpn2", "my", "login", "viewer",
    "cms", "stage", "db", "vpn1", "mx3", "forum2", "www3",
    "mail4", "admin2", "server2", "mx4", "sip", "proxy",
    "dashboard", "staging", "media", "api2", "webmail2",
    "mail5", "git", "ci", "jenkins", "gitlab", "grafana",
    "prometheus", "kibana", "elastic", "redis", "mongo",
    "postgres", "mysql", "rabbitmq", "kafka", "registry",
    "docker", "k8s", "kube", "argocd", "vault", "consul",
    "nomad", "traefik", "nginx", "haproxy", "monitoring",
    "analytics", "metrics", "status", "health", "uptime",
    "debug", "trace", "log", "logs", "sentry", "errors",
]


class SubdomainScanner:
    """Discover subdomains via DNS resolution."""

    def __init__(self, wordlist_size: int = 500) -> None:
        self.wordlist_size = wordlist_size

    async def scan(self, domain: str) -> tuple[list[str], list[Vulnerability]]:
        subdomains: list[str] = []
        vulns: list[Vulnerability] = []
        sem = asyncio.Semaphore(100)

        wordlist = COMMON_SUBDOMAINS[:self.wordlist_size]

        async def check_subdomain(sub: str) -> None:
            async with sem:
                full = f"{sub}.{domain}"
                try:
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, socket.getaddrinfo, full, None)
                    subdomains.append(full)
                except (socket.gaierror, socket.herror):
                    pass

        tasks = [check_subdomain(s) for s in wordlist]
        await asyncio.gather(*tasks, return_exceptions=True)

        if subdomains:
            vulns.append(Vulnerability(
                name="Subdomain Enumeration",
                severity=Severity.INFO,
                url=domain,
                description=f"Found {len(subdomains)} subdomains: {', '.join(subdomains[:10])}{'...' if len(subdomains) > 10 else ''}",
                recommendation="Review subdomains and ensure only intended ones are accessible",
                cwe="CWE-200",
            ))

        return subdomains, vulns
