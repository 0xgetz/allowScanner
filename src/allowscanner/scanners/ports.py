"""Async TCP port scanner.

Performs a fast connect() scan against a curated set of high-signal service
ports and flags exposed services that bug hunters and pentesters care about
(databases, caches, admin/RPC, plaintext protocols).
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Iterable

from ..core.logging import get_logger
from ..core.models import Severity, Vulnerability

logger = get_logger()

# port -> (service name, severity if exposed, why it matters)
NOTABLE_PORTS: dict[int, tuple[str, Severity, str]] = {
    21: ("FTP", Severity.MEDIUM, "FTP exposed — often allows anonymous or plaintext-credential access"),
    22: ("SSH", Severity.INFO, "SSH exposed to the internet — ensure key-only auth and fail2ban"),
    23: ("Telnet", Severity.HIGH, "Telnet transmits credentials in plaintext"),
    25: ("SMTP", Severity.INFO, "SMTP service exposed"),
    53: ("DNS", Severity.INFO, "DNS service exposed — check for open recursion/zone transfer"),
    110: ("POP3", Severity.LOW, "POP3 may transmit credentials in plaintext"),
    135: ("MSRPC", Severity.MEDIUM, "Windows RPC endpoint exposed"),
    139: ("NetBIOS", Severity.MEDIUM, "NetBIOS session service exposed"),
    143: ("IMAP", Severity.LOW, "IMAP may transmit credentials in plaintext"),
    445: ("SMB", Severity.HIGH, "SMB exposed — common ransomware/lateral-movement vector"),
    1433: ("MSSQL", Severity.HIGH, "Microsoft SQL Server exposed to the network"),
    1521: ("Oracle DB", Severity.HIGH, "Oracle database listener exposed"),
    2375: ("Docker API", Severity.CRITICAL, "Unauthenticated Docker daemon = full host takeover"),
    3306: ("MySQL", Severity.HIGH, "MySQL database exposed to the network"),
    3389: ("RDP", Severity.HIGH, "RDP exposed — brute-force and BlueKeep target"),
    5432: ("PostgreSQL", Severity.HIGH, "PostgreSQL database exposed to the network"),
    5601: ("Kibana", Severity.MEDIUM, "Kibana dashboard exposed"),
    5672: ("AMQP", Severity.MEDIUM, "Message broker (RabbitMQ/AMQP) exposed"),
    6379: ("Redis", Severity.CRITICAL, "Redis is frequently unauthenticated = data theft / RCE"),
    8080: ("HTTP-alt", Severity.INFO, "Alternate HTTP service"),
    8443: ("HTTPS-alt", Severity.INFO, "Alternate HTTPS service"),
    9200: ("Elasticsearch", Severity.HIGH, "Elasticsearch is frequently unauthenticated"),
    11211: ("Memcached", Severity.HIGH, "Memcached exposed — data leak and DDoS amplification"),
    15672: ("RabbitMQ UI", Severity.MEDIUM, "RabbitMQ management UI exposed"),
    27017: ("MongoDB", Severity.CRITICAL, "MongoDB is frequently unauthenticated = data breach"),
}

# A few extra common web/app ports worth probing even though they're low-risk by default.
_EXTRA_PORTS = [80, 443, 3000, 5000, 8000, 8888, 9000]

DEFAULT_PORTS: list[int] = sorted(set(NOTABLE_PORTS) | set(_EXTRA_PORTS))


class PortScanner:
    """Scan a host for open TCP ports using non-blocking connect attempts."""

    def __init__(
        self,
        ports: Iterable[int] | None = None,
        concurrency: int = 100,
        timeout: float = 3.0,
    ) -> None:
        self.ports = list(ports) if ports else list(DEFAULT_PORTS)
        self.timeout = timeout
        self._sem = asyncio.Semaphore(max(1, concurrency))

    async def scan(self, host: str) -> tuple[list[int], list[Vulnerability]]:
        """Return (open_ports, vulnerabilities) for ``host``."""
        open_ports: list[int] = []

        async def probe(port: int) -> None:
            async with self._sem:
                if await self._is_open(host, port):
                    open_ports.append(port)

        await asyncio.gather(*(probe(p) for p in self.ports), return_exceptions=True)
        open_ports.sort()

        vulns: list[Vulnerability] = []
        for port in open_ports:
            service, severity, note = NOTABLE_PORTS.get(port, (f"port {port}", Severity.INFO, "Open TCP port"))
            vulns.append(
                Vulnerability(
                    name=f"Open Port {port} ({service})",
                    severity=severity,
                    url=f"{host}:{port}",
                    description=note,
                    recommendation="Close the port or restrict it with a firewall if it should not be public",
                    cwe="CWE-668",
                )
            )

        logger.debug(f"Port scan for {host}: {len(open_ports)} open of {len(self.ports)} probed")
        return open_ports, vulns

    async def _is_open(self, host: str, port: int) -> bool:
        writer: asyncio.StreamWriter | None = None
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=self.timeout)
            return True
        except (TimeoutError, asyncio.TimeoutError, OSError):
            return False
        finally:
            if writer is not None:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
