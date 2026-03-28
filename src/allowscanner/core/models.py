"""Data models for AllowScanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    @property
    def color(self) -> str:
        return {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "cyan",
            Severity.INFO: "dim",
        }[self]

    def __lt__(self, other: Severity) -> bool:
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        return order.index(self) < order.index(other)


@dataclass
class Vulnerability:
    name: str
    severity: Severity
    url: str
    description: str = ""
    payload: str | None = None
    recommendation: str = ""
    cwe: str | None = None
    cvss: float | None = None


@dataclass
class Technology:
    name: str
    version: str | None = None
    category: str = ""


@dataclass
class SecurityHeader:
    name: str
    present: bool
    value: str | None = None
    recommendation: str = ""


@dataclass
class CertificateInfo:
    issuer: str = ""
    subject: str = ""
    not_before: str = ""
    not_after: str = ""
    protocol: str = ""
    cipher: str = ""
    days_remaining: int | None = None
    san: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    target_url: str
    base_domain: str
    scan_start: datetime = field(default_factory=datetime.now)
    scan_end: datetime | None = None
    duration_seconds: float = 0.0
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    technologies: list[Technology] = field(default_factory=list)
    security_headers: list[SecurityHeader] = field(default_factory=list)
    certificate: CertificateInfo | None = None
    dns_records: dict[str, Any] = field(default_factory=dict)
    subdomains: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    response_headers: dict[str, str] = field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)

    @property
    def score(self) -> int:
        """Calculate a 0-100 security score (100 = best)."""
        penalty = 0
        for v in self.vulnerabilities:
            penalty += {
                Severity.CRITICAL: 20,
                Severity.HIGH: 10,
                Severity.MEDIUM: 5,
                Severity.LOW: 2,
                Severity.INFO: 0,
            }[v.severity]
        return max(0, 100 - penalty)
