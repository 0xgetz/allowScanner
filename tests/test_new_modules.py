"""Tests for the port scanner, content-discovery fuzzer, and rate limiter."""

from __future__ import annotations

import asyncio
import socket

import pytest

from allowscanner.core.models import Severity
from allowscanner.scanners.fuzz import FuzzScanner
from allowscanner.scanners.http import RateLimiter
from allowscanner.scanners.ports import DEFAULT_PORTS, NOTABLE_PORTS, PortScanner


class _FakeResponse:
    def __init__(self, status: int) -> None:
        self.status = status


class _FakeSession:
    """Stands in for HttpClient: maps path suffixes to (status, body)."""

    def __init__(self, routes: dict[str, tuple[int, str]], default: tuple[int, str]) -> None:
        self.routes = routes
        self.default = default

    async def get(self, url: str, **kwargs: object) -> tuple[_FakeResponse, str]:
        for suffix, (status, body) in self.routes.items():
            if url.rstrip("/").endswith(suffix):
                return _FakeResponse(status), body
        status, body = self.default
        return _FakeResponse(status), body


# --- Port scanner ---------------------------------------------------------


async def test_port_scanner_detects_open_and_ignores_closed() -> None:
    # Bind a real ephemeral port on localhost so the test is deterministic.
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    open_port = server.getsockname()[1]

    # Find a port that is (almost certainly) closed.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
    probe.close()

    try:
        scanner = PortScanner(ports=[open_port, closed_port], timeout=1.0)
        open_ports, vulns = await scanner.scan("127.0.0.1")
        assert open_port in open_ports
        assert closed_port not in open_ports
        assert all(v.url.endswith(str(open_port)) for v in vulns)
    finally:
        server.close()


def test_default_ports_include_high_risk_services() -> None:
    for risky in (6379, 27017, 3306, 9200):
        assert risky in DEFAULT_PORTS
        assert risky in NOTABLE_PORTS


async def test_port_scanner_handles_unresolvable_host() -> None:
    scanner = PortScanner(ports=[80], timeout=0.5)
    open_ports, vulns = await scanner.scan("nonexistent.invalid.allowscanner")
    assert open_ports == []
    assert vulns == []


# --- Fuzzer ---------------------------------------------------------------


async def test_fuzz_reports_discovered_and_protected_paths() -> None:
    session = _FakeSession(
        routes={"/admin": (200, "admin panel here"), "/secret": (403, "forbidden")},
        default=(404, "not found"),
    )
    scanner = FuzzScanner(wordlist=["admin", "secret", "missing"])
    vulns = await scanner.scan("https://example.com", session)  # type: ignore[arg-type]
    names = {v.name for v in vulns}
    assert "Content Discovery: /admin" in names
    assert "Content Discovery: /secret" in names
    assert not any("missing" in n for n in names)
    protected = next(v for v in vulns if v.name.endswith("/secret"))
    assert protected.severity == Severity.INFO


async def test_fuzz_filters_soft_404_catch_all() -> None:
    # Server returns 200 for everything with near-identical bodies (soft 404).
    body = "x" * 500
    session = _FakeSession(routes={}, default=(200, body))
    scanner = FuzzScanner(wordlist=["admin", "backup", "config"])
    vulns = await scanner.scan("https://example.com", session)  # type: ignore[arg-type]
    assert vulns == []


# --- Rate limiter ---------------------------------------------------------


async def test_rate_limiter_paces_requests() -> None:
    limiter = RateLimiter(rate=20)  # 20/s => 50ms spacing
    loop = asyncio.get_event_loop()
    start = loop.time()
    for _ in range(5):
        await limiter.acquire()
    elapsed = loop.time() - start
    # 5 acquisitions at 50ms spacing => at least ~200ms (4 gaps), allow slack.
    assert elapsed >= 0.15


@pytest.mark.parametrize("rate", [1, 10, 100])
def test_rate_limiter_interval(rate: int) -> None:
    limiter = RateLimiter(rate=float(rate))
    assert limiter._min_interval == pytest.approx(1.0 / rate)
