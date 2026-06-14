"""Tests for injection verification and the environment self-test."""

from __future__ import annotations

import asyncio

from allowscanner.core.doctor import run_doctor
from allowscanner.core.models import Severity
from allowscanner.scanners.inject import InjectionScanner


class _Resp:
    def __init__(self, status: int = 200) -> None:
        self.status = status
        self.headers = {"Content-Type": "text/html"}


class _Session:
    """Fake HttpClient.get with configurable per-payload behaviour."""

    def __init__(
        self,
        *,
        xss_param: str | None = None,
        encode_xss: bool = False,
        bool_param: str | None = None,
        sleep_param: str | None = None,
    ) -> None:
        self.xss_param = xss_param
        self.encode_xss = encode_xss
        self.bool_param = bool_param
        self.sleep_param = sleep_param

    async def get(self, url: str):
        from urllib.parse import parse_qs, urlsplit

        q = parse_qs(urlsplit(url).query)
        body = "<html>baseline content here</html>"

        for name, values in q.items():
            val = values[0] if values else ""
            if self.xss_param and name == self.xss_param and "<" in val:
                inner = val.replace("<", "").replace(">", "").replace('"', "")
                body += f"&lt;{inner}&gt;" if self.encode_xss else f"<{inner}>"
            if self.bool_param and name == self.bool_param:
                if "1'='2" in val or "1=2" in val:
                    body += " DIFFERENT-FALSE-BRANCH-CONTENT-PADDING-1234567890"
            if self.sleep_param and name == self.sleep_param and ("SLEEP(5)" in val or "pg_sleep(5)" in val):
                await asyncio.sleep(0.3)
        return _Resp(), body


def _fast_scanner(**kwargs: object) -> InjectionScanner:
    return InjectionScanner(params=["id", "q"], sleep_seconds=5, time_threshold=0.2, **kwargs)  # type: ignore[arg-type]


def test_xss_unescaped_is_high() -> None:
    scanner = InjectionScanner(params=["q"])
    vulns = asyncio.run(scanner.scan("https://t.example/", _Session(xss_param="q")))  # type: ignore[arg-type]
    xss = [v for v in vulns if v.name == "Reflected XSS"]
    assert len(xss) == 1
    assert xss[0].severity == Severity.HIGH


def test_xss_encoded_is_info_only() -> None:
    scanner = InjectionScanner(params=["q"])
    vulns = asyncio.run(scanner.scan("https://t.example/", _Session(xss_param="q", encode_xss=True)))  # type: ignore[arg-type]
    assert all(v.severity != Severity.HIGH for v in vulns)
    assert any(v.name == "Parameter Reflection (encoded)" for v in vulns)


def test_boolean_sqli_detected() -> None:
    scanner = InjectionScanner(params=["id"])
    vulns = asyncio.run(scanner.scan("https://t.example/", _Session(bool_param="id")))  # type: ignore[arg-type]
    assert any(v.name == "SQL Injection (boolean-based blind)" for v in vulns)
    assert any(v.severity == Severity.CRITICAL for v in vulns)


def test_time_sqli_detected() -> None:
    scanner = _fast_scanner()
    vulns = asyncio.run(scanner.scan("https://t.example/", _Session(sleep_param="q")))  # type: ignore[arg-type]
    assert any(v.name == "SQL Injection (time-based blind)" for v in vulns)


def test_no_false_positive_on_inert_target() -> None:
    scanner = _fast_scanner()
    vulns = asyncio.run(scanner.scan("https://t.example/", _Session()))  # type: ignore[arg-type]
    assert vulns == []


def test_doctor_reports_dependencies() -> None:
    ok, lines = run_doctor(check_network=False)
    assert ok is True
    assert any("Python" in ln for ln in lines)
    assert any("aiohttp" in ln for ln in lines)
    assert all(not ln.startswith("FAIL") for ln in lines)
