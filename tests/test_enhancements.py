"""Tests for WAF detection and the Markdown/HTML report formatters."""

from __future__ import annotations

from collections.abc import Callable

from allowscanner.core.models import CertificateInfo, ScanResult, Severity, Technology, Vulnerability
from allowscanner.formatters import to_html, to_json, to_markdown
from allowscanner.scanners.waf import WafScanner


class _Headers:
    def __init__(self, data: dict[str, str]) -> None:
        self._data = data

    def get(self, key: str, default: str = "") -> str:
        return self._data.get(key, default)

    def items(self) -> list[tuple[str, str]]:
        return list(self._data.items())


class _Resp:
    def __init__(self, status: int, headers: dict[str, str] | None = None) -> None:
        self.status = status
        self.headers = _Headers(headers or {})


class _FakeSession:
    def __init__(self, handler: Callable[[str], tuple[_Resp | None, str]]) -> None:
        self._handler = handler

    async def get(self, url: str, **kwargs: object) -> tuple[_Resp | None, str]:
        return self._handler(url)


# --- WAF ------------------------------------------------------------------


async def test_waf_detects_cloudflare_from_headers() -> None:
    def handler(url: str) -> tuple[_Resp | None, str]:
        return _Resp(200, {"server": "cloudflare", "cf-ray": "7a1b2c3d4e5f"}), "<html>ok</html>"

    vulns = await WafScanner().scan("https://example.com", _FakeSession(handler))  # type: ignore[arg-type]
    assert any(v.name == "WAF/CDN Detected: Cloudflare" for v in vulns)


async def test_waf_detects_active_blocking_without_signature() -> None:
    def handler(url: str) -> tuple[_Resp | None, str]:
        if "allowscanner_test" in url:
            return _Resp(403), "Access Denied"
        return _Resp(200, {"server": "nginx"}), "<html>ok</html>"

    vulns = await WafScanner().scan("https://example.com", _FakeSession(handler))  # type: ignore[arg-type]
    assert any(v.name == "WAF/IPS Blocking Detected" for v in vulns)


async def test_waf_quiet_when_nothing_detected() -> None:
    def handler(url: str) -> tuple[_Resp | None, str]:
        return _Resp(200, {"server": "nginx"}), "<html>ok</html>"

    vulns = await WafScanner().scan("https://example.com", _FakeSession(handler))  # type: ignore[arg-type]
    assert vulns == []


# --- Formatters -----------------------------------------------------------


def _sample_result() -> ScanResult:
    result = ScanResult(target_url="https://example.com", base_domain="example.com")
    result.duration_seconds = 3.5
    result.vulnerabilities = [
        Vulnerability(
            name="Reflected XSS",
            severity=Severity.HIGH,
            url="https://example.com/?q=x",
            description="reflected",
            recommendation="Encode output",
            cwe="CWE-79",
        ),
        Vulnerability(
            name="Open Port 6379 (Redis)",
            severity=Severity.CRITICAL,
            url="example.com:6379",
            recommendation="Firewall it",
            cwe="CWE-668",
        ),
    ]
    result.open_ports = [443, 6379]
    result.technologies = [Technology(name="Nginx", category="Server")]
    result.certificate = CertificateInfo(
        issuer="Let's Encrypt",
        subject="example.com",
        protocol="TLSv1.3",
        supported_protocols=["TLSv1.2", "TLSv1.3"],
        days_remaining=42,
    )
    return result


def test_markdown_report_contains_key_sections() -> None:
    md = to_markdown(_sample_result())
    assert md.startswith("# AllowScanner Report")
    assert "| Severity | Finding | Location | CWE | Recommendation |" in md
    assert "Reflected XSS" in md
    assert "## Open Ports" in md
    assert "TLSv1.2, TLSv1.3" in md


def test_html_report_is_self_contained() -> None:
    html_doc = to_html(_sample_result())
    assert html_doc.startswith("<!doctype html>")
    assert "<style>" in html_doc
    assert "Reflected XSS" in html_doc
    assert "Open Port 6379" in html_doc
    assert "68/100" not in html_doc  # score computed, not hardcoded


def test_json_still_serializes_new_cert_field() -> None:
    import json

    data = json.loads(to_json(_sample_result()))
    assert data["certificate"]["supported_protocols"] == ["TLSv1.2", "TLSv1.3"]
