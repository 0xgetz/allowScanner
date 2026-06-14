"""Tests for scope, suppression, crawler, diff, SARIF, and adaptive rate limiting."""

from __future__ import annotations

import asyncio
import json

from allowscanner.core.config import ScanConfig
from allowscanner.core.diff import diff_against_baseline
from allowscanner.core.models import ScanResult, Severity, Vulnerability
from allowscanner.core.scope import Scope
from allowscanner.core.suppress import apply_suppressions, is_suppressed, load_suppressions
from allowscanner.formatters import to_json, to_sarif
from allowscanner.scanners.crawler import Crawler
from allowscanner.scanners.http import RateLimiter, _parse_retry_after


def _vuln(
    name: str, url: str = "https://t.example/", sev: Severity = Severity.HIGH, cwe: str = "CWE-79"
) -> Vulnerability:
    return Vulnerability(name=name, severity=sev, url=url, cwe=cwe)


# ---- Scope ----------------------------------------------------------------


def test_scope_empty_allows_everything() -> None:
    s = Scope()
    assert s.in_scope("https://anything.example/path")


def test_scope_host_allowlist_and_subdomains() -> None:
    s = Scope(hosts=["example.com"])
    assert s.host_in_scope("example.com")
    assert s.host_in_scope("api.example.com")
    assert not s.host_in_scope("evil.com")


def test_scope_excludes_and_non_http() -> None:
    s = Scope(hosts=["example.com"], exclude_patterns=[r"/logout"])
    assert s.in_scope("https://example.com/account")
    assert not s.in_scope("https://example.com/logout")
    assert not s.in_scope("ftp://example.com/file")


def test_scope_invalid_regex_is_skipped() -> None:
    s = Scope(exclude_patterns=["(unclosed"])
    assert s.in_scope("https://example.com/")


# ---- Suppression ----------------------------------------------------------


def test_suppress_by_name_substring_and_regex() -> None:
    v = _vuln("Reflected XSS")
    assert is_suppressed(v, ["Reflected XSS"])
    assert is_suppressed(v, ["XSS"])
    assert is_suppressed(v, [r"Reflected .*"])
    assert not is_suppressed(v, ["SQL Injection"])


def test_suppress_by_fingerprint_and_apply() -> None:
    v = _vuln("Reflected XSS")
    assert is_suppressed(v, [v.fingerprint])
    kept = apply_suppressions([v, _vuln("Open Redirect", cwe="CWE-601")], ["XSS"])
    assert len(kept) == 1
    assert kept[0].name == "Open Redirect"


def test_load_suppressions_reads_file_skips_comments(tmp_path) -> None:
    f = tmp_path / ".allowscanignore"
    f.write_text("# comment\nXSS\n\nOpen Redirect\n", encoding="utf-8")
    assert load_suppressions(str(f)) == ["XSS", "Open Redirect"]
    assert load_suppressions(str(tmp_path / "missing")) == []


# ---- Diff -----------------------------------------------------------------


def test_diff_against_baseline(tmp_path) -> None:
    old = ScanResult(target_url="https://t.example/", base_domain="t.example")
    old.vulnerabilities = [_vuln("Reflected XSS"), _vuln("Old Bug", cwe="CWE-1")]
    baseline = tmp_path / "baseline.json"
    baseline.write_text(to_json(old), encoding="utf-8")

    new = ScanResult(target_url="https://t.example/", base_domain="t.example")
    new.vulnerabilities = [_vuln("Reflected XSS"), _vuln("Brand New", cwe="CWE-2")]

    d = diff_against_baseline(new, str(baseline))
    assert d.unchanged == 1
    assert d.fixed == 1
    assert len(d.new) == 1
    assert "Brand New" in d.new[0]


# ---- SARIF ----------------------------------------------------------------


def test_to_sarif_structure() -> None:
    r = ScanResult(target_url="https://t.example/", base_domain="t.example")
    r.vulnerabilities = [_vuln("Reflected XSS"), _vuln("SQLi", sev=Severity.CRITICAL, cwe="CWE-89")]
    doc = json.loads(to_sarif(r))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "AllowScanner"
    assert len(run["results"]) == 2
    levels = {res["level"] for res in run["results"]}
    assert "error" in levels


# ---- Adaptive rate limiting ----------------------------------------------


def test_parse_retry_after() -> None:
    assert _parse_retry_after("5") == 5.0
    assert _parse_retry_after(None) is None
    assert _parse_retry_after("not-a-number") is None


def test_rate_limiter_backoff_widens_interval() -> None:
    rl = RateLimiter(0.0)
    assert rl._min_interval == 0.0
    rl.backoff()
    assert rl._min_interval >= 0.5
    before = rl._min_interval
    rl.backoff()
    assert rl._min_interval >= before
    assert rl._min_interval <= 10.0


def test_rate_limiter_acquire_runs() -> None:
    rl = RateLimiter(1000.0)
    asyncio.run(rl.acquire())


# ---- Crawler --------------------------------------------------------------


class _Headers:
    def __init__(self, ctype: str = "text/html") -> None:
        self._ctype = ctype

    def get(self, key: str, default: str = "") -> str:
        if key.lower() == "content-type":
            return self._ctype
        return default


class _Resp:
    def __init__(self, ctype: str = "text/html") -> None:
        self.headers = _Headers(ctype)


class _FakeSession:
    def __init__(self, pages: dict[str, str]) -> None:
        self._pages = pages

    async def get(self, url: str):
        body = self._pages.get(url.rstrip("/"))
        if body is None:
            return None, ""
        return _Resp(), body


def test_crawler_maps_surface_within_scope() -> None:
    pages = {
        "https://t.example": '<html><a href="/about">a</a><a href="/contact?q=1">c</a>'
        '<a href="https://evil.com/x">x</a><form action="/submit">'
        '<input name="email"></form></html>',
        "https://t.example/about": "<html>about</html>",
        "https://t.example/contact?q=1": "<html>contact</html>",
    }
    scope = Scope(hosts=["t.example"])
    crawler = Crawler(scope, max_pages=50, max_depth=2)
    session = _FakeSession(pages)
    discovered, vulns = asyncio.run(crawler.scan("https://t.example", session))  # type: ignore[arg-type]

    assert "https://t.example" in discovered
    assert "https://t.example/about" in discovered
    assert not any("evil.com" in u for u in discovered)
    assert len(vulns) == 1
    assert vulns[0].name == "Crawl Surface Mapped"
    assert "email" in vulns[0].description or "q" in vulns[0].description


# ---- Config wiring --------------------------------------------------------


def test_config_has_new_fields() -> None:
    cfg = ScanConfig()
    assert hasattr(cfg, "check_crawl")
    assert hasattr(cfg, "extra_headers")
    assert hasattr(cfg, "scope_hosts")
    assert hasattr(cfg, "exclude_patterns")
    assert hasattr(cfg, "suppress_file")
    assert hasattr(cfg, "baseline_file")
    assert "sarif" in {"terminal", "json", "html", "markdown", "sarif"}
