"""Tests for secrets, GraphQL, HTTP method, and takeover scanners."""

from __future__ import annotations

from collections.abc import Callable

from allowscanner.core.models import Severity
from allowscanner.scanners.graphql import GraphQLScanner
from allowscanner.scanners.methods import HttpMethodScanner
from allowscanner.scanners.secrets import SecretScanner
from allowscanner.scanners.takeover import TakeoverScanner


class _Headers:
    def __init__(self, data: dict[str, str]) -> None:
        self._data = data

    def get(self, key: str, default: str = "") -> str:
        return self._data.get(key, default)


class _Resp:
    def __init__(self, status: int, headers: dict[str, str] | None = None) -> None:
        self.status = status
        self.headers = _Headers(headers or {})


class _FakeSession:
    """Routes GET/request calls through a user-supplied handler."""

    def __init__(self, handler: Callable[[str, str], tuple[_Resp | None, str]]) -> None:
        self._handler = handler

    async def get(self, url: str, **kwargs: object) -> tuple[_Resp | None, str]:
        return self._handler("GET", url)

    async def request(self, method: str, url: str, **kwargs: object) -> tuple[_Resp | None, str]:
        return self._handler(method, url)


# --- Secrets --------------------------------------------------------------


async def test_secret_scanner_finds_keys_and_endpoints() -> None:
    html = '<html><body><script src="/static/app.js"></script><!-- AKIAABCDEFGHIJKLMNOP --></body></html>'
    js = 'var k="AIzaSyDmYx1234567890abcdefghijklmnop_QR";fetch("/api/users/me");'

    def handler(method: str, url: str) -> tuple[_Resp | None, str]:
        if url.endswith("/static/app.js"):
            return _Resp(200), js
        return _Resp(200), html

    scanner = SecretScanner()
    vulns = await scanner.scan("https://example.com", _FakeSession(handler))  # type: ignore[arg-type]
    names = [v.name for v in vulns]
    assert any("AWS Access Key ID" in n for n in names)
    assert any("Google API Key" in n for n in names)
    assert any("Endpoints Exposed in JavaScript" in n for n in names)
    aws = next(v for v in vulns if "AWS Access Key" in v.name)
    assert aws.severity == Severity.CRITICAL
    assert "AKIAABCDEFGHIJKLMNOP" not in aws.description  # redacted


async def test_secret_scanner_clean_page_has_no_findings() -> None:
    def handler(method: str, url: str) -> tuple[_Resp | None, str]:
        return _Resp(200), "<html><body>nothing to see</body></html>"

    vulns = await SecretScanner().scan("https://example.com", _FakeSession(handler))  # type: ignore[arg-type]
    assert vulns == []


# --- GraphQL --------------------------------------------------------------


async def test_graphql_detects_introspection() -> None:
    def handler(method: str, url: str) -> tuple[_Resp | None, str]:
        if url.endswith("/graphql"):
            return _Resp(200), '{"data":{"__schema":{"queryType":{"name":"Query"}}}}'
        return _Resp(404), "not found"

    vulns = await GraphQLScanner().scan("https://example.com", _FakeSession(handler))  # type: ignore[arg-type]
    assert any(v.name == "GraphQL Introspection Enabled" for v in vulns)


async def test_graphql_detects_endpoint_without_introspection() -> None:
    def handler(method: str, url: str) -> tuple[_Resp | None, str]:
        if url.endswith("/graphql"):
            return _Resp(400), '{"errors":[{"message":"Must provide query string"}],"graphql":true}'
        return _Resp(404), "nope"

    vulns = await GraphQLScanner().scan("https://example.com", _FakeSession(handler))  # type: ignore[arg-type]
    assert any(v.name == "GraphQL Endpoint Detected" for v in vulns)
    assert not any(v.name == "GraphQL Introspection Enabled" for v in vulns)


# --- HTTP methods ---------------------------------------------------------


async def test_method_scanner_flags_dangerous_verbs() -> None:
    def handler(method: str, url: str) -> tuple[_Resp | None, str]:
        if method == "OPTIONS":
            return _Resp(204, {"Allow": "GET, POST, PUT, DELETE, OPTIONS"}), ""
        if method in ("PUT", "DELETE"):
            return _Resp(200), ""
        return _Resp(405), ""

    vulns = await HttpMethodScanner().scan("https://example.com", _FakeSession(handler))  # type: ignore[arg-type]
    names = [v.name for v in vulns]
    assert "Dangerous HTTP Method Enabled: PUT" in names
    assert "Dangerous HTTP Method Enabled: DELETE" in names
    assert any(v.name == "HTTP Methods Advertised" for v in vulns)


# --- Takeover -------------------------------------------------------------


async def test_takeover_matches_cname_and_fingerprint() -> None:
    scanner = TakeoverScanner()

    async def fake_cname(host: str) -> str:
        return "myorg.github.io"

    async def fake_body(host: str, session: object) -> str:
        return "There isn't a GitHub Pages site here."

    scanner._cname = fake_cname  # type: ignore[method-assign]
    scanner._body = fake_body  # type: ignore[method-assign]

    vulns = await scanner.scan(["docs.example.com"], _FakeSession(lambda m, u: (None, "")))  # type: ignore[arg-type]
    assert len(vulns) == 1
    assert vulns[0].name == "Possible Subdomain Takeover: GitHub Pages"
    assert vulns[0].severity == Severity.HIGH


async def test_takeover_no_cname_no_finding() -> None:
    scanner = TakeoverScanner()

    async def fake_cname(host: str) -> str:
        return ""

    scanner._cname = fake_cname  # type: ignore[method-assign]
    vulns = await scanner.scan(["example.com"], _FakeSession(lambda m, u: (None, "")))  # type: ignore[arg-type]
    assert vulns == []
