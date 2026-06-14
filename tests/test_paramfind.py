"""Tests for hidden parameter discovery (ParamFinder)."""

from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, urlsplit

from allowscanner.core.models import Severity
from allowscanner.scanners.paramfind import DEFAULT_PARAMS, ParamFinder


class _Resp:
    def __init__(self, status: int = 200) -> None:
        self.status = status
        self.headers = {"Content-Type": "text/html"}


class _Session:
    """Fake HttpClient.get: reacts only to specific parameter names."""

    def __init__(self, reflect: set[str] | None = None, status_param: str | None = None) -> None:
        self.reflect = reflect or set()
        self.status_param = status_param
        self.calls = 0

    async def get(self, url: str):
        self.calls += 1
        q = parse_qs(urlsplit(url).query)
        body = "<html>baseline</html>"
        status = 200
        for name, values in q.items():
            val = values[0] if values else ""
            if name in self.reflect:
                body += f"<!-- {val} -->"
            if self.status_param and name == self.status_param:
                status = 500
        return _Resp(status), body


def test_finds_reflected_param() -> None:
    finder = ParamFinder(wordlist=["id", "page", "redirect", "q"])
    session = _Session(reflect={"redirect"})
    found, vulns = asyncio.run(finder.scan("https://t.example/", session))  # type: ignore[arg-type]
    assert found == ["redirect"]
    assert len(vulns) == 1
    assert vulns[0].severity == Severity.INFO
    assert "redirect" in vulns[0].description


def test_finds_status_changing_param() -> None:
    finder = ParamFinder(wordlist=["id", "page", "debug", "q"])
    session = _Session(status_param="debug")
    found, _ = asyncio.run(finder.scan("https://t.example/", session))  # type: ignore[arg-type]
    assert found == ["debug"]


def test_no_false_positive_when_nothing_reacts() -> None:
    finder = ParamFinder(wordlist=["id", "page", "q", "lang"])
    session = _Session()
    found, vulns = asyncio.run(finder.scan("https://t.example/", session))  # type: ignore[arg-type]
    assert found == []
    assert vulns == []


def test_multiple_reflected_params_bisected() -> None:
    names = [f"p{i}" for i in range(40)]
    finder = ParamFinder(wordlist=names, chunk_size=10)
    session = _Session(reflect={"p3", "p27"})
    found, _ = asyncio.run(finder.scan("https://t.example/", session))  # type: ignore[arg-type]
    assert found == ["p27", "p3"]


def test_preserves_existing_query_params() -> None:
    finder = ParamFinder(wordlist=["redirect"])
    extra = finder._build("https://t.example/?keep=1", {"redirect": "x"})
    q = parse_qs(urlsplit(extra).query)
    assert q["keep"] == ["1"]
    assert q["redirect"] == ["x"]


def test_dedupes_and_caps_wordlist() -> None:
    finder = ParamFinder(wordlist=["a", "a", "b", " c "], max_params=2)
    assert finder.names == ["a", "b"]


def test_default_wordlist_nonempty() -> None:
    assert len(DEFAULT_PARAMS) > 50
    assert "redirect" in DEFAULT_PARAMS
