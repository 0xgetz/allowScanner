"""Scope control: decide which URLs are in-scope for scanning/crawling."""

from __future__ import annotations

import re
from urllib.parse import urlparse


class Scope:
    """In-scope/out-of-scope decisions based on host allowlist and exclude regexes."""

    def __init__(self, hosts: list[str] | None = None, exclude_patterns: list[str] | None = None) -> None:
        self.hosts = [h.lower().strip().lstrip(".") for h in (hosts or []) if h.strip()]
        self._excludes: list[re.Pattern[str]] = []
        for pattern in exclude_patterns or []:
            try:
                self._excludes.append(re.compile(pattern))
            except re.error:
                # Skip invalid patterns rather than aborting the whole scan.
                continue

    def host_in_scope(self, host: str) -> bool:
        host = (host or "").lower()
        if not self.hosts:
            return True
        return any(host == h or host.endswith("." + h) for h in self.hosts)

    def in_scope(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
        except ValueError:
            return False
        if parsed.scheme not in ("http", "https"):
            return False
        if not self.host_in_scope(parsed.hostname or ""):
            return False
        return all(not pattern.search(url) for pattern in self._excludes)
