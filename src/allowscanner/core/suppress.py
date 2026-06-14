"""False-positive suppression via an ``.allowscanignore`` file.

Each non-comment line is matched against a finding's fingerprint, name, URL,
or ``name:url`` as an exact string, a substring, or a regex. Matching findings
are dropped from the report.
"""

from __future__ import annotations

import os
import re

from .models import Vulnerability


def load_suppressions(path: str | None) -> list[str]:
    """Load suppression patterns from ``path`` or a local ``.allowscanignore``."""
    candidate = path or ".allowscanignore"
    if not os.path.isfile(candidate):
        return []
    patterns: list[str] = []
    with open(candidate, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
    return patterns


def is_suppressed(vuln: Vulnerability, patterns: list[str]) -> bool:
    if not patterns:
        return False
    haystacks = [vuln.fingerprint, vuln.name, vuln.url, f"{vuln.name}:{vuln.url}"]
    for pattern in patterns:
        if pattern == vuln.fingerprint or any(pattern in h for h in haystacks):
            return True
        try:
            rx = re.compile(pattern)
        except re.error:
            continue
        if any(rx.search(h) for h in haystacks):
            return True
    return False


def apply_suppressions(vulns: list[Vulnerability], patterns: list[str]) -> list[Vulnerability]:
    if not patterns:
        return vulns
    return [v for v in vulns if not is_suppressed(v, patterns)]
