"""Diff a scan result against a baseline JSON report (by finding fingerprint)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from .models import ScanResult


def _fingerprint(name: str, url: str, cwe: str) -> str:
    raw = f"{name}|{url}|{cwe}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


@dataclass
class DiffResult:
    new: list[str]
    fixed: int
    unchanged: int


def diff_against_baseline(result: ScanResult, baseline_path: str) -> DiffResult:
    """Compare current findings to a baseline report saved as JSON (`-f json`)."""
    with open(baseline_path, encoding="utf-8") as fh:
        baseline = json.load(fh)

    base_fps: set[str] = set()
    for entry in baseline.get("vulnerabilities", []):
        base_fps.add(_fingerprint(entry.get("name", ""), entry.get("url", ""), entry.get("cwe") or ""))

    current = {v.fingerprint: v for v in result.vulnerabilities}
    new = [f"{v.severity.value}: {v.name} ({v.url})" for fp, v in current.items() if fp not in base_fps]
    fixed = sum(1 for fp in base_fps if fp not in current)
    unchanged = sum(1 for fp in current if fp in base_fps)
    return DiffResult(new=new, fixed=fixed, unchanged=unchanged)
