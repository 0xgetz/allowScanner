"""JSON output formatter."""

from __future__ import annotations

import json
from dataclasses import asdict
from enum import Enum

from .core.models import ScanResult


class _Encoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Enum):
            return o.value
        return super().default(o)


def to_json(result: ScanResult, indent: int = 2) -> str:
    """Convert ScanResult to JSON string."""
    data = asdict(result)
    # Convert datetime
    if data.get("scan_start"):
        data["scan_start"] = result.scan_start.isoformat()
    if data.get("scan_end"):
        data["scan_end"] = result.scan_end.isoformat()
    data["score"] = result.score
    return json.dumps(data, cls=_Encoder, indent=indent, ensure_ascii=False)
