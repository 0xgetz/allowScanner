"""Environment self-test for allowScanner.

``allowscanner --doctor`` runs this to verify the install before a scan, so the
first real run fails loudly here (with a fix hint) instead of mid-scan.
"""

from __future__ import annotations

import importlib
import platform
import socket
import sys
from importlib import metadata

REQUIRED_PACKAGES = {"aiohttp": "aiohttp", "dnspython": "dns", "rich": "rich"}
MIN_PYTHON = (3, 10)


def run_doctor(check_network: bool = True) -> tuple[bool, list[str]]:
    """Return (all_critical_checks_passed, human-readable report lines)."""
    lines: list[str] = []
    ok = True

    py = sys.version_info
    py_ok = (py.major, py.minor) >= MIN_PYTHON
    ok = ok and py_ok
    status = "PASS" if py_ok else "FAIL"
    lines.append(f"{status}  Python {platform.python_version()} (need >= {MIN_PYTHON[0]}.{MIN_PYTHON[1]})")

    try:
        version = metadata.version("allowscanner")
    except metadata.PackageNotFoundError:
        version = "dev (editable / not installed)"
    lines.append(f"INFO  allowScanner {version}")

    for dist_name, import_name in REQUIRED_PACKAGES.items():
        try:
            module = importlib.import_module(import_name)
        except Exception as exc:
            ok = False
            lines.append(f"FAIL  dependency '{dist_name}' not importable: {exc} (run: pip install {dist_name})")
            continue
        ver = getattr(module, "__version__", "?")
        lines.append(f"PASS  dependency '{dist_name}' ({ver})")

    if check_network:
        try:
            socket.getaddrinfo("example.com", 443)
            lines.append("PASS  DNS resolution (example.com)")
        except OSError as exc:
            lines.append(f"WARN  DNS resolution check failed: {exc} (scans need outbound network)")

    return ok, lines
