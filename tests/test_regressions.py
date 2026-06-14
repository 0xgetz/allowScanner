"""Regression tests for bugs fixed in the reliability pass.

Each test below pins a concrete crash or wrong-attribute bug that previously
slipped past the mocked unit tests but broke real end-to-end scans.
"""

from __future__ import annotations

import io

import pytest
from rich.console import Console

from allowscanner.core.config import ScanConfig
from allowscanner.core.exceptions import (
    AllowScannerError,
    ConfigurationError,
    SSLError,
    TimeoutError,
)
from allowscanner.formatters import to_json
from allowscanner.output import TerminalOutput
from allowscanner.core.models import ScanResult


def _silent_output() -> TerminalOutput:
    return TerminalOutput(Console(file=io.StringIO(), width=100))


def test_dns_table_handles_none_values() -> None:
    """Previously crashed with 'NoneType' object is not subscriptable.

    DNS records store None (not "") when a record is missing, so slicing
    dns.get("spf", "")[:60] blew up. The report must render cleanly instead.
    """
    result = ScanResult(target_url="https://example.com", base_domain="example.com")
    result.dns_records = {"dnssec": False, "spf": None, "dmarc": None, "dkim": None, "caa": False}
    _silent_output().print_full_report(result)  # must not raise


def test_full_report_with_no_findings_does_not_crash() -> None:
    result = ScanResult(target_url="https://example.com", base_domain="example.com")
    _silent_output().print_full_report(result)  # must not raise


def test_exceptions_expose_suggestion_attribute() -> None:
    """CLI error handlers read e.suggestion; it must exist on every error type."""
    for exc in (
        AllowScannerError("boom", suggestion="try again"),
        ConfigurationError("bad", config_key="timeout", suggestion="fix it"),
    ):
        assert exc.suggestion is not None


def test_timeout_error_accepts_duration_kwarg() -> None:
    """http/dns scanners raise TimeoutError(timeout_duration=...); wrong kwargs raised TypeError."""
    err = TimeoutError("timed out", operation="GET request", timeout_duration=15, url="https://example.com")
    assert err.context["timeout_duration"] == 15


def test_ssl_error_accepts_context_url() -> None:
    """http client raises SSLError(context={'url': ...}); url= was an invalid kwarg before."""
    err = SSLError("ssl boom", context={"url": "https://example.com"})
    assert err.context["url"] == "https://example.com"


def test_config_rejects_invalid_then_to_json_roundtrips() -> None:
    with pytest.raises(ConfigurationError):
        ScanConfig(timeout=0)
    result = ScanResult(target_url="https://example.com", base_domain="example.com")
    assert "example.com" in to_json(result)
