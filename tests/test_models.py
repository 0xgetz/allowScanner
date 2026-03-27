"""Tests for AllowScanner."""

import pytest
from allowscanner.core.models import Severity, Vulnerability, ScanResult
from allowscanner.core.config import ScanConfig


class TestModels:
    def test_severity_ordering(self):
        assert Severity.CRITICAL < Severity.HIGH
        assert Severity.HIGH < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.LOW
        assert Severity.LOW < Severity.INFO

    def test_severity_color(self):
        assert Severity.CRITICAL.color == "bold red"
        assert Severity.INFO.color == "dim"

    def test_vulnerability_creation(self):
        v = Vulnerability(
            name="Test Vuln",
            severity=Severity.HIGH,
            url="https://example.com",
            description="Test description",
            recommendation="Fix it",
            cwe="CWE-79",
        )
        assert v.name == "Test Vuln"
        assert v.severity == Severity.HIGH
        assert v.cwe == "CWE-79"

    def test_scan_result_score_perfect(self):
        result = ScanResult(target_url="https://example.com", base_domain="example.com")
        assert result.score == 100

    def test_scan_result_score_with_vulns(self):
        result = ScanResult(
            target_url="https://example.com",
            base_domain="example.com",
            vulnerabilities=[
                Vulnerability(name="v1", severity=Severity.CRITICAL, url="https://example.com"),
                Vulnerability(name="v2", severity=Severity.HIGH, url="https://example.com"),
                Vulnerability(name="v3", severity=Severity.MEDIUM, url="https://example.com"),
            ],
        )
        assert result.score == 65  # 100 - 20 - 10 - 5

    def test_scan_result_score_minimum_zero(self):
        vulns = [Vulnerability(name=f"v{i}", severity=Severity.CRITICAL, url="x") for i in range(10)]
        result = ScanResult(target_url="https://x.com", base_domain="x.com", vulnerabilities=vulns)
        assert result.score == 0

    def test_scan_result_counts(self):
        result = ScanResult(
            target_url="https://example.com",
            base_domain="example.com",
            vulnerabilities=[
                Vulnerability(name="v1", severity=Severity.CRITICAL, url="x"),
                Vulnerability(name="v2", severity=Severity.HIGH, url="x"),
                Vulnerability(name="v3", severity=Severity.HIGH, url="x"),
            ],
        )
        assert result.critical_count == 1
        assert result.high_count == 2


class TestConfig:
    def test_defaults(self):
        config = ScanConfig()
        assert config.concurrency == 50
        assert config.timeout == 15
        assert config.check_ssl is True
        assert config.check_dns is True

    def test_custom(self):
        config = ScanConfig(concurrency=100, timeout=30, check_ssl=False)
        assert config.concurrency == 100
        assert config.timeout == 30
        assert config.check_ssl is False


class TestScanner:
    def test_scanner_creation(self):
        from allowscanner import AllowScanner
        scanner = AllowScanner("https://example.com")
        assert scanner.target_url == "https://example.com"
        assert scanner.base_domain == "example.com"

    def test_scanner_trailing_slash(self):
        from allowscanner import AllowScanner
        scanner = AllowScanner("https://example.com/")
        assert scanner.target_url == "https://example.com"
