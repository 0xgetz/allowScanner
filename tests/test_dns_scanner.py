"""Comprehensive tests for DNSScanner."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from allowscanner.core.models import Severity
from allowscanner.scanners.dns import DNSScanner


class MockDNSAnswer:
    """Mock DNS answer."""

    def __init__(self, data: str) -> None:
        self.data = data

    def __str__(self) -> str:
        return self.data


class MockDNSResolver:
    """Mock DNS async resolver."""

    def __init__(self, answers: dict | None = None, raise_exception: Exception | None = None) -> None:
        self.answers = answers or {}
        self.raise_exception = raise_exception
        self.lifetime = 10

    async def resolve(self, qname: str, rdtype: str) -> list[MockDNSAnswer]:
        if self.raise_exception:
            raise self.raise_exception

        key = f"{qname}_{rdtype}"
        if key in self.answers:
            return [MockDNSAnswer(a) for a in self.answers[key]]
        raise Exception("NXDOMAIN")


@pytest.fixture
def scanner() -> DNSScanner:
    """Create a DNSScanner instance."""
    return DNSScanner()


class TestDNSSECDetection:
    """Test DNSSEC detection."""

    @pytest.mark.asyncio
    async def test_dnssec_enabled(
        self, scanner: DNSScanner
    ) -> None:
        """Test that DNSSEC is detected when enabled."""
        mock_answers = {
            "example.com_DNSKEY": ["DNSKEY record data"],
            "example.com_TXT": ["v=spf1 include:_spf.google.com ~all"],
            "_dmarc.example.com_TXT": ["v=DMARC1; p=reject"],
            "default._domainkey.example.com_TXT": ["DKIM record"],
            "example.com_CAA": ["0 issue letsencrypt.org"],
        }
        mock_resolver = MockDNSResolver(answers=mock_answers)

        with patch("dns.asyncresolver.Resolver", return_value=mock_resolver):
            records, vulns = await scanner.scan("example.com")

        assert records.get("dnssec") is True
        dnssec_vulns = [v for v in vulns if "DNSSEC Not Enabled" in v.name]
        assert len(dnssec_vulns) == 0

    @pytest.mark.asyncio
    async def test_dnssec_not_enabled(
        self, scanner: DNSScanner
    ) -> None:
        """Test that missing DNSSEC is detected."""
        mock_answers = {
            "example.com_TXT": ["v=spf1 ~all"],
            "_dmarc.example.com_TXT": ["v=DMARC1; p=none"],
            "example.com_CAA": ["0 issue letsencrypt.org"],
        }
        mock_resolver = MockDNSResolver(answers=mock_answers)

        with patch("dns.asyncresolver.Resolver", return_value=mock_resolver):
            records, vulns = await scanner.scan("example.com")

        assert records.get("dnssec") is False
        dnssec_vulns = [v for v in vulns if "DNSSEC Not Enabled" in v.name]
        assert len(dnssec_vulns) > 0
        assert dnssec_vulns[0].severity == Severity.MEDIUM


class TestSPFDetection:
    """Test SPF record detection."""

    @pytest.mark.asyncio
    async def test_spf_record_found(
        self, scanner: DNSScanner
    ) -> None:
        """Test that SPF record is detected when present."""
        mock_answers = {
            "example.com_DNSKEY": ["DNSKEY record"],
            "example.com_TXT": ["v=spf1 include:_spf.google.com -all"],
            "_dmarc.example.com_TXT": ["v=DMARC1; p=reject"],
            "example.com_CAA": ["0 issue letsencrypt.org"],
        }
        mock_resolver = MockDNSResolver(answers=mock_answers)

        with patch("dns.asyncresolver.Resolver", return_value=mock_resolver):
            records, vulns = await scanner.scan("example.com")

        assert records.get("spf") is not None
        assert "v=spf1" in records["spf"]
        spf_vulns = [v for v in vulns if "SPF Record Missing" in v.name]
        assert len(spf_vulns) == 0

    @pytest.mark.asyncio
    async def test_spf_record_missing(
        self, scanner: DNSScanner
    ) -> None:
        """Test that missing SPF record is detected."""
        mock_answers = {
            "example.com_DNSKEY": ["DNSKEY record"],
            "example.com_TXT": ["some other TXT record"],
            "_dmarc.example.com_TXT": ["v=DMARC1; p=reject"],
            "example.com_CAA": ["0 issue letsencrypt.org"],
        }
        mock_resolver = MockDNSResolver(answers=mock_answers)

        with patch("dns.asyncresolver.Resolver", return_value=mock_resolver):
            records, vulns = await scanner.scan("example.com")

        assert records.get("spf") is None
        spf_vulns = [v for v in vulns if "SPF Record Missing" in v.name]
        assert len(spf_vulns) > 0
        assert spf_vulns[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_spf_overly_permissive(
        self, scanner: DNSScanner
    ) -> None:
        """Test that overly permissive SPF (+all) is detected."""
        mock_answers = {
            "example.com_DNSKEY": ["DNSKEY record"],
            "example.com_TXT": ["v=spf1 +all"],
            "_dmarc.example.com_TXT": ["v=DMARC1; p=reject"],
            "example.com_CAA": ["0 issue letsencrypt.org"],
        }
        mock_resolver = MockDNSResolver(answers=mock_answers)

        with patch("dns.asyncresolver.Resolver", return_value=mock_resolver):
            records, vulns = await scanner.scan("example.com")

        permissive_vulns = [v for v in vulns if "Overly Permissive SPF" in v.name]
        assert len(permissive_vulns) > 0
        assert permissive_vulns[0].severity == Severity.MEDIUM


class TestDMARCDetection:
    """Test DMARC record detection."""

    @pytest.mark.asyncio
    async def test_dmarc_record_found(
        self, scanner: DNSScanner
    ) -> None:
        """Test that DMARC record is detected when present."""
        mock_answers = {
            "example.com_DNSKEY": ["DNSKEY record"],
            "example.com_TXT": ["v=spf1 ~all"],
            "_dmarc.example.com_TXT": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
            "example.com_CAA": ["0 issue letsencrypt.org"],
        }
        mock_resolver = MockDNSResolver(answers=mock_answers)

        with patch("dns.asyncresolver.Resolver", return_value=mock_resolver):
            records, vulns = await scanner.scan("example.com")

        assert records.get("dmarc") is not None
        assert "v=DMARC1" in records["dmarc"]
        dmarc_vulns = [v for v in vulns if "DMARC Record Missing" in v.name]
        assert len(dmarc_vulns) == 0

    @pytest.mark.asyncio
    async def test_dmarc_record_missing(
        self, scanner: DNSScanner
    ) -> None:
        """Test that missing DMARC record is detected."""
        mock_answers = {
            "example.com_DNSKEY": ["DNSKEY record"],
            "example.com_TXT": ["v=spf1 ~all"],
            "example.com_CAA": ["0 issue letsencrypt.org"],
        }
        mock_resolver = MockDNSResolver(answers=mock_answers)

        with patch("dns.asyncresolver.Resolver", return_value=mock_resolver):
            records, vulns = await scanner.scan("example.com")

        assert records.get("dmarc") is None
        dmarc_vulns = [v for v in vulns if "DMARC Record Missing" in v.name]
        assert len(dmarc_vulns) > 0
        assert dmarc_vulns[0].severity == Severity.MEDIUM


class TestDKIMDetection:
    """Test DKIM record detection."""

    @pytest.mark.asyncio
    async def test_dkim_record_found_default_selector(
        self, scanner: DNSScanner
    ) -> None:
        """Test that DKIM record is detected with default selector."""
        mock_answers = {
            "example.com_DNSKEY": ["DNSKEY record"],
            "example.com_TXT": ["v=spf1 ~all"],
            "_dmarc.example.com_TXT": ["v=DMARC1; p=reject"],
            "default._domainkey.example.com_TXT": ["v=DKIM1; k=rsa; p=MIGfMA0GCS..."],
            "example.com_CAA": ["0 issue letsencrypt.org"],
        }
        mock_resolver = MockDNSResolver(answers=mock_answers)

        with patch("dns.asyncresolver.Resolver", return_value=mock_resolver):
            records, vulns = await scanner.scan("example.com")

        assert records.get("dkim") is not None
        assert "default" in records["dkim"]

    @pytest.mark.asyncio
    async def test_dkim_record_found_google_selector(
        self, scanner: DNSScanner
    ) -> None:
        """Test that DKIM record is detected with google selector."""
        mock_answers = {
            "example.com_DNSKEY": ["DNSKEY record"],
            "example.com_TXT": ["v=spf1 ~all"],
            "_dmarc.example.com_TXT": ["v=DMARC1; p=reject"],
            "google._domainkey.example.com_TXT": ["v=DKIM1; k=rsa; p=MIGfMA0GCS..."],
            "example.com_CAA": ["0 issue letsencrypt.org"],
        }
        mock_resolver = MockDNSResolver(answers=mock_answers)

        with patch("dns.asyncresolver.Resolver", return_value=mock_resolver):
            records, vulns = await scanner.scan("example.com")

        assert records.get("dkim") is not None
        assert "google" in records["dkim"]

    @pytest.mark.asyncio
    async def test_dkim_record_missing(
        self, scanner: DNSScanner
    ) -> None:
        """Test that missing DKIM record is detected."""
        mock_answers = {
            "example.com_DNSKEY": ["DNSKEY record"],
            "example.com_TXT": ["v=spf1 ~all"],
            "_dmarc.example.com_TXT": ["v=DMARC1; p=reject"],
            "example.com_CAA": ["0 issue letsencrypt.org"],
        }
        mock_resolver = MockDNSResolver(answers=mock_answers)

        with patch("dns.asyncresolver.Resolver", return_value=mock_resolver):
            records, vulns = await scanner.scan("example.com")

        assert records.get("dkim") is None


class TestCAADetection:
    """Test CAA record detection."""

    @pytest.mark.asyncio
    async def test_caa_record_found(
        self, scanner: DNSScanner
    ) -> None:
        """Test that CAA record is detected when present."""
        mock_answers = {
            "example.com_DNSKEY": ["DNSKEY record"],
            "example.com_TXT": ["v=spf1 ~all"],
            "_dmarc.example.com_TXT": ["v=DMARC1; p=reject"],
            "example.com_CAA": ["0 issue letsencrypt.org", "0 issuewild ;"],
        }
        mock_resolver = MockDNSResolver(answers=mock_answers)

        with patch("dns.asyncresolver.Resolver", return_value=mock_resolver):
            records, vulns = await scanner.scan("example.com")

        assert records.get("caa") is True
        caa_vulns = [v for v in vulns if "CAA Record Missing" in v.name]
        assert len(caa_vulns) == 0

    @pytest.mark.asyncio
    async def test_caa_record_missing(
        self, scanner: DNSScanner
    ) -> None:
        """Test that missing CAA record is detected."""
        mock_answers = {
            "example.com_DNSKEY": ["DNSKEY record"],
            "example.com_TXT": ["v=spf1 ~all"],
            "_dmarc.example.com_TXT": ["v=DMARC1; p=reject"],
        }
        mock_resolver = MockDNSResolver(answers=mock_answers)

        with patch("dns.asyncresolver.Resolver", return_value=mock_resolver):
            records, vulns = await scanner.scan("example.com")

        assert records.get("caa") is False
        caa_vulns = [v for v in vulns if "CAA Record Missing" in v.name]
        assert len(caa_vulns) > 0
        assert caa_vulns[0].severity == Severity.LOW


class TestDNSErrorHandling:
    """Test DNS scanner error handling."""

    @pytest.mark.asyncio
    async def test_dns_resolution_failure(
        self, scanner: DNSScanner
    ) -> None:
        """Test that DNS resolution failures are handled."""
        mock_resolver = MockDNSResolver(raise_exception=Exception("Resolution failed"))

        with patch("dns.asyncresolver.Resolver", return_value=mock_resolver):
            records, vulns = await scanner.scan("example.com")

        # Should still return results, with all security checks marked as missing/failed
        assert records.get("dnssec") is False
        assert records.get("spf") is None
        assert records.get("dmarc") is None
        assert records.get("caa") is False


class TestCompleteDNSScan:
    """Test complete DNS security scan."""

    @pytest.mark.asyncio
    async def test_full_secure_configuration(
        self, scanner: DNSScanner
    ) -> None:
        """Test a fully secure DNS configuration."""
        mock_answers = {
            "example.com_DNSKEY": ["DNSKEY record"],
            "example.com_TXT": ["v=spf1 include:_spf.google.com -all"],
            "_dmarc.example.com_TXT": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
            "default._domainkey.example.com_TXT": ["v=DKIM1; k=rsa; p=MIGfMA0GCS..."],
            "example.com_CAA": ["0 issue letsencrypt.org"],
        }
        mock_resolver = MockDNSResolver(answers=mock_answers)

        with patch("dns.asyncresolver.Resolver", return_value=mock_resolver):
            records, vulns = await scanner.scan("example.com")

        # Should have all security records
        assert records.get("dnssec") is True
        assert records.get("spf") is not None
        assert records.get("dmarc") is not None
        assert records.get("dkim") is not None
        assert records.get("caa") is True

        # Should have minimal vulnerabilities
        assert len(vulns) == 0

    @pytest.mark.asyncio
    async def test_no_security_records(
        self, scanner: DNSScanner
    ) -> None:
        """Test domain with no security records."""
        mock_answers: dict[str, list[str]] = {}
        mock_resolver = MockDNSResolver(answers=mock_answers)

        with patch("dns.asyncresolver.Resolver", return_value=mock_resolver):
            records, vulns = await scanner.scan("example.com")

        # Should have all security checks marked as missing/failed
        assert records.get("dnssec") is False
        assert records.get("spf") is None
        assert records.get("dmarc") is None
        assert records.get("dkim") is None
        assert records.get("caa") is False

        # Should have vulnerabilities for missing records
        assert len(vulns) >= 4  # DNSSEC, SPF, DMARC, CAA
