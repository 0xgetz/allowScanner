"""DNS security scanner."""

from __future__ import annotations

import dns.asyncresolver
import dns.exception
import dns.name
import dns.resolver

from ..core.exceptions import DNSError, TimeoutError
from ..core.logging import get_logger
from ..core.models import Severity, Vulnerability

logger = get_logger()


class DNSScanner:
    """Check DNS security configuration (DNSSEC, SPF, DMARC, DKIM)."""

    async def scan(self, domain: str) -> tuple[dict, list[Vulnerability]]:
        """Scan domain for DNS security configuration.
        
        Args:
            domain: Domain name to scan
            
        Returns:
            Tuple of (DNS records dict, list of vulnerabilities)
            
        Raises:
            DNSError: If DNS operations fail critically
            ValidationError: If domain is invalid
        """
        # Validate domain
        if not domain or not isinstance(domain, str):
            raise DNSError(
                "Invalid domain name",
                domain=domain,
                suggestion="Provide a valid domain name (e.g., example.com)"
            )

        vulns: list[Vulnerability] = []
        records: dict[str, str | bool | None] = {}

        # DNSSEC check
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = 10

            # Set nameservers (use system default)
            try:
                answers = await resolver.resolve(domain, "DNSKEY")
                records["dnssec"] = True
                logger.debug(f"DNSSEC enabled for {domain}")
            except dns.resolver.NoAnswer:
                records["dnssec"] = False
                logger.debug(f"DNSSEC not enabled for {domain}")
            except dns.resolver.NXDOMAIN:
                records["dnssec"] = False
                logger.warning(f"Domain {domain} does not exist")
            except dns.exception.Timeout:
                records["dnssec"] = False
                logger.warning(f"DNS query timeout for DNSSEC check on {domain}")
                raise TimeoutError(
                    "DNS query timed out during DNSSEC check",
                    domain=domain,
                    record_type="DNSKEY",
                    timeout_seconds=resolver.lifetime,
                    suggestion="Try again or increase timeout"
                )
            except dns.exception.DNSException as e:
                records["dnssec"] = False
                logger.warning(f"DNSSEC check failed for {domain}: {e}")
        except Exception as e:
            records["dnssec"] = False
            logger.error(f"Unexpected error during DNSSEC check for {domain}: {e}")

        if not records.get("dnssec"):
            vulns.append(Vulnerability(
                name="DNSSEC Not Enabled",
                severity=Severity.MEDIUM,
                url=domain,
                description="Domain does not use DNSSEC, vulnerable to DNS spoofing",
                recommendation="Enable DNSSEC at your domain registrar",
                cwe="CWE-350",
            ))

        # SPF & DMARC checks
        spf_found = False
        dmarc_found = False

        # SPF check
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = 10

            try:
                answers = await resolver.resolve(domain, "TXT")
                for record in answers:
                    txt = str(record).strip('"')
                    if txt.startswith("v=spf1"):
                        spf_found = True
                        records["spf"] = txt
                        logger.debug(f"SPF record found for {domain}: {txt[:50]}...")

                        # Check for overly permissive SPF
                        if "+all" in txt:
                            vulns.append(Vulnerability(
                                name="Overly Permissive SPF Record",
                                severity=Severity.MEDIUM,
                                url=domain,
                                description="SPF record uses '+all' which allows any server to send email",
                                recommendation="Change '+all' to '-all' or '~all'",
                                cwe="CWE-940",
                            ))
            except dns.resolver.NoAnswer:
                logger.debug(f"No TXT records for {domain}")
            except dns.resolver.NXDOMAIN:
                logger.debug(f"Domain {domain} does not exist")
            except dns.exception.Timeout:
                logger.warning(f"DNS query timeout for SPF check on {domain}")
            except dns.exception.DNSException as e:
                logger.warning(f"SPF check failed for {domain}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during SPF check for {domain}: {e}")

        if not spf_found:
            records["spf"] = None
            vulns.append(Vulnerability(
                name="SPF Record Missing",
                severity=Severity.MEDIUM,
                url=domain,
                description="No SPF record found, email spoofing possible",
                recommendation="Add an SPF TXT record to your DNS",
                cwe="CWE-940",
            ))

        # DMARC check
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = 10

            try:
                answers = await resolver.resolve(f"_dmarc.{domain}", "TXT")
                for record in answers:
                    txt = str(record).strip('"')
                    if txt.startswith("v=DMARC1"):
                        dmarc_found = True
                        records["dmarc"] = txt
                        logger.debug(f"DMARC record found for {domain}")
            except dns.resolver.NoAnswer:
                logger.debug(f"No TXT records for _dmarc.{domain}")
            except dns.resolver.NXDOMAIN:
                logger.debug(f"Domain _dmarc.{domain} does not exist")
            except dns.exception.Timeout:
                logger.warning(f"DNS query timeout for DMARC check on {domain}")
            except dns.exception.DNSException as e:
                logger.warning(f"DMARC check failed for {domain}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during DMARC check for {domain}: {e}")

        if not dmarc_found:
            records["dmarc"] = None
            vulns.append(Vulnerability(
                name="DMARC Record Missing",
                severity=Severity.MEDIUM,
                url=domain,
                description="No DMARC record found, email authentication weak",
                recommendation="Add a DMARC policy record to _dmarc subdomain",
                cwe="CWE-940",
            ))

        # DKIM check (common selectors)
        dkim_found = False
        selectors = ["default", "google", "k1", "selector1", "s1", "mail"]

        for selector in selectors:
            try:
                resolver = dns.asyncresolver.Resolver()
                resolver.lifetime = 10

                try:
                    answers = await resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
                    if answers:
                        dkim_found = True
                        records["dkim"] = f"Found at selector: {selector}"
                        logger.debug(f"DKIM found for {domain} with selector {selector}")
                        break
                except dns.resolver.NoAnswer:
                    continue
                except dns.resolver.NXDOMAIN:
                    continue
                except dns.exception.Timeout:
                    logger.warning(f"DNS query timeout for DKIM check on {selector}._domainkey.{domain}")
                    continue
                except dns.exception.DNSException:
                    continue
            except Exception as e:
                logger.error(f"Unexpected error during DKIM check for {selector}._domainkey.{domain}: {e}")
                continue

        if not dkim_found:
            records["dkim"] = None

        # CAA (Certificate Authority Authorization) check
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = 10

            try:
                answers = await resolver.resolve(domain, "CAA")
                records["caa"] = True
                logger.debug(f"CAA records found for {domain}")
            except dns.resolver.NoAnswer:
                records["caa"] = False
                logger.debug(f"No CAA records for {domain}")
            except dns.resolver.NXDOMAIN:
                records["caa"] = False
            except dns.exception.Timeout:
                records["caa"] = False
                logger.warning(f"DNS query timeout for CAA check on {domain}")
            except dns.exception.DNSException:
                records["caa"] = False
        except Exception as e:
            records["caa"] = False
            logger.error(f"Unexpected error during CAA check for {domain}: {e}")

        if not records.get("caa"):
            vulns.append(Vulnerability(
                name="CAA Record Missing",
                severity=Severity.LOW,
                url=domain,
                description="No CAA record found. Any CA can issue certificates for this domain",
                recommendation="Add CAA records to restrict which CAs can issue certificates",
                cwe="CWE-295",
            ))

        return records, vulns
