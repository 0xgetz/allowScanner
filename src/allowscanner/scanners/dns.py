"""DNS security scanner."""

from __future__ import annotations

import dns.asyncresolver
import dns.resolver

from ..core.models import Vulnerability, Severity


class DNSScanner:
    """Check DNS security configuration (DNSSEC, SPF, DMARC, DKIM)."""

    async def scan(self, domain: str) -> tuple[dict, list[Vulnerability]]:
        vulns: list[Vulnerability] = []
        records: dict = {}

        # DNSSEC
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = 10
            answers = await resolver.resolve(domain, "DNSKEY")
            records["dnssec"] = True
        except Exception:
            records["dnssec"] = False
            vulns.append(Vulnerability(
                name="DNSSEC Not Enabled",
                severity=Severity.MEDIUM,
                url=domain,
                description="Domain does not use DNSSEC, vulnerable to DNS spoofing",
                recommendation="Enable DNSSEC at your domain registrar",
                cwe="CWE-350",
            ))

        # SPF & DMARC
        spf_found = False
        dmarc_found = False

        try:
            answers = await resolver.resolve(domain, "TXT")
            for record in answers:
                txt = str(record).strip('"')
                if txt.startswith("v=spf1"):
                    spf_found = True
                    records["spf"] = txt
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
        except Exception:
            pass

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

        # DMARC
        try:
            answers = await resolver.resolve(f"_dmarc.{domain}", "TXT")
            for record in answers:
                txt = str(record).strip('"')
                if txt.startswith("v=DMARC1"):
                    dmarc_found = True
                    records["dmarc"] = txt
        except Exception:
            pass

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

        # DKIM (common selectors)
        dkim_found = False
        for selector in ["default", "google", "k1", "selector1", "s1", "mail"]:
            try:
                answers = await resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
                if answers:
                    dkim_found = True
                    records["dkim"] = f"Found at selector: {selector}"
                    break
            except Exception:
                continue

        if not dkim_found:
            records["dkim"] = None

        # CAA (Certificate Authority Authorization)
        try:
            answers = await resolver.resolve(domain, "CAA")
            records["caa"] = True
        except Exception:
            records["caa"] = False
            # CAA missing is informational, not critical
            vulns.append(Vulnerability(
                name="CAA Record Missing",
                severity=Severity.LOW,
                url=domain,
                description="No CAA record found. Any CA can issue certificates for this domain",
                recommendation="Add CAA records to restrict which CAs can issue certificates",
                cwe="CWE-295",
            ))

        return records, vulns
