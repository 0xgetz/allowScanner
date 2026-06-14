"""Rich terminal output formatter."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from .core.models import ScanResult, Severity

BANNER = r"""[bold cyan]
    ___    __                _____
   /   |  / /___ _____  ____/ / (_)__  _____
  / /| | / / __ `/ __ \/ __  / / / _ \/ ___/
 / ___ |/ / /_/ / / / / /_/ / / /  __/ /
/_/  |_/_/\__,_/_/ /_/\__,_/_/_/\___/_/     [green]v2.0[/]
[/bold cyan]
[dim]Advanced Web Vulnerability Scanner[/dim]
"""


class TerminalOutput:
    """Format scan results for terminal display."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def print_banner(self) -> None:
        self.console.print(BANNER)

    def create_progress(self) -> Progress:
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console,
        )

    def print_summary(self, result: ScanResult) -> None:
        """Print scan summary panel."""
        score = result.score
        score_color = "green" if score >= 80 else "yellow" if score >= 50 else "red"

        summary = Text()
        summary.append("  Target: ", style="bold")
        summary.append(f"{result.target_url}\n")
        summary.append("  Domain: ", style="bold")
        summary.append(f"{result.base_domain}\n")
        summary.append("  Duration: ", style="bold")
        summary.append(f"{result.duration_seconds:.1f}s\n")
        summary.append("  Score: ", style="bold")
        summary.append(f"{score}/100\n", style=f"bold {score_color}")

        self.console.print(Panel(summary, title="📊 Scan Summary", border_style="cyan"))

    def print_technologies(self, result: ScanResult) -> None:
        """Print detected technologies."""
        if not result.technologies:
            return

        table = Table(title="🛠️ Detected Technologies", show_lines=False, border_style="blue")
        table.add_column("Technology", style="bold cyan")
        table.add_column("Category", style="dim")
        table.add_column("Version", style="green")

        for tech in sorted(result.technologies, key=lambda t: t.category):
            table.add_row(tech.name, tech.category, tech.version or "—")

        self.console.print(table)
        self.console.print()

    def print_vulnerabilities(self, result: ScanResult) -> None:
        """Print vulnerability report grouped by severity."""
        vulns = sorted(result.vulnerabilities, key=lambda v: v.severity)

        if not vulns:
            self.console.print(
                Panel(
                    "[bold green]✅ No vulnerabilities found![/]",
                    border_style="green",
                )
            )
            return

        # Severity counts
        counts: dict[Severity, int] = {}
        for v in vulns:
            counts[v.severity] = counts.get(v.severity, 0) + 1

        count_text = Text()
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            if sev in counts:
                count_text.append(f"  {sev.value}: {counts[sev]}", style=sev.color)
        self.console.print(Panel(count_text, title="⚠️ Vulnerability Summary", border_style="yellow"))
        self.console.print()

        # Detailed findings
        table = Table(
            title="🔍 Detailed Findings",
            show_lines=True,
            border_style="red",
            expand=True,
        )
        table.add_column("#", style="dim", width=4)
        table.add_column("Severity", width=10)
        table.add_column("Finding", style="bold", min_width=25)
        table.add_column("URL", style="cyan", min_width=30)
        table.add_column("Recommendation", style="green", min_width=20)
        table.add_column("CWE", style="dim", width=10)

        for i, v in enumerate(vulns, 1):
            sev_style = v.severity.color
            table.add_row(
                str(i),
                f"[{sev_style}]{v.severity.value}[/]",
                v.name,
                v.url[:60] + ("..." if len(v.url) > 60 else ""),
                v.recommendation[:50] + ("..." if len(v.recommendation) > 50 else ""),
                v.cwe or "—",
            )

        self.console.print(table)
        self.console.print()

    def print_ssl(self, result: ScanResult) -> None:
        """Print SSL/TLS information."""
        if not result.certificate:
            return

        cert = result.certificate
        tree = Tree("🔐 SSL/TLS Certificate")
        tree.add(f"Issuer: [cyan]{cert.issuer}[/]")
        tree.add(f"Subject: [cyan]{cert.subject}[/]")
        tree.add(f"Protocol: [cyan]{cert.protocol}[/]")
        tree.add(f"Cipher: [cyan]{cert.cipher}[/]")
        tree.add(f"Valid: [cyan]{cert.not_before}[/] → [cyan]{cert.not_after}[/]")

        if cert.days_remaining is not None:
            days = cert.days_remaining
            color = "green" if days > 30 else "yellow" if days > 0 else "red"
            tree.add(f"Expires in: [{color}]{days} days[/]")

        if cert.san:
            tree.add(f"SANs: [dim]{', '.join(cert.san[:5])}{'...' if len(cert.san) > 5 else ''}[/]")

        self.console.print(tree)
        self.console.print()

    def print_dns(self, result: ScanResult) -> None:
        """Print DNS security info."""
        if not result.dns_records:
            return

        table = Table(title="🌐 DNS Security", show_lines=False, border_style="blue")
        table.add_column("Record", style="bold")
        table.add_column("Status")
        table.add_column("Details", style="dim")

        dns = result.dns_records
        table.add_row("DNSSEC", "✅ Enabled" if dns.get("dnssec") else "❌ Disabled", "")
        table.add_row("SPF", "✅ Found" if dns.get("spf") else "❌ Missing", (dns.get("spf") or "")[:60])
        table.add_row("DMARC", "✅ Found" if dns.get("dmarc") else "❌ Missing", (dns.get("dmarc") or "")[:60])
        table.add_row("DKIM", "✅ Found" if dns.get("dkim") else "⚠️ Not detected", dns.get("dkim") or "")
        table.add_row("CAA", "✅ Found" if dns.get("caa") else "⚠️ Missing", "")

        self.console.print(table)
        self.console.print()

    def print_subdomains(self, result: ScanResult) -> None:
        """Print discovered subdomains."""
        if not result.subdomains:
            return

        self.console.print(
            Panel(
                "\n".join(f"  • {s}" for s in result.subdomains[:30]),
                title=f"🔎 Subdomains Found ({len(result.subdomains)})",
                border_style="cyan",
            )
        )
        self.console.print()

    def print_ports(self, result: ScanResult) -> None:
        """Print open TCP ports."""
        if not result.open_ports:
            return

        self.console.print(
            Panel(
                "  ".join(str(p) for p in result.open_ports),
                title=f"🔌 Open Ports ({len(result.open_ports)})",
                border_style="magenta",
            )
        )
        self.console.print()

    def print_security_headers(self, result: ScanResult) -> None:
        """Print security header status."""
        if not result.security_headers:
            return

        table = Table(title="🛡️ Security Headers", show_lines=False, border_style="green")
        table.add_column("Header", style="bold", min_width=30)
        table.add_column("Status", width=10)
        table.add_column("Value", style="dim", min_width=20)

        for h in result.security_headers:
            status = "[green]✅ Present[/]" if h.present else "[red]❌ Missing[/]"
            value = (h.value or h.recommendation or "")[:60]
            table.add_row(h.name, status, value)

        self.console.print(table)
        self.console.print()

    def print_full_report(self, result: ScanResult) -> None:
        """Print complete formatted report."""
        self.console.print()
        self.print_summary(result)
        self.print_technologies(result)
        self.print_vulnerabilities(result)
        self.print_ssl(result)
        self.print_dns(result)
        self.print_subdomains(result)
        self.print_ports(result)
        self.print_security_headers(result)
