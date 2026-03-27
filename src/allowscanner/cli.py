"""CLI entry point for AllowScanner."""

from __future__ import annotations

import argparse
import asyncio
import sys
from urllib.parse import urlparse

from rich.console import Console

from .core.config import ScanConfig
from .core.models import Severity
from .scanner import AllowScanner
from .output import TerminalOutput
from .formatters import to_json


console = Console()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="allowscanner",
        description="🛡️ AllowScanner — Advanced Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  allowscanner https://example.com
  allowscanner https://example.com -o report.json -f json
  allowscanner https://example.com --no-subdomains -c 100
  allowscanner https://example.com --only headers,ssl,dns
        """,
    )

    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument(
        "-f", "--format", choices=["terminal", "json", "markdown"],
        default="terminal", help="Output format (default: terminal)",
    )
    parser.add_argument("-c", "--concurrency", type=int, default=50, help="Max concurrent requests")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="Request timeout in seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    # Module toggles
    scan = parser.add_argument_group("scan modules")
    scan.add_argument("--no-ssl", action="store_true", help="Skip SSL/TLS checks")
    scan.add_argument("--no-dns", action="store_true", help="Skip DNS security checks")
    scan.add_argument("--no-headers", action="store_true", help="Skip security header checks")
    scan.add_argument("--no-vulns", action="store_true", help="Skip vulnerability scans")
    scan.add_argument("--no-admin", action="store_true", help="Skip admin panel discovery")
    scan.add_argument("--no-sensitive", action="store_true", help="Skip sensitive file checks")
    scan.add_argument("--no-tech", action="store_true", help="Skip technology detection")
    scan.add_argument("--no-subdomains", action="store_true", help="Skip subdomain enumeration")
    scan.add_argument("--no-cors", action="store_true", help="Skip CORS checks")
    scan.add_argument("--no-cookies", action="store_true", help="Skip cookie security checks")
    scan.add_argument("--only", help="Only run specific modules (comma-separated)")

    return parser.parse_args(argv)


def build_config(args: argparse.Namespace) -> ScanConfig:
    config = ScanConfig(
        concurrency=args.concurrency,
        timeout=args.timeout,
        verbose=args.verbose,
        no_color=args.no_color,
        output_format=args.format,
        output_file=args.output,
    )

    if args.only:
        modules = set(args.only.split(","))
        config.check_ssl = "ssl" in modules
        config.check_dns = "dns" in modules
        config.check_headers = "headers" in modules
        config.check_vulnerabilities = "vulns" in modules
        config.check_admin_panels = "admin" in modules
        config.check_sensitive_files = "sensitive" in modules
        config.check_technologies = "tech" in modules
        config.check_subdomains = "subdomains" in modules
        config.check_cors = "cors" in modules
        config.check_cookies = "cookies" in modules
    else:
        config.check_ssl = not args.no_ssl
        config.check_dns = not args.no_dns
        config.check_headers = not args.no_headers
        config.check_vulnerabilities = not args.no_vulns
        config.check_admin_panels = not args.no_admin
        config.check_sensitive_files = not args.no_sensitive
        config.check_technologies = not args.no_tech
        config.check_subdomains = not args.no_subdomains
        config.check_cors = not args.no_cors
        config.check_cookies = not args.no_cookies

    return config


async def async_main(args: argparse.Namespace) -> int:
    config = build_config(args)
    output = TerminalOutput(console)
    output.print_banner()

    # Validate URL
    parsed = urlparse(args.url)
    if parsed.scheme not in ("http", "https"):
        console.print("[red]❌ Error: URL must start with http:// or https://[/]")
        return 1

    target = args.url if parsed.scheme else f"https://{args.url}"

    console.print(f"  [dim]Target:[/] [cyan]{target}[/]")
    console.print(f"  [dim]Modules:[/] {', '.join(m for m in ['ssl','dns','headers','vulns','tech','subdomains','cors','cookies'] if getattr(config, f'check_{m}', True))}")
    console.print()

    scanner = AllowScanner(target, config)

    with output.create_progress() as progress:
        task = progress.add_task("Scanning...", total=100)
        result = await scanner.run()
        progress.update(task, completed=100)

    # Output
    if config.output_format == "json":
        json_output = to_json(result)
        if config.output_file:
            with open(config.output_file, "w") as f:
                f.write(json_output)
            console.print(f"\n[green]✅ JSON report saved to {config.output_file}[/]")
        else:
            console.print(json_output)
    else:
        output.print_full_report(result)

        if config.output_file:
            json_output = to_json(result)
            with open(config.output_file, "w") as f:
                f.write(json_output)
            console.print(f"\n[green]✅ Report also saved to {config.output_file}[/]")

    # Exit code based on severity
    if result.critical_count > 0:
        return 2
    elif result.high_count > 0:
        return 1
    return 0


def main() -> None:
    args = parse_args()
    try:
        exit_code = asyncio.run(async_main(args))
        sys.exit(exit_code)
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️ Scan interrupted[/]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]❌ Error: {e}[/]")
        if args.verbose:
            console.print_exception()
        sys.exit(1)


if __name__ == "__main__":
    main()
