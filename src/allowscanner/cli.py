"""CLI entry point for AllowScanner with enhanced error handling."""

from __future__ import annotations

import argparse
import asyncio
import sys
from urllib.parse import urlparse

from rich.console import Console

from .core.config import ScanConfig
from .core.diff import diff_against_baseline
from .core.exceptions import AllowScannerError, ConfigurationError, ValidationError
from .core.logging import get_logger
from .formatters import to_html, to_json, to_markdown, to_sarif
from .output import TerminalOutput
from .scanner import AllowScanner

console = Console()
logger = get_logger()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command line arguments with validation.

    Args:
        argv: Optional argument list (for testing)

    Returns:
        Parsed arguments namespace
    """
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

    parser.add_argument("url", nargs="?", help="Target URL to scan (must start with http:// or https://)")
    parser.add_argument("--doctor", action="store_true", help="Run an environment self-test and exit")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument(
        "-f",
        "--format",
        choices=["terminal", "json", "markdown", "html", "sarif"],
        default="terminal",
        help="Output format (default: terminal)",
    )
    parser.add_argument(
        "-c", "--concurrency", type=int, default=50, help="Max concurrent requests (1-1000, default: 50)"
    )
    parser.add_argument("-t", "--timeout", type=int, default=15, help="Request timeout in seconds (1-300, default: 15)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument(
        "--no-ssl-verify", action="store_true", help="Disable SSL certificate verification (use with caution)"
    )
    parser.add_argument("--log-file", help="Path to log file for structured logging")
    parser.add_argument(
        "-r", "--rate-limit", type=int, default=None, help="Max requests per second (default: unlimited)"
    )
    parser.add_argument("--ports", help="Comma-separated TCP ports to scan (default: common service ports)")
    parser.add_argument("-w", "--wordlist", help="Path to a custom path-fuzzing wordlist (one path per line)")
    parser.add_argument("-H", "--header", action="append", metavar="K:V", help="Extra request header (repeatable)")
    parser.add_argument("--cookie", help="Cookie header value sent with every request")
    parser.add_argument("--bearer", help="Bearer token (sets Authorization: Bearer <token>)")
    parser.add_argument(
        "--scope", action="append", metavar="HOST", help="In-scope host (repeatable); defaults to target host"
    )
    parser.add_argument(
        "--exclude", action="append", metavar="REGEX", help="Exclude URLs matching this regex (repeatable)"
    )
    parser.add_argument("--suppress", metavar="FILE", help="Suppression file (default: ./.allowscanignore)")
    parser.add_argument("--baseline", metavar="FILE", help="Baseline JSON report to diff against")

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
    scan.add_argument("--no-ports", action="store_true", help="Skip TCP port scan")
    scan.add_argument("--no-fuzz", action="store_true", help="Skip content discovery / path fuzzing")
    scan.add_argument("--no-secrets", action="store_true", help="Skip secret/endpoint discovery")
    scan.add_argument("--no-graphql", action="store_true", help="Skip GraphQL introspection check")
    scan.add_argument("--no-methods", action="store_true", help="Skip HTTP method audit")
    scan.add_argument("--no-takeover", action="store_true", help="Skip subdomain takeover detection")
    scan.add_argument("--no-waf", action="store_true", help="Skip WAF/CDN detection")
    scan.add_argument("--no-crawl", action="store_true", help="Skip crawler / surface mapping")
    scan.add_argument("--no-paramfind", action="store_true", help="Skip hidden-parameter discovery")
    scan.add_argument("--no-inject", action="store_true", help="Skip injection verification (XSS / blind SQLi)")
    scan.add_argument("--only", help="Only run specific modules (comma-separated)")

    return parser.parse_args(argv)


def validate_url(url: str) -> str:
    """Validate and sanitize the target URL.

    Args:
        url: URL to validate

    Returns:
        Validated and sanitized URL

    Raises:
        ValidationError: If URL is invalid
    """
    if not url or not isinstance(url, str):
        raise ValidationError(
            "Target URL cannot be empty", field="url", suggestion="Provide a valid URL as the first argument"
        )

    # Strip whitespace
    url = url.strip()

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    # Parse and validate
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValidationError(
            f"Invalid URL format: {url}",
            field="url",
            value=url,
            suggestion="URL must have a valid scheme (http/https) and domain",
        )

    if parsed.scheme not in ("http", "https"):
        raise ValidationError(
            f"Unsupported URL scheme: {parsed.scheme}",
            field="url",
            value=parsed.scheme,
            suggestion="Only http:// and https:// schemes are supported",
        )

    return url.rstrip("/")


def build_config(args: argparse.Namespace) -> ScanConfig:
    """Build ScanConfig from parsed arguments with validation.

    Args:
        args: Parsed command line arguments

    Returns:
        Validated ScanConfig

    Raises:
        ConfigurationError: If configuration is invalid
    """
    try:
        config = ScanConfig(
            concurrency=args.concurrency,
            timeout=args.timeout,
            verbose=args.verbose,
            no_color=args.no_color,
            output_format=args.format,
            output_file=args.output,
            verify_ssl=not args.no_ssl_verify,
            rate_limit=args.rate_limit,
        )

        if args.ports:
            try:
                config.port_list = [int(p) for p in args.ports.split(",") if p.strip()]
            except ValueError as e:
                raise ConfigurationError(
                    "Invalid --ports value",
                    config_key="ports",
                    suggestion="Use comma-separated integers, e.g. 22,80,443",
                ) from e
        if args.wordlist:
            try:
                with open(args.wordlist, encoding="utf-8") as fh:
                    config.fuzz_wordlist = [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]
            except OSError as e:
                raise ConfigurationError(
                    f"Could not read wordlist: {args.wordlist}", config_key="wordlist", suggestion="Check the file path"
                ) from e

        headers: dict[str, str] = {}
        for item in args.header or []:
            if ":" in item:
                key, _, value = item.partition(":")
                headers[key.strip()] = value.strip()
        if args.cookie:
            headers["Cookie"] = args.cookie
        if args.bearer:
            headers["Authorization"] = f"Bearer {args.bearer}"
        config.extra_headers = headers
        if args.scope:
            config.scope_hosts = args.scope
        if args.exclude:
            config.exclude_patterns = args.exclude
        config.suppress_file = args.suppress
        config.baseline_file = args.baseline

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
            config.check_ports = "ports" in modules
            config.check_fuzz = "fuzz" in modules
            config.check_secrets = "secrets" in modules
            config.check_graphql = "graphql" in modules
            config.check_methods = "methods" in modules
            config.check_takeover = "takeover" in modules
            config.check_waf = "waf" in modules
            config.check_crawl = "crawl" in modules
            config.check_paramfind = "paramfind" in modules
            config.check_inject = "inject" in modules
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
            config.check_ports = not args.no_ports
            config.check_fuzz = not args.no_fuzz
            config.check_secrets = not args.no_secrets
            config.check_graphql = not args.no_graphql
            config.check_methods = not args.no_methods
            config.check_takeover = not args.no_takeover
            config.check_waf = not args.no_waf
            config.check_crawl = not args.no_crawl
            config.check_paramfind = not args.no_paramfind
            config.check_inject = not args.no_inject

        return config

    except ConfigurationError:
        raise


async def async_main(args: argparse.Namespace) -> int:
    """Main async entry point.

    Args:
        args: Parsed command line arguments

    Returns:
        Exit code
    """
    try:
        # Validate URL
        target = validate_url(args.url)

        # Build configuration
        config = build_config(args)

        # Setup logging
        log_level = "DEBUG" if args.verbose else "INFO"
        get_logger(
            level=log_level,
            log_file=args.log_file if args.log_file else None,
            console_output=not args.no_color,
        )

        logger.info(f"Starting scan of {target}")

        # Create output handler
        output = TerminalOutput(console)
        output.print_banner()

        console.print(f"  [dim]Target:[/] [cyan]{target}[/]")
        console.print(
            f"  [dim]Modules:[/] {', '.join(m for m in ['ssl', 'dns', 'headers', 'vulns', 'tech', 'subdomains', 'ports', 'fuzz', 'secrets', 'graphql', 'methods', 'takeover', 'waf', 'crawl', 'paramfind', 'inject', 'cors', 'cookies'] if getattr(config, f'check_{m}', True))}"
        )
        console.print()

        # Run scanner
        scanner = AllowScanner(target, config)

        with output.create_progress() as progress:
            task = progress.add_task("Scanning...", total=100)
            result = await scanner.run()
            progress.update(task, completed=100)

        # Output results
        text_output: str | None = None
        if config.output_format == "json":
            text_output = to_json(result)
        elif config.output_format == "markdown":
            text_output = to_markdown(result)
        elif config.output_format == "html":
            text_output = to_html(result)
        elif config.output_format == "sarif":
            text_output = to_sarif(result)

        if text_output is not None:
            if config.output_file:
                with open(config.output_file, "w", encoding="utf-8") as f:
                    f.write(text_output)
                console.print(f"\n[green]✅ {config.output_format.upper()} report saved to {config.output_file}[/]")
            else:
                print(text_output)
        else:
            output.print_full_report(result)
            if config.output_file:
                with open(config.output_file, "w", encoding="utf-8") as f:
                    f.write(to_json(result))
                console.print(f"\n[green]✅ JSON report also saved to {config.output_file}[/]")

        if config.baseline_file and (config.output_format == "terminal" or config.output_file):
            diff = diff_against_baseline(result, config.baseline_file)
            console.print("\n[bold]Baseline diff:[/]")
            console.print(
                f"  [red]New:[/] {len(diff.new)}  [green]Fixed:[/] {diff.fixed}  [dim]Unchanged:[/] {diff.unchanged}"
            )
            for line in diff.new:
                console.print(f"    [red]+[/] {line}")

        # Exit code based on severity
        if result.critical_count > 0:
            return 2
        elif result.high_count > 0:
            return 1
        return 0

    except ValidationError as e:
        console.print(f"\n[red]❌ Validation Error: {e}[/]")
        if e.suggestion:
            console.print(f"  [yellow]💡 Suggestion: {e.suggestion}[/]")
        if args.verbose:
            console.print_exception()
        return 1

    except ConfigurationError as e:
        console.print(f"\n[red]❌ Configuration Error: {e}[/]")
        if e.suggestion:
            console.print(f"  [yellow]💡 Suggestion: {e.suggestion}[/]")
        if args.verbose:
            console.print_exception()
        return 1

    except AllowScannerError as e:
        console.print(f"\n[red]❌ Scanner Error: {e}[/]")
        if e.suggestion:
            console.print(f"  [yellow]💡 Suggestion: {e.suggestion}[/]")
        if args.verbose:
            console.print_exception()
        return 1


def main() -> None:
    """Main entry point with error handling."""
    args = parse_args()

    if args.doctor:
        from .core.doctor import run_doctor

        ok, lines = run_doctor()
        console.print("[bold]allowScanner environment check[/]\n")
        for line in lines:
            console.print(line)
        console.print(
            f"\n{'[green]All required checks passed.[/]' if ok else '[red]Some checks failed — see above.[/]'}"
        )
        sys.exit(0 if ok else 1)

    if not args.url:
        console.print(
            "[red]\u274c No target URL given.[/] Usage: [cyan]allowscanner <url>[/]  (or [cyan]allowscanner --doctor[/])"
        )
        sys.exit(2)
    try:
        exit_code = asyncio.run(async_main(args))
        sys.exit(exit_code)
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️ Scan interrupted by user[/]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]❌ Unexpected Error: {e}[/]")
        if args.verbose:
            console.print_exception()
        sys.exit(1)


if __name__ == "__main__":
    main()
