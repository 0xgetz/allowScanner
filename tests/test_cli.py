"""Comprehensive tests for CLI argument parsing."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from allowscanner.cli import build_config, parse_args


class TestParseArgsValid:
    """Test valid CLI argument parsing."""

    def test_basic_url_parsing(self) -> None:
        """Test that basic URL is parsed correctly."""
        args = parse_args(["https://example.com"])
        assert args.url == "https://example.com"

    def test_url_with_path(self) -> None:
        """Test that URL with path is parsed correctly."""
        args = parse_args(["https://example.com/path/to/page"])
        assert args.url == "https://example.com/path/to/page"

    def test_concurrency_option(self) -> None:
        """Test that concurrency option is parsed correctly."""
        args = parse_args(["https://example.com", "-c", "100"])
        assert args.concurrency == 100

    def test_timeout_option(self) -> None:
        """Test that timeout option is parsed correctly."""
        args = parse_args(["https://example.com", "-t", "30"])
        assert args.timeout == 30

    def test_output_file_option(self) -> None:
        """Test that output file option is parsed correctly."""
        args = parse_args(["https://example.com", "-o", "report.json"])
        assert args.output == "report.json"

    def test_format_option_terminal(self) -> None:
        """Test that format option 'terminal' is parsed correctly."""
        args = parse_args(["https://example.com", "-f", "terminal"])
        assert args.format == "terminal"

    def test_format_option_json(self) -> None:
        """Test that format option 'json' is parsed correctly."""
        args = parse_args(["https://example.com", "-f", "json"])
        assert args.format == "json"

    def test_format_option_markdown(self) -> None:
        """Test that format option 'markdown' is parsed correctly."""
        args = parse_args(["https://example.com", "-f", "markdown"])
        assert args.format == "markdown"

    def test_verbose_flag(self) -> None:
        """Test that verbose flag is parsed correctly."""
        args = parse_args(["https://example.com", "-v"])
        assert args.verbose is True

    def test_no_color_flag(self) -> None:
        """Test that no-color flag is parsed correctly."""
        args = parse_args(["https://example.com", "--no-color"])
        assert args.no_color is True

    def test_multiple_flags(self) -> None:
        """Test that multiple flags are parsed correctly."""
        args = parse_args([
            "https://example.com",
            "-c", "100",
            "-t", "30",
            "-o", "report.json",
            "-f", "json",
            "-v",
            "--no-color",
        ])
        assert args.concurrency == 100
        assert args.timeout == 30
        assert args.output == "report.json"
        assert args.format == "json"
        assert args.verbose is True
        assert args.no_color is True


class TestParseArgsScanModules:
    """Test scan module toggle arguments."""

    def test_no_ssl_flag(self) -> None:
        """Test that --no-ssl flag is parsed correctly."""
        args = parse_args(["https://example.com", "--no-ssl"])
        assert args.no_ssl is True

    def test_no_dns_flag(self) -> None:
        """Test that --no-dns flag is parsed correctly."""
        args = parse_args(["https://example.com", "--no-dns"])
        assert args.no_dns is True

    def test_no_headers_flag(self) -> None:
        """Test that --no-headers flag is parsed correctly."""
        args = parse_args(["https://example.com", "--no-headers"])
        assert args.no_headers is True

    def test_no_vulns_flag(self) -> None:
        """Test that --no-vulns flag is parsed correctly."""
        args = parse_args(["https://example.com", "--no-vulns"])
        assert args.no_vulns is True

    def test_no_admin_flag(self) -> None:
        """Test that --no-admin flag is parsed correctly."""
        args = parse_args(["https://example.com", "--no-admin"])
        assert args.no_admin is True

    def test_no_sensitive_flag(self) -> None:
        """Test that --no-sensitive flag is parsed correctly."""
        args = parse_args(["https://example.com", "--no-sensitive"])
        assert args.no_sensitive is True

    def test_no_tech_flag(self) -> None:
        """Test that --no-tech flag is parsed correctly."""
        args = parse_args(["https://example.com", "--no-tech"])
        assert args.no_tech is True

    def test_no_subdomains_flag(self) -> None:
        """Test that --no-subdomains flag is parsed correctly."""
        args = parse_args(["https://example.com", "--no-subdomains"])
        assert args.no_subdomains is True

    def test_no_cors_flag(self) -> None:
        """Test that --no-cors flag is parsed correctly."""
        args = parse_args(["https://example.com", "--no-cors"])
        assert args.no_cors is True

    def test_no_cookies_flag(self) -> None:
        """Test that --no-cookies flag is parsed correctly."""
        args = parse_args(["https://example.com", "--no-cookies"])
        assert args.no_cookies is True

    def test_only_option(self) -> None:
        """Test that --only option is parsed correctly."""
        args = parse_args(["https://example.com", "--only", "ssl,headers,dns"])
        assert args.only == "ssl,headers,dns"


class TestParseArgsInvalid:
    """Test invalid CLI argument parsing."""

    def test_invalid_format_option(self) -> None:
        """Test that invalid format option raises error."""
        with pytest.raises(SystemExit):
            parse_args(["https://example.com", "-f", "xml"])

    def test_missing_url(self) -> None:
        """Test that missing URL raises error."""
        with pytest.raises(SystemExit):
            parse_args([])

    def test_invalid_concurrency_type(self) -> None:
        """Test that invalid concurrency type raises error."""
        with pytest.raises(SystemExit):
            parse_args(["https://example.com", "-c", "abc"])

    def test_invalid_timeout_type(self) -> None:
        """Test that invalid timeout type raises error."""
        with pytest.raises(SystemExit):
            parse_args(["https://example.com", "-t", "xyz"])


class TestBuildConfig:
    """Test configuration building from parsed args."""

    def test_default_config(self) -> None:
        """Test that default config has all modules enabled."""
        args = parse_args(["https://example.com"])
        config = build_config(args)

        assert config.check_ssl is True
        assert config.check_dns is True
        assert config.check_headers is True
        assert config.check_vulnerabilities is True
        assert config.check_admin_panels is True
        assert config.check_sensitive_files is True
        assert config.check_technologies is True
        assert config.check_subdomains is True
        assert config.check_cors is True
        assert config.check_cookies is True

    def test_config_with_concurrency(self) -> None:
        """Test that config respects concurrency setting."""
        args = parse_args(["https://example.com", "-c", "200"])
        config = build_config(args)

        assert config.concurrency == 200

    def test_config_with_timeout(self) -> None:
        """Test that config respects timeout setting."""
        args = parse_args(["https://example.com", "-t", "60"])
        config = build_config(args)

        assert config.timeout == 60

    def test_config_with_format(self) -> None:
        """Test that config respects format setting."""
        args = parse_args(["https://example.com", "-f", "json"])
        config = build_config(args)

        assert config.output_format == "json"

    def test_config_with_output_file(self) -> None:
        """Test that config respects output file setting."""
        args = parse_args(["https://example.com", "-o", "output.json"])
        config = build_config(args)

        assert config.output_file == "output.json"

    def test_config_with_verbose(self) -> None:
        """Test that config respects verbose setting."""
        args = parse_args(["https://example.com", "-v"])
        config = build_config(args)

        assert config.verbose is True

    def test_config_disable_ssl(self) -> None:
        """Test that config disables SSL when --no-ssl is set."""
        args = parse_args(["https://example.com", "--no-ssl"])
        config = build_config(args)

        assert config.check_ssl is False

    def test_config_disable_multiple_modules(self) -> None:
        """Test that config disables multiple modules."""
        args = parse_args([
            "https://example.com",
            "--no-ssl",
            "--no-dns",
            "--no-headers",
        ])
        config = build_config(args)

        assert config.check_ssl is False
        assert config.check_dns is False
        assert config.check_headers is False

    def test_config_only_option_overrides(self) -> None:
        """Test that --only option overrides other module settings."""
        args = parse_args([
            "https://example.com",
            "--no-ssl",  # This should be ignored when --only is set
            "--only", "ssl,dns",
        ])
        config = build_config(args)

        assert config.check_ssl is True  # Enabled by --only
        assert config.check_dns is True  # Enabled by --only
        assert config.check_headers is False  # Not in --only

    def test_config_only_single_module(self) -> None:
        """Test that --only with single module works."""
        args = parse_args(["https://example.com", "--only", "headers"])
        config = build_config(args)

        assert config.check_headers is True
        assert config.check_ssl is False
        assert config.check_dns is False


class TestHelpOutput:
    """Test help output."""

    def test_help_flag(self) -> None:
        """Test that --help flag shows help and exits."""
        with pytest.raises(SystemExit) as exc_info:
            parse_args(["--help"])
        assert exc_info.value.code == 0

    def test_help_contains_description(self) -> None:
        """Test that help output contains description."""
        with patch("sys.stdout") as mock_stdout:
            with pytest.raises(SystemExit):
                parse_args(["--help"])
            # Help should have been printed
            assert mock_stdout.write.called
