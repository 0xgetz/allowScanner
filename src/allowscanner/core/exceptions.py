"""Custom exceptions for AllowScanner.

Provides a hierarchy of exceptions for robust error handling across
all scanner modules.
"""

from __future__ import annotations

from typing import Any


class AllowScannerError(Exception):
    """Base exception for all AllowScanner errors.

    All custom exceptions inherit from this base class.
    Provides consistent error handling and logging.
    """

    def __init__(
        self,
        message: str,
        context: dict[str, Any] | None = None,
        original_error: Exception | None = None,
        suggestion: str | None = None,
    ) -> None:
        self.message = message
        self.context = context or {}
        self.original_error = original_error
        self.suggestion = suggestion
        super().__init__(self.message)

    def __str__(self) -> str:
        if self.context:
            details_str = ", ".join(f"{k}={v}" for k, v in self.context.items())
            return f"{self.message} ({details_str})"
        return self.message


class ValidationError(AllowScannerError):
    """Raised when input validation fails.

    Used for invalid URLs, malformed configurations, or invalid parameters.
    """

    def __init__(
        self,
        message: str,
        field: str | None = None,
        value: str | None = None,
        suggestion: str | None = None,
        context: dict[str, Any] | None = None,
        original_error: Exception | None = None,
    ) -> None:
        ctx = context or {}
        if field:
            ctx["field"] = field
        if value:
            ctx["value"] = value
        super().__init__(message, context=ctx, original_error=original_error, suggestion=suggestion)


class NetworkError(AllowScannerError):
    """Raised when a network operation fails.

    Used for connection failures, DNS resolution errors, timeouts, etc.
    """

    def __init__(
        self,
        message: str,
        url: str | None = None,
        host: str | None = None,
        port: int | None = None,
        original_error: Exception | None = None,
        suggestion: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        ctx = context or {}
        if url:
            ctx["url"] = url
        if host:
            ctx["host"] = host
        if port:
            ctx["port"] = port
        super().__init__(message, context=ctx, original_error=original_error, suggestion=suggestion)


class SSLError(AllowScannerError):
    """Raised when SSL/TLS operations fail.

    Used for certificate verification failures, handshake errors, etc.
    """

    def __init__(
        self,
        message: str,
        host: str | None = None,
        port: int | None = None,
        certificate_info: dict[str, Any] | None = None,
        original_error: Exception | None = None,
        suggestion: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        ctx = context or {}
        if host:
            ctx["host"] = host
        if port:
            ctx["port"] = port
        if certificate_info:
            ctx["certificate_info"] = certificate_info
        super().__init__(message, context=ctx, original_error=original_error, suggestion=suggestion)


class DNSError(AllowScannerError):
    """Raised when DNS operations fail.

    Used for DNS resolution failures, DNSSEC validation errors, etc.
    """

    def __init__(
        self,
        message: str,
        domain: str | None = None,
        record_type: str | None = None,
        original_error: Exception | None = None,
        suggestion: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        ctx = context or {}
        if domain:
            ctx["domain"] = domain
        if record_type:
            ctx["record_type"] = record_type
        super().__init__(message, context=ctx, original_error=original_error, suggestion=suggestion)


class TimeoutError(AllowScannerError):
    """Raised when an operation times out.

    Used for network timeouts, DNS query timeouts, etc.
    """

    def __init__(
        self,
        message: str,
        operation: str | None = None,
        host: str | None = None,
        port: int | None = None,
        timeout_duration: float | None = None,
        url: str | None = None,
        suggestion: str | None = None,
        context: dict[str, Any] | None = None,
        original_error: Exception | None = None,
    ) -> None:
        ctx = context or {}
        if operation:
            ctx["operation"] = operation
        if host:
            ctx["host"] = host
        if port:
            ctx["port"] = port
        if timeout_duration:
            ctx["timeout_duration"] = timeout_duration
        if url:
            ctx["url"] = url
        super().__init__(message, context=ctx, original_error=original_error, suggestion=suggestion)


class ConfigurationError(AllowScannerError):
    """Raised when configuration is invalid.

    Used for invalid scan configurations, missing required settings, etc.
    """

    def __init__(
        self,
        message: str,
        config_key: str | None = None,
        config_value: str | None = None,
        allowed_values: list[str] | None = None,
        suggestion: str | None = None,
        context: dict[str, Any] | None = None,
        original_error: Exception | None = None,
    ) -> None:
        ctx = context or {}
        if config_key:
            ctx["config_key"] = config_key
        if config_value:
            ctx["config_value"] = config_value
        if allowed_values:
            ctx["allowed_values"] = allowed_values
        super().__init__(message, context=ctx, original_error=original_error, suggestion=suggestion)


class ScannerError(AllowScannerError):
    """Raised when a scanner module encounters an error.

    Used for errors during scanning operations that don't fit other categories.
    """

    def __init__(
        self,
        message: str,
        scanner_name: str | None = None,
        target: str | None = None,
        original_error: Exception | None = None,
        suggestion: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        ctx = context or {}
        if scanner_name:
            ctx["scanner_name"] = scanner_name
        if target:
            ctx["target"] = target
        super().__init__(message, context=ctx, original_error=original_error, suggestion=suggestion)
