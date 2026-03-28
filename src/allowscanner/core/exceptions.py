"""Custom exceptions for AllowScanner.

Provides a hierarchy of exceptions for robust error handling across
all scanner modules.
"""

from __future__ import annotations

from typing import Dict, Optional


class AllowScannerError(Exception):
    """Base exception for all AllowScanner errors.
    
    All custom exceptions inherit from this base class.
    Provides consistent error handling and logging.
    """

    def __init__(
        self,
        message: str,
        context: Optional[Dict] = None,
        original_error: Optional[Exception] = None,
        suggestion: Optional[str] = None,
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
        field: Optional[str] = None,
        value: Optional[str] = None,
        suggestion: Optional[str] = None,
        context: Optional[Dict] = None,
        original_error: Optional[Exception] = None,
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
        url: Optional[str] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        original_error: Optional[Exception] = None,
        suggestion: Optional[str] = None,
        context: Optional[Dict] = None,
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
        host: Optional[str] = None,
        port: Optional[int] = None,
        certificate_info: Optional[Dict] = None,
        original_error: Optional[Exception] = None,
        suggestion: Optional[str] = None,
        context: Optional[Dict] = None,
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
        domain: Optional[str] = None,
        record_type: Optional[str] = None,
        original_error: Optional[Exception] = None,
        suggestion: Optional[str] = None,
        context: Optional[Dict] = None,
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
        operation: Optional[str] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        timeout_duration: Optional[float] = None,
        url: Optional[str] = None,
        suggestion: Optional[str] = None,
        context: Optional[Dict] = None,
        original_error: Optional[Exception] = None,
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
        config_key: Optional[str] = None,
        config_value: Optional[str] = None,
        allowed_values: Optional[list] = None,
        suggestion: Optional[str] = None,
        context: Optional[Dict] = None,
        original_error: Optional[Exception] = None,
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
        scanner_name: Optional[str] = None,
        target: Optional[str] = None,
        original_error: Optional[Exception] = None,
        suggestion: Optional[str] = None,
        context: Optional[Dict] = None,
    ) -> None:
        ctx = context or {}
        if scanner_name:
            ctx["scanner_name"] = scanner_name
        if target:
            ctx["target"] = target
        super().__init__(message, context=ctx, original_error=original_error, suggestion=suggestion)
