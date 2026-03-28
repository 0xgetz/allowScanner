"""Custom exceptions for AllowScanner.

Provides a hierarchy of exceptions for robust error handling across
all scanner modules.
"""

from __future__ import annotations


class AllowScannerError(Exception):
    """Base exception for all AllowScanner errors.
    
    All custom exceptions inherit from this base class.
    Provides consistent error handling and logging.
    """

    def __init__(self, message: str, details: dict | None = None) -> None:
        self.message = message
        self.details = details or {}
        super().__init__(self.message)

    def __str__(self) -> str:
        if self.details:
            details_str = ", ".join(f"{k}={v}" for k, v in self.details.items())
            return f"{self.message} ({details_str})"
        return self.message


class ValidationError(AllowScannerError):
    """Raised when input validation fails.
    
    Used for invalid URLs, malformed configurations, or invalid parameters.
    """

    def __init__(self, message: str, field: str | None = None, value: str | None = None, suggestion: str | None = None) -> None:
        details = {}
        if field:
            details["field"] = field
        if value:
            details["value"] = value
        if suggestion:
            details["suggestion"] = suggestion
        super().__init__(message, details)


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
    ) -> None:
        details = {}
        if url:
            details["url"] = url
        if host:
            details["host"] = host
        if port:
            details["port"] = port
        if original_error:
            details["original_error"] = type(original_error).__name__
        if suggestion:
            details["suggestion"] = suggestion
        super().__init__(message, details)


class SSLError(AllowScannerError):
    """Raised when SSL/TLS operations fail.
    
    Used for certificate verification failures, handshake errors, etc.
    """

    def __init__(
        self,
        message: str,
        host: str | None = None,
        port: int | None = None,
        certificate_info: dict | None = None,
        original_error: Exception | None = None,
        suggestion: str | None = None,
    ) -> None:
        details = {}
        if host:
            details["host"] = host
        if port:
            details["port"] = port
        if certificate_info:
            details["certificate_info"] = certificate_info
        if original_error:
            details["original_error"] = type(original_error).__name__
        if suggestion:
            details["suggestion"] = suggestion
        super().__init__(message, details)


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
    ) -> None:
        details = {}
        if domain:
            details["domain"] = domain
        if record_type:
            details["record_type"] = record_type
        if original_error:
            details["original_error"] = type(original_error).__name__
        if suggestion:
            details["suggestion"] = suggestion
        super().__init__(message, details)


class TimeoutError(AllowScannerError):
    """Raised when an operation times out.
    
    Used for network timeouts, DNS query timeouts, etc.
    """

    def __init__(
        self,
        message: str,
        operation: str | None = None,
        timeout_seconds: float | None = None,
        url: str | None = None,
        host: str | None = None,
        suggestion: str | None = None,
    ) -> None:
        details = {}
        if operation:
            details["operation"] = operation
        if timeout_seconds:
            details["timeout_seconds"] = timeout_seconds
        if url:
            details["url"] = url
        if host:
            details["host"] = host
        if suggestion:
            details["suggestion"] = suggestion
        super().__init__(message, details)


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
    ) -> None:
        details = {}
        if config_key:
            details["config_key"] = config_key
        if config_value:
            details["config_value"] = config_value
        if allowed_values:
            details["allowed_values"] = allowed_values
        if suggestion:
            details["suggestion"] = suggestion
        super().__init__(message, details)


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
    ) -> None:
        details = {}
        if scanner_name:
            details["scanner_name"] = scanner_name
        if target:
            details["target"] = target
        if original_error:
            details["original_error"] = type(original_error).__name__
        if suggestion:
            details["suggestion"] = suggestion
        super().__init__(message, details)
