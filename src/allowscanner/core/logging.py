"""Structured logging framework for AllowScanner.

Provides consistent logging across all scanner modules with:
- File and console handlers
- JSON structured logging option
- Correlation IDs for tracking scan sessions
- Multiple log levels
"""

from __future__ import annotations

import json
import logging
import sys
import uuid
from collections.abc import Awaitable, Callable, MutableMapping
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

# Default log format for console output
DEFAULT_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s - %(message)s"
DEFAULT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Log level mapping
LOG_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


class StructuredFormatter(logging.Formatter):
    """Custom formatter that outputs JSON for structured logging."""

    def __init__(self, json_format: bool = False) -> None:
        super().__init__()
        self.json_format = json_format

    def format(self, record: logging.LogRecord) -> str:
        if self.json_format:
            return self._format_json(record)
        return self._format_text(record)

    def _format_json(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add correlation ID if present
        if hasattr(record, "correlation_id"):
            log_data["correlation_id"] = record.correlation_id

        # Add extra fields
        if hasattr(record, "extra_fields"):
            log_data.update(record.extra_fields)

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data)

    def _format_text(self, record: logging.LogRecord) -> str:
        """Format log record as text."""
        # Add correlation ID prefix if present
        prefix = ""
        if hasattr(record, "correlation_id"):
            prefix = f"[{record.correlation_id[:8]}] "

        record.msg = f"{prefix}{record.getMessage()}"
        return super().format(record)


if TYPE_CHECKING:
    _LoggerAdapterBase = logging.LoggerAdapter[logging.Logger]
else:
    _LoggerAdapterBase = logging.LoggerAdapter


class CorrelationLogAdapter(_LoggerAdapterBase):
    """Logger adapter that adds correlation ID to all log messages."""

    def process(self, msg: Any, kwargs: MutableMapping[str, Any]) -> tuple[Any, MutableMapping[str, Any]]:
        # Add correlation ID to extra fields
        extra = kwargs.get("extra", {})
        extra["correlation_id"] = (self.extra or {}).get("correlation_id", "unknown")
        kwargs["extra"] = extra
        return msg, kwargs


class AllowScannerLogger:
    """Main logging manager for AllowScanner.

    Handles logger configuration, correlation IDs, and structured logging.
    """

    def __init__(
        self,
        name: str = "allowscanner",
        level: str = "INFO",
        log_file: Path | str | None = None,
        json_format: bool = False,
        console_output: bool = True,
        correlation_id: str | None = None,
    ) -> None:
        self.name = name
        self.level = LOG_LEVELS.get(level.upper(), logging.INFO)
        self.log_file = Path(log_file) if log_file else None
        self.json_format = json_format
        self.console_output = console_output
        self.correlation_id = correlation_id or str(uuid.uuid4())

        self._logger = self._setup_logger()
        self._adapter = CorrelationLogAdapter(self._logger, {"correlation_id": self.correlation_id})

    def _setup_logger(self) -> logging.Logger:
        """Configure and return the logger instance."""
        logger = logging.getLogger(self.name)
        logger.setLevel(self.level)

        # Remove existing handlers to avoid duplicates
        logger.handlers.clear()

        # Create formatter
        formatter = StructuredFormatter(json_format=self.json_format)

        # Console handler
        if self.console_output:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(self.level)
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

        # File handler
        if self.log_file:
            try:
                # Ensure log directory exists
                self.log_file.parent.mkdir(parents=True, exist_ok=True)

                file_handler = logging.FileHandler(self.log_file)
                file_handler.setLevel(self.level)
                file_handler.setFormatter(formatter)
                logger.addHandler(file_handler)
            except OSError as e:
                # Fall back to console-only logging
                logger.warning(f"Could not create log file {self.log_file}: {e}")

        return logger

    def get_logger(self) -> logging.LoggerAdapter[logging.Logger]:
        """Get the logger adapter with correlation ID."""
        return self._adapter

    def set_correlation_id(self, correlation_id: str) -> None:
        """Update the correlation ID for this logger."""
        self.correlation_id = correlation_id
        self._adapter.extra = {"correlation_id": correlation_id}

    def debug(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._adapter.debug(msg, *args, **kwargs)

    def info(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._adapter.info(msg, *args, **kwargs)

    def warning(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._adapter.warning(msg, *args, **kwargs)

    def error(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._adapter.error(msg, *args, **kwargs)

    def critical(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._adapter.critical(msg, *args, **kwargs)

    def exception(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._adapter.exception(msg, *args, **kwargs)


# Global logger instance (lazy initialized)
_logger: AllowScannerLogger | None = None


def get_logger(
    name: str = "allowscanner",
    level: str = "INFO",
    log_file: Path | str | None = None,
    json_format: bool = False,
    console_output: bool = True,
    correlation_id: str | None = None,
) -> AllowScannerLogger:
    """Get or create the global logger instance.

    Args:
        name: Logger name (default: "allowscanner")
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path for logging
        json_format: Use JSON structured logging
        console_output: Enable console output
        correlation_id: Optional correlation ID for session tracking

    Returns:
        AllowScannerLogger instance
    """
    global _logger

    if _logger is None:
        _logger = AllowScannerLogger(
            name=name,
            level=level,
            log_file=log_file,
            json_format=json_format,
            console_output=console_output,
            correlation_id=correlation_id,
        )

    return _logger


def log_scan_session(func: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
    """Decorator to log scan session start and end."""
    import functools

    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        logger = get_logger()
        correlation_id = str(uuid.uuid4())
        logger.set_correlation_id(correlation_id)

        logger.info("Starting scan session", extra={"correlation_id": correlation_id})
        try:
            result = await func(*args, **kwargs)
            logger.info("Scan session completed successfully", extra={"correlation_id": correlation_id})
            return result
        except Exception as e:
            logger.error(f"Scan session failed: {e}", exc_info=True, extra={"correlation_id": correlation_id})
            raise

    return wrapper
