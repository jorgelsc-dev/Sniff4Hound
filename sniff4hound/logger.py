"""
NDJSON Logger for Sniff4Hound

Provides structured logging in newline-delimited JSON format.
Each log line is a complete JSON object, easy to parse and index.

Usage:
    from sniff4hound.logger import get_logger
    logger = get_logger(__name__)
    logger.info("Message", key="value")
    logger.error("Error occurred", error="details", status_code=500)
"""

from __future__ import annotations

import json
import logging
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .utils import json_dumps


_LOG_RECORD_BUILTINS = set(
    logging.LogRecord(
        name="",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="",
        args=(),
        exc_info=None,
    ).__dict__
) | {"asctime", "message"}


def _jsonable_log_value(value):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if isinstance(value, dict):
        return {str(key): _jsonable_log_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable_log_value(item) for item in value]
    return str(value)


class NDJsonFormatter(logging.Formatter):
    """Formatter that outputs structured logs as newline-delimited JSON."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as NDJSON."""
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Add fields passed as either `extra={"field": ...}` or
        # `extra={"extra_fields": {...}}`.
        extras = {}
        extra_fields = getattr(record, "extra_fields", None)
        if isinstance(extra_fields, dict):
            extras.update(extra_fields)
        for key, value in record.__dict__.items():
            if key in _LOG_RECORD_BUILTINS or key == "extra_fields" or key.startswith("_"):
                continue
            extras[key] = value
        if extras:
            log_entry.update({key: _jsonable_log_value(value) for key, value in extras.items()})

        return json_dumps(log_entry)


class NDJsonHandler(logging.Handler):
    """Handler that writes logs to a file in NDJSON format."""

    def __init__(self, filepath: Path | str, mode: str = "a", encoding: str = "utf-8"):
        super().__init__()
        self.filepath = Path(filepath)
        self.filepath.parent.mkdir(parents=True, exist_ok=True)
        self.mode = mode
        self.encoding = encoding
        self._lock = threading.RLock()
        self._file = None

    def _get_file(self):
        """Get or create file handle."""
        if self._file is None or self._file.closed:
            self._file = open(self.filepath, self.mode, encoding=self.encoding)
        return self._file

    def emit(self, record: logging.LogRecord) -> None:
        """Emit a log record."""
        try:
            with self._lock:
                msg = self.format(record)
                file = self._get_file()
                file.write(msg + "\n")
                file.flush()
        except Exception:
            self.handleError(record)

    def close(self):
        """Close the file handle."""
        with self._lock:
            if self._file is not None:
                try:
                    self._file.close()
                except Exception:
                    pass
                finally:
                    self._file = None
        super().close()


def get_logger(name: str, log_file: Path | str | None = None, level: int = logging.INFO) -> logging.Logger:
    """
    Get or create a logger with NDJSON output.

    Args:
        name: Logger name (typically __name__)
        log_file: Optional file path for NDJSON output. If None, logs to stderr.
        level: Logging level (default: INFO)

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Remove any existing handlers to prevent duplicates and close file
    # descriptors from an earlier configuration.
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:
            pass
    logger.propagate = False

    # Console handler (stderr)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(NDJsonFormatter())
    logger.addHandler(console_handler)

    # File handler if specified
    if log_file:
        file_handler = NDJsonHandler(log_file)
        file_handler.setFormatter(NDJsonFormatter())
        logger.addHandler(file_handler)

    return logger


def get_request_logger(name: str = "sniff4hound.requests") -> logging.Logger:
    """Get logger for HTTP request tracking."""
    return get_logger(name)


def get_capture_logger(name: str = "sniff4hound.capture") -> logging.Logger:
    """Get logger for packet capture events."""
    return get_logger(name)


def get_honeypot_logger(name: str = "sniff4hound.honeypot") -> logging.Logger:
    """Get logger for honeypot events."""
    return get_logger(name)


class LoggerContext:
    """Context manager for temporary logger configuration."""

    def __init__(self, logger: logging.Logger, level: int = logging.DEBUG):
        self.logger = logger
        self.level = level
        self.old_level = None

    def __enter__(self):
        self.old_level = self.logger.level
        self.logger.setLevel(self.level)
        return self.logger

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logger.setLevel(self.old_level)
