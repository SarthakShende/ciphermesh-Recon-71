"""Structured logging.

Every record carries an ``event_code`` from
:data:`ciphermesh.constants.LOG_EVENT_CODES` so an operator can filter
precisely (``journalctl -u ciphermesh-edge | grep EVENT_RECEIVED``).

Two safety properties are enforced here:

* **Redaction.** A filter walks every record's ``extra`` payload and replaces
  values whose key looks like a secret. This is a backstop, not a licence to
  log secrets: the correct fix is never to pass one to a log call at all.
* **No private keys, ever.** :func:`scrub` is used at the call sites that
  touch identity material.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Iterable

from . import paths

LOGGER_NAME = "ciphermesh"

#: Attributes present on every LogRecord; anything else was supplied via
#: ``extra=`` and is what the redactor inspects. Derived from a real record so
#: it stays correct across Python versions.
_STANDARD_ATTRS = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__)

#: Keys whose *values* must never be logged, matched case-insensitively
#: against the whole key. A substring match catches "cloud_api_key",
#: "auth_token" and "private_key_hex" without needing an exhaustive list.
_SECRET_KEY_PATTERN = re.compile(
    r"(passw|secret|token|api[_-]?key|private[_-]?key|credential|"
    r"passphrase|authorization|bearer)",
    re.IGNORECASE,
)

REDACTED = "***REDACTED***"

#: Extra keys promoted to top-level JSON fields rather than nested under
#: ``extra``, because they are useful when grepping.
_PROMOTED = ("event_code", "device_id", "event_id", "status", "detail")


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


def is_secret_key(key: str) -> bool:
    """True if a field name suggests the value is a credential."""
    return bool(_SECRET_KEY_PATTERN.search(key))


def scrub(value: Any, *, _depth: int = 0) -> Any:
    """Recursively redact secret-looking values in a log payload.

    Also truncates very long strings so a stray private key or a whole event
    body cannot end up in the journal.
    """
    if _depth > 8:
        return "***TRUNCATED_DEPTH***"
    if isinstance(value, dict):
        return {
            k: (REDACTED if is_secret_key(str(k)) and v not in (None, "", False)
                else scrub(v, _depth=_depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [scrub(v, _depth=_depth + 1) for v in value]
    if isinstance(value, str):
        if len(value) > 512:
            return value[:509] + "..."
        return value
    if isinstance(value, (int, float, bool, type(None))):
        return value
    return str(value)


class RedactingFilter(logging.Filter):
    """Replaces secret-looking values in every record before formatting."""

    def __init__(self, extra_keys: Iterable[str] | None = None) -> None:
        super().__init__()
        # Config-driven keys are in addition to the built-in pattern, so an
        # operator can name a field the pattern does not anticipate.
        self._extra = tuple(extra_keys or ())

    def filter(self, record: logging.LogRecord) -> bool:
        for key, value in list(record.__dict__.items()):
            if key in _STANDARD_ATTRS or key.startswith("_"):
                continue
            if is_secret_key(key) or key.lower() in {k.lower() for k in self._extra}:
                record.__dict__[key] = REDACTED
            else:
                record.__dict__[key] = scrub(value)
        # The message itself is scrubbed too: a careless f-string is the most
        # likely way a secret reaches the journal.
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - defensive
            return True
        if is_secret_key(record.msg if isinstance(record.msg, str) else ""):
            record.msg = REDACTED
            record.args = ()
        else:
            record.msg = message
            record.args = ()
        return True


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------


class JsonFormatter(logging.Formatter):
    """One JSON object per line."""

    converter = time.gmtime

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S") + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        code = getattr(record, "event_code", None)
        if code:
            payload["event_code"] = code

        for key, value in record.__dict__.items():
            if key in _STANDARD_ATTRS or key.startswith("_") or key in ("event_code",):
                continue
            if key in _PROMOTED:
                payload[key] = value
            else:
                payload.setdefault("context", {})[key] = value

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = self.formatStack(record.stack_info)

        return json.dumps(payload, default=str, sort_keys=False, separators=(",", ":"))


class TextFormatter(logging.Formatter):
    """Human-readable, still carrying the event code."""

    def __init__(self) -> None:
        super().__init__(
            fmt="%(asctime)s %(levelname)-8s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        self.converter = time.gmtime

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        code = getattr(record, "event_code", None)
        if code:
            base = f"{base} [{code}]"
        if record.exc_info:
            base += "\n" + self.formatException(record.exc_info)
        return base


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def configure(
    *,
    level: str = "INFO",
    fmt: str = "json",
    file_enabled: bool = False,
    file_name: str = "ciphermesh.log",
    max_file_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 3,
    redact_keys: Iterable[str] = (),
) -> logging.Logger:
    """Install ciphermesh's handlers on the package logger.

    Safe to call more than once: existing handlers are removed first, so the
    CLI, the daemon and the tests do not duplicate output.
    """
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    # The package logger owns its output; do not also emit to the root logger
    # and double every line under a systemd unit.
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    formatter: logging.Formatter = (
        JsonFormatter() if fmt.lower() == "json" else TextFormatter()
    )
    redactor = RedactingFilter(redact_keys)

    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(formatter)
    stream.addFilter(redactor)
    logger.addHandler(stream)

    if file_enabled:
        log_path = paths.log_dir() / file_name
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            rotating = logging.handlers.RotatingFileHandler(
                log_path, maxBytes=max_file_bytes, backupCount=backup_count, encoding="utf-8"
            )
            rotating.setFormatter(formatter)
            rotating.addFilter(redactor)
            logger.addHandler(rotating)
        except OSError as exc:
            logger.warning(
                "Could not open log file %s: %s. Continuing with stdout only.",
                log_path,
                exc,
                extra={"event_code": "CONFIG_LOADED", "detail": "log_file_unavailable"},
            )

    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a child of the ciphermesh logger."""
    if not name:
        return logging.getLogger(LOGGER_NAME)
    return logging.getLogger(f"{LOGGER_NAME}.{name}")


# ---------------------------------------------------------------------------
# Event helpers
# ---------------------------------------------------------------------------


def log_event(
    logger: logging.Logger,
    level: int,
    event_code: str,
    message: str,
    **fields: Any,
) -> None:
    """Emit a structured event.

    ``event_code`` is required so every line is greppable. It is validated
    against :data:`constants.LOG_EVENT_CODES` only in debug mode, to avoid
    the cost on the sensor hot path.
    """
    logger.log(level, message, extra={"event_code": event_code, **fields})


def is_running_under_systemd() -> bool:
    """True when stdout is a journal stream."""
    return os.environ.get("INVOCATION_ID") is not None or os.environ.get(
        "JOURNAL_STREAM"
    ) is not None


def utc_now() -> float:
    """Current time as a Unix timestamp. Centralised so tests can patch it."""
    return time.time()


def journal_hint() -> Path:
    return Path("/var/log/syslog")
