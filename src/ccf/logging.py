"""Structured logging setup (structlog)."""

from __future__ import annotations

import logging
import sys
from typing import cast

import structlog

from .config import get_settings


def configure_logging() -> None:
    settings = get_settings()
    # Resolve the level defensively: an unknown/misspelled CCF_LOG_LEVEL must not
    # crash startup (logging.getLevelName returns a "Level FOO" string for unknown
    # names, which structlog's filtering wrapper would reject). Fall back to INFO.
    level = logging.getLevelName(settings.log_level.upper())
    if not isinstance(level, int):
        level = logging.INFO
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level,
    )

    processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    if settings.log_json:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return cast(structlog.stdlib.BoundLogger, structlog.get_logger(name))
