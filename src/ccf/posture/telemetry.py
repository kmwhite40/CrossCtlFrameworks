"""Guarded metric updates for the posture path.

Every increment goes through :func:`observe`, because instrumentation must
never break the thing it measures: a scan that dies because Prometheus is
unhappy is a worse outcome than missing telemetry. The same discipline
``fedramp20x/monitoring.py`` and ``readiness.py`` already apply.

Metrics are imported *inside* each caller (``# noqa: PLC0415``) to avoid an
import cycle with the API package, matching those modules.
"""

from __future__ import annotations

from collections.abc import Callable

from ..logging import get_logger

log = get_logger(__name__)


def observe(what: str, fn: Callable[[], None]) -> None:
    """Run a metric update, swallowing and logging any failure."""
    try:
        fn()
    except Exception as e:
        log.warning("posture.metrics_failed", metric=what, error=str(e)[:200])
