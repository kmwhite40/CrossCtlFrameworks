"""Render Concord's POA&M rows into the CR26 VER family's vulnerability shape.

See docs/superpowers/specs/2026-09-18-cr26-ver-family-design.md.

Two rules govern everything here, and both exist because a JSON Schema
constrains shape rather than honesty:

* A field the platform cannot defend is **omitted**, never approximated. Nine
  optional fields have no source and stay absent (spec §3.4).
* `format: date-time` is **not enforced** in this environment -- see
  :func:`ccf.cr26.validation.enforced_formats` -- so a malformed date reaches
  the deliverable with ``ok: True``. Correctness here is by construction and by
  exact-string test, not by validation.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from ..patching.sla import RemediationWindow, classify

#: `classify` buckets that answer the present-tense question `isOverdue` asks.
#: Every other bucket omits the object rather than claiming `false`, which
#: would be the favourable answer for a row nobody measured (spec §3.2).
_OVERDUE_BY_BUCKET: dict[str, bool] = {"breached": True, "within_sla": False}


def is_blank(value: Any) -> bool:
    """True when ``value`` carries no usable text.

    A blank test, never a ``None`` test: five separate omission rules (spec §7)
    ask this one question, and a column holding ``""`` or ``"   "`` is as
    absent as one holding ``NULL``. The UI saves narrative with ``str(...)``
    and no strip, so a cleared field persists as the empty string.

    A non-string is blank rather than coerced: ``str(["a"])`` would put a repr
    into a federal document.
    """
    return not isinstance(value, str) or not value.strip()


def _first_written(*values: Any) -> str | None:
    """The first value with content, stripped -- or ``None`` if none has any."""
    for value in values:
        if not is_blank(value):
            return str(value).strip()
    return None


def _overdue_status(poam: Any, *, today: date, window: RemediationWindow) -> dict[str, bool] | None:
    """``{"isOverdue": ...}``, or ``None`` when the question has no answer.

    ``allowed_days`` is resolved per severity by :class:`RemediationWindow`,
    which gives an unrecognised severity the *strictest* window rather than the
    most generous.
    """
    bucket = classify(poam, allowed_days=window.days_for(poam.severity), today=today)
    value = _OVERDUE_BY_BUCKET.get(bucket)
    return None if value is None else {"isOverdue": value}


def render_vulnerability(
    poam: Any, *, today: date, window: RemediationWindow
) -> tuple[dict[str, Any] | None, list[str]]:
    """One POA&M as a ``vulnerabilityDetail``, or ``None`` and why not.

    The reason list is non-empty **if and only if** the detail is ``None``, and
    every reason that applies is reported rather than the first: an operator
    told about one missing field would fix it and come straight back for the
    next.
    """
    reasons: list[str] = []

    detected_at = poam.identified_on
    if detected_at is None:
        reasons.append("no identification date")

    source = _first_written(poam.scanner, poam.source)
    if source is None:
        reasons.append("no detection source")

    description = _first_written(poam.weakness, poam.title)
    if description is None:
        reasons.append("no description")

    if reasons:
        return None, reasons

    detail: dict[str, Any] = {
        # `type: string` -- measured. An int fails validation outright.
        "providerTrackingId": str(poam.id),
        "detection": {
            # A DATE widened to a date-time: a DECLARED CONVENTION (spec §3.3),
            # not a measured instant. Stated so no reader mistakes it.
            "detectedAt": f"{detected_at.isoformat()}T00:00:00Z",
            "detectionSource": source,
        },
        "vulnerabilityDescription": description,
    }
    overdue = _overdue_status(poam, today=today, window=window)
    if overdue is not None:
        detail["overdueStatus"] = overdue
    return detail, []
