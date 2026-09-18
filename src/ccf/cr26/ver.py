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

import copy
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from ..patching.sla import FLAW_SOURCES, RemediationWindow, accepted_weakness_state, classify

#: An omitted row: its id and one reason. The id is an int for a row read from
#: the POA&M table, and a str for one keyed on a `providerTrackingId` that came
#: from stored JSON an admin may have edited -- the document's own field is
#: `type: string` with no numeric pattern, so int was always the narrower
#: assumption. Reported verbatim rather than coerced: an id nobody can parse is
#: still the id the operator has to go and look at.
OmittedRow = tuple[int | str, str]

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


@dataclass(frozen=True)
class VerRendering:
    """Every candidate row's destination, produced in ONE walk.

    Two passes over the same rows would let `active`, `accepted`, `omitted` and
    `counts` drift apart; the SDR split exactly this work and spent a review
    round merging it back. `counts` partitions the input, and its parts sum to
    the number of rows considered -- a partition that does not add up is how a
    row disappears without anyone noticing.
    """

    active: list[dict[str, Any]] = field(default_factory=list)
    accepted: list[dict[str, Any]] = field(default_factory=list)
    #: One tuple per (id, reason) pair, so a row failing three rules appears
    #: three times. `counts["omitted"]` counts ROWS.
    omitted: list[OmittedRow] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)


def render_all(
    poams: Sequence[Any], *, today: date, window: RemediationWindow
) -> VerRendering:
    """Filter to flaws, partition accepted from not-accepted, render each.

    A row that is not scanner-derived is **out of scope**, not omitted: nothing
    is wrong with it, it simply is not a vulnerability (spec §2.1). Collapsing
    that into the omitted list would bury a real data gap among healthy rows.
    """
    out = VerRendering(
        counts={"excluded_not_a_flaw": 0, "rendered": 0, "omitted": 0}
    )
    for poam in poams:
        if (poam.source or "") not in FLAW_SOURCES:
            out.counts["excluded_not_a_flaw"] += 1
            continue

        reasons: list[str] = []
        state = accepted_weakness_state(poam, today=today)
        if state == "unknown":
            # Neither document. `active` means "not accepted", which is the
            # favourable answer for a row nobody can measure.
            reasons.append("not measurable as accepted or not")

        detail, render_reasons = render_vulnerability(poam, today=today, window=window)
        reasons.extend(render_reasons)

        if reasons or detail is None:
            out.counts["omitted"] += 1
            out.omitted.extend((poam.id, reason) for reason in reasons)
            continue

        out.counts["rendered"] += 1
        (out.accepted if state == "accepted" else out.active).append(detail)
    return out


def _tracking_id(entry: Any) -> str | None:
    """The id an entry is keyed on, or ``None`` if it has none."""
    if not isinstance(entry, dict):
        return None
    detail = entry.get("vulnerabilityDetail")
    if not isinstance(detail, dict):
        return None
    value = detail.get("providerTrackingId")
    return None if is_blank(value) else str(value).strip()


def _as_row_id(tid: str) -> int | str:
    """``int(tid)`` when ``tid`` is all digits, the bare string otherwise.

    ``providerTrackingId`` is ``type: string`` with no numeric pattern, so a
    non-numeric id is unusual but legitimate -- especially on the authored
    side, which is stored JSON an admin may have hand-edited. Widening the
    type rather than coercing or swallowing the row: an id nobody can parse
    as a number is still the id an operator has to go and look at, and
    dropping it here would silently drop provider content on exactly the
    "this vulnerability was remediated" path the omission rule exists to
    report.
    """
    return int(tid) if tid.isdigit() else tid


def merge_accepted(
    authored: Sequence[dict[str, Any]], derived: Sequence[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[OmittedRow]]:
    """Refresh each accepted vulnerability, keeping its authored rationale.

    ``acceptanceRationale`` is the one field the platform cannot derive -- no
    POA&M column holds it -- so an admin authors it into the stored document
    and every re-seed preserves it, exactly as the SDR preserves
    ``ksiImplementation``.

    An entry with no rationale is **omitted and named**, never emitted with
    ``""``: the empty string validates while asserting the provider gave a
    blank reason for accepting a vulnerability.

    Entries are ordered by numeric tracking id so a re-seed produces a
    byte-identical document when nothing has changed.
    """
    by_id = {
        tid: entry
        for entry in authored
        if (tid := _tracking_id(entry)) is not None
    }
    seen: set[str] = set()
    merged: list[dict[str, Any]] = []
    omitted: list[OmittedRow] = []

    for detail in derived:
        tid = detail.get("providerTrackingId")
        if is_blank(tid):
            # Unreachable by construction when `derived` comes from
            # `render_all`: `render_vulnerability` always sets
            # `providerTrackingId = str(poam.id)` from a non-null primary
            # key, so no detail it emits can land here blank.
            continue
        tid = str(tid).strip()
        seen.add(tid)
        rationale = (by_id.get(tid) or {}).get("acceptanceRationale")
        if is_blank(rationale):
            omitted.append((_as_row_id(tid), "no acceptance rationale"))
            continue
        merged.append(
            {
                "vulnerabilityDetail": copy.deepcopy(detail),
                "acceptanceRationale": str(rationale).strip(),
            }
        )

    for tid in by_id:
        if tid not in seen:
            omitted.append((_as_row_id(tid), "no longer an accepted vulnerability"))

    merged.sort(key=lambda e: int(e["vulnerabilityDetail"]["providerTrackingId"]))
    # `row[0]` is `int | str`: a plain `.sort()` would raise the moment one
    # omitted id is numeric and another is not. Numeric ids sort first, in
    # numeric order -- matching the old all-int behaviour exactly -- with any
    # non-numeric ids following in string order.
    omitted.sort(key=lambda row: (isinstance(row[0], str), row[0]))
    return merged, omitted
