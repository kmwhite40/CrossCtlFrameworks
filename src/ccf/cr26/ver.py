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
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import POAM
from ..models_cr26 import Cr26Document
from ..patching.sla import FLAW_SOURCES, RemediationWindow, accepted_weakness_state, classify
from .store import put_document

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


def _detected_at(poam: Any) -> str | None:
    """The rendered ``detection.detectedAt``, or ``None`` when the row carries
    no identification date.

    ONE helper with TWO callers on purpose: :func:`render_vulnerability` writes
    this string into the document, and :func:`render_all` decides period
    membership by comparing it (spec §2.2). The midnight-UTC convention (§3.3)
    and the period boundary therefore agree **by construction** -- compare
    ``poam.identified_on`` directly and the two can drift, which is precisely
    how a row dated the period's first day could render at that day's midnight
    and still be judged to fall outside a window starting at it.
    """
    value = poam.identified_on
    # A DATE widened to a date-time: a DECLARED CONVENTION (spec §3.3), not a
    # measured instant. Stated so no reader mistakes it.
    return None if value is None else f"{value.isoformat()}T00:00:00Z"


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

    detected_at = _detected_at(poam)
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
            "detectedAt": detected_at,
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
    #: Rows the walk SAW but could not place, keyed on `providerTrackingId`
    #: (`str(poam.id)`) -> every reason that applied. `merge_accepted` needs
    #: this to tell "this row is no longer accepted" from "this row is still
    #: accepted and could not be rendered this cycle": absence from `accepted`
    #: alone cannot tell them apart, and reading it as the first DESTROYS the
    #: human-written rationale over a blanked title (spec §5.1).
    unplaced: dict[str, list[str]] = field(default_factory=dict)
    #: Rows the two SCOPING filters excluded -- not a flaw, or outside the
    #: period. Also not "no longer accepted", and not a defect either: an
    #: authored entry keyed on one of these must be dropped from the document
    #: WITHOUT an omission record, exactly as the row itself is (spec §7).
    excluded: set[str] = field(default_factory=set)


def render_all(
    poams: Sequence[Any],
    *,
    today: date,
    window: RemediationWindow,
    period: tuple[datetime, datetime] | None = None,
) -> VerRendering:
    """Filter to flaws and to the period, partition accepted from not-accepted,
    render each.

    Two SCOPING filters run first and **neither produces an omission** (spec
    §7). A row they exclude is not a defect -- it belongs to a different report:

    * not scanner-derived (§2.1) -- it is a control deficiency, not a
      vulnerability. Collapsing that into the omitted list would bury a real
      data gap among healthy rows.
    * ``detectedAt`` outside ``period`` (§2.2) -- nothing is wrong with it; it
      belongs to another reporting period.

    ``period`` is optional because the contrast between the schemas is the
    whole point: VDR's and AVI's arrays are *"with activity in this period"*,
    while `ver_history`'s two are *"**All** ..."*. `ver_history` passes no
    period and filters nothing.

    Both ends are INCLUSIVE. The lower edge follows from §3.3's midnight
    convention -- a row identified on the period's first day renders at that
    day's midnight and must fall inside a window whose ``from`` is that same
    midnight -- and the upper edge is inclusive for symmetry, so a row
    identified on the last day is covered by the report ending that day rather
    than falling between two reports.
    """
    # Both sides are `%Y-%m-%dT%H:%M:%SZ` in UTC, produced by `_instant` and
    # `_detected_at`, so a string comparison IS the chronological one:
    # fixed-width, zero-padded, most-significant-first, one zone. `_instant`
    # refuses a naive bound, so no comparison here can silently shift.
    bounds = None if period is None else (_instant(period[0]), _instant(period[1]))
    out = VerRendering(
        counts={
            "excluded_not_a_flaw": 0,
            "excluded_outside_period": 0,
            "rendered": 0,
            "omitted": 0,
        }
    )
    for poam in poams:
        if (poam.source or "") not in FLAW_SOURCES:
            out.counts["excluded_not_a_flaw"] += 1
            out.excluded.add(str(poam.id))
            continue

        detected_at = _detected_at(poam)
        # A row with no identification date cannot be placed in any period, so
        # it falls through to rule 1 below and is omitted and NAMED rather than
        # quietly excluded: that absence is a defect, not a different report.
        if bounds is not None and detected_at is not None and not (
            bounds[0] <= detected_at <= bounds[1]
        ):
            out.counts["excluded_outside_period"] += 1
            out.excluded.add(str(poam.id))
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
            out.unplaced[str(poam.id)] = reasons
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


def _omitted_sort_key(row: OmittedRow) -> tuple[bool, Any]:
    """The one ordering rule for an :data:`OmittedRow` list, used everywhere
    one is sorted.

    ``row[0]`` is ``int | str``: a bare ``sorted()``/``.sort()`` raises
    ``TypeError`` the moment one omitted id is numeric (a POA&M row) and
    another is not (an admin-edited ``providerTrackingId``). Numeric ids sort
    first, in numeric order -- matching the old all-int behaviour exactly --
    with any non-numeric ids following in string order.

    :func:`merge_accepted` and :func:`_seed` both sort an ``OmittedRow`` list
    and must agree on the order, so this is the single body both call rather
    than two hand-written copies of the same tuple that could drift --
    exactly the "one rule expressed in two places" shape that cost the
    sibling SDR module a full review round.
    """
    return (isinstance(row[0], str), row[0])


@dataclass(frozen=True)
class AcceptedMerge:
    """What one merge of the accepted half produced.

    A dataclass rather than the old ``(merged, omitted)`` tuple because the
    seed's ``counts`` must describe the SEED: which rows actually reached this
    document, and which the merge itself left out. Deriving those by matching
    on reason strings would tie the counts to their wording.
    """

    #: The document's ``acceptedVulnerabilities``, ordered by tracking id so a
    #: re-seed with nothing changed produces a byte-identical document.
    entries: list[dict[str, Any]]
    omitted: list[OmittedRow]


def merge_accepted(
    authored: Sequence[dict[str, Any]],
    derived: Sequence[dict[str, Any]],
    *,
    unplaced: Mapping[str, Sequence[str]] | None = None,
    excluded: Collection[str] = (),
) -> AcceptedMerge:
    """Refresh each accepted vulnerability, keeping its authored rationale.

    ``acceptanceRationale`` is the one field the platform cannot derive -- no
    POA&M column holds it -- so an admin authors it into the stored document
    and every re-seed preserves it, exactly as the SDR preserves
    ``ksiImplementation``.

    An entry with no rationale is **omitted and named**, never emitted with
    ``""``: the empty string validates while asserting the provider gave a
    blank reason for accepting a vulnerability.

    **An authored entry absent from ``derived`` has three possible causes and
    they must not be collapsed** (spec §5.1). Absence alone cannot tell them
    apart, so the walk hands over what it saw:

    * in ``derived`` -- refresh the detail, keep the rationale.
    * in ``unplaced`` -- the row still exists and is still accepted; it could
      not be RENDERED this cycle (rules 1-3) or became UNMEASURABLE (rule 4).
      The authored entry is kept **verbatim**, rationale and stored detail
      alike, and reported with a reason naming the real cause. One cycle stale
      and labelled beats destroyed: ``put_document`` replaces the stored body,
      so reporting this as "no longer an accepted vulnerability" irrecoverably
      destroyed a human-written rationale over a blanked title -- and fixing
      the title did not bring it back.
    * in ``excluded`` -- a SCOPING filter excluded the row (not a flaw, or
      outside this report's period). Not a defect and not an omission (§7), so
      the entry leaves this period's document with no reason reported at all.
    * seen nowhere -- genuinely no longer an accepted vulnerability. Dropped
      and reported, which is the only case where that reason is TRUE.
    """
    unplaced = unplaced or {}
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

    for tid, entry in by_id.items():
        if tid in seen or tid in excluded:
            continue
        reasons = list(unplaced.get(tid) or ())
        if not reasons:
            omitted.append((_as_row_id(tid), "no longer an accepted vulnerability"))
            continue
        rationale = entry.get("acceptanceRationale")
        if is_blank(rationale):
            # Nothing to preserve, and keeping it would emit an entry with no
            # `acceptanceRationale` -- required by the schema.
            omitted.append((_as_row_id(tid), "no acceptance rationale"))
            continue
        merged.append(copy.deepcopy(entry))
        omitted.extend(
            (_as_row_id(tid), f"detail not refreshed: {reason}") for reason in reasons
        )

    merged.sort(key=lambda e: int(e["vulnerabilityDetail"]["providerTrackingId"]))
    omitted.sort(key=_omitted_sort_key)
    return AcceptedMerge(merged, omitted)


def _instant(value: datetime) -> str:
    """A UTC instant in the shape the schemas use.

    `format: date-time` is NOT enforced here (spec §4), so this function is the
    only thing standing between a malformed value and the deliverable.

    A naive datetime is **refused, never guessed at** (spec §6.1.1).
    ``datetime.astimezone`` reads a naive value as *local* time, so a server in
    ``America/New_York`` silently turned a posted ``2026-09-01T00:00:00`` into
    ``2026-09-01T04:00:00Z`` -- and, across a DST boundary, changed the
    window's length as well. The route rejects a naive period with 422, but
    this guard is deliberately library-level: the correctness of the one field
    that says *which activity this report covers* must not depend on which
    caller got there first.
    """
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(
            "a naive datetime has no instant: supply a timezone-aware value "
            f"(got {value!r})"
        )
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class VerSeedResult:
    """What one seed produced, and what it could not say.

    `omitted_poam_ids` is the deliverable's own to-do list and is worth more to
    an operator than the document beside it -- nothing in the document says a
    vulnerability was left out.
    """

    document: Cr26Document
    omitted_poam_ids: list[OmittedRow]
    counts: dict[str, int]


async def _poam_rows(session: AsyncSession, system_id: int) -> list[POAM]:
    """EVERY POA&M for this system, flaws and control deficiencies alike.

    The flaw filter deliberately lives downstream in :func:`render_all`, not in
    this query: `counts["excluded_not_a_flaw"]` can only be reported by code
    that SEES the excluded rows. Filtering here would make the exclusion
    invisible and the count a lie. Do not "optimise" it into the WHERE clause.
    """
    return list(
        (
            await session.execute(
                select(POAM).where(POAM.system_id == system_id).order_by(POAM.id.asc())
            )
        ).scalars()
    )


async def _current(session: AsyncSession, system_id: int, kind: str) -> dict[str, Any]:
    row = (
        await session.execute(
            select(Cr26Document).where(
                Cr26Document.system_id == system_id, Cr26Document.kind == kind
            )
        )
    ).scalars().first()
    return dict(row.document) if row is not None and row.document else {}


def _carry_uri(document: dict[str, Any], current: dict[str, Any]) -> None:
    """Keep an authored CPO URI. Never invent one -- the document stays invalid
    until a CPO is published, which is the honest state."""
    uri = current.get("certificationPackageOverviewUri")
    if not is_blank(uri):
        document["certificationPackageOverviewUri"] = str(uri).strip()


async def _seed(
    session: AsyncSession,
    *,
    system_id: int,
    kind: str,
    build: Any,
    today: date | None = None,
    period: tuple[datetime, datetime] | None = None,
) -> VerSeedResult:
    today = today or datetime.now(UTC).date()
    rows = await _poam_rows(session, system_id)
    rendering = render_all(
        rows, today=today, window=RemediationWindow(), period=period
    )
    current = await _current(session, system_id, kind)
    document, extra_omitted = build(rendering, current)
    _carry_uri(document, current)
    stored = await put_document(
        session, system_id=system_id, kind=kind, document=document
    )
    omitted: list[OmittedRow] = [*rendering.omitted, *extra_omitted]
    omitted.sort(key=_omitted_sort_key)
    return VerSeedResult(
        document=stored,
        omitted_poam_ids=omitted,
        counts=dict(rendering.counts),
    )


async def seed_vdr(
    session: AsyncSession,
    *,
    system_id: int,
    period_from: datetime,
    period_to: datetime,
    today: date | None = None,
) -> VerSeedResult:
    """Non-accepted vulnerabilities for the caller's reporting period."""

    def build(
        rendering: VerRendering, _current: dict[str, Any]
    ) -> tuple[dict[str, Any], list[OmittedRow]]:
        return {
            "reportPeriod": {
                "from": _instant(period_from),
                "to": _instant(period_to),
            },
            "vulnerabilities": rendering.active,
        }, []

    return await _seed(
        session,
        system_id=system_id,
        kind="vdr",
        build=build,
        today=today,
        period=(period_from, period_to),
    )


async def seed_avi(
    session: AsyncSession,
    *,
    system_id: int,
    period_from: datetime,
    period_to: datetime,
    today: date | None = None,
) -> VerSeedResult:
    """Accepted vulnerabilities, keeping each authored acceptance rationale."""

    def build(
        rendering: VerRendering, current: dict[str, Any]
    ) -> tuple[dict[str, Any], list[OmittedRow]]:
        authored = current.get("acceptedVulnerabilities")
        merge = merge_accepted(
            authored if isinstance(authored, list) else [],
            rendering.accepted,
            unplaced=rendering.unplaced,
            excluded=rendering.excluded,
        )
        return {
            "reportPeriod": {
                "from": _instant(period_from),
                "to": _instant(period_to),
            },
            "acceptedVulnerabilities": merge.entries,
        }, merge.omitted

    return await _seed(
        session,
        system_id=system_id,
        kind="avi",
        build=build,
        today=today,
        period=(period_from, period_to),
    )


async def seed_ver_history(
    session: AsyncSession, *, system_id: int, today: date | None = None
) -> VerSeedResult:
    """Both halves at once. No period -- the schema has none, and carries
    ``generatedAt`` instead."""

    def build(
        rendering: VerRendering, current: dict[str, Any]
    ) -> tuple[dict[str, Any], list[OmittedRow]]:
        authored = current.get("acceptedVulnerabilities")
        merge = merge_accepted(
            authored if isinstance(authored, list) else [],
            rendering.accepted,
            unplaced=rendering.unplaced,
            excluded=rendering.excluded,
        )
        return {
            "generatedAt": _instant(datetime.now(UTC)),
            "activeVulnerabilities": rendering.active,
            "acceptedVulnerabilities": merge.entries,
        }, merge.omitted

    return await _seed(session, system_id=system_id, kind="ver_history", build=build, today=today)
