"""Seed a FedRAMP Ongoing Certification Report from what the platform holds.

See docs/superpowers/specs/2026-09-19-cr26-ocr-design.md.

This deliverable INVERTS the ones before it. The CPO and SDR are mostly
rendered from platform data; the VER family is partly. The OCR is almost
entirely authored: of its nine required fields, one -- ``acceptedVulner-
abilities`` -- is a defensible platform-derived summary, and the other eight
are human statements about the business: what changed, what is planned, which
agencies use the product, what incidents occurred.

**The rule this module exists to enforce: a required field with no authored
content is OMITTED, and the document is invalid until a human supplies it**
(spec §2). That is not a bug to be worked around -- it is the guard. Emitting
an empty value to make the document validate would be filing a report that
lies. ``reportableIncidents`` is the sharpest case: the schema's own
description says an empty ``incidents`` array *attests that no FedRAMP
Reportable Incidents occurred*. Manufacturing that from nothing authored would
be a false statement to a federal regulator, not a harmless placeholder --
spec §1.2 calls it the most serious instance of this programme's signature
defect. This seeder never manufactures it: it is carried forward *only* when
a human has actually supplied the ``incidents`` key.

**The authored signal for all six of these fields is the KEY'S PRESENCE, not
its length.** The seeder itself never writes any of these six keys when
nothing was authored -- so if a key is there at all, a human's own ``PUT`` is
the only thing that could have put it there, empty or not. An authored ``[]``
is that human's attestation that nothing happened, and it is exactly as real
as an authored non-empty list. An earlier version of this module discarded an
authored empty list for the four plain array fields while honouring it for
``reportableIncidents`` -- the same signal, trusted in one place and not the
other, for a reason (an empty array "reads as none") that in fact applies
identically to both: it explains why the SEEDER must never fabricate an empty
value, not why an authored one should be thrown away. The practical cost was
concrete: a quarter in which genuinely nothing happened -- the OCR's most
common case -- became unfileable, because the operator's honest ``[]`` for
``certificationDataChanges``/``transformativeChanges``/``updatedRecommend-
ations``/``activeAgencies`` was silently dropped and the document could never
validate.

**The derived summary and the AVI's own array are NOT asserted to agree**
(review round 2). ``acceptedVulnerabilities`` counts the whole population of
this system's accepted weaknesses in period; the AVI's own array is narrower
by two further filters this count does not apply -- see :func:`_avi_gap` and
its docstring for the measured transcript and why narrowing the count to
match the AVI would be the wrong fix.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import POAM
from ..models_cr26 import Cr26Document
from ..patching.sla import FLAW_SOURCES, RemediationWindow, accepted_weakness_state
from .store import put_document
from .ver import OmittedRow, is_blank, merge_accepted, render_all

_CERTIFICATION_DATA_CHANGES_FIELD = "certificationDataChanges"
_PLANNED_CHANGES_FIELD = "plannedCertificationDataChanges"
_TRANSFORMATIVE_CHANGES_FIELD = "transformativeChanges"
_UPDATED_RECOMMENDATIONS_FIELD = "updatedRecommendations"
_ACTIVE_AGENCIES_FIELD = "activeAgencies"
_INCIDENTS_FIELD = "reportableIncidents"

#: What one of the six authored fields (spec §3.4) is, given the CURRENTLY
#: stored ``ocr`` document -- ``(value, "")`` if it carries genuinely
#: authored content, ``(None, reason)`` if it does not. The reason
#: distinguishes a field nobody ever touched from one a human authored but
#: left unusable: collapsing those two into one message ("no authored X")
#: destroys the second case's content with no record of what was actually
#: wrong with it (review round 2, minor 1).
_Extractor = Callable[[dict[str, Any]], "tuple[Any | None, str]"]


def _array_extractor(key: str, absent_reason: str) -> _Extractor:
    """An extractor for a plain authored array field.

    PRESENCE is the authored signal, not length: the seeder never writes
    ``key`` itself when nothing was authored (the key reaches ``document``
    only via this function's own non-``None`` return, from
    :func:`seed_ocr`'s single walk over :data:`_AUTHORED_FIELDS`), so a key
    that IS present, at any length, can only have come from a human's own
    ``PUT``. An authored ``[]`` is that human's attestation that nothing
    happened this period -- the OCR's most common case -- and discarding it
    would make the document unfileable in exactly that case.
    """

    def extract(current: dict[str, Any]) -> tuple[Any | None, str]:
        if key not in current:
            return None, absent_reason
        value = current[key]
        if isinstance(value, list):
            return value, ""
        return (
            None,
            f"an authored {key} was present but not usable: expected a list "
            f"of strings, got {type(value).__name__}",
        )

    return extract


def _extract_planned_changes(current: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    """``plannedCertificationDataChanges`` carries its OWN required keys
    (``planningHorizonThrough``, ``changes``), so a half-filled one is
    schema-INVALID, not merely incomplete (spec §3.4). Treated as wholly
    unauthored rather than filed half-complete: both required keys must be
    present and usable, or the whole object is omitted and named -- with a
    reason that says WHICH requirement was missing, rather than a single
    "nothing authored" message that would be false for a half-filled object.

    ``changes`` MAY be an empty list here, exactly as an authored empty list
    is honoured for the four plain array fields (:func:`_array_extractor`):
    this object's completeness is judged by whether both of ITS OWN required
    keys are present and valid, not by whether ``changes`` itself is
    non-empty. A human who set a real planning horizon and has genuinely
    nothing planned has still authored this object.
    """
    if _PLANNED_CHANGES_FIELD not in current:
        return None, (
            "no authored forward-looking commitment: plannedCertificationData"
            "Changes needs both planningHorizonThrough and changes, and a "
            "half-filled one is invalid rather than incomplete"
        )
    value = current[_PLANNED_CHANGES_FIELD]
    if not isinstance(value, dict):
        return None, (
            "an authored plannedCertificationDataChanges was present but not "
            "usable: expected an object with planningHorizonThrough and "
            "changes"
        )
    if is_blank(value.get("planningHorizonThrough")):
        return None, (
            "an authored plannedCertificationDataChanges was present but "
            "planningHorizonThrough was missing or blank"
        )
    if not isinstance(value.get("changes"), list):
        return None, (
            "an authored plannedCertificationDataChanges was present but "
            "changes was not a list"
        )
    return value, ""


def _extract_reportable_incidents(
    current: dict[str, Any],
) -> tuple[dict[str, Any] | None, str]:
    """``reportableIncidents`` has exactly one required key, ``incidents``.
    Its presence -- not its length -- is the authored signal, matching
    :func:`_array_extractor`'s presence rule: an empty ``incidents`` array
    with the key genuinely present IS the schema's own attestation of "none
    occurred" (spec §1.2), and this function must return it rather than
    treating it as absent.

    A malformed value (e.g. ``incidents`` authored as a string rather than a
    list) is refused, but with a reason that says a value WAS present and
    unusable -- not the same "no authored incident attestation" message the
    truly-absent case uses, which would misstate what happened and, worse,
    give an operator no clue that their authored text was just discarded by
    :func:`ccf.cr26.store.put_document` replacing the body in place.
    """
    if _INCIDENTS_FIELD not in current:
        return None, (
            "no authored incident attestation -- an empty `incidents` array "
            "is a positive statement that none occurred, and the seeder "
            "must never manufacture that statement on a human's behalf"
        )
    value = current[_INCIDENTS_FIELD]
    if not isinstance(value, dict):
        return None, (
            "an authored reportableIncidents was present but not usable: "
            "expected an object with an `incidents` list"
        )
    if not isinstance(value.get("incidents"), list):
        return None, (
            "an authored reportableIncidents was present but `incidents` "
            "was not a list"
        )
    return value, ""


#: Every authored field (spec §3.4), in the order checked and reported --
#: matching the spec table's own order. ONE ordered table walked once in
#: :func:`seed_ocr`, rather than a hand-copied block per field: the reporting
#: order is DATA here, not control flow, so it cannot drift from a comment
#: describing it the way an earlier version of this module did (review round
#: 2, minor 2 -- a comment claimed `certificationDataChanges` lived in a
#: tuple it was never actually part of).
_AUTHORED_FIELDS: tuple[tuple[str, _Extractor], ...] = (
    (
        _CERTIFICATION_DATA_CHANGES_FIELD,
        _array_extractor(
            _CERTIFICATION_DATA_CHANGES_FIELD,
            "no authored summary of changes to FedRAMP Certification Data "
            "since the previous report",
        ),
    ),
    (_PLANNED_CHANGES_FIELD, _extract_planned_changes),
    (
        _TRANSFORMATIVE_CHANGES_FIELD,
        _array_extractor(
            _TRANSFORMATIVE_CHANGES_FIELD,
            "no authored judgment on which changes during this period were "
            "transformative",
        ),
    ),
    (
        _UPDATED_RECOMMENDATIONS_FIELD,
        _array_extractor(
            _UPDATED_RECOMMENDATIONS_FIELD,
            "no authored recommendations or best practices for customers",
        ),
    ),
    (
        _ACTIVE_AGENCIES_FIELD,
        _array_extractor(
            _ACTIVE_AGENCIES_FIELD,
            "no authored list of agencies using the product -- commercial "
            "knowledge the platform does not hold",
        ),
    ),
    (_INCIDENTS_FIELD, _extract_reportable_incidents),
)


@dataclass(frozen=True)
class OcrSeedResult:
    """What one seed produced, and what a human still owes.

    ``missing_fields`` is the to-do list: every one of the six authored
    fields (spec §3.4) left out for want of an author, paired with a reason
    written for the person who has to supply it -- distinguishing a field
    nobody touched from one authored but left unusable. It does NOT include
    ``certificationPackageOverviewUri`` -- carried forward like the SDR's, and
    surfaced through ``document.validation_errors`` instead, matching
    :func:`ccf.cr26.sdr.seed_sdr`'s precedent.

    ``accepted_count`` is reported beside the prose summary so an operator can
    reconcile it against the AVI's own records without parsing a sentence.

    ``avi_gap`` is the honest accounting the derived summary owes (review
    round 2): which of the rows ``accepted_count`` counted the AVI will NOT be
    able to report right now, and why. See :func:`_avi_gap`.

    No field here defaults to the favourable answer ("nothing is owed", "zero
    accepted", "no gap") -- a result type whose whole purpose is to say what
    is still owed must not let a caller construct one by omission.
    """

    document: Cr26Document
    missing_fields: list[tuple[str, str]]
    accepted_count: int
    avi_gap: list[OmittedRow]


async def _poam_rows(session: AsyncSession, system_id: int) -> list[POAM]:
    """Every POA&M for this system -- flaws and non-flaws alike, exactly as
    :mod:`ccf.cr26.ver`'s own query does, so a source filter applied here is
    visible rather than baked into the WHERE clause."""
    return list(
        (
            await session.execute(
                select(POAM).where(POAM.system_id == system_id).order_by(POAM.id.asc())
            )
        ).scalars()
    )


async def _current(session: AsyncSession, system_id: int, kind: str) -> dict[str, Any]:
    """The system's currently stored document of ``kind``, or ``{}`` if none.

    Generic over ``kind`` -- read only, never :func:`ccf.cr26.store.
    put_document` -- so the same helper serves both this system's ``ocr``
    document (the URI carry-forward and the six authored fields) and its
    ``avi`` document (:func:`_avi_gap`'s read-only pipeline), without a
    second copy of the same query hardcoded to a different kind.
    """
    row = (
        await session.execute(
            select(Cr26Document).where(
                Cr26Document.system_id == system_id, Cr26Document.kind == kind
            )
        )
    ).scalars().first()
    return dict(row.document) if row is not None and row.document else {}


def _carry_uri(document: dict[str, Any], current: dict[str, Any]) -> None:
    """Keep an authored CPO URI. Never invent one -- the document stays
    invalid until a CPO is published, the same honest-failure posture as
    :func:`ccf.cr26.ver._carry_uri` and :func:`ccf.cr26.sdr.seed_sdr`."""
    uri = current.get("certificationPackageOverviewUri")
    if not is_blank(uri):
        document["certificationPackageOverviewUri"] = str(uri).strip()


def _accepted_rows(
    poams: Sequence[POAM], *, period_from: date, period_to: date, today: date
) -> list[POAM]:
    """This system's accepted weaknesses inside this period -- the whole
    population the derived ``acceptedVulnerabilities`` sentence counts.

    Scanner-derived flaws only (:data:`ccf.patching.sla.FLAW_SOURCES`), dated
    inside ``[period_from, period_to]`` (both ends INCLUSIVE, matching
    :func:`ccf.cr26.ver.render_all`), bucketed with the SAME function the
    AVI's own walk calls, :func:`ccf.patching.sla.accepted_weakness_state`.

    **This is the whole population, not the AVI's array, and the two are NOT
    asserted to agree** (review round 2 -- an earlier version of this
    docstring wrongly claimed they "cannot disagree"). Measured, one system,
    one period, three `risk_accepted` in-period `scan` rows::

        AVI acceptedVulnerabilities: 1
        AVI omitted_poam_ids: [(47, "no acceptance rationale"),
                                (48, "no description")]
        OCR accepted_count: 3

    The AVI's own ``acceptedVulnerabilities`` is narrower by two further
    filters this count does not apply: :func:`ccf.cr26.ver.render_vulnerability`
    can refuse a row (no description, no detection source), and
    :func:`ccf.cr26.ver.merge_accepted` omits any accepted row with no
    acceptance rationale -- the DEFAULT state of an elapsed accepted weakness
    nobody has declared or documented. Narrowing this count to match the
    AVI's array would hide accepted vulnerabilities from the summary
    *because* they are undocumented -- the favourable answer, and the wrong
    direction under a rule obliging disclosure. The gap runs toward
    over-reporting, which is safe; :func:`_avi_gap` makes it visible rather
    than assumed away.

    A row with no ``identified_on`` cannot be placed in any period and is
    excluded here, exactly as it never reaches the AVI's rendered array
    either (spec §2.2's period membership question has no answer for it).
    """
    return [
        poam
        for poam in poams
        if (poam.source or "") in FLAW_SOURCES
        and poam.identified_on is not None
        and period_from <= poam.identified_on <= period_to
        and accepted_weakness_state(poam, today=today) == "accepted"
    ]


async def _avi_gap(
    session: AsyncSession,
    *,
    system_id: int,
    poams: Sequence[POAM],
    accepted_ids: set[int],
    today: date,
) -> list[OmittedRow]:
    """Which of ``accepted_ids`` the AVI, seeded right now, would NOT be able
    to report, and why (review round 2 -- see :func:`_accepted_rows` for the
    measured transcript this closes the loop on).

    Read-only: renders and merges exactly as :func:`ccf.cr26.ver.seed_avi`
    would -- the SAME :func:`ccf.cr26.ver.render_all` and
    :func:`ccf.cr26.ver.merge_accepted` calls, against the CURRENTLY stored
    ``avi`` document's authored entries -- but writes nothing. This computes
    what the AVI WOULD produce right now, rather than a second,
    hand-maintained copy of "why AVI omits a row": reusing the real pipeline
    is what keeps this from silently drifting out of step with
    :func:`ccf.cr26.ver.seed_avi` the way a parallel reimplementation
    eventually would.

    ``period=None`` on purpose: ``accepted_ids`` already reflects this
    period's own boundary (:func:`_accepted_rows`), and re-deriving period
    membership here a second way would be exactly the "one rule expressed in
    two places" shape this programme keeps being bitten by.
    """
    if not accepted_ids:
        return []

    rendering = render_all(poams, today=today, window=RemediationWindow())
    avi_document = await _current(session, system_id, "avi")
    authored_raw = avi_document.get("acceptedVulnerabilities")
    authored = authored_raw if isinstance(authored_raw, list) else []
    merge = merge_accepted(
        authored,
        rendering.accepted,
        unplaced=rendering.unplaced,
        excluded=rendering.excluded,
        column_rationale=rendering.column_rationale,
    )

    reportable_ids: set[int] = set()
    for entry in merge.entries:
        tid = entry.get("vulnerabilityDetail", {}).get("providerTrackingId")
        try:
            reportable_ids.add(int(tid))
        except (TypeError, ValueError):
            continue

    gap_ids = accepted_ids - reportable_ids
    if not gap_ids:
        return []

    reasons_by_id: dict[int, list[str]] = {}
    for row_id, reason in (*rendering.omitted, *merge.omitted):
        if isinstance(row_id, int) and row_id in gap_ids:
            reasons_by_id.setdefault(row_id, []).append(reason)

    gap: list[OmittedRow] = []
    for poam_id in sorted(gap_ids):
        reasons = reasons_by_id.get(poam_id)
        if reasons:
            gap.extend((poam_id, reason) for reason in reasons)
        else:
            # Not reachable given render_all's/merge_accepted's own
            # partition -- every accepted, flaw-sourced, rendered-or-not row
            # lands in one of the two omitted lists above or in
            # `merge.entries`. Reported by id rather than silently dropped
            # if that partition is ever wrong.
            gap.append((poam_id, "not reflected in the AVI for an unrecognised reason"))
    return gap


def _accepted_summary(count: int) -> str:
    """The derived ``acceptedVulnerabilities`` sentence (spec §3.3).

    Always emitted, including ``count == 0``: a derived zero is MEASURED --
    the platform saw the whole population and can say so -- unlike the six
    fields below, where an empty answer cannot be told apart from an
    unmeasured one. States the count and points at the AVI, nothing more --
    the cross-reference is the schema's own required wording. It does NOT
    assert the count agrees with the AVI's own array; see
    :func:`_accepted_rows` and :func:`_avi_gap`.
    """
    noun = "vulnerability" if count == 1 else "vulnerabilities"
    return (
        f"{count} accepted {noun} for this reporting period. "
        "Full records are reported per VER-RPT-AVI."
    )


async def seed_ocr(
    session: AsyncSession,
    *,
    system_id: int,
    period_from: date,
    period_to: date,
    today: date | None = None,
) -> OcrSeedResult:
    """Seed this system's Ongoing Certification Report.

    Of the nine required fields:

    * ``certificationPackageOverviewUri`` -- carried forward if authored,
      never invented (spec §3.1).
    * ``reportPeriod`` -- from the caller's ``period_from``/``period_to``,
      rendered as ``format: date`` (``date.isoformat()``), NOT the VER
      family's ``date-time``. Reusing :func:`ccf.cr26.ver._instant` here would
      fail loudly rather than silently -- ``date`` IS enforced in this
      environment while ``date-time`` is not (spec §3.2) -- which is exactly
      why it is not imported.
    * ``acceptedVulnerabilities`` -- derived, always present, a summary
      sentence over the whole population of this system's accepted
      weaknesses in period (spec §3.3). NOT asserted to agree with the AVI's
      own array -- see :attr:`OcrSeedResult.avi_gap`.
    * The other six -- carried forward verbatim when authored into the
      previously stored ``ocr`` document, OMITTED and named in
      ``missing_fields`` when not (spec §3.4). Nothing here merges platform
      data into them, unlike the SDR's ``keySecurityIndicators``: the
      platform holds no derived half of any of these six fields at all.

    A freshly seeded OCR against a system with nothing authored is INVALID by
    design -- exactly like a freshly seeded CPO or SDR. That invalidity IS the
    guard (spec §2): a document that validates is a document someone could
    file, and the result object does not travel with it.
    """
    today = today or datetime.now(UTC).date()
    poams = await _poam_rows(session, system_id)
    current = await _current(session, system_id, "ocr")

    accepted_rows = _accepted_rows(
        poams, period_from=period_from, period_to=period_to, today=today
    )
    accepted_count = len(accepted_rows)
    avi_gap = await _avi_gap(
        session,
        system_id=system_id,
        poams=poams,
        accepted_ids={poam.id for poam in accepted_rows},
        today=today,
    )

    document: dict[str, Any] = {
        "reportPeriod": {
            "from": period_from.isoformat(),
            "to": period_to.isoformat(),
        },
        "acceptedVulnerabilities": _accepted_summary(accepted_count),
    }
    _carry_uri(document, current)

    missing_fields: list[tuple[str, str]] = []
    for key, extractor in _AUTHORED_FIELDS:
        value, reason = extractor(current)
        if value is None:
            missing_fields.append((key, reason))
        else:
            document[key] = value

    row = await put_document(session, system_id=system_id, kind="ocr", document=document)
    return OcrSeedResult(
        document=row,
        missing_fields=missing_fields,
        accepted_count=accepted_count,
        avi_gap=avi_gap,
    )
