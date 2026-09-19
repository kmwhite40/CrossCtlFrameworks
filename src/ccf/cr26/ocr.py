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
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import POAM
from ..models_cr26 import Cr26Document
from ..patching.sla import FLAW_SOURCES, accepted_weakness_state
from .store import put_document
from .ver import is_blank

#: Plain authored array fields with no platform source at all (spec §3.4),
#: in the order they are checked and reported -- ``certificationDataChanges``
#: first and ``activeAgencies`` last, matching the spec table's own order
#: around the two object fields (:data:`_PLANNED_CHANGES_FIELD`,
#: :data:`_INCIDENTS_FIELD`), which :func:`seed_ocr` checks interleaved with
#: these. Every one of them is carried forward verbatim when a human has
#: authored it into the previously stored document, and OMITTED -- named here
#: rather than silently -- when not.
_CERTIFICATION_DATA_CHANGES_FIELD = "certificationDataChanges"
_CERTIFICATION_DATA_CHANGES_REASON = (
    "no authored summary of changes to FedRAMP Certification Data since the "
    "previous report"
)

_AUTHORED_ARRAY_FIELDS: tuple[tuple[str, str], ...] = (
    (
        "transformativeChanges",
        "no authored judgment on which changes during this period were "
        "transformative",
    ),
    (
        "updatedRecommendations",
        "no authored recommendations or best practices for customers",
    ),
    (
        "activeAgencies",
        "no authored list of agencies using the product -- commercial "
        "knowledge the platform does not hold",
    ),
)

_PLANNED_CHANGES_FIELD = "plannedCertificationDataChanges"
_PLANNED_CHANGES_REASON = (
    "no authored forward-looking commitment: plannedCertificationDataChanges "
    "needs both planningHorizonThrough and changes, and a half-filled one is "
    "invalid rather than incomplete"
)
_INCIDENTS_FIELD = "reportableIncidents"
_INCIDENTS_REASON = (
    "no authored incident attestation -- an empty `incidents` array is a "
    "positive statement that none occurred, and the seeder must never "
    "manufacture that statement on a human's behalf"
)


@dataclass(frozen=True)
class OcrSeedResult:
    """What one seed produced, and what a human still owes.

    ``missing_fields`` is the to-do list: every one of the six authored
    fields (spec §3.4) left out for want of an author, paired with a reason
    written for the person who has to supply it. It does NOT include
    ``certificationPackageOverviewUri`` -- carried forward like the SDR's, and
    surfaced through ``document.validation_errors`` instead, matching
    :func:`ccf.cr26.sdr.seed_sdr`'s precedent.

    ``accepted_count`` is reported beside the prose summary so an operator can
    reconcile it against the AVI's own records without parsing a sentence.
    """

    document: Cr26Document
    missing_fields: list[tuple[str, str]] = field(default_factory=list)
    accepted_count: int = 0


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


async def _current(session: AsyncSession, system_id: int) -> dict[str, Any]:
    """The system's currently stored ``ocr`` document, or ``{}`` if none."""
    row = (
        await session.execute(
            select(Cr26Document).where(
                Cr26Document.system_id == system_id, Cr26Document.kind == "ocr"
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


def _accepted_count(
    poams: Sequence[POAM], *, period_from: date, period_to: date, today: date
) -> int:
    """How many of this system's accepted weaknesses fall in this period.

    The SAME partition :func:`ccf.cr26.ver.render_all` scopes the AVI to --
    scanner-derived flaws only (:data:`ccf.patching.sla.FLAW_SOURCES`), dated
    inside ``[period_from, period_to]`` -- bucketed with the SAME function the
    AVI's own walk calls, :func:`ccf.patching.sla.accepted_weakness_state`, so
    the OCR's summary and the AVI's records are counting the same thing and
    cannot disagree (spec §3.3).

    A row with no ``identified_on`` cannot be placed in any period and is
    excluded here, exactly as it never reaches the AVI's rendered array either
    (spec §2.2's period membership question has no answer for it).

    Both ends are INCLUSIVE, matching :func:`ccf.cr26.ver.render_all`.
    """
    count = 0
    for poam in poams:
        if (poam.source or "") not in FLAW_SOURCES:
            continue
        identified = poam.identified_on
        if identified is None or not (period_from <= identified <= period_to):
            continue
        if accepted_weakness_state(poam, today=today) == "accepted":
            count += 1
    return count


def _accepted_summary(count: int) -> str:
    """The derived ``acceptedVulnerabilities`` sentence (spec §3.3).

    Always emitted, including ``count == 0``: a derived zero is MEASURED --
    the platform saw the whole population and can say so -- unlike the six
    fields below, where an empty answer cannot be told apart from an
    unmeasured one. States the count and points at the AVI, nothing more.
    """
    noun = "vulnerability" if count == 1 else "vulnerabilities"
    return (
        f"{count} accepted {noun} for this reporting period. "
        "Full records are reported per VER-RPT-AVI."
    )


def _authored_array(current: dict[str, Any], key: str) -> list[Any] | None:
    """The stored value for a plain authored array field, or ``None`` if it
    carries no authored content.

    PRESENCE is the authored signal, not length -- matching
    :func:`_authored_reportable_incidents`. The seeder never writes this key
    itself when nothing was authored (see :func:`seed_ocr`: the key is added
    to the document only from this function's own non-``None`` return), so a
    key that IS present, at any length, can only have come from a human's own
    ``PUT``. An authored ``[]`` is that human's attestation that nothing
    happened this period -- the OCR's most common case -- and discarding it
    would make the document unfileable in exactly that case. Only a missing
    key or a non-list value is unauthored.
    """
    value = current.get(key)
    return value if isinstance(value, list) else None


def _authored_planned_changes(current: dict[str, Any]) -> dict[str, Any] | None:
    """The stored ``plannedCertificationDataChanges``, or ``None``.

    This object carries its OWN required keys (``planningHorizonThrough``,
    ``changes``), so a half-filled one is schema-INVALID, not merely
    incomplete (spec §3.4). Treated as wholly unauthored rather than filed
    half-complete: both required keys must be present and usable, or the
    whole object is omitted and named.

    ``changes`` MAY be an empty list here, exactly as an authored empty list
    is honoured for the four plain array fields above (:func:`_authored_
    array`): this object's completeness is judged by whether both of ITS OWN
    required keys are present and valid, not by whether ``changes`` itself is
    non-empty. A human who set a real planning horizon and has genuinely
    nothing planned has still authored this object.
    """
    value = current.get(_PLANNED_CHANGES_FIELD)
    if not isinstance(value, dict):
        return None
    if is_blank(value.get("planningHorizonThrough")):
        return None
    if not isinstance(value.get("changes"), list):
        return None
    return value


def _authored_reportable_incidents(current: dict[str, Any]) -> dict[str, Any] | None:
    """The stored ``reportableIncidents``, or ``None``.

    This object has exactly one required key, ``incidents``. Its presence --
    not its length -- is the authored signal, matching :func:`_authored_
    array`'s presence rule: an empty ``incidents`` array with the key
    genuinely present IS the schema's own attestation of "none occurred"
    (spec §1.2), and this function must return it rather than treating it as
    absent. What this function refuses is a document that never carries the
    key at all, or carries something that is not a list under it -- both of
    those are exactly as unauthored as a missing object.
    """
    value = current.get(_INCIDENTS_FIELD)
    if not isinstance(value, dict):
        return None
    if not isinstance(value.get("incidents"), list):
        return None
    return value


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
      sentence over the SAME partition the AVI counts (spec §3.3).
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
    current = await _current(session, system_id)
    accepted_count = _accepted_count(
        poams, period_from=period_from, period_to=period_to, today=today
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

    changes = _authored_array(current, _CERTIFICATION_DATA_CHANGES_FIELD)
    if changes is None:
        missing_fields.append(
            (_CERTIFICATION_DATA_CHANGES_FIELD, _CERTIFICATION_DATA_CHANGES_REASON)
        )
    else:
        document[_CERTIFICATION_DATA_CHANGES_FIELD] = changes

    planned = _authored_planned_changes(current)
    if planned is None:
        missing_fields.append((_PLANNED_CHANGES_FIELD, _PLANNED_CHANGES_REASON))
    else:
        document[_PLANNED_CHANGES_FIELD] = planned

    for key, reason in _AUTHORED_ARRAY_FIELDS:
        value = _authored_array(current, key)
        if value is None:
            missing_fields.append((key, reason))
        else:
            document[key] = value

    incidents = _authored_reportable_incidents(current)
    if incidents is None:
        missing_fields.append((_INCIDENTS_FIELD, _INCIDENTS_REASON))
    else:
        document[_INCIDENTS_FIELD] = incidents

    row = await put_document(session, system_id=system_id, kind="ocr", document=document)
    return OcrSeedResult(
        document=row, missing_fields=missing_fields, accepted_count=accepted_count
    )
