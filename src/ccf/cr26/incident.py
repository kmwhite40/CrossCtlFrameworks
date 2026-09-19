"""Seed a FedRAMP Incident Report from continuity, not from platform data.

See docs/superpowers/specs/2026-09-19-cr26-incident-design.md.

Concord holds no incident data at all. Every field -- the description, the
timeline, the impact, the indicators of compromise, the root cause -- is a
human statement, so this deliverable takes the OCR's shape (spec §2): seed
the scaffold, carry what was authored, omit what was not, and let the
document stay invalid until it is true. The platform's only real
contribution is identity, continuity, validation and a to-do list.

**One incident, three filings, one tracking id (spec §1).** ``providerTrack-
ingId`` must stay consistent across a incident's Initial, Ongoing and Final
reports, and a system has many incidents over time. Keying
``cr26_documents`` on the tracking id alone would put all three reports of
one incident in the same row, so filing an Ongoing would overwrite the
Initial -- exactly the loss migration ``0081`` (``document_key``) was added
to prevent. **``document_key`` is ``"{providerTrackingId}/{reportType}"``**,
so every filed report gets its own row, and the three reports of one
incident sort adjacent to each other.

**Continuity is the seeder's only real service (spec §2.1).** Seeding an
``Ongoing`` for an incident that already has an ``Initial`` copies the
still-true facts forward -- the description, the timeline, the coordinator,
the affected agencies -- so an operator does not retype them into three
documents that could disagree about the same incident. The source is the
**most recent prior report that was actually filed** for the same tracking
id, walked backward from ``reportType`` in lifecycle order
``Initial -> Ongoing -> Final`` (:func:`_prior_report`) -- not the oldest
report, and not a field-by-field merge across every prior report. Fields
authored on *this* report always win; continuity only fills what this
report does not have.

**Never carried forward: ``reportType`` and ``resolvedAt``.** ``reportType``
is the identity of the report being written, sourced only from the caller.
``resolvedAt`` asserts the incident is over; copying it from a prior report
onto a new one would assert a resolution nobody restated. The seeder never
writes ``resolvedAt`` itself either -- a seeded ``Final`` with no authored
``resolvedAt`` is invalid, and that is correct: something is genuinely still
owed. If ``resolvedAt`` *is* authored on this exact report already, it is
preserved verbatim, never rewritten -- see :func:`_resolved_at_problem` for
the one case (spec §3.4.1) where it is also flagged as still-owed instead.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models_cr26 import Cr26Document
from .store import put_document
from .ver import is_blank

#: The lifecycle order carry-forward walks backward through (spec §2.1).
#: A tuple, not a set: order is the whole point -- :func:`_prior_report`
#: indexes into it to find what comes strictly BEFORE a given report type.
_LIFECYCLE: tuple[str, ...] = ("Initial", "Ongoing", "Final")

#: Every optional field that is authored in practice and carried forward
#: verbatim when this report does not have it (spec §3.3), in the exact
#: order the spec's own table lists them. ``certificationPackageOverviewUri``
#: is handled separately (spec §3.1: carried from this report, else the
#: prior one, but distinct from this list because an absent one BLOCKS
#: validity); ``reportType`` and ``resolvedAt`` are handled separately too,
#: and deliberately absent from this tuple -- see the module docstring.
#:
#: ``timeline`` and ``potentialImpact`` need no special-casing to carry
#: "whole or not at all" (spec §3.3): every field here is copied as a single
#: value, never merged key-by-key with a prior report's value of the same
#: field, so a half-authored ``timeline`` on this report is never topped up
#: from a prior one's ``timeline`` -- it is simply what this report's author
#: wrote.
_CARRY_FIELDS: tuple[str, ...] = (
    "federalIncidentCoordinator",
    "incidentDescription",
    "timeline",
    "potentialImpact",
    "functionalImpact",
    "recoveryPlan",
    "affectedAgencies",
    "observedActivity",
    "indicatorsOfCompromise",
    "relatedCveIds",
    "rootCause",
    "responseAndRecoveryActivities",
)


def _validate_tracking_id(provider_tracking_id: str) -> str:
    """Refuse what cannot be filed or safely keyed (spec §1.1, §3.1).

    A blank tracking id cannot identify an incident at all. One containing
    ``/`` would make ``document_key`` ambiguous -- ``document_key`` is
    ``"{trackingId}/{reportType}"``, and a ``/`` inside the tracking id half
    would let two different incidents' keys collide or let one incident's
    key be mis-split. Both are refused here, at the seeder, with a
    ``ValueError`` the route turns into a 422 -- not omitted and named like
    the optional fields below, because an unidentifiable report cannot be
    filed at all.
    """
    stripped = provider_tracking_id.strip()
    if not stripped:
        raise ValueError("providerTrackingId must not be blank")
    if "/" in stripped:
        raise ValueError(
            "providerTrackingId must not contain '/': document_key is "
            "'{providerTrackingId}/{reportType}', and a '/' inside the "
            "tracking id would make that key ambiguous"
        )
    return stripped


def _parses_as_iso8601_instant(value: Any) -> bool:
    """True when ``value`` is a string ``datetime.fromisoformat`` accepts.

    Used only for :func:`_resolved_at_problem` (spec §3.4.1): ``date-time``
    is NOT enforced by this environment's validator (see
    :mod:`ccf.cr26.validation`), so a ``resolvedAt`` like ``"whenever"``
    satisfies the schema's own ``required`` conditional while asserting
    nothing true. This is Concord's own, stricter check, not the schema's.
    """
    if not isinstance(value, str):
        return False
    try:
        datetime.fromisoformat(value)
    except ValueError:
        return False
    return True


async def _document_at_key(
    session: AsyncSession, system_id: int, document_key: str
) -> tuple[bool, dict[str, Any]]:
    """Whether a row exists at exactly ``(system_id, "incident",
    document_key)``, and its content if so.

    Existence and content are returned separately, not folded into "``{}``
    means absent" the way :mod:`ccf.cr26.ocr`'s and :mod:`ccf.cr26.sdr`'s
    single-row ``_current`` helpers do: those deliverables have exactly one
    row per system, so a missing row and an empty one are interchangeable
    for their purposes. An incident has up to three, distinguished only by
    this key, and :func:`_prior_report` must be able to tell "the closest
    prior report was filed, but has nothing carry-worthy in it" apart from
    "the closest prior report was never filed at all, keep looking further
    back" -- the first stops the search at that report; the second must not.
    """
    row = (
        await session.execute(
            select(Cr26Document).where(
                Cr26Document.system_id == system_id,
                Cr26Document.kind == "incident",
                Cr26Document.document_key == document_key,
            )
        )
    ).scalars().first()
    if row is None:
        return False, {}
    return True, (dict(row.document) if row.document else {})


async def _prior_report(
    session: AsyncSession, system_id: int, tracking_id: str, report_type: str
) -> tuple[str | None, dict[str, Any]]:
    """The most recent prior report actually filed for this tracking id, in
    lifecycle order ``Initial -> Ongoing -> Final`` (spec §2.1).

    Walks backward from ``report_type`` and stops at the first report type
    that has a row, however sparse -- it does not skip past a filed-but-
    mostly-empty report to reach an earlier, fuller one. Filing an Ongoing
    with nothing carry-worthy in it and then a Final must read the Ongoing
    (which has nothing to offer) as the continuity source, not silently
    reach back to the Initial instead.

    Returns ``(None, {})`` when nothing has been filed for any earlier
    lifecycle stage, and also when ``report_type`` itself is not one of the
    three lifecycle stages -- an invalid ``reportType`` the schema's own
    ``enum`` will refuse (making the document invalid, which is correct);
    there is no ordering to walk in that case, so continuity is skipped
    rather than guessed at.
    """
    if report_type not in _LIFECYCLE:
        return None, {}
    idx = _LIFECYCLE.index(report_type)
    for candidate in reversed(_LIFECYCLE[:idx]):
        key = f"{tracking_id}/{candidate}"
        exists, document = await _document_at_key(session, system_id, key)
        if exists:
            return key, document
    return None, {}


def _resolved_at_problem(report_type: str, resolved_at: Any) -> tuple[str, str] | None:
    """What, if anything, ``resolvedAt`` still owes a Final report (spec
    §3.2, §3.4.1).

    Two distinct failures, both reported as ``("resolvedAt", reason)``:

    * absent entirely -- the schema's own ``required`` conditional will
      already say so in ``validation_errors``, but this is reported here too
      because :attr:`IncidentSeedResult.missing_required` is meant to be the
      operator-facing to-do list, and an operator should not have to parse a
      JSON Schema error to learn the one thing a Final report still needs.
    * present but unparseable, e.g. ``"whenever"`` -- measured (spec §3.4.1)
      to satisfy the schema's conditional (which only checks the key is
      *present*) while ``format: date-time`` goes unenforced, so a document
      like this validates while asserting something untrue in the one field
      that closes a federal incident. Reported, never rewritten or dropped:
      the seeder must not silently discard an operator's authored value.

    Only ever called for a ``Final`` report -- ``resolvedAt`` is optional
    for an Initial or Ongoing, so neither failure applies to them.
    """
    if resolved_at is None:
        return (
            "resolvedAt",
            "no authored resolvedAt -- required for a Final report, and the "
            "seeder never invents or carries one forward",
        )
    if not _parses_as_iso8601_instant(resolved_at):
        return (
            "resolvedAt",
            f"authored resolvedAt {resolved_at!r} does not parse as an "
            "ISO-8601 instant -- the schema's date-time format is not "
            "enforced here, so this document would validate while "
            "asserting a resolution time that is not one",
        )
    return None


@dataclass(frozen=True)
class IncidentSeedResult:
    """What one seed produced, what continuity supplied, and what a human
    still owes (spec §4).

    ``carried_from`` and ``carried_fields`` exist so an operator can see
    what the platform asserted on their behalf: continuity puts words into a
    federal filing, and that must be visible, not silent. ``carried_from``
    is the prior report's ``document_key``, but only when continuity
    actually supplied something -- ``None`` both when no prior report exists
    and when one exists but had nothing this report needed, so its presence
    always means "this report contains words a human did not write here".

    ``missing_required`` and ``missing_advisory`` are deliberately separate
    (spec §4): collapsing them would tell an operator that a missing
    ``rootCause`` blocks filing when it does not, or that a missing
    ``resolvedAt`` on a Final is merely advisory when it is the one thing
    that makes the document invalid. ``missing_required`` pairs a field with
    why it is still owed; ``missing_advisory`` is bare names -- there is
    only one reason anything appears there: nobody has authored it yet,
    anywhere in this incident's history.
    """

    document: Cr26Document
    document_key: str
    carried_from: str | None
    carried_fields: list[str]
    missing_required: list[tuple[str, str]]
    missing_advisory: list[str]


async def seed_incident(
    session: AsyncSession,
    *,
    system_id: int,
    provider_tracking_id: str,
    report_type: str,
) -> IncidentSeedResult:
    """Seed (or re-seed) one report of one incident.

    ``report_type`` is not validated against the three lifecycle stages
    here -- only the tracking id is refused outright (spec §3.1). An
    unrecognised ``reportType`` reaches the document and the schema's own
    ``enum`` refuses it, exactly like every other CR26 seeder's posture on a
    value the schema, not this module, is the authority over. The route
    narrows this further with its own request model.

    Re-seeding the same ``(providerTrackingId, reportType)`` is how a filed
    report is amended (spec §6, out of scope otherwise): it reads whatever
    is already stored at that exact key as "authored on this report" and
    keeps every field of it, then fills only what is still missing from
    continuity. It is not a way to erase previously authored content by
    calling this function with less context -- there is no content parameter
    here at all; every field this function can populate comes from what was
    already stored, at this key or the prior one.
    """
    tracking_id = _validate_tracking_id(provider_tracking_id)
    document_key = f"{tracking_id}/{report_type}"

    _exists, current = await _document_at_key(session, system_id, document_key)
    prior_key, prior = await _prior_report(session, system_id, tracking_id, report_type)

    document: dict[str, Any] = {
        "reportType": report_type,
        "providerTrackingId": tracking_id,
    }
    carried_fields: list[str] = []

    # certificationPackageOverviewUri (spec §3.1): carried from this report,
    # else the prior one, never invented. `is_blank`, not `is not None` --
    # matching every other CR26 seeder's identical carry-the-URI logic
    # (`ccf.cr26.ocr._carry_uri`, `ccf.cr26.ver._carry_uri`), because the UI
    # persists a cleared field as `""`, not `null`.
    uri = current.get("certificationPackageOverviewUri")
    if not is_blank(uri):
        document["certificationPackageOverviewUri"] = str(uri).strip()
    else:
        prior_uri = prior.get("certificationPackageOverviewUri")
        if not is_blank(prior_uri):
            document["certificationPackageOverviewUri"] = str(prior_uri).strip()
            carried_fields.append("certificationPackageOverviewUri")

    # resolvedAt: NEVER read from `prior` -- see the module docstring. Only
    # ever preserved when authored on this exact report already; the seeder
    # itself supplies nothing here.
    if "resolvedAt" in current:
        document["resolvedAt"] = current["resolvedAt"]

    # The twelve authored-in-practice fields (spec §3.3): authored on this
    # report wins outright; carried forward whole, never merged, when this
    # report does not have it; otherwise absent and named as advisory.
    missing_advisory: list[str] = []
    for field_name in _CARRY_FIELDS:
        if field_name in current:
            document[field_name] = current[field_name]
        elif field_name in prior:
            document[field_name] = prior[field_name]
            carried_fields.append(field_name)
        else:
            missing_advisory.append(field_name)

    carried_from = prior_key if carried_fields else None

    missing_required: list[tuple[str, str]] = []
    if "certificationPackageOverviewUri" not in document:
        missing_required.append(
            (
                "certificationPackageOverviewUri",
                "no authored certificationPackageOverviewUri on this report "
                "or the most recent prior report -- never invented",
            )
        )
    if report_type == "Final":
        problem = _resolved_at_problem(report_type, document.get("resolvedAt"))
        if problem is not None:
            missing_required.append(problem)

    row = await put_document(
        session,
        system_id=system_id,
        kind="incident",
        document=document,
        document_key=document_key,
    )
    return IncidentSeedResult(
        document=row,
        document_key=document_key,
        carried_from=carried_from,
        carried_fields=carried_fields,
        missing_required=missing_required,
        missing_advisory=missing_advisory,
    )
