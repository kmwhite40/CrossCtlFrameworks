"""FedRAMP CR26 deliverable documents: read, author, seed.

The verdict travelling with every response is the point of these endpoints
rather than a detail. :func:`ccf.cr26.store.put_document` already records *why*
a document failed validation; surfacing that on every write is what lets an
author work against the published schema instead of guessing which of the
CPO's ten required fields are still owed.

Two gates, following the precedent in ``api/routes/patching.py`` of splitting
by what an action *means*:

* **Reading is open to any authenticated principal.** A deliverable is
  compliance content about a system the caller can already see.
* **Authoring is ``admin`` alone** -- the same gate as approving a waiver. A
  CPO is a declaration to the government about the offering, carrying the
  provider's name, its FedRAMP package id and its assessor. Loosening this
  later is easy; tightening it after people have authored is not.

A system belonging to another tenant is **404, never 403**, matching
``api/routes/posture.py``'s ``_owned_test``: confirming that an id exists is
itself a disclosure.
"""

from __future__ import annotations

from datetime import date
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...cr26.cpo import seed_cpo
from ...cr26.incident import seed_incident
from ...cr26.ocr import seed_ocr
from ...cr26.sdr import seed_sdr
from ...cr26.store import DELIVERABLE_KINDS, put_document
from ...cr26.ver import VerSeedResult, seed_avi, seed_vdr, seed_ver_history
from ...models import System
from ...models_cr26 import DOCUMENT_KEY_MAX_LENGTH, Cr26Document
from ..auth_deps import get_principal, require_role
from ..deps import get_session

router = APIRouter(prefix="/api", tags=["cr26"])

#: Authoring a CR26 deliverable is a declaration to the government, gated like
#: a waiver approval. See the module docstring.
AUTHOR_ROLES = ("admin",)


class DocumentIn(BaseModel):
    """The document to store. Any JSON object -- the schema is the constraint."""

    document: dict[str, Any]


def _summary(row: Cr26Document) -> dict[str, Any]:
    """A row without its body, for the list view.

    ``document_key`` is included even though it is ``None`` for every
    single-instance deliverable: once a keyed one exists (the Incident
    Report), several rows share a ``kind`` in this response, and
    ``document_key`` is the only thing that tells them apart. It is not
    secret -- the incident seed route already returns it in its own
    response.
    """
    return {
        "kind": row.kind,
        "document_key": row.document_key,
        "is_valid": row.is_valid,
        "validation_errors": row.validation_errors,
        "ruleset_version": row.ruleset_version,
        "schema_version": row.schema_version,
        "updated_at": row.updated_at,
        "updated_by": row.updated_by,
    }


def _full(row: Cr26Document) -> dict[str, Any]:
    return {**_summary(row), "document": row.document}


async def _owned_system(
    session: AsyncSession, system_id: int, principal: Principal
) -> System:
    """The system, or 404 -- including when it belongs to another tenant.

    404 rather than 403, matching ``posture.py``: confirming an id exists is
    itself a disclosure. A soft-deleted system is equally absent, since its
    rows are invisible to every list view and a document written against one
    would be unreachable and permanent.
    """
    system = await session.get(System, system_id)
    if (
        system is None
        or system.deleted_at is not None
        or (principal.org_id is not None and system.organization_id != principal.org_id)
    ):
        raise HTTPException(status_code=404, detail="Unknown system")
    return system


def _checked_kind(kind: str) -> str:
    """Refuse a kind before touching the database.

    ``common`` is rejected by name rather than lumped in with an unknown kind:
    it IS a vendored schema -- the shared ``$defs`` target the other ten
    reference -- but it is not a document any system files, so a caller naming
    it has made a different mistake and deserves a different message.
    """
    if kind not in DELIVERABLE_KINDS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"not a CR26 deliverable kind: {kind!r} "
                f"(expected one of {list(DELIVERABLE_KINDS)})"
            ),
        )
    return kind


def _checked_document_key(document_key: str | None) -> str | None:
    """Refuse a ``document_key`` too long for the column before it reaches
    Postgres as a raw ``StringDataRightTruncationError`` (a 500), on BOTH
    doors this route pair opens (review round 2, "M2 at the other door" --
    measured live: a 200-character key on ``PUT`` crashed rather than
    refused).

    This is deliberately the ONLY thing this generic route checks about
    ``document_key`` -- it stays format-agnostic (no blank/``/`` rule, no
    assumption about ``"{x}/{y}"`` shape): a future per-instance deliverable
    (e.g. SCN) may key itself differently from the Incident Report, and
    baking the Incident Report's own key format into this shared route would
    make the generic surface serve one deliverable. A length bound is not a
    format rule, though -- it is the column's own physical limit, and every
    caller of this route shares that one limit regardless of key shape, so
    it belongs here even though the format rules do not.

    Bounded against :data:`ccf.models_cr26.DOCUMENT_KEY_MAX_LENGTH`, read
    from the column's own declared type -- not a second hardcoded number,
    which is exactly what produced the crash this function exists to
    prevent: :mod:`ccf.cr26.incident`'s tracking-id check bounds the SAME
    column independently, for the same reason, and the two must read one
    source rather than risk drifting apart.
    """
    if document_key is not None and len(document_key) > DOCUMENT_KEY_MAX_LENGTH:
        raise HTTPException(
            status_code=422,
            detail=(
                f"document_key is too long: {len(document_key)} characters, "
                f"and document_key is limited to {DOCUMENT_KEY_MAX_LENGTH}"
            ),
        )
    return document_key


@router.get("/systems/{system_id}/cr26-documents")
async def list_documents(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    """Every deliverable authored for this system, with its verdict, no bodies.

    No ``document_key`` filter: this lists every row regardless of kind or
    key, including every filing of every incident. ``_summary`` carries
    ``document_key`` precisely so those rows are distinguishable here rather
    than all reading ``"incident"`` with no way to tell them apart.
    """
    await _owned_system(session, system_id, principal)
    rows = (
        await session.execute(
            select(Cr26Document)
            .where(Cr26Document.system_id == system_id)
            .order_by(Cr26Document.kind)
        )
    ).scalars().all()
    return [_summary(row) for row in rows]


@router.get("/systems/{system_id}/cr26-documents/{kind}")
async def get_document(
    system_id: int,
    kind: str,
    document_key: str | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """This system's document of ``kind``, at ``document_key`` (default
    ``None``, i.e. the NULL key).

    ``document_key`` is an optional query parameter, not part of the path:
    omitting it is unchanged from before this parameter existed. Filtering
    ``Cr26Document.document_key == document_key`` -- rather than branching on
    whether a key was supplied -- is what ``ccf.cr26.store.put_document``
    already does for exactly this reason: SQLAlchemy compiles
    ``Column == None`` to ``IS NULL``, so a caller who supplies nothing gets
    precisely the pre-0081 ``(system_id, kind)`` row and no other, with no
    separate code path to keep in sync with the unique constraint's own
    NULLS NOT DISTINCT behaviour.

    A per-instance deliverable (the Incident Report) has several rows under
    one ``kind``, distinguished only by this key -- a caller must supply the
    key that :func:`ccf.cr26.incident.seed_incident`'s own response returned
    as ``document_key`` to read a specific filing back.
    """
    await _owned_system(session, system_id, principal)
    _checked_kind(kind)
    document_key = _checked_document_key(document_key)
    row = (
        await session.execute(
            select(Cr26Document).where(
                Cr26Document.system_id == system_id,
                Cr26Document.kind == kind,
                Cr26Document.document_key == document_key,
            )
        )
    ).scalars().first()
    if row is None:
        raise HTTPException(status_code=404, detail=f"no {kind} document for that system")
    return _full(row)


@router.put("/systems/{system_id}/cr26-documents/{kind}")
async def put_cr26_document(
    system_id: int,
    kind: str,
    body: DocumentIn,
    *,
    document_key: str | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*AUTHOR_ROLES)),
) -> dict[str, Any]:
    """Author or replace this system's document of ``kind``, at
    ``document_key`` (default ``None``, i.e. the NULL key).

    An invalid document is stored, not refused -- a draft is necessarily
    incomplete, and the verdict comes back with it so the author can see what
    is still missing.

    ``document_key`` matters most for a per-instance deliverable: without it,
    this route always wrote (and overwrote) the single NULL-keyed row for
    ``kind`` regardless of which specific incident report a caller meant --
    the exact loss keying by ``document_key`` (migration ``0081``) exists to
    prevent, reachable through this route even though
    :func:`ccf.cr26.incident.seed_incident` itself never writes a NULL key.
    A caller authoring a specific incident report's content must supply the
    same key :func:`ccf.cr26.incident.seed_incident` returned as
    ``document_key`` -- e.g. ``?document_key=INC-1%2FInitial``.
    """
    await _owned_system(session, system_id, principal)
    _checked_kind(kind)
    document_key = _checked_document_key(document_key)
    row = await put_document(
        session,
        system_id=system_id,
        kind=kind,
        document=body.document,
        document_key=document_key,
        updated_by=principal.email,
    )
    await session.commit()
    await session.refresh(row)
    return _full(row)


@router.post("/systems/{system_id}/cr26-documents/cpo/seed")
async def seed_cpo_document(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*AUTHOR_ROLES)),
) -> dict[str, Any]:
    """Seed the CPO skeleton, preserving anything already authored.

    The result is **invalid by design**: the platform can supply three of the
    CPO's ten required fields, and inventing the other seven would produce a
    document that validates and is wrong. The returned
    ``validation_errors`` name what a human still owes.
    """
    await _owned_system(session, system_id, principal)
    row = await seed_cpo(session, system_id=system_id)
    await session.commit()
    await session.refresh(row)
    return _full(row)


@router.post("/systems/{system_id}/cr26-documents/sdr/seed")
async def seed_sdr_document(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*AUTHOR_ROLES)),
) -> dict[str, Any]:
    """Render the SDR from the SSP and the KSI tables, preserving narrative.

    Two things the document itself cannot say travel beside it, which is why
    this returns more than ``_full`` alone:

    * ``omitted_ksi_ids`` -- the indicators left out for want of an authored
      ``ksiImplementation``. Emitting them with an empty array would satisfy
      the schema while saying nothing, so the gap would be invisible; this
      list is the deliverable's own to-do list.
    * ``ssp_project_id`` -- which of the system's SSP projects it rendered
      from. ``SSPProject.system_id`` has no unique constraint, so the choice
      is real and an operator should never have to guess it.
    * ``controls_missing_description`` -- controls that reached the document
      with no ``controlImplementationDescription``, because the SSP entry has
      none written or carried only ``[DRAFT]`` scaffolding. Nothing in the
      document says so on its own: the scaffolded ``Planned`` status is
      omitted as untranslatable, so this list is the only signal.
    * ``controls_with_dropped_parts`` -- controls that kept a description but
      lost at least one narrative part to that same filter. Harder to notice
      than the list above, because such a control still carries a description
      and a status and reads complete.
    * ``rendered_control_count`` -- how many controls were rendered at all.
      ``0`` with a non-``None`` ``ssp_project_id`` means an empty SSP project
      won the most-recently-updated selection.
    * ``omitted_requirements`` -- what happened to each authored
      ``fedRampRequirements`` entry that needed attention, not only the ones
      left out of the document. ``fedRampRequirements`` is authored
      narrative, exactly like ``ksiImplementation``, and every one of its
      required fields validates cleanly while saying nothing (``frrID: ""``,
      ``frrImplementation: []``) -- so, like ``omitted_ksi_ids``, this list is
      the only signal such a gap ever produces. Most entries name something
      dropped from the document; some name a repair to an entry that is
      still PRESENT -- a duplicate ``frrID`` kept rather than discarded, or a
      schema-invalid optional field silently emptied.

    Like the CPO seed, the result is **invalid by design**:
    ``certificationPackageOverviewUri`` is required at the root and cannot be
    invented, so the document stays invalid until someone publishes the CPO
    and supplies its URI.
    """
    await _owned_system(session, system_id, principal)
    result = await seed_sdr(session, system_id=system_id)
    await session.commit()
    await session.refresh(result.document)
    return {
        **_full(result.document),
        "omitted_ksi_ids": result.omitted_ksi_ids,
        "ssp_project_id": result.ssp_project_id,
        "controls_missing_description": result.controls_missing_description,
        "controls_with_dropped_parts": result.controls_with_dropped_parts,
        "rendered_control_count": result.rendered_control_count,
        "omitted_requirements": result.omitted_requirements,
    }


class VerPeriod(BaseModel):
    """The reporting window, supplied by the caller.

    Nothing in the platform records what a previous report covered, so
    VER-RPT-PER's "all activity since the previous report" is an obligation on
    the operator. The document records the window it actually covered.

    Both ends are **aware** datetimes, and a naive one is refused with 422
    rather than coerced (spec §6.1.1). ``datetime.astimezone`` treats a naive
    value as *local* time, so a naive pair posted to a server in
    ``America/New_York`` was stored as ``04:00:00Z``/``05:00:00Z`` -- a window
    the operator never asked for, and, because that pair straddles a DST
    boundary, an hour longer than the one they posted.

    ``AwareDatetime`` rather than a validator of our own for a second reason:
    a *mixed* naive/aware pair reached ``_ordered``'s comparison and raised
    ``TypeError``, which pydantic does not wrap into a validation error the
    way it wraps ``ValueError``, so the caller got a 500. Rejecting at the
    field means the comparison only ever sees two aware values.
    """

    model_config = ConfigDict(populate_by_name=True)

    period_from: AwareDatetime = Field(alias="from")
    period_to: AwareDatetime = Field(alias="to")

    @model_validator(mode="after")
    def _ordered(self) -> VerPeriod:
        if self.period_from >= self.period_to:
            raise ValueError("'from' must be strictly before 'to'")
        return self


def _ver_body(result: VerSeedResult) -> dict[str, Any]:
    """``_full`` plus the two fields nothing in the document itself carries.

    Neither ``omitted_poam_ids`` nor ``counts`` has a home inside the
    document's own JSON: they are the only operator-facing signal that a
    vulnerability was left out of it.
    """
    return {
        **_full(result.document),
        "omitted_poam_ids": result.omitted_poam_ids,
        "counts": result.counts,
    }


@router.post("/systems/{system_id}/cr26-documents/vdr/seed")
async def seed_vdr_document(
    system_id: int,
    period: VerPeriod,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*AUTHOR_ROLES)),
) -> dict[str, Any]:
    """Seed this system's Vulnerability Detail Report. Admin only."""
    await _owned_system(session, system_id, principal)
    result = await seed_vdr(
        session,
        system_id=system_id,
        period_from=period.period_from,
        period_to=period.period_to,
    )
    await session.commit()
    await session.refresh(result.document)
    return _ver_body(result)


@router.post("/systems/{system_id}/cr26-documents/avi/seed")
async def seed_avi_document(
    system_id: int,
    period: VerPeriod,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*AUTHOR_ROLES)),
) -> dict[str, Any]:
    """Seed this system's Accepted Vulnerability Inventory. Admin only."""
    await _owned_system(session, system_id, principal)
    result = await seed_avi(
        session,
        system_id=system_id,
        period_from=period.period_from,
        period_to=period.period_to,
    )
    await session.commit()
    await session.refresh(result.document)
    return _ver_body(result)


@router.post("/systems/{system_id}/cr26-documents/ver_history/seed")
async def seed_ver_history_document(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*AUTHOR_ROLES)),
) -> dict[str, Any]:
    """Seed this system's Historical VER Activity. Admin only. No period --
    the schema has none; the document carries ``generatedAt`` instead."""
    await _owned_system(session, system_id, principal)
    result = await seed_ver_history(session, system_id=system_id)
    await session.commit()
    await session.refresh(result.document)
    return _ver_body(result)


class OcrPeriod(BaseModel):
    """The OCR's reporting window -- **dates**, not the VER family's aware
    datetimes. The OCR's ``reportPeriod`` is ``format: date``
    (``$def: reportPeriodDate``), a different ``$def`` from the VER family's
    ``reportPeriodDateTime``, so it takes a different request model rather
    than reusing :class:`VerPeriod`: a plain ``date`` has no naive/aware
    distinction to guard against, and posting a datetime here would only
    produce a value the schema itself rejects downstream.
    """

    model_config = ConfigDict(populate_by_name=True)

    period_from: date = Field(alias="from")
    period_to: date = Field(alias="to")

    @model_validator(mode="after")
    def _ordered(self) -> OcrPeriod:
        if self.period_from >= self.period_to:
            raise ValueError("'from' must be strictly before 'to'")
        return self


@router.post("/systems/{system_id}/cr26-documents/ocr/seed")
async def seed_ocr_document(
    system_id: int,
    period: OcrPeriod,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*AUTHOR_ROLES)),
) -> dict[str, Any]:
    """Seed this system's Ongoing Certification Report. Admin only.

    This deliverable is almost entirely authored (spec §1): of its nine
    required fields, only ``acceptedVulnerabilities`` is platform-derived.
    ``missing_fields``, ``accepted_count``, and ``avi_gap`` travel beside the
    document for the same reason ``omitted_ksi_ids`` and ``omitted_poam_ids``
    do on the SDR and VER routes -- nothing in the document itself says a
    field was left out, what a derived summary counted, or which of the
    counted vulnerabilities the AVI cannot yet report. Deleting any of them
    from this response would leave every seeder-level test green while an
    operator stopped seeing what they still owe.
    """
    await _owned_system(session, system_id, principal)
    result = await seed_ocr(
        session,
        system_id=system_id,
        period_from=period.period_from,
        period_to=period.period_to,
    )
    await session.commit()
    await session.refresh(result.document)
    return {
        **_full(result.document),
        "missing_fields": result.missing_fields,
        "accepted_count": result.accepted_count,
        "avi_gap": result.avi_gap,
    }


class IncidentSeedIn(BaseModel):
    """What only the caller can supply for an Incident Report (spec §3.1):
    which of the three lifecycle reports this is, and the tracking id that
    must stay consistent across all three. Everything else the seeder can
    produce comes from continuity, not from this request body.

    ``report_type`` is a ``Literal`` of the three lifecycle stages rather
    than a plain ``str``: the module-level ``seed_incident`` deliberately
    leaves an unrecognised ``reportType`` for the vendored schema's own
    ``enum`` to refuse (matching this programme's posture everywhere else --
    the schema is the authority on shape), but this request body is a
    narrower, human-facing surface where FastAPI's own 422 is the cheaper
    and earlier place to catch a typo than a round trip through validation.
    """

    model_config = ConfigDict(populate_by_name=True)

    provider_tracking_id: str = Field(alias="providerTrackingId")
    report_type: Literal["Initial", "Ongoing", "Final"] = Field(alias="reportType")


@router.post("/systems/{system_id}/cr26-documents/incident/seed")
async def seed_incident_document(
    system_id: int,
    body: IncidentSeedIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*AUTHOR_ROLES)),
) -> dict[str, Any]:
    """Seed or amend one report of one incident. Admin only.

    Unlike every other CR26 seed route, this one can have more than one row
    per system under the same ``kind`` -- ``document_key`` is
    ``"{providerTrackingId}/{reportType}"`` (spec §1.1), so filing an
    Ongoing report never overwrites a filed Initial. A blank tracking id, or
    one containing ``/``, is refused with 422 rather than reaching the
    seeder's ``ValueError`` as a 500 -- an unidentifiable or ambiguously-keyed
    report cannot be filed at all (spec §3.1).

    ``document_key``, ``carried_from``, ``carried_fields``,
    ``missing_required`` and ``missing_advisory`` all travel beside the
    document, for the same reason the OCR route's extra fields do: nothing
    in the document's own JSON says which report this is among an incident's
    three, what continuity supplied on the operator's behalf, or what still
    blocks filing versus what is merely worth knowing. Dropping any of them
    from this response would leave the seeder-level tests green while an
    operator lost the only signal for each of those questions.
    """
    await _owned_system(session, system_id, principal)
    try:
        result = await seed_incident(
            session,
            system_id=system_id,
            provider_tracking_id=body.provider_tracking_id,
            report_type=body.report_type,
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    await session.commit()
    await session.refresh(result.document)
    return {
        **_full(result.document),
        "document_key": result.document_key,
        "carried_from": result.carried_from,
        "carried_fields": result.carried_fields,
        "missing_required": result.missing_required,
        "missing_advisory": result.missing_advisory,
    }
