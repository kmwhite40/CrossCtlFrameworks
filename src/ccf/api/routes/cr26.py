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
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...cr26.cpo import seed_cpo
from ...cr26.ocr import seed_ocr
from ...cr26.sdr import seed_sdr
from ...cr26.store import DELIVERABLE_KINDS, put_document
from ...cr26.ver import VerSeedResult, seed_avi, seed_vdr, seed_ver_history
from ...models import System
from ...models_cr26 import Cr26Document
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
    """A row without its body, for the list view."""
    return {
        "kind": row.kind,
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


@router.get("/systems/{system_id}/cr26-documents")
async def list_documents(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    """Every deliverable authored for this system, with its verdict, no bodies."""
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
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """The system's NULL-keyed document of ``kind``.

    Explicit ``document_key IS NULL`` rather than a bare ``(system_id, kind)``
    filter: since 0081 that pair is no longer necessarily unique -- a
    per-instance deliverable can have several rows of the same kind,
    distinguished by key. This route is not key-aware (that belongs with
    whichever deliverable needs it) and every deliverable it serves today is
    NULL-keyed, so filtering explicitly for the NULL key is what keeps this
    route's behaviour identical to before 0081 rather than leaving
    ``.first()`` to pick arbitrarily once a keyed row exists.
    """
    await _owned_system(session, system_id, principal)
    _checked_kind(kind)
    row = (
        await session.execute(
            select(Cr26Document).where(
                Cr26Document.system_id == system_id,
                Cr26Document.kind == kind,
                Cr26Document.document_key.is_(None),
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
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*AUTHOR_ROLES)),
) -> dict[str, Any]:
    """Author or replace this system's document of ``kind``.

    An invalid document is stored, not refused -- a draft is necessarily
    incomplete, and the verdict comes back with it so the author can see what
    is still missing.
    """
    await _owned_system(session, system_id, principal)
    _checked_kind(kind)
    row = await put_document(
        session,
        system_id=system_id,
        kind=kind,
        document=body.document,
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
