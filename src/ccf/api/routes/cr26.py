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

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...cr26.cpo import seed_cpo
from ...cr26.store import DELIVERABLE_KINDS, put_document
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
    await _owned_system(session, system_id, principal)
    _checked_kind(kind)
    row = (
        await session.execute(
            select(Cr26Document).where(
                Cr26Document.system_id == system_id, Cr26Document.kind == kind
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
