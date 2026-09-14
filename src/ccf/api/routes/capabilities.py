"""Capability endpoints — the reusable unit of implementation.

A capability is authored once per organization and mapped to many controls, so
one decision ("Conditional Access enforces MFA") is stated once instead of
restated in every dependent control, per project, per framework.

Scoping follows the rest of the tenant-owned API: ``organization_id`` comes
from the calling principal and is never read from a request body, and the
app-level ``auth_gate_middleware`` supplies the write gate, so routes do not
re-declare one (see ``api/routes/risks.py`` for the same pattern).

Edge collections are replaced with ``PUT`` rather than mutated per item: the
client already holds the whole set, and replace-set is idempotent.
"""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...capability.derive import derive_for_system
from ...capability.service import capabilities_for_control, framework_reach
from ...catalog.canonical import canonicalize
from ...models_capability import (
    Capability,
    CapabilityComponent,
    CapabilityControl,
    CapabilityKsi,
    CapabilityRisk,
)
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api", tags=["capabilities"])

_STATUSES = (
    "not_implemented",
    "planned",
    "partial",
    "implemented",
    "inherited",
    "not_applicable",
)


class CapabilityIn(BaseModel):
    key: str | None = None
    title: str
    statement: str | None = None
    purpose: str | None = None
    responsible_role: str | None = None
    solution: str | None = None
    status: str = "not_implemented"
    notes: str | None = None


class CapabilityPatch(BaseModel):
    title: str | None = None
    statement: str | None = None
    purpose: str | None = None
    responsible_role: str | None = None
    solution: str | None = None
    status: str | None = None
    notes: str | None = None


class ControlEdgesIn(BaseModel):
    control_ids: list[str]


class ComponentEdgesIn(BaseModel):
    component_ids: list[int]


class RiskEdgesIn(BaseModel):
    risk_ids: list[int]


class KsiEdgesIn(BaseModel):
    ksi_identifiers: list[str]


def _out(c: Capability) -> dict[str, Any]:
    return {
        "id": c.id,
        "organization_id": c.organization_id,
        "key": c.key,
        "title": c.title,
        "statement": c.statement,
        "purpose": c.purpose,
        "responsible_role": c.responsible_role,
        "solution": c.solution,
        "status": c.status,
        "notes": c.notes,
        "created_at": c.created_at,
        "updated_at": c.updated_at,
    }


def _slug(title: str) -> str:
    """A stable, readable key from a title."""
    s = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return (s or "capability")[:56]


async def _unique_key(session: AsyncSession, *, org_id: int | None, base: str) -> str:
    """``base``, suffixed until unique within the organization.

    The key is server-generated so callers need not invent one; a supplied key
    is honoured verbatim and collides loudly with 409 rather than being
    silently renamed.
    """
    stmt = select(Capability.key)
    if org_id is not None:
        stmt = stmt.where(Capability.organization_id == org_id)
    taken = set((await session.execute(stmt)).scalars().all())
    if base not in taken:
        return base
    for n in range(2, 1000):
        candidate = f"{base}-{n}"
        if candidate not in taken:
            return candidate
    raise HTTPException(status_code=409, detail="Could not allocate a unique capability key")


async def _get_or_404(
    session: AsyncSession, capability_id: int, principal: Principal
) -> Capability:
    cap = await session.get(Capability, capability_id)
    if cap is None:
        raise HTTPException(status_code=404, detail="Unknown capability")
    if principal.org_id is not None and cap.organization_id != principal.org_id:
        # Indistinguishable from absent: never confirm existence across tenants.
        raise HTTPException(status_code=404, detail="Unknown capability")
    return cap


def _require_status(value: str | None) -> None:
    if value is not None and value not in _STATUSES:
        raise HTTPException(status_code=422, detail=f"status must be one of {_STATUSES}")


@router.get("/capabilities")
async def list_capabilities(
    solution: str | None = None,
    status: str | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    """Capabilities visible to the caller, newest first."""
    stmt = select(Capability).order_by(Capability.id.desc())
    if principal.org_id is not None:
        stmt = stmt.where(Capability.organization_id == principal.org_id)
    if solution:
        stmt = stmt.where(Capability.solution == solution)
    if status:
        stmt = stmt.where(Capability.status == status)
    return [_out(c) for c in (await session.execute(stmt)).scalars().all()]


@router.post("/capabilities", status_code=201)
async def create_capability(
    body: CapabilityIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Create a capability. A key is generated from the title when omitted."""
    _require_status(body.status)
    if body.key:
        stmt = select(Capability).where(Capability.key == body.key)
        if principal.org_id is not None:
            stmt = stmt.where(Capability.organization_id == principal.org_id)
        if (await session.execute(stmt)).scalars().first() is not None:
            raise HTTPException(
                status_code=409, detail=f"capability key already in use: {body.key!r}"
            )
        key = body.key
    else:
        key = await _unique_key(session, org_id=principal.org_id, base=_slug(body.title))

    cap = Capability(
        organization_id=principal.org_id,
        key=key,
        title=body.title,
        statement=body.statement,
        purpose=body.purpose,
        responsible_role=body.responsible_role,
        solution=body.solution,
        status=body.status,
        notes=body.notes,
    )
    session.add(cap)
    await session.flush()
    await session.commit()
    return _out(cap)


@router.get("/capabilities/{capability_id}")
async def get_capability(
    capability_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    return _out(await _get_or_404(session, capability_id, principal))


@router.patch("/capabilities/{capability_id}")
async def update_capability(
    capability_id: int,
    body: CapabilityPatch,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    _require_status(body.status)
    cap = await _get_or_404(session, capability_id, principal)
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(cap, field, value)
    await session.commit()
    # `updated_at` carries an onupdate, so the row is stale after commit;
    # refresh explicitly rather than letting serialization trigger a lazy
    # load outside the async context (MissingGreenlet).
    await session.refresh(cap)
    return _out(cap)


@router.delete("/capabilities/{capability_id}", status_code=204)
async def delete_capability(
    capability_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> None:
    cap = await _get_or_404(session, capability_id, principal)
    await session.delete(cap)  # edges cascade
    await session.commit()


async def _replace_edges(
    session: AsyncSession,
    *,
    model: type[Any],
    capability_id: int,
    org_id: int | None,
    column: str,
    values: list[Any],
) -> list[Any]:
    """Replace one edge collection wholesale; idempotent for the same set."""
    await session.execute(delete(model).where(model.capability_id == capability_id))
    unique: list[Any] = []
    for v in values:
        if v not in unique:
            unique.append(v)
    for v in unique:
        session.add(
            model(organization_id=org_id, capability_id=capability_id, **{column: v})
        )
    await session.flush()
    await session.commit()
    return unique


@router.put("/capabilities/{capability_id}/controls")
async def set_controls(
    capability_id: int,
    body: ControlEdgesIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Replace the control edges, storing the canonical form of each id.

    Canonicalizing on the way in means the database holds one spelling, so the
    zero-padded/canonical difference never has to be reconciled at read time.
    """
    cap = await _get_or_404(session, capability_id, principal)
    canonical: list[str] = []
    for raw in body.control_ids:
        c = canonicalize(raw)
        if c is None:
            raise HTTPException(
                status_code=422, detail=f"not a recognisable control id: {raw!r}"
            )
        canonical.append(c.value)
    stored = await _replace_edges(
        session,
        model=CapabilityControl,
        capability_id=cap.id,
        org_id=cap.organization_id,
        column="control_id",
        values=canonical,
    )
    return {"capability_id": cap.id, "control_ids": stored}


@router.put("/capabilities/{capability_id}/components")
async def set_components(
    capability_id: int,
    body: ComponentEdgesIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    cap = await _get_or_404(session, capability_id, principal)
    stored = await _replace_edges(
        session,
        model=CapabilityComponent,
        capability_id=cap.id,
        org_id=cap.organization_id,
        column="component_id",
        values=body.component_ids,
    )
    return {"capability_id": cap.id, "component_ids": stored}


@router.put("/capabilities/{capability_id}/risks")
async def set_risks(
    capability_id: int,
    body: RiskEdgesIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    cap = await _get_or_404(session, capability_id, principal)
    stored = await _replace_edges(
        session,
        model=CapabilityRisk,
        capability_id=cap.id,
        org_id=cap.organization_id,
        column="risk_id",
        values=body.risk_ids,
    )
    return {"capability_id": cap.id, "risk_ids": stored}


@router.put("/capabilities/{capability_id}/ksis")
async def set_ksis(
    capability_id: int,
    body: KsiEdgesIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    cap = await _get_or_404(session, capability_id, principal)
    stored = await _replace_edges(
        session,
        model=CapabilityKsi,
        capability_id=cap.id,
        org_id=cap.organization_id,
        column="ksi_identifier",
        values=body.ksi_identifiers,
    )
    return {"capability_id": cap.id, "ksi_identifiers": stored}


@router.get("/capabilities/{capability_id}/frameworks")
async def capability_frameworks(
    capability_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Every framework requirement this capability reaches via the crosswalk."""
    cap = await _get_or_404(session, capability_id, principal)
    return {
        "capability_id": cap.id,
        "frameworks": await framework_reach(session, capability_id=cap.id),
    }


@router.get("/controls/{control_id}/capabilities")
async def control_capabilities(
    control_id: str,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    """Which capabilities claim this control, in either spelling of its id."""
    caps = await capabilities_for_control(session, control_id=control_id)
    if principal.org_id is not None:
        caps = [c for c in caps if c.organization_id == principal.org_id]
    return [_out(c) for c in caps]


@router.post("/systems/{system_id}/derive-status")
async def derive_status(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Annotate this system's control implementations from capability coverage.

    Never writes ``status`` and never creates a row — see
    :mod:`ccf.capability.derive`.
    """
    n = await derive_for_system(session, system_id=system_id)
    await session.commit()
    return {"system_id": system_id, "rows_annotated": n}
