"""Assurance graph API — authorization digital twin + impact analysis."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...assurance import builder, impact
from ...auth import Principal
from ...models_assurance import AssuranceNode
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api/assurance", tags=["assurance"])


@router.post("/graph/rebuild")
async def rebuild_graph(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """Rebuild the assurance graph for the caller's org (all orgs for a global principal)."""
    runs = await builder.rebuild(session, org_id=principal.org_id)
    await session.commit()
    return {"rebuilt": runs}


@router.get("/graph/systems/{system_id}")
async def system_graph(
    system_id: int,
    hops: int = 5,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """The connected subgraph around a system — its authorization digital twin."""
    return await impact.subgraph(
        session, org_id=principal.org_id, entity_type="system",
        entity_id=str(system_id), max_hops=hops,
    )


async def _resolve_ksi_entity_id(
    session: AsyncSession, org_id: int | None, ksi_id: str
) -> str | None:
    """KSI nodes are keyed ``<system_id>:<ksi_id>`` — find one for this ksi id."""
    stmt = select(AssuranceNode.entity_id).where(AssuranceNode.entity_type == "ksi")
    if org_id is not None:
        stmt = stmt.where(AssuranceNode.organization_id == org_id)
    for eid in (await session.execute(stmt)).scalars().all():
        if eid.endswith(f":{ksi_id}"):
            return eid
    return None


async def _impact(
    session: AsyncSession, principal: Principal, entity_types: list[str], entity_id: str
) -> dict[str, Any]:
    for et in entity_types:
        result = await impact.impact_for(
            session, org_id=principal.org_id, entity_type=et, entity_id=entity_id
        )
        if result["root"] is not None:
            return result
    raise HTTPException(404, "entity not present in the assurance graph (rebuild the graph?)")


@router.get("/impact/evidence/{evidence_id}")
async def impact_evidence(
    evidence_id: str,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    return await _impact(session, principal, ["evidence_object", "evidence"], evidence_id)


@router.get("/impact/control-tests/{test_id}")
async def impact_control_test(
    test_id: str,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    return await _impact(session, principal, ["control_test"], test_id)


@router.get("/impact/ksis/{ksi_id}")
async def impact_ksi(
    ksi_id: str,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    eid = await _resolve_ksi_entity_id(session, principal.org_id, ksi_id)
    if eid is None:
        raise HTTPException(404, "KSI not present in the assurance graph")
    return await impact.impact_for(
        session, org_id=principal.org_id, entity_type="ksi", entity_id=eid
    )


@router.get("/impact/vendors/{vendor_id}")
async def impact_vendor(
    vendor_id: str,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    return await _impact(session, principal, ["vendor"], vendor_id)


@router.get("/impact/connectors/{connector_id}")
async def impact_connector(
    connector_id: str,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    return await _impact(session, principal, ["connector"], connector_id)
