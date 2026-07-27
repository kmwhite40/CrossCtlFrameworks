"""JSON CRUD API for system-boundary entities (components, inventory items,
information types, interconnections) — Boundary & inventory feature
(Keystone #1), Task 6.

Every handler resolves the target ``System`` through
``require_system_in_scope`` (org-scoping + soft-delete 404), passes
``org_id``/``system_id`` from that resolved row (never from the request body)
into ``ccf.boundary.service``, and validates the request body against a small
set of controlled vocabularies before it ever reaches the DB — this keeps
downstream OSCAL export from ever seeing an invalid ``type``/``status``/
``direction``/``agreement_type``/``asset_type``/impact value.

PATCH/DELETE key the underlying service functions by primary key alone, so
after fetching the target row this module additionally checks
``row.system_id == system_id`` from the URL — otherwise an admin could reach
into another system in the *same* org (a mismatched path) and mutate a row
that isn't part of the system they're scoped to. That check is done directly
here (a plain ``session.get``), not by round-tripping through ``list_*``.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...boundary import service
from ...models import InformationType, Interconnection, InventoryItem, SystemComponent
from ..auth_deps import require_role
from ..deps import get_session
from .systems import require_system_in_scope

router = APIRouter(prefix="/api/systems/{system_id}/boundary", tags=["boundary"])

# --------------------------------------------------------------------------
# Controlled vocabularies (mirrors the DB-level constraints where present;
# enforced here too so a violation 422s before it reaches the DB / OSCAL export).
# --------------------------------------------------------------------------

COMPONENT_TYPES = frozenset(
    {
        "this-system",
        "system",
        "interconnection",
        "software",
        "hardware",
        "service",
        "policy",
        "physical",
        "process-procedure",
        "plan",
        "guidance",
        "standard",
        "validation",
        "network",
    }
)
COMPONENT_STATUSES = frozenset(
    {"operational", "under-development", "under-major-modification", "disposition", "other"}
)
INTERCONNECTION_DIRECTIONS = frozenset({"incoming", "outgoing", "bidirectional"})
INTERCONNECTION_AGREEMENT_TYPES = frozenset({"ISA", "MOU", "MOA", "none"})
INVENTORY_ASSET_TYPES = frozenset(
    {"software", "hardware", "firmware", "virtual", "network", "appliance", "other"}
)
FIPS199_IMPACTS = frozenset({"low", "moderate", "high"})


def _check_choice(value: str | None, allowed: frozenset[str], field: str) -> None:
    if value is not None and value not in allowed:
        raise HTTPException(422, f"{field} must be one of {sorted(allowed)}")


# --------------------------------------------------------------------------
# Request models
# --------------------------------------------------------------------------


class ComponentIn(BaseModel):
    type: str
    title: str
    description: str | None = None
    status: str = "operational"
    purpose: str | None = None
    responsible_role: str | None = None
    props: dict[str, Any] | None = None

    def validated(self) -> dict[str, Any]:
        _check_choice(self.type, COMPONENT_TYPES, "type")
        _check_choice(self.status, COMPONENT_STATUSES, "status")
        return self.model_dump(exclude_none=True)


class ComponentPatch(BaseModel):
    type: str | None = None
    title: str | None = None
    description: str | None = None
    status: str | None = None
    purpose: str | None = None
    responsible_role: str | None = None
    props: dict[str, Any] | None = None

    def validated(self) -> dict[str, Any]:
        _check_choice(self.type, COMPONENT_TYPES, "type")
        _check_choice(self.status, COMPONENT_STATUSES, "status")
        return self.model_dump(exclude_none=True)


class InventoryItemIn(BaseModel):
    asset_id: str
    description: str | None = None
    asset_type: str
    component_id: int | None = None
    vendor_name: str | None = None
    model: str | None = None
    version: str | None = None
    serial_number: str | None = None
    hostname: str | None = None
    ip_address: str | None = None
    virtual: bool = False
    public: bool = False
    baseline_config: str | None = None
    props: dict[str, Any] | None = None

    def validated(self) -> dict[str, Any]:
        _check_choice(self.asset_type, INVENTORY_ASSET_TYPES, "asset_type")
        return self.model_dump(exclude_none=True)


class InventoryItemPatch(BaseModel):
    asset_id: str | None = None
    description: str | None = None
    asset_type: str | None = None
    component_id: int | None = None
    vendor_name: str | None = None
    model: str | None = None
    version: str | None = None
    serial_number: str | None = None
    hostname: str | None = None
    ip_address: str | None = None
    virtual: bool | None = None
    public: bool | None = None
    baseline_config: str | None = None
    props: dict[str, Any] | None = None

    def validated(self) -> dict[str, Any]:
        _check_choice(self.asset_type, INVENTORY_ASSET_TYPES, "asset_type")
        return self.model_dump(exclude_none=True)


class InformationTypeIn(BaseModel):
    title: str
    description: str | None = None
    categorization_system: str | None = None
    nist_800_60_id: str | None = None
    confidentiality_impact: str | None = None
    integrity_impact: str | None = None
    availability_impact: str | None = None
    adjustment_justification: str | None = None
    props: dict[str, Any] | None = None

    def validated(self) -> dict[str, Any]:
        _check_choice(self.confidentiality_impact, FIPS199_IMPACTS, "confidentiality_impact")
        _check_choice(self.integrity_impact, FIPS199_IMPACTS, "integrity_impact")
        _check_choice(self.availability_impact, FIPS199_IMPACTS, "availability_impact")
        return self.model_dump(exclude_none=True)


class InformationTypePatch(BaseModel):
    title: str | None = None
    description: str | None = None
    categorization_system: str | None = None
    nist_800_60_id: str | None = None
    confidentiality_impact: str | None = None
    integrity_impact: str | None = None
    availability_impact: str | None = None
    adjustment_justification: str | None = None
    props: dict[str, Any] | None = None

    def validated(self) -> dict[str, Any]:
        _check_choice(self.confidentiality_impact, FIPS199_IMPACTS, "confidentiality_impact")
        _check_choice(self.integrity_impact, FIPS199_IMPACTS, "integrity_impact")
        _check_choice(self.availability_impact, FIPS199_IMPACTS, "availability_impact")
        return self.model_dump(exclude_none=True)


class InterconnectionIn(BaseModel):
    remote_system_name: str
    remote_org: str | None = None
    direction: str
    connection_type: str | None = None
    data_description: str | None = None
    agreement_type: str
    agreement_ref: str | None = None
    agreement_date: date | None = None
    expires_on: date | None = None
    authorization_status: str | None = None
    props: dict[str, Any] | None = None

    def validated(self) -> dict[str, Any]:
        _check_choice(self.direction, INTERCONNECTION_DIRECTIONS, "direction")
        _check_choice(self.agreement_type, INTERCONNECTION_AGREEMENT_TYPES, "agreement_type")
        return self.model_dump(exclude_none=True)


class InterconnectionPatch(BaseModel):
    remote_system_name: str | None = None
    remote_org: str | None = None
    direction: str | None = None
    connection_type: str | None = None
    data_description: str | None = None
    agreement_type: str | None = None
    agreement_ref: str | None = None
    agreement_date: date | None = None
    expires_on: date | None = None
    authorization_status: str | None = None
    props: dict[str, Any] | None = None

    def validated(self) -> dict[str, Any]:
        _check_choice(self.direction, INTERCONNECTION_DIRECTIONS, "direction")
        _check_choice(self.agreement_type, INTERCONNECTION_AGREEMENT_TYPES, "agreement_type")
        return self.model_dump(exclude_none=True)


def _out(row: Any) -> dict[str, Any]:
    """Serialize an ORM row to a plain dict, skipping SQLAlchemy internals."""
    return {k: v for k, v in vars(row).items() if not k.startswith("_")}


# --------------------------------------------------------------------------
# SystemComponent
# --------------------------------------------------------------------------


@router.get("/components")
async def list_components(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "assessor")),
) -> list[dict[str, Any]]:
    await require_system_in_scope(session, system_id, principal)
    rows = await service.list_components(session, system_id)
    return [_out(r) for r in rows]


@router.post("/components", status_code=201)
async def create_component(
    system_id: int,
    body: ComponentIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "assessor")),
) -> dict[str, Any]:
    sys = await require_system_in_scope(session, system_id, principal)
    row = await service.create_component(
        session, system_id=system_id, org_id=sys.organization_id, data=body.validated()
    )
    await session.commit()
    return _out(row)


@router.patch("/components/{component_id}")
async def update_component(
    system_id: int,
    component_id: int,
    body: ComponentPatch,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "assessor")),
) -> dict[str, Any]:
    await require_system_in_scope(session, system_id, principal)
    existing = await session.get(SystemComponent, component_id)
    if existing is None or existing.system_id != system_id:
        raise HTTPException(404, "component not found")
    row = await service.update_component(
        session, component_id=component_id, data=body.validated()
    )
    if row is None:
        raise HTTPException(404, "component not found")
    await session.commit()
    return _out(row)


@router.delete("/components/{component_id}", status_code=204)
async def delete_component(
    system_id: int,
    component_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "assessor")),
) -> None:
    await require_system_in_scope(session, system_id, principal)
    existing = await session.get(SystemComponent, component_id)
    if existing is None or existing.system_id != system_id:
        raise HTTPException(404, "component not found")
    await service.delete_component(session, component_id=component_id)
    await session.commit()


# --------------------------------------------------------------------------
# InventoryItem
# --------------------------------------------------------------------------


@router.get("/inventory")
async def list_inventory(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "assessor")),
) -> list[dict[str, Any]]:
    await require_system_in_scope(session, system_id, principal)
    rows = await service.list_inventory_items(session, system_id)
    return [_out(r) for r in rows]


@router.post("/inventory", status_code=201)
async def create_inventory(
    system_id: int,
    body: InventoryItemIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "assessor")),
) -> dict[str, Any]:
    sys = await require_system_in_scope(session, system_id, principal)
    row = await service.create_inventory_item(
        session, system_id=system_id, org_id=sys.organization_id, data=body.validated()
    )
    await session.commit()
    return _out(row)


@router.patch("/inventory/{item_id}")
async def update_inventory(
    system_id: int,
    item_id: int,
    body: InventoryItemPatch,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "assessor")),
) -> dict[str, Any]:
    await require_system_in_scope(session, system_id, principal)
    existing = await session.get(InventoryItem, item_id)
    if existing is None or existing.system_id != system_id:
        raise HTTPException(404, "inventory item not found")
    row = await service.update_inventory_item(session, item_id=item_id, data=body.validated())
    if row is None:
        raise HTTPException(404, "inventory item not found")
    await session.commit()
    return _out(row)


@router.delete("/inventory/{item_id}", status_code=204)
async def delete_inventory(
    system_id: int,
    item_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "assessor")),
) -> None:
    await require_system_in_scope(session, system_id, principal)
    existing = await session.get(InventoryItem, item_id)
    if existing is None or existing.system_id != system_id:
        raise HTTPException(404, "inventory item not found")
    await service.delete_inventory_item(session, item_id=item_id)
    await session.commit()


# --------------------------------------------------------------------------
# InformationType
# --------------------------------------------------------------------------


@router.get("/information-types")
async def list_information_types(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "assessor")),
) -> list[dict[str, Any]]:
    await require_system_in_scope(session, system_id, principal)
    rows = await service.list_information_types(session, system_id)
    return [_out(r) for r in rows]


@router.post("/information-types", status_code=201)
async def create_information_type(
    system_id: int,
    body: InformationTypeIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "assessor")),
) -> dict[str, Any]:
    sys = await require_system_in_scope(session, system_id, principal)
    row = await service.create_information_type(
        session, system_id=system_id, org_id=sys.organization_id, data=body.validated()
    )
    await session.commit()
    return _out(row)


@router.patch("/information-types/{info_type_id}")
async def update_information_type(
    system_id: int,
    info_type_id: int,
    body: InformationTypePatch,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "assessor")),
) -> dict[str, Any]:
    await require_system_in_scope(session, system_id, principal)
    existing = await session.get(InformationType, info_type_id)
    if existing is None or existing.system_id != system_id:
        raise HTTPException(404, "information type not found")
    row = await service.update_information_type(
        session, info_type_id=info_type_id, data=body.validated()
    )
    if row is None:
        raise HTTPException(404, "information type not found")
    await session.commit()
    return _out(row)


@router.delete("/information-types/{info_type_id}", status_code=204)
async def delete_information_type(
    system_id: int,
    info_type_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "assessor")),
) -> None:
    await require_system_in_scope(session, system_id, principal)
    existing = await session.get(InformationType, info_type_id)
    if existing is None or existing.system_id != system_id:
        raise HTTPException(404, "information type not found")
    await service.delete_information_type(session, info_type_id=info_type_id)
    await session.commit()


# --------------------------------------------------------------------------
# Interconnection
# --------------------------------------------------------------------------


@router.get("/interconnections")
async def list_interconnections(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "assessor")),
) -> list[dict[str, Any]]:
    await require_system_in_scope(session, system_id, principal)
    rows = await service.list_interconnections(session, system_id)
    return [_out(r) for r in rows]


@router.post("/interconnections", status_code=201)
async def create_interconnection(
    system_id: int,
    body: InterconnectionIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "assessor")),
) -> dict[str, Any]:
    sys = await require_system_in_scope(session, system_id, principal)
    row = await service.create_interconnection(
        session, system_id=system_id, org_id=sys.organization_id, data=body.validated()
    )
    await session.commit()
    return _out(row)


@router.patch("/interconnections/{interconnection_id}")
async def update_interconnection(
    system_id: int,
    interconnection_id: int,
    body: InterconnectionPatch,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "assessor")),
) -> dict[str, Any]:
    await require_system_in_scope(session, system_id, principal)
    existing = await session.get(Interconnection, interconnection_id)
    if existing is None or existing.system_id != system_id:
        raise HTTPException(404, "interconnection not found")
    row = await service.update_interconnection(
        session, interconnection_id=interconnection_id, data=body.validated()
    )
    if row is None:
        raise HTTPException(404, "interconnection not found")
    await session.commit()
    return _out(row)


@router.delete("/interconnections/{interconnection_id}", status_code=204)
async def delete_interconnection(
    system_id: int,
    interconnection_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin", "assessor")),
) -> None:
    await require_system_in_scope(session, system_id, principal)
    existing = await session.get(Interconnection, interconnection_id)
    if existing is None or existing.system_id != system_id:
        raise HTTPException(404, "interconnection not found")
    await service.delete_interconnection(session, interconnection_id=interconnection_id)
    await session.commit()
