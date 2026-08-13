"""Boundary & inventory CRUD — thin async service functions per entity.

Each ``create_*`` accepts a structured dict (so a future connector mapper can
call the same functions) and sets ``organization_id``/``system_id`` server-side
from the explicit ``org_id``/``system_id`` parameters — never from ``data`` — so
a client can never reassign a row to another tenant or system. All reads/writes
go through the caller's (tenant-clamped) session; RLS enforces isolation.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import InformationType, Interconnection, InventoryItem, SystemComponent

# Fields a caller must never set directly via ``data`` — ownership/identity and
# server-generated bookkeeping columns.
_PROTECTED_FIELDS = frozenset(
    {"id", "organization_id", "system_id", "oscal_uuid", "created_at", "updated_at"}
)


def _clean(data: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in data.items() if k not in _PROTECTED_FIELDS}


# --------------------------------------------------------------------------
# SystemComponent
# --------------------------------------------------------------------------


async def create_component(
    session: AsyncSession, *, system_id: int, org_id: int, data: dict[str, Any]
) -> SystemComponent:
    row = SystemComponent(organization_id=org_id, system_id=system_id, **_clean(data))
    session.add(row)
    await session.flush()
    return row


async def update_component(
    session: AsyncSession, *, component_id: int, data: dict[str, Any]
) -> SystemComponent | None:
    row = await session.get(SystemComponent, component_id)
    if row is None:
        return None
    for key, value in _clean(data).items():
        setattr(row, key, value)
    await session.flush()
    return row


async def delete_component(session: AsyncSession, *, component_id: int) -> None:
    row = await session.get(SystemComponent, component_id)
    if row is not None:
        await session.delete(row)
        await session.flush()


async def list_components(session: AsyncSession, system_id: int) -> Sequence[SystemComponent]:
    result = await session.execute(
        select(SystemComponent)
        .where(SystemComponent.system_id == system_id)
        .order_by(SystemComponent.id)
    )
    return result.scalars().all()


# --------------------------------------------------------------------------
# InventoryItem
# --------------------------------------------------------------------------


async def create_inventory_item(
    session: AsyncSession, *, system_id: int, org_id: int, data: dict[str, Any]
) -> InventoryItem:
    row = InventoryItem(organization_id=org_id, system_id=system_id, **_clean(data))
    session.add(row)
    await session.flush()
    return row


async def update_inventory_item(
    session: AsyncSession, *, item_id: int, data: dict[str, Any]
) -> InventoryItem | None:
    row = await session.get(InventoryItem, item_id)
    if row is None:
        return None
    for key, value in _clean(data).items():
        setattr(row, key, value)
    await session.flush()
    return row


async def delete_inventory_item(session: AsyncSession, *, item_id: int) -> None:
    row = await session.get(InventoryItem, item_id)
    if row is not None:
        await session.delete(row)
        await session.flush()


async def list_inventory_items(session: AsyncSession, system_id: int) -> Sequence[InventoryItem]:
    result = await session.execute(
        select(InventoryItem)
        .where(InventoryItem.system_id == system_id)
        .order_by(InventoryItem.id)
    )
    return result.scalars().all()


# --------------------------------------------------------------------------
# InformationType
# --------------------------------------------------------------------------


async def create_information_type(
    session: AsyncSession, *, system_id: int, org_id: int, data: dict[str, Any]
) -> InformationType:
    row = InformationType(organization_id=org_id, system_id=system_id, **_clean(data))
    session.add(row)
    await session.flush()
    return row


async def update_information_type(
    session: AsyncSession, *, info_type_id: int, data: dict[str, Any]
) -> InformationType | None:
    row = await session.get(InformationType, info_type_id)
    if row is None:
        return None
    for key, value in _clean(data).items():
        setattr(row, key, value)
    await session.flush()
    return row


async def delete_information_type(session: AsyncSession, *, info_type_id: int) -> None:
    row = await session.get(InformationType, info_type_id)
    if row is not None:
        await session.delete(row)
        await session.flush()


async def list_information_types(
    session: AsyncSession, system_id: int
) -> Sequence[InformationType]:
    result = await session.execute(
        select(InformationType)
        .where(InformationType.system_id == system_id)
        .order_by(InformationType.id)
    )
    return result.scalars().all()


# --------------------------------------------------------------------------
# Interconnection
# --------------------------------------------------------------------------


async def create_interconnection(
    session: AsyncSession, *, system_id: int, org_id: int, data: dict[str, Any]
) -> Interconnection:
    row = Interconnection(organization_id=org_id, system_id=system_id, **_clean(data))
    session.add(row)
    await session.flush()
    return row


async def update_interconnection(
    session: AsyncSession, *, interconnection_id: int, data: dict[str, Any]
) -> Interconnection | None:
    row = await session.get(Interconnection, interconnection_id)
    if row is None:
        return None
    for key, value in _clean(data).items():
        setattr(row, key, value)
    await session.flush()
    return row


async def delete_interconnection(session: AsyncSession, *, interconnection_id: int) -> None:
    row = await session.get(Interconnection, interconnection_id)
    if row is not None:
        await session.delete(row)
        await session.flush()


async def list_interconnections(
    session: AsyncSession, system_id: int
) -> Sequence[Interconnection]:
    result = await session.execute(
        select(Interconnection)
        .where(Interconnection.system_id == system_id)
        .order_by(Interconnection.id)
    )
    return result.scalars().all()
