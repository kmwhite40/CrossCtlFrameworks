"""User CRUD — organization-scoped, admin-managed."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...models import User
from ..auth_deps import get_principal, require_role
from ..deps import get_session

router = APIRouter(prefix="/api/users", tags=["users"])

ROLE = r"^(admin|control_owner|assessor|viewer)$"


class UserCreate(BaseModel):
    organization_id: int
    email: EmailStr
    full_name: str | None = None
    role: str = Field("viewer", pattern=ROLE)


class UserUpdate(BaseModel):
    full_name: str | None = None
    role: str | None = Field(None, pattern=ROLE)
    active: bool | None = None


async def _require_user_in_scope(
    session: AsyncSession, uid: int, principal: Principal
) -> User:
    user = (await session.execute(select(User).where(User.id == uid))).scalar_one_or_none()
    if user is None or (
        principal.org_id is not None and user.organization_id != principal.org_id
    ):
        raise HTTPException(404, "user not found")
    return user


@router.get("")
async def list_users(
    session: AsyncSession = Depends(get_session),
    organization_id: int | None = None,
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    stmt = select(User).order_by(User.email)
    org_filter = principal.org_id if principal.org_id is not None else organization_id
    if org_filter is not None:
        stmt = stmt.where(User.organization_id == org_filter)
    rows = (await session.execute(stmt)).scalars().all()
    return [
        {
            "id": u.id,
            "organization_id": u.organization_id,
            "email": u.email,
            "full_name": u.full_name,
            "role": u.role,
            "active": u.active,
        }
        for u in rows
    ]


@router.post("", status_code=201)
async def create_user(
    body: UserCreate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    data = body.model_dump()
    if principal.org_id is not None:
        data["organization_id"] = principal.org_id
    obj = User(**data)
    session.add(obj)
    await session.commit()
    await session.refresh(obj)
    return {"id": obj.id, "email": obj.email, "role": obj.role}


@router.patch("/{uid}")
async def update_user(
    uid: int,
    body: UserUpdate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    obj = await _require_user_in_scope(session, uid, principal)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(obj, k, v)
    await session.commit()
    await session.refresh(obj)
    return {"id": obj.id, "role": obj.role, "active": obj.active}
