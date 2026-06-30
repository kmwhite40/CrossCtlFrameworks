"""FastAPI dependency helpers."""

from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import Principal
from ..db import get_session_factory, set_session_tenant
from .auth_deps import get_principal_optional


async def get_session(
    principal: Principal | None = Depends(get_principal_optional),
) -> AsyncIterator[AsyncSession]:
    """Request-scoped session bound to the caller's org for row-level security.

    The tenant context is a defense-in-depth backstop *beneath* the explicit
    app-layer org scoping; global/unscoped/anonymous principals (and auth-disabled
    mode) leave it cleared, which the RLS policies treat as bypass.
    """
    org_id = principal.org_id if principal is not None else None
    factory = get_session_factory()
    async with factory() as session:
        await set_session_tenant(session, org_id)
        yield session


SessionDep = Depends(get_session)
