"""Diagram API — Mermaid source for boundary/coverage/landscape diagrams."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...governance import diagrams
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api/diagrams", tags=["diagrams"])


@router.get("/systems/{system_id}/{kind}", response_class=PlainTextResponse)
async def system_diagram(
    system_id: int,
    kind: str,
    session: AsyncSession = Depends(get_session),
) -> str:
    """Mermaid source for a system diagram (authorization-boundary|control-coverage)."""
    fn = diagrams.DIAGRAMS.get(kind)
    if fn is None:
        raise HTTPException(404, f"unknown diagram kind: {kind}")
    try:
        return await fn(session, system_id)
    except ValueError as e:
        raise HTTPException(404, str(e)) from e


@router.get("/system-landscape", response_class=PlainTextResponse)
async def landscape(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> str:
    """Mermaid flowchart of every system and its ATO status."""
    return await diagrams.system_landscape(session, org_id=principal.org_id)


@router.get("/kinds")
async def kinds() -> dict[str, Any]:
    return {"system": list(diagrams.DIAGRAMS.keys()), "org": ["system-landscape"]}
