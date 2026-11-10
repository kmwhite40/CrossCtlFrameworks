"""An organization's own Slack/Teams alert channel, over JSON.

``GET``/``PUT``/``DELETE /api/org/notify-channel`` and
``POST /api/org/notify-channel/test``. Every route -- the read too, since a
channel is configuration -- needs ``require_role("admin")``: an admin of the
organization, or a platform admin (unscoped) naming one with
``?organization_id=``. A tenant admin naming another organization is refused
(:func:`resolve_caller_org`).

The URL is a secret: no response carries it (``masked_view``), and the request
field is ``webhook_url`` so the audit middleware redacts it from the recorded
body. It is a plain ``str`` without pydantic constraints on purpose: a
validation error echoes the rejected input, so length and shape are checked by
:func:`ccf.governance.org_channel.refusal`, whose messages never repeat it.

See docs/superpowers/specs/2026-11-09-org-notify-channels-design.md (section 6).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...ai.cipher import CredentialStorageError
from ...auth import Principal
from ...governance import org_channel
from ...models import Organization
from ..auth_deps import require_role, resolve_caller_org
from ..deps import get_session

router = APIRouter(prefix="/api/org/notify-channel", tags=["notify-channel"])


class ChannelIn(BaseModel):
    #: Omitted (or empty) keeps the stored URL and changes only the settings.
    webhook_url: str | None = None
    min_severity: str = "critical"
    enabled: bool = True


async def _org(session: AsyncSession, principal: Principal, requested: int | None) -> int:
    """The organization this request acts on: the caller's, or the one a
    platform admin names. A tenant naming another org is a 403."""
    org_id = resolve_caller_org(principal.org_id, requested)
    if org_id is None:
        raise HTTPException(
            400, "organization_id is required: a platform administrator names the organization"
        )
    exists = (
        await session.execute(
            select(Organization.id).where(
                Organization.id == org_id, Organization.deleted_at.is_(None)
            )
        )
    ).scalar_one_or_none()
    if exists is None:
        raise HTTPException(404, "no such organization")
    return org_id


def _actor(principal: Principal) -> str:
    return principal.email or "system"


@router.get("")
async def get_channel(
    organization_id: int | None = Query(default=None),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    org_id = await _org(session, principal, organization_id)
    return org_channel.masked_view(await org_channel.get(session, org_id))


@router.put("")
async def put_channel(
    body: ChannelIn,
    organization_id: int | None = Query(default=None),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    org_id = await _org(session, principal, organization_id)
    try:
        ch = await org_channel.save(
            session,
            org_id,
            actor=_actor(principal),
            url=body.webhook_url,
            min_severity=body.min_severity,
            enabled=body.enabled,
        )
    except org_channel.ChannelRefusedError as exc:
        raise HTTPException(400, str(exc)) from None
    except CredentialStorageError as exc:
        raise HTTPException(400, str(exc)) from None
    await session.commit()
    return org_channel.masked_view(ch)


@router.delete("")
async def delete_channel(
    organization_id: int | None = Query(default=None),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    org_id = await _org(session, principal, organization_id)
    if not await org_channel.remove(session, org_id, actor=_actor(principal)):
        raise HTTPException(404, "this organization has no alert channel")
    await session.commit()
    return {"configured": False}


@router.post("/test")
async def test_channel(
    organization_id: int | None = Query(default=None),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> dict[str, Any]:
    org_id = await _org(session, principal, organization_id)
    try:
        result = await org_channel.send_stored_test(session, org_id)
    except org_channel.ChannelRefusedError as exc:
        raise HTTPException(400, str(exc)) from None
    if not result.ok:
        raise HTTPException(502, result.error or "the test post failed")
    return {"ok": True, "status_code": result.status_code}
