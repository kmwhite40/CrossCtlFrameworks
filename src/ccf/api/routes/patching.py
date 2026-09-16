"""Flaw-remediation endpoints: the SLA report, the policy, and campaigns.

Two role gates, not one: declaring the remediation window (``POLICY_ROLES``)
is a risk-posture decision, gated like a waiver approval; creating a campaign
or completing a wave (``PATCHER_ROLES``) is an operational assertion that work
was scheduled or done on a production system, and admits ``control_owner`` as
the operator who would actually do it. Reading a report is unrestricted.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...models import System
from ...models_patching import PatchCampaign, PatchWave, RemediationPolicy
from ...patching.service import (
    PatchingError,
    complete_wave,
    create_campaign,
    measure_system,
    resolve_window,
    waves_for,
)
from ...patching.sla import FEDRAMP_TIMEFRAMES
from ..audit import record_event
from ..auth_deps import get_principal, require_role
from ..deps import get_session

router = APIRouter(prefix="/api", tags=["patching"])

#: The roles that may declare the organization's flaw-remediation window.
#:
#: Deliberately ``admin`` only, matching ``api/routes/waivers.py``'s
#: ``APPROVER_ROLES`` and ``api/routes/enforcement.py``'s ``ENFORCER_ROLES``.
#: This is a risk-posture decision, not an operational one: it sets the
#: numbers a flaw is measured against, and a report that reads compliant only
#: because the window was quietly widened (see Important 5) is the same kind
#: of false claim as a risk acceptance nobody with authority signed off on.
#: ``models.py``'s ``user_role`` enum is exactly
#: ``admin | control_owner | assessor | viewer`` -- the previous value here
#: (``"admin", "issm", "isso"``) named two roles the database cannot store,
#: so the effective gate was already ``admin`` only; this makes that explicit.
POLICY_ROLES = ("admin",)

#: The roles that may create a campaign or assert one of its waves was
#: completed.
#:
#: ``admin`` plus ``control_owner``, unlike ``POLICY_ROLES`` above --
#: scheduling and running a patch wave is an operational action on a system,
#: not a risk-posture decision, and ``control_owner`` is precisely the
#: operator who would do it: the party responsible for the system being
#: patched. Excluding it (the earlier ``"admin", "issm", "isso"`` named no
#: role the database can store, so it silently locked control_owner out) left
#: only admins able to run the one workflow this feature exists for.
#: ``assessor`` and ``viewer`` stay out for the same reasons ``waivers.py``
#: and ``enforcement.py`` give: an assessor's independence is compromised by
#: also being able to assert the finding it evaluates was fixed, and a viewer
#: is read-only by definition -- see Important 8, which closed the campaign
#: creation endpoint that used to let a viewer write these rows at all.
PATCHER_ROLES = ("admin", "control_owner")


class PolicyIn(BaseModel):
    critical_days: int = FEDRAMP_TIMEFRAMES["critical"]
    high_days: int = FEDRAMP_TIMEFRAMES["high"]
    moderate_days: int = FEDRAMP_TIMEFRAMES["moderate"]
    low_days: int = FEDRAMP_TIMEFRAMES["low"]
    source: str | None = None
    notes: str | None = None


class CampaignIn(BaseModel):
    name: str
    window_start: date
    window_end: date
    wave_size: int = 5
    notes: str | None = None


class WaveCompleteIn(BaseModel):
    evidence_ref: str | None = None
    remediation_plan_id: int | None = None


def _campaign_out(c: PatchCampaign, waves: list[PatchWave] | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": c.id,
        "system_id": c.system_id,
        "name": c.name,
        "status": c.status,
        "window_start": c.window_start,
        "window_end": c.window_end,
        "created_by": c.created_by,
        "completed_at": c.completed_at,
        "notes": c.notes,
    }
    if waves is not None:
        out["waves"] = [_wave_out(w) for w in waves]
    return out


def _wave_out(w: PatchWave) -> dict[str, Any]:
    return {
        "id": w.id,
        "campaign_id": w.campaign_id,
        "sequence": w.sequence,
        "name": w.name,
        "status": w.status,
        "poam_ids": w.poam_ids,
        "completed_at": w.completed_at,
        "completed_by": w.completed_by,
        "evidence_ref": w.evidence_ref,
        "remediation_plan_id": w.remediation_plan_id,
    }


async def _owned_system(
    session: AsyncSession, system_id: int, principal: Principal
) -> System:
    system = await session.get(System, system_id)
    if (
        system is None
        or system.deleted_at is not None
        or (principal.org_id is not None and system.organization_id != principal.org_id)
    ):
        raise HTTPException(404, "system not found")
    return system


async def _owned_campaign(
    session: AsyncSession, campaign_id: int, principal: Principal
) -> PatchCampaign:
    """404 rather than 403 for another tenant's campaign: confirming an id
    exists is itself a disclosure."""
    c = (
        await session.execute(
            select(PatchCampaign).where(PatchCampaign.id == campaign_id)
        )
    ).scalars().first()
    if c is None or (
        principal.org_id is not None and c.organization_id != principal.org_id
    ):
        raise HTTPException(404, "patch campaign not found")
    return c


@router.get("/systems/{system_id}/flaw-remediation")
async def flaw_remediation(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """How this system's flaw remediation measures against the declared window."""
    await _owned_system(session, system_id, principal)
    report = await measure_system(session, system_id=system_id)
    return report.as_dict()


@router.get("/remediation-policy")
async def get_policy(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    """The organization's declared window, or the defaults it falls back to."""
    row = (
        await session.execute(
            select(RemediationPolicy).where(
                RemediationPolicy.organization_id == principal.org_id
            )
        )
    ).scalars().first()
    window = await resolve_window(session, principal.org_id)
    return {
        "window": window.as_dict(),
        # Stated rather than implied: a caller should know whether it is looking
        # at a decision or at a default.
        "source": row.source if row else "fedramp-default",
        "explicit": row is not None,
        "notes": row.notes if row else None,
    }


@router.put("/remediation-policy")
async def set_policy(
    body: PolicyIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*POLICY_ROLES)),
) -> dict[str, Any]:
    """Declare the organization's flaw-remediation window.

    ``exclude_unset`` rather than a full ``model_dump()``: ``PolicyIn``
    defaults every ``*_days`` field to the FedRAMP value, so a full dump would
    make a partial PUT -- an org sending only ``{"moderate_days": 45}`` to
    adjust one window -- silently reset the three fields it did not mention
    back to the FedRAMP defaults, potentially *widening* them and moving
    already-breached flaws back to within_sla on the next report.
    """
    values = body.model_dump(exclude_unset=True)
    days = {k: v for k, v in values.items() if k.endswith("_days")}
    if any(v < 1 for v in days.values()):
        raise HTTPException(400, "every window must be at least one day")
    row = (
        await session.execute(
            select(RemediationPolicy).where(
                RemediationPolicy.organization_id == principal.org_id
            )
        )
    ).scalars().first()
    if row is None:
        row = RemediationPolicy(organization_id=principal.org_id)
        session.add(row)
    for key, value in values.items():
        setattr(row, key, value)
    await session.flush()
    await record_event(
        session,
        actor=principal.email,
        action="update",
        entity_type="remediation_policy",
        entity_id=str(row.id),
        diff={"event": "declared", **days, "source": values.get("source", row.source)},
    )
    await session.commit()
    await session.refresh(row)
    window = await resolve_window(session, principal.org_id)
    return {"window": window.as_dict(), "source": row.source, "explicit": True}


@router.post("/systems/{system_id}/patch-campaigns", status_code=201)
async def create(
    system_id: int,
    body: CampaignIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*PATCHER_ROLES)),
) -> dict[str, Any]:
    """Plan a campaign of ordered waves over the system's open flaws.

    Role-gated like completing a wave (``PATCHER_ROLES``): an ungated POST let
    a ``viewer`` write campaign and wave rows and, through the overlapping-
    window refusal, block a legitimate maintenance window on any system in
    their org.
    """
    await _owned_system(session, system_id, principal)
    try:
        campaign = await create_campaign(
            session,
            system_id=system_id,
            name=body.name,
            window_start=body.window_start,
            window_end=body.window_end,
            actor=principal.email,
            wave_size=body.wave_size,
        )
    except PatchingError as e:
        raise HTTPException(409, str(e)) from e
    if body.notes:
        campaign.notes = body.notes
    await session.commit()
    await session.refresh(campaign)
    return _campaign_out(campaign, await waves_for(session, campaign.id))


@router.get("/patch-campaigns")
async def list_campaigns(
    system_id: int | None = None,
    status: str | None = None,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[dict[str, Any]]:
    stmt = select(PatchCampaign).order_by(PatchCampaign.id.desc())
    if principal.org_id is not None:
        stmt = stmt.where(PatchCampaign.organization_id == principal.org_id)
    if system_id is not None:
        stmt = stmt.where(PatchCampaign.system_id == system_id)
    if status is not None:
        stmt = stmt.where(PatchCampaign.status == status)
    return [_campaign_out(c) for c in (await session.execute(stmt)).scalars().all()]


@router.get("/patch-campaigns/{campaign_id}")
async def get_campaign(
    campaign_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    c = await _owned_campaign(session, campaign_id, principal)
    return _campaign_out(c, await waves_for(session, c.id))


@router.post("/patch-waves/{wave_id}/complete")
async def complete(
    wave_id: int,
    body: WaveCompleteIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*PATCHER_ROLES)),
) -> dict[str, Any]:
    """Record that a wave's work was done.

    Role-gated: this is an assertion about a production system, and it becomes
    SI-2 evidence. It records completion -- Concord applies no patches.
    """
    wave = (
        await session.execute(select(PatchWave).where(PatchWave.id == wave_id))
    ).scalars().first()
    if wave is None:
        raise HTTPException(404, "patch wave not found")
    # Ownership is checked through the parent campaign, matching the row's own
    # RLS predicate.
    await _owned_campaign(session, wave.campaign_id, principal)
    try:
        await complete_wave(
            session,
            wave,
            actor=principal.email,
            evidence_ref=body.evidence_ref,
            remediation_plan_id=body.remediation_plan_id,
        )
    except PatchingError as e:
        raise HTTPException(409, str(e)) from e
    await session.commit()
    await session.refresh(wave)
    return _wave_out(wave)
