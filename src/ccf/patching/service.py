"""Resolve the declared window, measure a system, and run patch campaigns.

The measurement half reads POA&Ms and the organization's
:class:`~ccf.models_patching.RemediationPolicy`, falling back to the FedRAMP
defaults so a deployment that never set a policy is still measured.

The campaign half organizes work into ordered waves. Three things it refuses,
each for a reason worth stating:

* **A campaign with no open flaws.** There is nothing to schedule, and an empty
  campaign someone later "completes" is a false record of work.
* **Overlapping windows on one system.** Two campaigns patching the same assets
  in the same window is how a maintenance window becomes an outage.
* **Completing waves out of order, or twice.** Sequencing is the control -- the
  first wave is a canary -- and a later wave before its canary defeats the
  point.

A wave **records** completion; it does not cause it. Concord has no
endpoint-management provider, so completion carries an evidence reference or
points at an enforcement plan when a deployment supplies one.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..constants import POAM_ACTIVE_STATUSES
from ..logging import get_logger
from ..models import POAM, System
from ..models_enforcement import RemediationPlan
from ..models_patching import PatchCampaign, PatchWave, RemediationPolicy
from .sla import FLAW_SOURCES, RemediationWindow, SlaReport, measure

log = get_logger(__name__)


class PatchingError(ValueError):
    """A refusal. Raised rather than returned so no caller can ignore it."""


async def _audit(
    session: AsyncSession, *, organization_id: int | None, **kw: Any
) -> None:
    """Append a tenant-scoped audit event (see :func:`ccf.api.audit.record_event`).

    ``organization_id`` is required with no default, deliberately: NULL means
    "platform-wide, visible to every tenant" under migration 0044's
    ``tenant_isolation`` policy, so a call site that forgets it would publish
    this event to every organization rather than merely leave it unscoped.
    """
    from ..api.audit import record_event  # noqa: PLC0415 - avoids an import cycle

    await record_event(session, organization_id=organization_id, **kw)
    # record_event flushes its own row; this flushes the caller's pending
    # business objects alongside it, which this module's callers rely on.
    await session.flush()


async def resolve_window(
    session: AsyncSession, org_id: int | None
) -> RemediationWindow:
    """This organization's declared window, or the FedRAMP defaults.

    The fallback is deliberate: measuring against nothing would report every
    flaw as compliant, which is worse than measuring against the numbers an
    assessor would apply anyway.
    """
    # ``.first()``, matching ``get_policy``/``set_policy`` in api/routes/patching.py:
    # ``organization_id`` is nullable and Postgres treats NULLs as distinct under
    # the unique constraint, so two unscoped rows are (barely) possible, and this
    # must degrade the same way that endpoint does rather than 500 on
    # ``scalar_one_or_none()``'s "more than one row" error.
    policy = (
        await session.execute(
            select(RemediationPolicy).where(RemediationPolicy.organization_id == org_id)
        )
    ).scalars().first()
    if policy is None:
        return RemediationWindow()
    return RemediationWindow(
        critical=policy.critical_days,
        high=policy.high_days,
        moderate=policy.moderate_days,
        low=policy.low_days,
    )


async def _flaw_poams(
    session: AsyncSession, *, system_id: int, open_only: bool = False
) -> list[POAM]:
    """Scan-sourced POA&Ms for one system."""
    stmt = select(POAM).where(
        POAM.system_id == system_id, POAM.source.in_(FLAW_SOURCES)
    )
    if open_only:
        stmt = stmt.where(POAM.status.in_(POAM_ACTIVE_STATUSES))
    stmt = stmt.order_by(POAM.id)
    return list((await session.execute(stmt)).scalars().all())


async def measure_system(
    session: AsyncSession, *, system_id: int, today: date | None = None
) -> SlaReport:
    """Flaw-remediation performance for one system against its window."""
    system = await session.get(System, system_id)
    if system is None or system.deleted_at is not None:
        raise PatchingError(f"unknown system: {system_id}")
    window = await resolve_window(session, system.organization_id)
    poams = await _flaw_poams(session, system_id=system_id)
    return measure(poams, window=window, today=today or datetime.now(UTC).date())


def plan_waves(poam_ids: list[int], *, wave_size: int) -> list[list[int]]:
    """Split findings into ordered batches, smallest first.

    The first wave is a **canary of one**: the whole reason for sequencing is
    that a bad patch's blast radius is bounded by the wave it went out in, and
    a first wave the same size as the rest gives up most of that protection.
    The remainder is split evenly by ``wave_size``.
    """
    if wave_size < 1:
        raise PatchingError(f"wave_size must be at least 1, got {wave_size}")
    if not poam_ids:
        return []
    if len(poam_ids) == 1:
        return [list(poam_ids)]
    canary, rest = [poam_ids[0]], poam_ids[1:]
    batches = [rest[i : i + wave_size] for i in range(0, len(rest), wave_size)]
    return [canary, *batches]


async def _overlapping(
    session: AsyncSession, *, system_id: int, start: date, end: date
) -> PatchCampaign | None:
    """An active campaign on this system whose window overlaps [start, end].

    Two ranges overlap when each starts before the other ends -- inclusive on
    both edges, because a campaign ending the day another begins is still two
    sets of patches landing on the same assets that day.
    """
    return (
        await session.execute(
            select(PatchCampaign)
            .where(
                PatchCampaign.system_id == system_id,
                PatchCampaign.status.in_(("planned", "in_progress")),
                and_(
                    PatchCampaign.window_start <= end,
                    PatchCampaign.window_end >= start,
                ),
            )
            .order_by(PatchCampaign.id)
        )
    ).scalars().first()


async def create_campaign(
    session: AsyncSession,
    *,
    system_id: int,
    name: str,
    window_start: date,
    window_end: date,
    actor: str,
    wave_size: int = 5,
) -> PatchCampaign:
    """Build a campaign of ordered waves over the system's open flaws."""
    system = await session.get(System, system_id)
    if system is None or system.deleted_at is not None:
        raise PatchingError(f"unknown system: {system_id}")
    if window_end < window_start:
        raise PatchingError("window_end is before window_start")

    clash = await _overlapping(
        session, system_id=system_id, start=window_start, end=window_end
    )
    if clash is not None:
        raise PatchingError(
            f"campaign {clash.id} ({clash.name!r}) already covers "
            f"{clash.window_start}..{clash.window_end} on this system"
        )

    open_flaws = await _flaw_poams(session, system_id=system_id, open_only=True)
    if not open_flaws:
        # An empty campaign someone later "completes" is a false record of work.
        raise PatchingError("no open scan-sourced findings to remediate on this system")

    campaign = PatchCampaign(
        organization_id=system.organization_id,
        system_id=system_id,
        name=name,
        status="planned",
        window_start=window_start,
        window_end=window_end,
        created_by=actor,
    )
    session.add(campaign)
    await session.flush()

    batches = plan_waves([p.id for p in open_flaws], wave_size=wave_size)
    for index, batch in enumerate(batches, start=1):
        session.add(
            PatchWave(
                campaign_id=campaign.id,
                sequence=index,
                name=f"Wave {index}" + (" (canary)" if index == 1 else ""),
                poam_ids=batch,
                window_start=window_start,
                window_end=window_end,
            )
        )
    await session.flush()
    await _audit(
        session,
        organization_id=campaign.organization_id,
        actor=actor,
        action="create",
        entity_type="patch_campaign",
        entity_id=str(campaign.id),
        diff={
            "event": "planned",
            "system_id": system_id,
            "window": [str(window_start), str(window_end)],
            "findings": len(open_flaws),
            "waves": [len(b) for b in batches],
        },
    )
    return campaign


async def waves_for(session: AsyncSession, campaign_id: int) -> list[PatchWave]:
    return list(
        (
            await session.execute(
                select(PatchWave)
                .where(PatchWave.campaign_id == campaign_id)
                .order_by(PatchWave.sequence)
            )
        )
        .scalars()
        .all()
    )


async def complete_wave(
    session: AsyncSession,
    wave: PatchWave,
    *,
    actor: str,
    evidence_ref: str | None = None,
    remediation_plan_id: int | None = None,
) -> PatchWave:
    """Record that a wave's work was done.

    Refuses a wave already decided, one whose predecessors are still pending
    (sequencing is the control, so completing wave 3 before wave 1 would claim
    the canary protected a batch it never preceded), one on a campaign that is
    already cancelled or completed, one whose cited remediation plan is not an
    applied plan for this same campaign's tenant and system, and one asserted
    with no evidence at all.
    """
    if wave.status != "pending":
        raise PatchingError(f"wave {wave.sequence} is already {wave.status}")

    campaign = await session.get(PatchCampaign, wave.campaign_id)
    if campaign is None:
        raise PatchingError(f"wave {wave.id} has no campaign")
    if campaign.status in ("cancelled", "completed"):
        raise PatchingError(
            f"campaign {campaign.id} is {campaign.status}; its waves can no "
            "longer be completed"
        )

    earlier = [
        w
        for w in await waves_for(session, wave.campaign_id)
        if w.sequence < wave.sequence and w.status == "pending"
    ]
    if earlier:
        raise PatchingError(
            f"wave {earlier[0].sequence} is still pending; complete waves in order"
        )

    # A cited plan must actually have applied, to this campaign's own tenant
    # and system -- otherwise this row would read to an assessor as "applied
    # by enforcement plan N" when the plan never ran, was refused, or belongs
    # to a different organization entirely. FK enforcement alone does not
    # catch this: it bypasses RLS and does not know about ``status``.
    if remediation_plan_id is not None:
        plan = await session.get(RemediationPlan, remediation_plan_id)
        if (
            plan is None
            or plan.organization_id != campaign.organization_id
            or plan.system_id != campaign.system_id
            or plan.status != "applied"
        ):
            raise PatchingError(
                f"remediation plan {remediation_plan_id} is not an applied plan "
                "for this campaign's system"
            )

    # ``evidence_ref`` stays free text (a change ticket, a screenshot
    # reference, an Intune report id -- see models_patching.py) rather than a
    # foreign key into Evidence: Concord has no endpoint-management provider,
    # so what proves a wave ran often lives outside this system entirely, and
    # forcing it through the Evidence table would either reject legitimate
    # proof or require uploading a document for a pointer. But *something*
    # must be supplied -- a blank string is the same as nothing -- or an
    # applied plan; a wave with neither is a claim with no way to check it.
    evidence_ref = (evidence_ref or "").strip() or None
    if evidence_ref is None and remediation_plan_id is None:
        raise PatchingError(
            "completing a wave requires evidence_ref or an applied remediation_plan_id"
        )

    wave.status = "completed"
    wave.completed_at = datetime.now(UTC)
    wave.completed_by = actor
    wave.evidence_ref = evidence_ref
    wave.remediation_plan_id = remediation_plan_id

    waves = await waves_for(session, wave.campaign_id)
    remaining = [w for w in waves if w.status == "pending"]
    skipped = [w for w in waves if w.status == "skipped"]
    # Explicit rather than "not remaining": a campaign is only genuinely
    # finished once every wave has reached a terminal state, and naming
    # ``skipped`` here (even though nothing can set it yet -- the DB
    # constraint permits it) keeps this rollup's vocabulary matching
    # ``WAVE_STATUSES`` instead of an implicit "anything but pending".
    finished = not remaining
    campaign.status = "completed" if finished else "in_progress"
    if finished:
        campaign.completed_at = datetime.now(UTC)
        if skipped:
            log.info(
                "campaign %s completed with %d skipped wave(s)",
                campaign.id,
                len(skipped),
            )
    await session.flush()
    await _audit(
        session,
        organization_id=campaign.organization_id,
        actor=actor,
        action="update",
        entity_type="patch_wave",
        entity_id=str(wave.id),
        diff={
            "event": "completed",
            "campaign_id": wave.campaign_id,
            "sequence": wave.sequence,
            "poams": wave.poam_ids,
            "evidence_ref": evidence_ref,
            "remediation_plan_id": remediation_plan_id,
        },
    )
    return wave
