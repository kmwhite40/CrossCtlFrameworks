"""The plan lifecycle: plan, approve, apply, reverse -- and every refusal.

Read the refusals first; they are the design. Nothing is written without:

* a **write credential** the operator deliberately created (checked at plan
  time *and again* at apply time **and at reverse time**, because approval may
  be hours old and a revoked credential must not be honoured on a stale
  authorisation -- reverse is a second write path to the tenant and gets
  exactly the same re-checks apply does, not a weaker version of them);
* a **persisted plan**, built from a recorded observation rather than a guess,
  whose steps are stored so the plan that was approved is the plan that is
  applied;
* an **approval from someone other than the requester**, reusing
  :func:`ccf.governance.waivers.can_approve`;
* a resource count inside the **blast radius**, re-checked at apply and at
  reverse;
* **reversal data** captured before the change, without which a step is never
  planned;
* an **approval that has not gone stale**: an ``approved`` plan older than
  :attr:`ccf.config.Settings.enforcement_approval_max_age_hours` refuses at
  apply, because the resource set it was reviewed against may no longer
  reflect the tenant.

Every transition is audited through the tamper-evident chain, and an applied
plan emits an ``enforced`` event -- the seam a significant-change process reads.
SCN itself is deliberately not built here (spec §7).
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..governance import bus
from ..governance.waivers import can_approve
from ..logging import get_logger
from ..models import System
from ..models_enforcement import RemediationPlan
from ..models_grc import ControlTest, ControlTestResult
from ..posture.drift import findings_for_result
from ..posture.latest import latest_result_ids
from . import registry as _registry  # noqa: F401 - registers providers
from .types import (
    RemediationProvider,
    RemediationStep,
    StepOutcome,
    build_steps,
    provider_for,
)

log = get_logger(__name__)


class EnforcementError(ValueError):
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


async def _bind_provider(
    session: AsyncSession, check_key: str, org_id: int | None
) -> RemediationProvider | None:
    """The provider for a check, bound to this organization's WRITE credential.

    A distinct ``connector_type`` from the read credential, so a deployment
    that never created one cannot write: there is no fallback path, by
    construction.
    """
    from ..connectors.credentials import resolve_credential  # noqa: PLC0415

    cls = provider_for(check_key)
    if cls is None:
        return None
    credential = await resolve_credential(session, org_id, cls.write_credential_type)
    return cls(credential=credential)


def _limit(explicit: int | None) -> int:
    return explicit if explicit is not None else get_settings().enforcement_max_resources


async def _latest_findings(
    session: AsyncSession, *, system_id: int, check_key: str
) -> tuple[int | None, list[Any]]:
    """The most recent recorded findings for one check on one system.

    Read from the recorded result, never re-scanned: a plan is built from what
    was observed and reviewed, so what an approver sees is what was measured.
    """
    latest = latest_result_ids()
    row = (
        await session.execute(
            select(ControlTestResult.id)
            .join(ControlTest, ControlTest.id == ControlTestResult.control_test_id)
            .join(latest, latest.c.result_id == ControlTestResult.id)
            .where(ControlTest.system_id == system_id, ControlTest.check_key == check_key)
        )
    ).scalars().first()
    if row is None:
        return None, []
    return row, await findings_for_result(session, row)


async def create_plan(
    session: AsyncSession,
    *,
    system_id: int,
    check_key: str,
    actor: str,
    only: Sequence[str] | None = None,
    max_resources: int | None = None,
    provider: RemediationProvider | None = None,
) -> RemediationPlan:
    """Build and persist a plan, or persist the refusal.

    A refusal is a **stored row**, not an exception: "we considered changing
    this and declined" is a decision someone should be able to find later. The
    exceptions here are for questions that have no plan at all -- an unknown
    system, or a check nothing can remediate.
    """
    system = await session.get(System, system_id)
    if system is None or system.deleted_at is not None:
        raise EnforcementError(f"unknown system: {system_id}")
    chosen = provider or await _bind_provider(session, check_key, system.organization_id)
    if chosen is None:
        raise EnforcementError(f"no remediation provider handles check {check_key!r}")

    plan = RemediationPlan(
        organization_id=system.organization_id,
        system_id=system_id,
        check_key=check_key,
        provider_key=chosen.key,
        requested_by=actor,
        status="draft",
    )
    session.add(plan)
    await session.flush()

    async def refuse(reason: str) -> RemediationPlan:
        plan.status = "refused"
        plan.refusal_reason = reason
        await session.flush()
        await _audit(
            session,
            organization_id=plan.organization_id,
            actor=actor,
            action="create",
            entity_type="remediation_plan",
            entity_id=str(plan.id),
            diff={"event": "refused", "check_key": check_key, "reason": reason},
        )
        log.info("enforcement.refused", plan=plan.id, reason=reason)
        return plan

    # The write credential is checked before anything else is computed: there
    # is no point planning a change this deployment cannot make, and an
    # operator should learn that from the refusal rather than from an apply.
    if not await chosen.is_write_configured():
        return await refuse(
            f"no write credential configured for {chosen.write_credential_type!r}; "
            f"requires {', '.join(chosen.required_permissions) or 'write scopes'}"
        )

    result_id, findings = await _latest_findings(
        session, system_id=system_id, check_key=check_key
    )
    if result_id is None:
        return await refuse(
            f"no recorded result for {check_key!r} on this system; scan before remediating"
        )
    plan.result_id = result_id

    steps, refusal = await build_steps(
        findings, chosen, max_resources=_limit(max_resources), only=only
    )
    if refusal is not None:
        return await refuse(refusal)

    plan.steps = [s.to_dict() for s in steps]
    plan.resource_count = len(steps)
    plan.status = "pending_approval"
    await session.flush()
    await _audit(
        session,
        organization_id=plan.organization_id,
        actor=actor,
        action="create",
        entity_type="remediation_plan",
        entity_id=str(plan.id),
        diff={
            "event": "planned",
            "check_key": check_key,
            "provider": chosen.key,
            "resources": [s.resource_id for s in steps],
        },
    )
    return plan


async def approve_plan(
    session: AsyncSession, plan: RemediationPlan, *, approver: str
) -> RemediationPlan:
    """Approve a plan. The requester may not approve their own."""
    if plan.status != "pending_approval":
        raise EnforcementError(f"plan is not awaiting approval (status={plan.status})")
    if not can_approve(plan.requested_by, approver, is_global=False):
        # is_global=False deliberately: enforcement gets no development
        # exemption. A waiver silences a finding; this changes a production
        # system, and "auth is disabled" is not a reason to skip the second
        # pair of eyes.
        raise EnforcementError("the requester may not approve their own remediation plan")
    plan.status = "approved"
    plan.approved_by = approver
    plan.approved_at = datetime.now(UTC)
    await session.flush()
    await _audit(
        session,
        organization_id=plan.organization_id,
        actor=approver,
        action="update",
        entity_type="remediation_plan",
        entity_id=str(plan.id),
        diff={"event": "approved", "approved_by": approver, "resources": plan.resource_count},
    )
    return plan


async def _run_steps(
    plan: RemediationPlan,
    steps: list[RemediationStep],
    action: Any,
    *,
    verb: str,
) -> list[StepOutcome]:
    """Run one operation over every step, isolated per resource.

    A provider raising on one resource must not discard the record of the
    others: a partial change has to be fully described, or nobody knows what
    state the environment is in.
    """
    outcomes: list[StepOutcome] = []
    now = datetime.now(UTC).isoformat()
    for step in steps:
        try:
            outcome = await action(step)
        except Exception as e:
            log.warning(
                "enforcement.step_failed",
                plan=plan.id,
                resource=step.resource_id,
                verb=verb,
                error=str(e)[:200],
            )
            outcome = StepOutcome(step.resource_id, "failed", str(e)[:300])
        outcomes.append(
            StepOutcome(outcome.resource_id, outcome.status, outcome.detail, at=now)
        )
    return outcomes


async def apply_plan(
    session: AsyncSession,
    plan: RemediationPlan,
    *,
    actor: str,
    max_resources: int | None = None,
    provider: RemediationProvider | None = None,
) -> RemediationPlan:
    """Apply an approved plan, re-checking every precondition first.

    Approval may be hours old. The write credential may have been revoked, the
    blast radius may have been tightened, and the approval itself may have
    gone stale since, so all three are re-checked -- cheap, where honouring a
    stale authorisation is not. A refusal here leaves the plan ``approved``
    rather than consuming it: nothing was done, so nothing changes.

    Locks the plan row (``SELECT ... FOR UPDATE``) before checking its status:
    two concurrent ``POST /apply`` calls both reading ``approved`` would
    otherwise both run every step, with the second UPDATE silently overwriting
    the first's recorded ``outcomes`` -- harmless for an idempotent
    ``accountEnabled=false``, not for a future destructive action. The lock
    forces the second call to wait, then see ``applied`` and refuse cleanly.
    """
    plan = (
        await session.execute(
            select(RemediationPlan).where(RemediationPlan.id == plan.id).with_for_update()
        )
    ).scalar_one()
    if plan.status != "approved":
        raise EnforcementError(f"plan is not approved (status={plan.status})")
    if plan.approved_at is not None:
        max_age_hours = get_settings().enforcement_approval_max_age_hours
        if max_age_hours and datetime.now(UTC) - plan.approved_at > timedelta(
            hours=max_age_hours
        ):
            raise EnforcementError(
                f"approval is more than {max_age_hours}h old; the resource set it "
                "was reviewed against may be stale -- create and approve a new plan"
            )
    chosen = provider or await _bind_provider(
        session, plan.check_key, plan.organization_id
    )
    if chosen is None:
        raise EnforcementError(f"no remediation provider handles check {plan.check_key!r}")
    if not await chosen.is_write_configured():
        raise EnforcementError(
            f"no write credential configured for {chosen.write_credential_type!r}"
        )
    limit = _limit(max_resources)
    if plan.resource_count > limit:
        raise EnforcementError(
            f"{plan.resource_count} resources exceeds the enforcement limit of {limit}"
        )

    steps = [RemediationStep.from_dict(s) for s in (plan.steps or [])]
    outcomes = await _run_steps(plan, steps, chosen.apply, verb="apply")
    plan.outcomes = [o.to_dict() for o in outcomes]
    plan.applied_at = datetime.now(UTC)
    # "applied" means at least one resource changed; if none did, the plan
    # failed -- reporting it as applied would claim a change that never
    # happened.
    plan.status = "applied" if any(o.status == "applied" for o in outcomes) else "failed"
    await session.flush()
    await _audit(
        session,
        organization_id=plan.organization_id,
        actor=actor,
        action="update",
        entity_type="remediation_plan",
        entity_id=str(plan.id),
        diff={
            "event": "applied",
            "status": plan.status,
            "outcomes": [o.to_dict() for o in outcomes],
        },
    )
    # The seam a significant-change process reads: an applied configuration
    # change on a system under authorization is a candidate SCN. SCN proper is
    # its own capability; stubbing it would produce a record nobody sends.
    #
    # ``outcomes`` (and so each changed resource's identifier, e.g. an Entra
    # UPN) goes out to every webhook subscribed to this org's events. That is
    # intentional, not an oversight: an SCN/ticketing integration receiving
    # "a remediation applied" with no record of *which* resources changed
    # would be useless for the review it exists to trigger. Delivery is HMAC
    # -signed and follows this bus's existing org-scoping rule (a hook bound
    # to this organization, or a deployment-registered ``organization_id is
    # None`` hook that receives every org's events -- unchanged here, and the
    # same rule every other entity this bus fans out already follows).
    await bus.emit(
        session,
        verb="enforced",
        entity_type="remediation_plan",
        entity_id=plan.id,
        summary=(
            f"Applied remediation for {plan.check_key} on system {plan.system_id}: "
            f"{sum(1 for o in outcomes if o.status == 'applied')} of {len(outcomes)} resources"
        ),
        org_id=plan.organization_id,
        actor=actor,
        payload={
            "check_key": plan.check_key,
            "provider": plan.provider_key,
            "approved_by": plan.approved_by,
            "outcomes": [o.to_dict() for o in outcomes],
        },
    )
    return plan


async def reverse_plan(
    session: AsyncSession,
    plan: RemediationPlan,
    *,
    actor: str,
    max_resources: int | None = None,
    provider: RemediationProvider | None = None,
) -> RemediationPlan:
    """Undo an applied plan, restoring each step's captured ``current_state``.

    A second write path to the tenant, so it re-checks exactly what
    :func:`apply_plan` re-checks and for the same reason: the apply may have
    happened hours ago, the write credential may since have been revoked, and
    the blast radius may since have been tightened. Without these, revoking a
    write credential after a bad apply would not stop the reverse -- the
    refusal would live only in whichever provider happens to check for a
    missing credential itself (today m365's ``_patch`` does, by returning
    ``skipped``; a future provider that omits that guard would have a
    completely unguarded write path). Locks the plan row for the same
    concurrent-write reason :func:`apply_plan` does.

    Steps whose outcome is ``applied`` *or* ``uncertain`` are reversed --
    ``uncertain`` covers a write whose result is unknown (e.g. a timeout that
    arrived after the far end actually applied the change): the capture is
    exactly the same "did we maybe change this?" case ``applied`` is, and
    replaying it is safe by construction -- reversal restores the step's
    captured *prior* state, which is a no-op if the write never actually
    landed. Only a step recorded ``failed`` (the provider knows it did not
    happen) or ``skipped`` is excluded: undoing a change that was never made
    would itself be a change.
    """
    plan = (
        await session.execute(
            select(RemediationPlan).where(RemediationPlan.id == plan.id).with_for_update()
        )
    ).scalar_one()
    if plan.status != "applied":
        raise EnforcementError(f"plan is not applied (status={plan.status})")
    chosen = provider or await _bind_provider(
        session, plan.check_key, plan.organization_id
    )
    if chosen is None:
        raise EnforcementError(f"no remediation provider handles check {plan.check_key!r}")
    if not await chosen.is_write_configured():
        raise EnforcementError(
            f"no write credential configured for {chosen.write_credential_type!r}"
        )
    limit = _limit(max_resources)
    if plan.resource_count > limit:
        raise EnforcementError(
            f"{plan.resource_count} resources exceeds the enforcement limit of {limit}"
        )

    reversible = {
        o.get("resource_id")
        for o in (plan.outcomes or [])
        if o.get("status") in ("applied", "uncertain")
    }
    steps = [
        RemediationStep.from_dict(s)
        for s in (plan.steps or [])
        if s.get("resource_id") in reversible
    ]
    outcomes = await _run_steps(plan, steps, chosen.reverse, verb="reverse")
    plan.outcomes = [*(plan.outcomes or []), *[o.to_dict() for o in outcomes]]
    plan.reversed_at = datetime.now(UTC)
    plan.status = "reversed"
    await session.flush()
    await _audit(
        session,
        organization_id=plan.organization_id,
        actor=actor,
        action="update",
        entity_type="remediation_plan",
        entity_id=str(plan.id),
        diff={"event": "reversed", "outcomes": [o.to_dict() for o in outcomes]},
    )
    return plan
