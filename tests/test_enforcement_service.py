"""The lifecycle: every refusal verified by observing that nothing was written."""

from __future__ import annotations

import itertools

import pytest
from sqlalchemy import select

from ccf.db import session_scope
from ccf.enforcement.service import (
    EnforcementError,
    apply_plan,
    approve_plan,
    create_plan,
    reverse_plan,
)
from ccf.enforcement.types import RemediationStep, StepOutcome
from ccf.governance.control_tests import record_result
from ccf.models import AuditLog, Event, Organization, System
from ccf.models_enforcement import RemediationPlan
from ccf.models_grc import ControlTest
from ccf.posture.types import ResourceFinding

_SEQ = itertools.count()
CHECK = "m365.identity.stale_accounts"


class _Provider:
    """Records every call, so "did not write" is observed rather than assumed."""

    key = "fake_account"
    write_credential_type = "fake_write"
    required_permissions = ("Fake.ReadWrite.All",)
    handled_checks = (CHECK,)

    def __init__(self, *, write_ok: bool = True, fail: set[str] | None = None) -> None:
        self.write_ok = write_ok
        self.fail = fail or set()
        self.applied: list[str] = []
        self.reversed: list[str] = []

    def handles(self, check_key: str) -> bool:
        return check_key == CHECK

    async def is_write_configured(self) -> bool:
        return self.write_ok

    async def plan(self, findings) -> list[RemediationStep]:
        return [
            RemediationStep(
                resource_id=f.resource_id,
                resource_type=f.resource_type,
                action="disable_account",
                description=f"disable {f.resource_id}",
                current_state={"accountEnabled": True},
                target_state={"accountEnabled": False},
            )
            for f in findings
        ]

    async def apply(self, step: RemediationStep) -> StepOutcome:
        if step.resource_id in self.fail:
            return StepOutcome(step.resource_id, "failed", "403 forbidden")
        self.applied.append(step.resource_id)
        return StepOutcome(step.resource_id, "applied", "disabled")

    async def reverse(self, step: RemediationStep) -> StepOutcome:
        self.reversed.append(step.resource_id)
        return StepOutcome(step.resource_id, "applied", "re-enabled")


async def _scanned(session, *, failing: int = 3) -> tuple[System, ControlTest]:
    org = Organization(name=f"EnfSvcOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"EnfSvcSys-{next(_SEQ)}")
    session.add(sys_)
    await session.flush()
    test = ControlTest(
        organization_id=org.id,
        system_id=sys_.id,
        control_id="AC-2",
        name="Stale accounts",
        method="connector",
        check_key=CHECK,
    )
    session.add(test)
    await session.flush()
    findings = [
        ResourceFinding(f"user-{i}@acme.gov", "entra_user", "fail", "stale")
        for i in range(failing)
    ]
    await record_result(
        session, test, status="fail", detail=f"{failing} stale", evaluated=failing,
        failing=failing, resources=findings,
    )
    return sys_, test


async def _plan(session, sys_, provider, **kw) -> RemediationPlan:
    return await create_plan(
        session,
        system_id=sys_.id,
        check_key=CHECK,
        actor=kw.pop("actor", "isso@acme.gov"),
        provider=provider,
        **kw,
    )


# ── plan-time refusals ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_plan_is_created_pending_approval_and_writes_nothing() -> None:
    async with session_scope() as session:
        sys_, _ = await _scanned(session)
        provider = _Provider()
        plan = await _plan(session, sys_, provider)
        assert plan.status == "pending_approval"
        assert plan.resource_count == 3
        assert len(plan.steps) == 3
        assert plan.steps[0]["current_state"] == {"accountEnabled": True}
        assert provider.applied == [], "planning must never write"


@pytest.mark.asyncio
async def test_no_write_credential_refuses_and_never_calls_apply() -> None:
    async with session_scope() as session:
        sys_, _ = await _scanned(session)
        provider = _Provider(write_ok=False)
        plan = await _plan(session, sys_, provider)
        assert plan.status == "refused"
        assert "write credential" in (plan.refusal_reason or "")
        assert provider.applied == []


@pytest.mark.asyncio
async def test_exceeding_the_blast_radius_refuses_at_plan_time() -> None:
    async with session_scope() as session:
        sys_, _ = await _scanned(session, failing=5)
        provider = _Provider()
        plan = await _plan(session, sys_, provider, max_resources=2)
        assert plan.status == "refused"
        assert "exceeds the enforcement limit" in (plan.refusal_reason or "")
        assert provider.applied == []


@pytest.mark.asyncio
async def test_a_check_with_no_provider_is_refused() -> None:
    async with session_scope() as session:
        sys_, _ = await _scanned(session)
        with pytest.raises(EnforcementError, match="no remediation provider"):
            await create_plan(
                session,
                system_id=sys_.id,
                check_key="nothing.handles.this",
                actor="isso@acme.gov",
            )


@pytest.mark.asyncio
async def test_a_check_never_scanned_is_refused() -> None:
    """Remediating from no observation would mean writing on a guess."""
    async with session_scope() as session:
        org = Organization(name=f"EnfSvcOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"Bare-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        provider = _Provider()
        plan = await _plan(session, sys_, provider)
        assert plan.status == "refused"
        assert "no recorded result" in (plan.refusal_reason or "")
        assert provider.applied == []


@pytest.mark.asyncio
async def test_a_refused_plan_cannot_be_approved() -> None:
    async with session_scope() as session:
        sys_, _ = await _scanned(session)
        provider = _Provider(write_ok=False)
        plan = await _plan(session, sys_, provider)
        with pytest.raises(EnforcementError, match="not awaiting approval"):
            await approve_plan(session, plan, approver="ao@acme.gov")


# ── approval ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_requester_cannot_approve_their_own_plan() -> None:
    async with session_scope() as session:
        sys_, _ = await _scanned(session)
        provider = _Provider()
        plan = await _plan(session, sys_, provider, actor="isso@acme.gov")
        with pytest.raises(EnforcementError, match="may not approve"):
            await approve_plan(session, plan, approver="isso@acme.gov")
        assert plan.status == "pending_approval", "a refused approval changes nothing"


@pytest.mark.asyncio
async def test_approval_records_who_and_when() -> None:
    async with session_scope() as session:
        sys_, _ = await _scanned(session)
        plan = await _plan(session, sys_, _Provider())
        await approve_plan(session, plan, approver="ao@acme.gov")
        assert plan.status == "approved"
        assert plan.approved_by == "ao@acme.gov"
        assert plan.approved_at is not None


# ── apply ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_apply_without_approval_is_refused() -> None:
    async with session_scope() as session:
        sys_, _ = await _scanned(session)
        provider = _Provider()
        plan = await _plan(session, sys_, provider)
        with pytest.raises(EnforcementError, match="not approved"):
            await apply_plan(session, plan, actor="ao@acme.gov", provider=provider)
        assert provider.applied == []


@pytest.mark.asyncio
async def test_an_approved_plan_applies_every_step() -> None:
    async with session_scope() as session:
        sys_, _ = await _scanned(session)
        provider = _Provider()
        plan = await _plan(session, sys_, provider)
        await approve_plan(session, plan, approver="ao@acme.gov")
        await apply_plan(session, plan, actor="ao@acme.gov", provider=provider)
        assert plan.status == "applied"
        assert sorted(provider.applied) == [f"user-{i}@acme.gov" for i in range(3)]
        assert len(plan.outcomes) == 3
        assert {o["status"] for o in plan.outcomes} == {"applied"}
        assert plan.applied_at is not None


@pytest.mark.asyncio
async def test_applying_twice_is_refused() -> None:
    async with session_scope() as session:
        sys_, _ = await _scanned(session)
        provider = _Provider()
        plan = await _plan(session, sys_, provider)
        await approve_plan(session, plan, approver="ao@acme.gov")
        await apply_plan(session, plan, actor="ao@acme.gov", provider=provider)
        first = list(provider.applied)
        with pytest.raises(EnforcementError, match="not approved"):
            await apply_plan(session, plan, actor="ao@acme.gov", provider=provider)
        assert provider.applied == first, "the second apply wrote nothing"


@pytest.mark.asyncio
async def test_a_credential_revoked_between_approval_and_apply_refuses() -> None:
    """Approval may be hours old; a stale authorisation must not be honoured."""
    async with session_scope() as session:
        sys_, _ = await _scanned(session)
        provider = _Provider()
        plan = await _plan(session, sys_, provider)
        await approve_plan(session, plan, approver="ao@acme.gov")
        provider.write_ok = False  # revoked in the meantime
        with pytest.raises(EnforcementError, match="write credential"):
            await apply_plan(session, plan, actor="ao@acme.gov", provider=provider)
        assert provider.applied == []
        assert plan.status == "approved", "the plan is not consumed by a refusal"


@pytest.mark.asyncio
async def test_a_blast_radius_tightened_after_approval_refuses_at_apply() -> None:
    async with session_scope() as session:
        sys_, _ = await _scanned(session, failing=3)
        provider = _Provider()
        plan = await _plan(session, sys_, provider)
        await approve_plan(session, plan, approver="ao@acme.gov")
        with pytest.raises(EnforcementError, match="exceeds the enforcement limit"):
            await apply_plan(
                session, plan, actor="ao@acme.gov", provider=provider, max_resources=1
            )
        assert provider.applied == []


@pytest.mark.asyncio
async def test_one_failing_step_does_not_abandon_the_others() -> None:
    async with session_scope() as session:
        sys_, _ = await _scanned(session)
        provider = _Provider(fail={"user-1@acme.gov"})
        plan = await _plan(session, sys_, provider)
        await approve_plan(session, plan, approver="ao@acme.gov")
        await apply_plan(session, plan, actor="ao@acme.gov", provider=provider)
        assert sorted(provider.applied) == ["user-0@acme.gov", "user-2@acme.gov"]
        by_resource = {o["resource_id"]: o["status"] for o in plan.outcomes}
        assert by_resource["user-1@acme.gov"] == "failed"
        assert plan.status == "applied", "partially, and fully described"
        assert len(plan.outcomes) == 3


@pytest.mark.asyncio
async def test_a_plan_where_every_step_fails_is_failed() -> None:
    async with session_scope() as session:
        sys_, _ = await _scanned(session, failing=2)
        provider = _Provider(fail={"user-0@acme.gov", "user-1@acme.gov"})
        plan = await _plan(session, sys_, provider)
        await approve_plan(session, plan, approver="ao@acme.gov")
        await apply_plan(session, plan, actor="ao@acme.gov", provider=provider)
        assert plan.status == "failed"
        assert provider.applied == []


@pytest.mark.asyncio
async def test_a_provider_raising_is_a_failed_outcome_not_a_crash() -> None:
    """One resource's exception must not discard the record of the others."""

    class _Exploding(_Provider):
        async def apply(self, step: RemediationStep) -> StepOutcome:
            if step.resource_id == "user-0@acme.gov":
                raise RuntimeError("boom")
            return await super().apply(step)

    async with session_scope() as session:
        sys_, _ = await _scanned(session, failing=2)
        provider = _Exploding()
        plan = await _plan(session, sys_, provider)
        await approve_plan(session, plan, approver="ao@acme.gov")
        await apply_plan(session, plan, actor="ao@acme.gov", provider=provider)
        by_resource = {o["resource_id"]: o["status"] for o in plan.outcomes}
        assert by_resource["user-0@acme.gov"] == "failed"
        assert by_resource["user-1@acme.gov"] == "applied"


# ── reverse ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_reverse_restores_every_applied_step() -> None:
    async with session_scope() as session:
        sys_, _ = await _scanned(session)
        provider = _Provider()
        plan = await _plan(session, sys_, provider)
        await approve_plan(session, plan, approver="ao@acme.gov")
        await apply_plan(session, plan, actor="ao@acme.gov", provider=provider)
        await reverse_plan(session, plan, actor="ao@acme.gov", provider=provider)
        assert plan.status == "reversed"
        assert sorted(provider.reversed) == [f"user-{i}@acme.gov" for i in range(3)]
        assert plan.reversed_at is not None


@pytest.mark.asyncio
async def test_reverse_skips_a_step_that_never_applied() -> None:
    """Undoing a change that was never made would itself be a change."""
    async with session_scope() as session:
        sys_, _ = await _scanned(session)
        provider = _Provider(fail={"user-1@acme.gov"})
        plan = await _plan(session, sys_, provider)
        await approve_plan(session, plan, approver="ao@acme.gov")
        await apply_plan(session, plan, actor="ao@acme.gov", provider=provider)
        await reverse_plan(session, plan, actor="ao@acme.gov", provider=provider)
        assert "user-1@acme.gov" not in provider.reversed


@pytest.mark.asyncio
async def test_reversing_an_unapplied_plan_is_refused() -> None:
    async with session_scope() as session:
        sys_, _ = await _scanned(session)
        provider = _Provider()
        plan = await _plan(session, sys_, provider)
        with pytest.raises(EnforcementError, match="not applied"):
            await reverse_plan(session, plan, actor="ao@acme.gov", provider=provider)
        assert provider.reversed == []


# ── the record ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_every_transition_is_audited_through_the_hash_chain() -> None:
    async with session_scope() as session:
        sys_, _ = await _scanned(session)
        provider = _Provider()
        plan = await _plan(session, sys_, provider)
        await approve_plan(session, plan, approver="ao@acme.gov")
        await apply_plan(session, plan, actor="ao@acme.gov", provider=provider)
        await reverse_plan(session, plan, actor="ao@acme.gov", provider=provider)
        rows = (
            await session.execute(
                select(AuditLog)
                .where(
                    AuditLog.entity_type == "remediation_plan",
                    AuditLog.entity_id == str(plan.id),
                )
                .order_by(AuditLog.id)
            )
        ).scalars().all()
        assert [r.diff.get("event") for r in rows] == [
            "planned", "approved", "applied", "reversed",
        ]
        assert all(r.row_hash for r in rows), "the chain must cover enforcement"


@pytest.mark.asyncio
async def test_an_applied_plan_emits_an_enforced_event() -> None:
    """The seam an SCN process reads. SCN itself is not built here."""
    async with session_scope() as session:
        sys_, _ = await _scanned(session)
        provider = _Provider()
        plan = await _plan(session, sys_, provider)
        await approve_plan(session, plan, approver="ao@acme.gov")
        await apply_plan(session, plan, actor="ao@acme.gov", provider=provider)
        events = (
            await session.execute(
                select(Event).where(
                    Event.entity_type == "remediation_plan",
                    Event.entity_id == str(plan.id),
                )
            )
        ).scalars().all()
        assert [e.verb for e in events] == ["enforced"]


@pytest.mark.asyncio
async def test_a_refusal_is_audited_too() -> None:
    """A refused plan is a decision someone should be able to find."""
    async with session_scope() as session:
        sys_, _ = await _scanned(session)
        plan = await _plan(session, sys_, _Provider(write_ok=False))
        rows = (
            await session.execute(
                select(AuditLog).where(
                    AuditLog.entity_type == "remediation_plan",
                    AuditLog.entity_id == str(plan.id),
                )
            )
        ).scalars().all()
        assert [r.diff.get("event") for r in rows] == ["refused"]
