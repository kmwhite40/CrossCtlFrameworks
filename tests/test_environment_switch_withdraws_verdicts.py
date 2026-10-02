"""Changing a system's environment withdraws the old cloud's verdicts.

A system scanned as AWS and then re-declared as Microsoft 365 kept its AWS
``pass`` rows: retirement removes only rows that never held a verdict, the scan
skips out-of-scope providers so nothing refreshes them, and every posture reader
went on crediting controls from them -- a compliance number made better by
evidence about a cloud the system no longer uses.

Each test first shows the old verdict credits the control, so it can fail.
"""

from __future__ import annotations

import itertools

from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select

from ccf.analytics.framework_posture import system_framework_posture
from ccf.analytics.gaps import compliance_gaps
from ccf.api.auth_deps import get_principal, get_principal_optional
from ccf.api.main import create_app
from ccf.auth import Principal
from ccf.db import session_scope
from ccf.governance.control_tests import record_result
from ccf.models import POAM, Control, Organization, System, SystemProfile
from ccf.models_grc import ControlTest, ControlTestResult
from ccf.posture.evaluations import control_evaluations_for_system
from ccf.posture.latest import OUT_OF_SCOPE_EVIDENCE_REF
from ccf.posture.scope import apply_provider_scope

_SEQ = itertools.count()


async def _aws_system_with(status: str, *, source: str = "generated") -> tuple[int, int, int]:
    """An AWS system whose one AWS check on AC-2 last recorded ``status``."""
    async with session_scope() as session:
        org = Organization(name=f"SwitchOrg{next(_SEQ)}")
        session.add(org)
        await session.flush()
        system = System(organization_id=org.id, name=f"switch-{next(_SEQ)}", baseline="moderate")
        session.add(system)
        # AC-2 in the Moderate baseline, so framework posture has something to
        # credit. High alongside Moderate: FIPS-199 baselines nest, and setting
        # Moderate alone breaks that invariant for the shared catalog (see
        # test_attested_only_is_named._moderate_system).
        existing = (
            await session.execute(select(Control).where(Control.identifier == "AC-2"))
        ).scalars().first()
        if existing is None:
            session.add(
                Control(
                    identifier="AC-2", sequence_control="AC-2", fisma_mod=True, fisma_high=True
                )
            )
        else:
            existing.fisma_mod = True
            existing.fisma_high = True
        await session.flush()
        session.add(
            SystemProfile(system_id=system.id, answers={}, cloud_platform="aws_govcloud")
        )
        test = ControlTest(
            organization_id=org.id,
            system_id=system.id,
            control_id="AC-2",
            control_ids=["AC-2"],
            name="aws.iam.account_management",
            method="connector",
            source=source,
            check_key=f"aws.iam.account_management.{next(_SEQ)}",
            check_source="platform",
            connector_type="aws_govcloud",
        )
        session.add(test)
        await session.flush()
        await record_result(session, test, status=status, detail="observed", evaluated=3)
        return org.id, system.id, test.id


async def _declare(system_id: int, cloud_platform: str) -> dict:
    async with session_scope() as session:
        profile = (
            await session.execute(
                select(SystemProfile).where(SystemProfile.system_id == system_id)
            )
        ).scalars().one()
        profile.cloud_platform = cloud_platform
        await session.flush()
        system = await session.get(System, system_id)
        return await apply_provider_scope(session, system=system, actor="test")


async def _passing(org_id: int, system_id: int) -> set[str]:
    async with session_scope() as session:
        posture = await system_framework_posture(session, org_id=org_id, system_id=system_id)
    return set(posture.get("passing") or [])


async def test_an_old_pass_stops_crediting_the_control() -> None:
    """The defect itself, through the framework posture every page reads."""
    org_id, system_id, _ = await _aws_system_with("pass")
    assert "AC-2" in await _passing(org_id, system_id), "harness cannot fail"

    out = await _declare(system_id, "m365_gcc_high")

    assert "AC-2" not in await _passing(org_id, system_id)
    assert [w["control_id"] for w in out["withdrawn"]] == ["AC-2"]


async def test_the_drilldown_does_not_show_the_old_pass() -> None:
    """``latest_result_ids`` skips zero-resource results; the withdrawal must be
    the exception, or this reader falls back to the AWS pass."""
    org_id, system_id, _ = await _aws_system_with("pass")
    async with session_scope() as session:
        before = await control_evaluations_for_system(session, system_id=system_id, org_id=org_id)
    assert [e["status"] for e in before] == ["pass"], "harness cannot fail"

    await _declare(system_id, "m365_gcc_high")

    async with session_scope() as session:
        after = await control_evaluations_for_system(session, system_id=system_id, org_id=org_id)
    assert [e["status"] for e in after] == ["not_applicable"]


async def test_the_gaps_page_does_not_count_it_as_clean() -> None:
    """``compliance_gaps`` builds its own "latest"; it must see the withdrawal too."""
    org_id, system_id, _ = await _aws_system_with("pass")
    async with session_scope() as session:
        before = await compliance_gaps(session, org_id)
    assert len(before["clean"]) == 1, "harness cannot fail"

    await _declare(system_id, "m365_gcc_high")

    async with session_scope() as session:
        after = await compliance_gaps(session, org_id)
    assert after["clean"] == []


async def test_history_is_kept_and_the_reason_is_recorded() -> None:
    _org_id, system_id, test_id = await _aws_system_with("pass")
    await _declare(system_id, "m365_gcc_high")
    async with session_scope() as session:
        results = (
            await session.execute(
                select(ControlTestResult)
                .where(ControlTestResult.control_test_id == test_id)
                .order_by(ControlTestResult.id)
            )
        ).scalars().all()
    assert [r.status for r in results] == ["pass", "not_applicable"]
    assert results[-1].evidence_ref == OUT_OF_SCOPE_EVIDENCE_REF
    assert "m365_gcc_high" in (results[-1].detail or "")


async def test_withdrawal_is_idempotent() -> None:
    """Every scan applies scope; results must not stack."""
    _org_id, system_id, test_id = await _aws_system_with("pass")
    await _declare(system_id, "m365_gcc_high")
    second = await _declare(system_id, "m365_gcc_high")
    assert second["withdrawn"] == []
    async with session_scope() as session:
        n = (
            await session.execute(
                select(func.count()).where(ControlTestResult.control_test_id == test_id)
            )
        ).scalar_one()
    assert n == 2


async def test_an_open_poam_from_an_earlier_failure_stays_open() -> None:
    """Leaving scope is not a fix. ``record_result`` resolves only on ``pass``."""
    _org_id, system_id, test_id = await _aws_system_with("fail")
    async with session_scope() as session:
        before = (
            await session.execute(
                select(POAM.status).where(POAM.source_ref == f"control_test:{test_id}")
            )
        ).scalars().all()
    assert before, "harness cannot fail: the fail opened no POA&M"

    await _declare(system_id, "m365_gcc_high")

    async with session_scope() as session:
        after = (
            await session.execute(
                select(POAM.status).where(POAM.source_ref == f"control_test:{test_id}")
            )
        ).scalars().all()
    assert after == before


async def test_switching_back_lets_a_new_scan_verdict_count_again() -> None:
    org_id, system_id, test_id = await _aws_system_with("pass")
    await _declare(system_id, "m365_gcc_high")
    back = await _declare(system_id, "aws_govcloud")
    assert back["withdrawn"] == []
    async with session_scope() as session:
        test = await session.get(ControlTest, test_id)
        await record_result(session, test, status="pass", detail="observed", evaluated=3)
    assert "AC-2" in await _passing(org_id, system_id)


async def test_an_in_scope_check_is_not_touched() -> None:
    _org_id, system_id, _ = await _aws_system_with("pass")
    out = await _declare(system_id, "aws_govcloud")
    assert out["withdrawn"] == [] and out["retired"] == []


async def test_a_human_authored_test_is_not_withdrawn() -> None:
    _org_id, system_id, _ = await _aws_system_with("pass", source="authored")
    out = await _declare(system_id, "m365_gcc_high")
    assert out["withdrawn"] == []


async def test_an_empty_collection_page_is_still_not_latest() -> None:
    """The exception is the marker, not ``not_applicable``: a scan whose page came
    back empty also rolls up to ``not_applicable`` with nothing evaluated, and
    that outage must still not displace the last real verdict."""
    org_id, system_id, test_id = await _aws_system_with("pass")
    async with session_scope() as session:
        test = await session.get(ControlTest, test_id)
        await record_result(session, test, status="not_applicable", detail="empty page")
        evals = await control_evaluations_for_system(session, system_id=system_id, org_id=org_id)
    assert [e["status"] for e in evals] == ["pass"]


async def test_the_selector_applies_it_immediately() -> None:
    """Through the route: correct the moment the choice changes, not after a scan."""
    org_id, system_id, _ = await _aws_system_with("pass")
    app = create_app()

    def _principal() -> Principal:
        return Principal(user_id=1, email="owner@customer.gov", org_id=org_id, role="admin")

    app.dependency_overrides[get_principal] = _principal
    app.dependency_overrides[get_principal_optional] = _principal
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", headers={"Origin": "http://test"}
    ) as c:
        r = await c.post(
            f"/systems/{system_id}/environment", data={"cloud_platform": "m365_gcc_high"}
        )
    assert r.status_code == 303, r.text
    assert "AC-2" not in await _passing(org_id, system_id)
