"""Scan orchestration: generated tests, idempotence, and human edits."""

from __future__ import annotations

import itertools
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from ccf.db import session_scope
from ccf.governance.control_tests import record_result
from ccf.models import POAM, Organization, System, Task
from ccf.models_grc import ControlTest, ControlTestResult
from ccf.posture import scan as scan_mod
from ccf.posture.checks import CheckOutcome, PostureCheck, ResourceFinding
from ccf.posture.scan import effective_verdict, scan_for_system

_SEQ = itertools.count()

CHECK = PostureCheck(
    key="demo.bucket.public",
    title="Buckets block public access",
    provider="demo_provider",
    resource_type="bucket",
    expected="public access blocked",
    control_ids=("AC-3",),
)


def _outcome(*verdicts: str) -> CheckOutcome:
    findings = tuple(
        ResourceFinding(f"res-{i}", "bucket", v, "observed") for i, v in enumerate(verdicts)
    )
    return CheckOutcome.from_findings(CHECK, findings)


class _FakeConnector:
    key = "demo_provider"

    def __init__(self, outcomes: list[CheckOutcome]) -> None:
        self._outcomes = outcomes

    def is_configured(self) -> bool:
        return True

    async def scan(self) -> list[CheckOutcome]:
        return self._outcomes


def _patch(monkeypatch: pytest.MonkeyPatch, outcomes: list[CheckOutcome]) -> None:
    """_connector_for_org is async, so the replacement must be too."""

    async def _fake_connector(*a: object, **k: object) -> _FakeConnector:
        return _FakeConnector(outcomes)

    monkeypatch.setattr(scan_mod, "checks_for", lambda provider: (CHECK,))
    monkeypatch.setattr(scan_mod, "_connector_for_org", _fake_connector)


async def _system(session) -> System:
    org = Organization(name=f"ScanOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"ScanSys-{next(_SEQ)}")
    session.add(sys_)
    await session.flush()
    return sys_


async def test_scan_creates_a_generated_test_and_a_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, [_outcome("pass", "fail", "pass")])
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await scan_for_system(
            session, system_id=sys_.id, connector_key="demo_provider"
        )
        assert out["checks_run"] == 1
        assert out["results"][0]["verdict"] == "fail"

        t = (
            await session.execute(
                select(ControlTest).where(ControlTest.system_id == sys_.id)
            )
        ).scalars().one()
        assert t.source == "generated"
        assert t.check_key == "demo.bucket.public"
        assert t.control_id == "AC-3"

        r = (
            await session.execute(
                select(ControlTestResult).where(ControlTestResult.control_test_id == t.id)
            )
        ).scalars().one()
        assert r.status == "fail"
        assert r.evaluated == 3
        assert r.failing == 1
        assert r.expected == "public access blocked"


async def test_rescanning_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, [_outcome("pass")])
    async with session_scope() as session:
        sys_ = await _system(session)
        await scan_for_system(session, system_id=sys_.id, connector_key="demo_provider")
        await scan_for_system(session, system_id=sys_.id, connector_key="demo_provider")
        tests = (
            await session.execute(
                select(ControlTest).where(ControlTest.system_id == sys_.id)
            )
        ).scalars().all()
        assert len(tests) == 1  # one test
        results = (
            await session.execute(
                select(ControlTestResult).where(
                    ControlTestResult.control_test_id == tests[0].id
                )
            )
        ).scalars().all()
        assert len(results) == 2  # two runs of it -- history is the point


async def test_human_edits_survive_a_rescan(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, [_outcome("pass")])
    async with session_scope() as session:
        sys_ = await _system(session)
        await scan_for_system(session, system_id=sys_.id, connector_key="demo_provider")
        t = (
            await session.execute(
                select(ControlTest).where(ControlTest.system_id == sys_.id)
            )
        ).scalars().one()
        t.name = "Renamed by a human"
        t.frequency = "quarterly"
        t.active = False
        await session.flush()

        await scan_for_system(session, system_id=sys_.id, connector_key="demo_provider")
        await session.refresh(t)
        assert t.name == "Renamed by a human"
        assert t.frequency == "quarterly"
        assert t.active is False


async def test_generated_test_is_written_with_its_connector_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, [_outcome("pass")])
    async with session_scope() as session:
        sys_ = await _system(session)
        await scan_for_system(session, system_id=sys_.id, connector_key="demo_provider")
        t = (
            await session.execute(
                select(ControlTest).where(ControlTest.system_id == sys_.id)
            )
        ).scalars().one()
        assert t.connector_type == "demo_provider"


async def test_generated_test_with_a_frequency_is_not_picked_up_by_run_due(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A human setting a frequency on a generated test (a supported edit --
    see test_human_edits_survive_a_rescan) must not hand it to the scheduler.
    Posture-scan-generated tests are only evaluated by an explicit scan;
    run_due picking one up would evaluate it via the generic
    connector-freshness heuristic, which has nothing to say about a posture
    check and would bury the real posture verdict under an irrelevant warn.
    """
    from ccf.governance.control_tests import run_due  # noqa: PLC0415

    _patch(monkeypatch, [_outcome("pass")])
    async with session_scope() as session:
        sys_ = await _system(session)
        await scan_for_system(session, system_id=sys_.id, connector_key="demo_provider")
        t = (
            await session.execute(
                select(ControlTest).where(ControlTest.system_id == sys_.id)
            )
        ).scalars().one()
        t.frequency = "quarterly"
        t.last_status = "pass"
        t.last_tested_at = datetime.now(UTC) - timedelta(days=200)  # long overdue
        await session.flush()

        counts = await run_due(session, today=datetime.now(UTC).date())
        assert counts["evaluated"] == 0

        await session.refresh(t)
        assert t.last_status == "pass"  # untouched by the scheduler


async def test_scan_skips_an_inactive_generated_test(monkeypatch: pytest.MonkeyPatch) -> None:
    """A deactivated generated test (active=False, a supported human edit --
    see test_human_edits_survive_a_rescan) must not still be scanned: no new
    result, no alert, no POA&M through a test the human turned off.
    """
    _patch(monkeypatch, [_outcome("pass")])
    async with session_scope() as session:
        sys_ = await _system(session)
        await scan_for_system(session, system_id=sys_.id, connector_key="demo_provider")
        t = (
            await session.execute(
                select(ControlTest).where(ControlTest.system_id == sys_.id)
            )
        ).scalars().one()
        t.active = False
        await session.flush()
        test_id = t.id

    # Re-scan with an outcome that would otherwise alert and open a POA&M.
    _patch(monkeypatch, [_outcome("fail")])
    async with session_scope() as session:
        out = await scan_for_system(
            session, system_id=sys_.id, connector_key="demo_provider"
        )
        assert out["checks_run"] == 0

        results = (
            await session.execute(
                select(ControlTestResult).where(ControlTestResult.control_test_id == test_id)
            )
        ).scalars().all()
        assert len(results) == 1  # only the original pass; nothing new recorded

        t = await session.get(ControlTest, test_id)
        assert t.last_status == "pass"  # untouched by the skipped scan

        task = (
            await session.execute(
                select(Task).where(Task.dedupe_key == f"ctltest-fix:{test_id}")
            )
        ).scalar_one_or_none()
        assert task is None

        poam = (
            await session.execute(
                select(POAM).where(POAM.source_ref == f"control_test:{test_id}")
            )
        ).scalar_one_or_none()
        assert poam is None


async def test_empty_fleet_is_not_applicable(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, [_outcome()])
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await scan_for_system(
            session, system_id=sys_.id, connector_key="demo_provider"
        )
        assert out["results"][0]["verdict"] == "not_applicable"


async def test_unconfigured_connector_scans_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _no_connector(*a: object, **k: object) -> None:
        return None

    monkeypatch.setattr(scan_mod, "checks_for", lambda provider: (CHECK,))
    monkeypatch.setattr(scan_mod, "_connector_for_org", _no_connector)
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await scan_for_system(
            session, system_id=sys_.id, connector_key="demo_provider"
        )
        assert out["checks_run"] == 0
        assert out["reason"] == "connector not configured for this organization"


async def test_unknown_check_is_skipped_not_guessed_at(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A connector returning an outcome this build has no definition for has
    no control to attribute it to."""
    ghost = PostureCheck(
        key="demo.ghost",
        title="Ghost",
        provider="demo_provider",
        resource_type="bucket",
        expected="x",
        control_ids=("AC-3",),
    )
    _patch(monkeypatch, [CheckOutcome.from_findings(ghost, ())])
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await scan_for_system(
            session, system_id=sys_.id, connector_key="demo_provider"
        )
        assert out["checks_run"] == 0


async def test_unknown_system_raises() -> None:
    async with session_scope() as session:
        with pytest.raises(ValueError, match="unknown system"):
            await scan_for_system(
                session, system_id=999999, connector_key="demo_provider"
            )


async def test_effective_verdict_prefers_a_fresh_deterministic_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, [_outcome("fail")])
    async with session_scope() as session:
        sys_ = await _system(session)
        await scan_for_system(session, system_id=sys_.id, connector_key="demo_provider")
        out = await effective_verdict(session, system_id=sys_.id, control_id="AC-3")
        assert out["source"] == "deterministic"
        assert out["verdict"] == "fail"
        assert out["failing"] == 1


async def test_effective_verdict_is_none_when_nothing_observed() -> None:
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await effective_verdict(session, system_id=sys_.id, control_id="AC-3")
        assert out["source"] is None
        assert out["verdict"] is None


async def test_effective_verdict_treats_a_stale_result_as_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, [_outcome("fail")])
    async with session_scope() as session:
        sys_ = await _system(session)
        await scan_for_system(session, system_id=sys_.id, connector_key="demo_provider")
        r = (
            await session.execute(
                select(ControlTestResult).order_by(ControlTestResult.id.desc()).limit(1)
            )
        ).scalars().one()
        r.run_at = datetime.now(UTC) - timedelta(days=scan_mod.STALE_AFTER_DAYS + 5)
        await session.flush()
        out = await effective_verdict(session, system_id=sys_.id, control_id="AC-3")
        assert out["source"] is None


async def test_effective_verdict_ignores_a_manually_run_test() -> None:
    """A human clicking run-test on an authored ControlTest is not a
    deterministic check that read the environment. effective_verdict must not
    report that result as {"source": "deterministic", ...} -- that claim is
    reserved for posture-scan-generated tests.
    """
    async with session_scope() as session:
        sys_ = await _system(session)
        t = ControlTest(
            organization_id=sys_.organization_id,
            system_id=sys_.id,
            control_id="AC-3",
            name="Manually run test",
            method="manual",
            # source defaults to "authored" -- a human-defined test, not a
            # posture-scan-generated one.
        )
        session.add(t)
        await session.flush()
        await record_result(session, t, status="fail", detail="a human ran this")

        out = await effective_verdict(session, system_id=sys_.id, control_id="AC-3")
        assert out["source"] is None
        assert out["verdict"] is None
        assert out["reason"] == "no fresh deterministic result"
