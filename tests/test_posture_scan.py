"""Scan orchestration: generated tests, idempotence, and human edits."""

from __future__ import annotations

import itertools
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from ccf.db import session_scope
from ccf.governance.control_tests import record_result, remediation_guidance
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

    async def scan(self, checks: object = None) -> list[CheckOutcome]:
        # ``checks`` is accepted and ignored: this double returns canned
        # outcomes, and what is asserted here is the recording path, not
        # resolution (which tests/test_posture_resolve.py covers).
        return self._outcomes


def _patch(monkeypatch: pytest.MonkeyPatch, outcomes: list[CheckOutcome]) -> None:
    """_connector_for_org is async, so the replacement must be too."""

    async def _fake_connector(*a: object, **k: object) -> _FakeConnector:
        return _FakeConnector(outcomes)

    async def _fake_resolve(*a: object, **k: object) -> tuple[object, ...]:
        return (SimpleNamespace(check=CHECK, endpoint="/demo", source="platform"),)

    monkeypatch.setattr(scan_mod, "resolve_checks", _fake_resolve)
    monkeypatch.setattr(scan_mod, "_connector_for_org", _fake_connector)


def _patch_resolved(
    monkeypatch: pytest.MonkeyPatch,
    *,
    checks: tuple[PostureCheck, ...],
    outcomes: list[CheckOutcome],
) -> None:
    async def _fake_connector(*a: object, **k: object) -> _FakeConnector:
        return _FakeConnector(outcomes)

    async def _fake_resolve(*a: object, **k: object) -> tuple[object, ...]:
        return tuple(
            SimpleNamespace(check=c, endpoint=f"/{c.key}", source="platform")
            for c in checks
        )

    monkeypatch.setattr(scan_mod, "resolve_checks", _fake_resolve)
    monkeypatch.setattr(scan_mod, "_connector_for_org", _fake_connector)


async def _system(session) -> System:
    org = Organization(name=f"ScanOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"ScanSys-{next(_SEQ)}")
    session.add(sys_)
    await session.flush()
    return sys_


def test_remediation_guidance_uses_known_playbook() -> None:
    test = ControlTest(
        organization_id=1,
        system_id=1,
        control_id="IA-2",
        name="MFA registered",
        check_key="m365.identity.mfa_registered",
        connector_type="msgraph",
        expected="every user has MFA",
    )
    text = remediation_guidance(test, "1 of 2 entra_user(s) failing")
    assert "authentication-methods registration campaign" in text
    assert "Suggested milestones:" in text
    assert "Graph authentication method registration report" in text


def test_remediation_guidance_falls_back_for_unknown_check() -> None:
    test = ControlTest(
        organization_id=1,
        system_id=1,
        control_id="AC-3",
        name="Custom check",
        check_key="custom.check",
        connector_type="custom",
        expected="expected state",
    )
    text = remediation_guidance(test, "observed")
    assert "review the failing resources from the latest custom scan" in text
    assert "Suggested milestones:" not in text


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
        assert t.expected == "public access blocked"

        r = (
            await session.execute(
                select(ControlTestResult).where(ControlTestResult.control_test_id == t.id)
            )
        ).scalars().one()
        assert r.status == "fail"
        assert r.evaluated == 3
        assert r.failing == 1
        assert r.expected == "public access blocked"


async def test_scan_reports_expected_and_skipped_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    other = PostureCheck(
        key="demo.bucket.encrypted",
        title="Buckets are encrypted",
        provider="demo_provider",
        resource_type="bucket",
        expected="server-side encryption enabled",
        control_ids=("SC-28",),
        required_permissions=("storage:ReadEncryption",),
    )
    _patch_resolved(
        monkeypatch,
        checks=(CHECK, other),
        outcomes=[_outcome("pass")],
    )
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await scan_for_system(
            session, system_id=sys_.id, connector_key="demo_provider"
        )

        assert out["checks_expected"] == 2
        assert out["checks_run"] == 1
        assert out["skipped_checks"] == [
            {
                "check_key": "demo.bucket.encrypted",
                "title": "Buckets are encrypted",
                "control_ids": ["SC-28"],
                "resource_type": "bucket",
                "source": "platform",
                "required_permissions": ["storage:ReadEncryption"],
                "reason": "connector returned no outcome for this check",
            }
        ]


async def test_failed_scan_poam_gets_remediation_guidance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, [_outcome("fail")])
    async with session_scope() as session:
        sys_ = await _system(session)
        await scan_for_system(session, system_id=sys_.id, connector_key="demo_provider")
        poam = (
            await session.execute(select(POAM).where(POAM.system_id == sys_.id))
        ).scalars().one()

        assert poam.remediation_plan is not None
        assert "Remediation objective" in poam.remediation_plan
        assert "public access blocked" in poam.remediation_plan
        assert "SSP impact" in poam.remediation_plan


async def test_all_not_applicable_detail_does_not_read_as_a_clean_fleet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unlicensed tenant makes every finding not_applicable. The recorded
    detail must not say "0 of 500 failing" -- that reads as a fully assessed,
    clean 500-user fleet when in truth nothing was actually evaluated."""
    _patch(monkeypatch, [_outcome(*(["not_applicable"] * 500))])
    async with session_scope() as session:
        sys_ = await _system(session)
        await scan_for_system(session, system_id=sys_.id, connector_key="demo_provider")

        t = (
            await session.execute(
                select(ControlTest).where(ControlTest.system_id == sys_.id)
            )
        ).scalars().one()
        r = (
            await session.execute(
                select(ControlTestResult).where(ControlTestResult.control_test_id == t.id)
            )
        ).scalars().one()
        assert r.status == "not_applicable"
        assert r.evaluated == 500  # the raw fetch count is still preserved
        assert r.detail == "no resources in scope"
        assert "500" not in (r.detail or "")


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


# ── CRITICAL 3 (PR #13 review): provenance is persisted on the generated test ─


async def test_a_generated_test_persists_its_check_source(
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
        assert t.check_source == "platform"  # from the fake resolver's source="platform"


# ── CRITICAL 2 (PR #13 review): a pack cannot outrank the platform for the
# same control, even by running more recently ────────────────────────────────


async def test_effective_verdict_prefers_platform_over_a_more_recent_pack_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A tenant installs a Form A rule that reuses a platform evaluator under
    a distinct key with a weakened parameter -- e.g. stale_accounts at 3650
    days instead of the platform's 90. Both checks evidence the same
    control (never a *key* collision, which packs.catalog already refuses).
    The platform's own check fails a stale account; the pack's weakened copy
    passes the same account. Recorded in that order -- platform first, pack
    second, so the pack's 'pass' is both more recent AND is exactly what a
    naive "most recent result wins" precedence would have surfaced for the
    control before this fix -- the platform's 'fail' must still be believed.
    """
    platform_check = PostureCheck(
        key="demo.platform.stale_accounts",
        title="Stale accounts (platform)",
        provider="demo_provider",
        resource_type="entra_user",
        expected="no account idle past 90 days",
        control_ids=("AC-2",),
    )
    pack_check = PostureCheck(
        key="org.stale_accounts.3650d",
        title="Stale accounts (tenant, weakened)",
        provider="demo_provider",
        resource_type="entra_user",
        expected="no account idle past 3650 days",
        control_ids=("AC-2",),
    )
    platform_outcome = CheckOutcome.from_findings(
        platform_check, (ResourceFinding("u1", "entra_user", "fail", "idle 200 days"),)
    )
    pack_outcome = CheckOutcome.from_findings(
        pack_check,
        (ResourceFinding("u1", "entra_user", "pass", "idle 200 days, under 3650"),),
    )

    async def _fake_resolve(*a: object, **k: object) -> tuple[object, ...]:
        return (
            SimpleNamespace(check=platform_check, endpoint="/demo/a", source="platform"),
            SimpleNamespace(
                check=pack_check, endpoint="/demo/b", source="pack:evil-pack"
            ),
        )

    class _TwoCheckConnector:
        key = "demo_provider"

        def is_configured(self) -> bool:
            return True

        async def scan(self, checks: object = None) -> list[CheckOutcome]:
            # Platform result recorded first, pack result second: the pack
            # result is the more recently recorded of the two.
            return [platform_outcome, pack_outcome]

    async def _fake_connector(*a: object, **k: object) -> _TwoCheckConnector:
        return _TwoCheckConnector()

    monkeypatch.setattr(scan_mod, "resolve_checks", _fake_resolve)
    monkeypatch.setattr(scan_mod, "_connector_for_org", _fake_connector)

    async with session_scope() as session:
        sys_ = await _system(session)
        await scan_for_system(session, system_id=sys_.id, connector_key="demo_provider")

        tests = (
            await session.execute(
                select(ControlTest).where(ControlTest.system_id == sys_.id)
            )
        ).scalars().all()
        by_key = {t.check_key: t for t in tests}
        assert by_key["demo.platform.stale_accounts"].check_source == "platform"
        assert by_key["org.stale_accounts.3650d"].check_source == "pack:evil-pack"

        out = await effective_verdict(session, system_id=sys_.id, control_id="AC-2")
        assert out["verdict"] == "fail", "the platform's own check must not be overridden"
        assert out["check_source"] == "platform"


async def test_effective_verdict_falls_back_to_pack_when_no_platform_result_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Precedence is "prefer platform when it exists", not "ignore packs" --
    a control with only a pack-sourced result must still surface it."""
    _patch(monkeypatch, [_outcome("fail")])  # the fake resolver's source is "platform"

    async def _fake_resolve(*a: object, **k: object) -> tuple[object, ...]:
        return (SimpleNamespace(check=CHECK, endpoint="/demo", source="pack:only-pack"),)

    monkeypatch.setattr(scan_mod, "resolve_checks", _fake_resolve)
    async with session_scope() as session:
        sys_ = await _system(session)
        await scan_for_system(session, system_id=sys_.id, connector_key="demo_provider")
        out = await effective_verdict(session, system_id=sys_.id, control_id="AC-3")
        assert out["verdict"] == "fail"
        assert out["check_source"] == "pack:only-pack"


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


async def test_the_scan_response_names_the_controls_and_where_to_read_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A consumer had to decode the response through Concord's own check keys.

    `demo.bucket.public` -- or `m365.identity.mfa_registered` in production --
    means nothing to a caller that does not already know which control it
    evidences, so the result carries the control ids and points at the endpoint
    that expresses them in the framework the system is held to.
    """
    _patch(monkeypatch, [_outcome("pass", "fail")])
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await scan_for_system(
            session, system_id=sys_.id, connector_key="demo_provider"
        )
    assert out["results"][0]["control_ids"] == ["AC-3"]
    assert out["framework_posture_url"] == f"/api/systems/{sys_.id}/framework-posture"


async def test_the_scan_report_adds_up(monkeypatch: pytest.MonkeyPatch) -> None:
    """`checks_expected == checks_run + len(skipped_checks)`, always.

    This is the arithmetic that makes the report trustworthy. Without it the
    three numbers are three separate claims, and a check that silently fell out
    of the loop would leave them disagreeing with nobody noticing -- which is the
    whole reason the scan reports them instead of just `checks_run`.
    """
    ran = PostureCheck(
        key="demo.bucket.public",
        title="Buckets block public access",
        provider="demo_provider",
        resource_type="bucket",
        expected="public access blocked",
        control_ids=("AC-3",),
    )
    silent = PostureCheck(
        key="demo.bucket.encrypted",
        title="Buckets are encrypted",
        provider="demo_provider",
        resource_type="bucket",
        expected="server-side encryption enabled",
        control_ids=("SC-28",),
    )
    _patch_resolved(monkeypatch, checks=(ran, silent), outcomes=[_outcome("pass")])
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await scan_for_system(
            session, system_id=sys_.id, connector_key="demo_provider"
        )
    assert out["checks_expected"] == out["checks_run"] + len(out["skipped_checks"])


async def test_an_inactive_test_is_named_in_the_report_and_still_adds_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A human deactivated the test, so the check ran and recorded nothing.

    That is a third reason a check produced no result, and it has to appear
    beside the other two -- an operator looking at "1 of 2 checks run" needs the
    sentence, not the subtraction.
    """
    _patch(monkeypatch, [_outcome("fail")])
    async with session_scope() as session:
        sys_ = await _system(session)
        await scan_for_system(session, system_id=sys_.id, connector_key="demo_provider")
        test = (
            await session.execute(
                select(ControlTest).where(ControlTest.system_id == sys_.id)
            )
        ).scalars().one()
        test.active = False
        await session.flush()

        out = await scan_for_system(
            session, system_id=sys_.id, connector_key="demo_provider"
        )

    assert out["checks_run"] == 0
    reasons = [s["reason"] for s in out["skipped_checks"]]
    assert reasons == ["generated control test is inactive"]
    assert out["checks_expected"] == out["checks_run"] + len(out["skipped_checks"])


async def test_an_outcome_for_an_unknown_check_is_reported_separately(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A connector returned something this build has no definition for.

    It must be visible -- a log line is not a report -- but it must not land in
    `skipped_checks`, which holds *expected* checks that did not run. Mixing it
    in would break the sum above while looking like extra diligence.
    """
    stranger = PostureCheck(
        key="demo.unknown.thing",
        title="Something this build does not define",
        provider="demo_provider",
        resource_type="bucket",
        expected="?",
        control_ids=("XX-1",),
    )
    findings = (ResourceFinding("res-0", "bucket", "fail", "observed"),)
    _patch_resolved(
        monkeypatch,
        checks=(CHECK,),
        outcomes=[_outcome("pass"), CheckOutcome.from_findings(stranger, findings)],
    )
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await scan_for_system(
            session, system_id=sys_.id, connector_key="demo_provider"
        )

    assert [u["check_key"] for u in out["unexpected_outcomes"]] == ["demo.unknown.thing"]
    assert out["unexpected_outcomes"][0]["reason"]
    assert all(s["check_key"] != "demo.unknown.thing" for s in out["skipped_checks"])
    assert out["checks_expected"] == out["checks_run"] + len(out["skipped_checks"])


async def test_an_unconfigured_connector_answers_the_same_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every key a caller reads is present whether or not a credential exists.

    A response that grows and shrinks its own keys forces the consumer to guess
    which branch it is on.
    """
    async def _no_connector(*a: object, **k: object) -> None:
        return None

    async def _fake_resolve(*a: object, **k: object) -> tuple[object, ...]:
        return (SimpleNamespace(check=CHECK, endpoint="/demo", source="platform"),)

    monkeypatch.setattr(scan_mod, "resolve_checks", _fake_resolve)
    monkeypatch.setattr(scan_mod, "_connector_for_org", _no_connector)
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await scan_for_system(
            session, system_id=sys_.id, connector_key="demo_provider"
        )
    for key in (
        "checks_expected",
        "checks_run",
        "results",
        "skipped_checks",
        "unexpected_outcomes",
        "reason",
    ):
        assert key in out, key
    assert out["checks_expected"] == out["checks_run"] + len(out["skipped_checks"])
    assert out["skipped_checks"][0]["reason"] == (
        "connector not configured for this organization"
    )
