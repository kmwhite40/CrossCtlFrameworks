"""Scan orchestration: generated tests, idempotence, and human edits."""

from __future__ import annotations

import itertools
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from ccf.db import session_scope
from ccf.models import Organization, System
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
