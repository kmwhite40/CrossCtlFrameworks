"""Telemetry for drift and suppression -- and the cardinality rule."""

from __future__ import annotations

import itertools
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import update

from ccf.api.metrics import (
    POSTURE_CHECK_RESULTS,
    POSTURE_DETAIL_PRUNED,
    POSTURE_DRIFT_TRANSITIONS,
    POSTURE_FAILING_RESOURCES,
    POSTURE_METRICS,
    WAIVER_SUPPRESSIONS,
)
from ccf.db import session_scope
from ccf.governance.control_tests import record_result
from ccf.models import Organization, System
from ccf.models_grc import ControlTest, ControlTestResult
from ccf.models_waivers import Waiver
from ccf.posture import scan as scan_mod
from ccf.posture.retention import prune_resource_detail
from ccf.posture.types import CheckOutcome, PostureCheck, ResourceFinding

_SEQ = itertools.count()

CHECK = PostureCheck(
    key="metrics.demo.check",
    title="Demo",
    provider="demo_provider",
    resource_type="entra_user",
    expected="everything is fine",
    control_ids=("AC-2",),
)


def _f(rid: str, verdict: str, observed: str = "o") -> ResourceFinding:
    return ResourceFinding(
        resource_id=rid, resource_type="entra_user", verdict=verdict, observed=observed
    )


def _counter(metric, **labels) -> float:
    """The current value of one counter/gauge sample, or 0.0 if not yet set."""
    for sample in metric.collect()[0].samples:
        if sample.name.endswith(("_total", "")) and all(
            sample.labels.get(k) == v for k, v in labels.items()
        ):
            if sample.name.endswith("_created"):
                continue
            return float(sample.value)
    return 0.0


# ── the cardinality rule, asserted structurally ──────────────────────────────


def test_no_posture_metric_carries_a_resource_or_check_label() -> None:
    """A fleet of 10,000 users would put 10,000 series into Prometheus from one
    check. Asserted on the definitions so a later addition cannot break it."""
    forbidden = {"resource_id", "resource", "check", "check_key", "test_id", "control_id"}
    for metric in POSTURE_METRICS:
        labels = set(metric._labelnames)
        assert not (labels & forbidden), f"{metric._name} labels {labels & forbidden}"


def test_the_metric_registry_lists_every_posture_metric() -> None:
    """POSTURE_METRICS is what the rule above is enforced against, so a metric
    missing from it is a metric nobody checks."""
    assert set(POSTURE_METRICS) == {
        POSTURE_CHECK_RESULTS,
        POSTURE_DRIFT_TRANSITIONS,
        WAIVER_SUPPRESSIONS,
        POSTURE_DETAIL_PRUNED,
        POSTURE_FAILING_RESOURCES,
    }


# ── scan counters ────────────────────────────────────────────────────────────


class _FakeConnector:
    key = "demo_provider"

    def __init__(self, outcomes: list[CheckOutcome]) -> None:
        self._outcomes = outcomes

    def is_configured(self) -> bool:
        return True

    async def scan(self, checks: object = None) -> list[CheckOutcome]:
        return self._outcomes


def _patch(monkeypatch: pytest.MonkeyPatch, outcomes: list[CheckOutcome]) -> None:
    async def _fake_connector(*a: object, **k: object) -> _FakeConnector:
        return _FakeConnector(outcomes)

    async def _fake_resolve(*a: object, **k: object) -> tuple[object, ...]:
        return (SimpleNamespace(check=CHECK, endpoint="/demo", source="platform"),)

    monkeypatch.setattr(scan_mod, "resolve_checks", _fake_resolve)
    monkeypatch.setattr(scan_mod, "_connector_for_org", _fake_connector)


async def _system(session) -> System:
    org = Organization(name=f"MetricsOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"MetricsSys-{next(_SEQ)}")
    session.add(sys_)
    await session.flush()
    return sys_


def _outcome(*verdicts: str) -> CheckOutcome:
    findings = tuple(_f(f"res-{i}", v) for i, v in enumerate(verdicts))
    return CheckOutcome.from_findings(CHECK, findings)


@pytest.mark.asyncio
async def test_a_scan_counts_one_result_per_check_by_verdict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = _counter(POSTURE_CHECK_RESULTS, verdict="fail")
    _patch(monkeypatch, [_outcome("fail", "pass")])
    async with session_scope() as session:
        sys_ = await _system(session)
        await scan_mod.scan_for_system(
            session, system_id=sys_.id, connector_key="demo_provider"
        )
    assert _counter(POSTURE_CHECK_RESULTS, verdict="fail") == before + 1


@pytest.mark.asyncio
async def test_a_first_scan_counts_no_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    """There is no baseline, so there is nothing to count."""
    before = _counter(POSTURE_DRIFT_TRANSITIONS, kind="appeared")
    _patch(monkeypatch, [_outcome("fail")])
    async with session_scope() as session:
        sys_ = await _system(session)
        await scan_mod.scan_for_system(
            session, system_id=sys_.id, connector_key="demo_provider"
        )
    assert _counter(POSTURE_DRIFT_TRANSITIONS, kind="appeared") == before


@pytest.mark.asyncio
async def test_a_second_scan_counts_drift_transitions_by_kind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = _counter(POSTURE_DRIFT_TRANSITIONS, kind="regressed")
    async with session_scope() as session:
        sys_ = await _system(session)
        _patch(monkeypatch, [_outcome("pass")])
        await scan_mod.scan_for_system(
            session, system_id=sys_.id, connector_key="demo_provider"
        )
        _patch(monkeypatch, [_outcome("fail")])
        await scan_mod.scan_for_system(
            session, system_id=sys_.id, connector_key="demo_provider"
        )
    assert _counter(POSTURE_DRIFT_TRANSITIONS, kind="regressed") == before + 1


@pytest.mark.asyncio
async def test_the_failing_gauge_reflects_the_latest_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, [_outcome("fail", "fail", "pass")])
    async with session_scope() as session:
        sys_ = await _system(session)
        await scan_mod.scan_for_system(
            session, system_id=sys_.id, connector_key="demo_provider"
        )
        assert _counter(POSTURE_FAILING_RESOURCES, system_id=str(sys_.id)) == 2.0
        _patch(monkeypatch, [_outcome("pass", "pass", "pass")])
        await scan_mod.scan_for_system(
            session, system_id=sys_.id, connector_key="demo_provider"
        )
        assert _counter(POSTURE_FAILING_RESOURCES, system_id=str(sys_.id)) == 0.0


@pytest.mark.asyncio
async def test_a_failing_metrics_call_does_not_fail_a_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Telemetry must never break what it measures."""

    def _boom(*a: object, **k: object) -> None:
        raise RuntimeError("prometheus is unhappy")

    monkeypatch.setattr(POSTURE_CHECK_RESULTS, "labels", _boom)
    _patch(monkeypatch, [_outcome("fail")])
    async with session_scope() as session:
        sys_ = await _system(session)
        out = await scan_mod.scan_for_system(
            session, system_id=sys_.id, connector_key="demo_provider"
        )
        assert out["checks_run"] == 1, "the result must still have been recorded"


# ── suppression and pruning counters ─────────────────────────────────────────


async def _test_with_waiver(session, *, waive: bool) -> ControlTest:
    sys_ = await _system(session)
    test = ControlTest(
        organization_id=sys_.organization_id,
        system_id=sys_.id,
        control_id="AC-2",
        name="Demo",
        method="connector",
        check_key=f"metrics.suppression.{next(_SEQ)}",
    )
    session.add(test)
    await session.flush()
    if waive:
        session.add(
            Waiver(
                organization_id=sys_.organization_id,
                system_id=sys_.id,
                check_key=test.check_key,
                rationale="accepted",
                status="approved",
            )
        )
        await session.flush()
    return test


@pytest.mark.asyncio
async def test_a_suppressed_finding_increments_the_waiver_counter() -> None:
    before = _counter(WAIVER_SUPPRESSIONS)
    async with session_scope() as session:
        test = await _test_with_waiver(session, waive=True)
        await record_result(
            session, test, status="fail", detail="failing", evaluated=1, failing=1,
            resources=[_f("res-0", "fail")],
        )
    assert _counter(WAIVER_SUPPRESSIONS) == before + 1


@pytest.mark.asyncio
async def test_an_unsuppressed_failure_does_not_increment_it() -> None:
    before = _counter(WAIVER_SUPPRESSIONS)
    async with session_scope() as session:
        test = await _test_with_waiver(session, waive=False)
        await record_result(
            session, test, status="fail", detail="failing", evaluated=1, failing=1,
            resources=[_f("res-0", "fail")],
        )
    assert _counter(WAIVER_SUPPRESSIONS) == before


@pytest.mark.asyncio
async def test_pruning_counts_the_rows_it_deleted() -> None:
    before = _counter(POSTURE_DETAIL_PRUNED)
    async with session_scope() as session:
        test = await _test_with_waiver(session, waive=False)
        old = await record_result(
            session, test, status="fail", detail="1", evaluated=2, failing=2,
            resources=[_f("a", "fail"), _f("b", "fail")],
        )
        await session.execute(
            update(ControlTestResult)
            .where(ControlTestResult.id == old.id)
            .values(run_at=datetime.now(UTC) - timedelta(days=500))
        )
        await record_result(
            session, test, status="fail", detail="2", evaluated=1, failing=1,
            resources=[_f("a", "fail")],
        )
        out = await prune_resource_detail(session, retain_days=30)
    assert _counter(POSTURE_DETAIL_PRUNED) == before + out["deleted"]


@pytest.mark.asyncio
async def test_a_dry_run_counts_nothing() -> None:
    """It deleted nothing, so reporting deletions would be a lie in a graph."""
    before = _counter(POSTURE_DETAIL_PRUNED)
    async with session_scope() as session:
        test = await _test_with_waiver(session, waive=False)
        old = await record_result(
            session, test, status="fail", detail="1", evaluated=1, failing=1,
            resources=[_f("a", "fail")],
        )
        await session.execute(
            update(ControlTestResult)
            .where(ControlTestResult.id == old.id)
            .values(run_at=datetime.now(UTC) - timedelta(days=500))
        )
        await record_result(
            session, test, status="fail", detail="2", evaluated=1, failing=1,
            resources=[_f("a", "fail")],
        )
        dry = await prune_resource_detail(session, retain_days=30, dry_run=True)
        assert dry["deleted"] >= 1, "the fixture must have had something to delete"
    assert _counter(POSTURE_DETAIL_PRUNED) == before
