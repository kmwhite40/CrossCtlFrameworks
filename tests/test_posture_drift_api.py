"""Reading the history: drift between the last two scans, and one resource's timeline."""

from __future__ import annotations

import itertools

import pytest
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.db import session_scope
from ccf.governance.control_tests import record_result
from ccf.models import Organization, System
from ccf.models_grc import ControlTest
from ccf.models_waivers import Waiver
from ccf.posture.drift import latest_drift, resource_timeline
from ccf.posture.types import ResourceFinding

_SEQ = itertools.count()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://test")


def _f(rid: str, verdict: str, observed: str = "observed") -> ResourceFinding:
    return ResourceFinding(
        resource_id=rid, resource_type="entra_user", verdict=verdict, observed=observed
    )


async def _test_on_new_system(session) -> ControlTest:
    org = Organization(name=f"DriftOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"DriftSys-{next(_SEQ)}")
    session.add(sys_)
    await session.flush()
    test = ControlTest(
        organization_id=org.id,
        system_id=sys_.id,
        control_id="IA-2",
        name="MFA",
        method="connector",
        check_key=f"drift.check.{next(_SEQ)}",
    )
    session.add(test)
    await session.flush()
    return test


# ── latest_drift ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_drift_reports_every_kind_between_the_last_two_scans() -> None:
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        await record_result(
            session, test, status="fail", detail="scan 1", evaluated=4, failing=2,
            resources=[
                _f("regressing@acme.gov", "pass"),
                _f("recovering@acme.gov", "fail"),
                _f("vanishing@acme.gov", "fail"),
                _f("steady@acme.gov", "pass"),
            ],
        )
        await record_result(
            session, test, status="fail", detail="scan 2", evaluated=4, failing=2,
            resources=[
                _f("regressing@acme.gov", "fail"),
                _f("recovering@acme.gov", "pass"),
                _f("arriving@acme.gov", "fail"),
                _f("steady@acme.gov", "pass"),
            ],
        )
        drift = await latest_drift(session, test_id=test.id)
        kinds = {t.resource_id: t.kind for t in drift}
        assert kinds == {
            "arriving@acme.gov": "appeared",
            "recovering@acme.gov": "recovered",
            "regressing@acme.gov": "regressed",
            "vanishing@acme.gov": "disappeared",
        }
        assert "steady@acme.gov" not in kinds, "an unchanged resource is not drift"


@pytest.mark.asyncio
async def test_a_first_scan_reports_no_drift_rather_than_everything_appeared() -> None:
    """There is no baseline, and inventing one would report a first scan as
    wholesale change -- drowning the real signal on day one."""
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        await record_result(
            session, test, status="fail", detail="first", evaluated=2, failing=2,
            resources=[_f("a@acme.gov", "fail"), _f("b@acme.gov", "fail")],
        )
        assert await latest_drift(session, test_id=test.id) == []


@pytest.mark.asyncio
async def test_a_test_with_no_results_reports_no_drift() -> None:
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        assert await latest_drift(session, test_id=test.id) == []


@pytest.mark.asyncio
async def test_drift_compares_the_two_most_recent_results_only() -> None:
    """Not the first and last: drift means "what changed in this scan"."""
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        await record_result(
            session, test, status="pass", detail="scan 1", evaluated=1, failing=0,
            resources=[_f("r@acme.gov", "pass")],
        )
        await record_result(
            session, test, status="fail", detail="scan 2", evaluated=1, failing=1,
            resources=[_f("r@acme.gov", "fail")],
        )
        await record_result(
            session, test, status="fail", detail="scan 3", evaluated=1, failing=1,
            resources=[_f("r@acme.gov", "fail")],
        )
        # Scan 2 -> 3 is unchanged, so there is no drift even though scan 1
        # differs from scan 3.
        assert await latest_drift(session, test_id=test.id) == []


@pytest.mark.asyncio
async def test_another_tests_resources_do_not_leak_into_drift() -> None:
    async with session_scope() as session:
        mine = await _test_on_new_system(session)
        other = await _test_on_new_system(session)
        for t in (mine, other):
            await record_result(
                session, t, status="pass", detail="1", evaluated=1, failing=0,
                resources=[_f(f"r-{t.id}@acme.gov", "pass")],
            )
            await record_result(
                session, t, status="fail", detail="2", evaluated=1, failing=1,
                resources=[_f(f"r-{t.id}@acme.gov", "fail")],
            )
        drift = await latest_drift(session, test_id=mine.id)
        assert [t.resource_id for t in drift] == [f"r-{mine.id}@acme.gov"]


# ── resource_timeline ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_timeline_is_newest_first_and_carries_the_waiver() -> None:
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        await record_result(
            session, test, status="pass", detail="1", evaluated=1, failing=0,
            resources=[_f("r@acme.gov", "pass", "fine")],
        )
        await record_result(
            session, test, status="fail", detail="2", evaluated=1, failing=1,
            resources=[_f("r@acme.gov", "fail", "broke")],
        )
        w = Waiver(
            organization_id=test.organization_id,
            system_id=test.system_id,
            check_key=test.check_key,
            rationale="accepted",
            status="approved",
        )
        session.add(w)
        await session.flush()
        await record_result(
            session, test, status="fail", detail="3", evaluated=1, failing=1,
            resources=[_f("r@acme.gov", "fail", "still broken, accepted")],
        )

        timeline = await resource_timeline(session, test_id=test.id, resource_id="r@acme.gov")
        assert [e["verdict"] for e in timeline] == ["fail", "fail", "pass"]
        assert timeline[0]["observed"] == "still broken, accepted"
        assert timeline[0]["waiver_id"] == w.id
        assert timeline[1]["waiver_id"] is None
        assert all(e["run_at"] is not None for e in timeline)


@pytest.mark.asyncio
async def test_a_timeline_excludes_other_resources_and_other_tests() -> None:
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        await record_result(
            session, test, status="fail", detail="1", evaluated=2, failing=1,
            resources=[_f("mine@acme.gov", "fail"), _f("theirs@acme.gov", "pass")],
        )
        timeline = await resource_timeline(session, test_id=test.id, resource_id="mine@acme.gov")
        assert len(timeline) == 1
        assert timeline[0]["verdict"] == "fail"


@pytest.mark.asyncio
async def test_a_timeline_for_an_unseen_resource_is_empty() -> None:
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        assert await resource_timeline(session, test_id=test.id, resource_id="nobody") == []


@pytest.mark.asyncio
async def test_a_timeline_respects_its_limit() -> None:
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        for i in range(5):
            await record_result(
                session, test, status="fail", detail=f"{i}", evaluated=1, failing=1,
                resources=[_f("r@acme.gov", "fail", f"scan {i}")],
            )
        limited = await resource_timeline(
            session, test_id=test.id, resource_id="r@acme.gov", limit=2
        )
        assert len(limited) == 2
        assert limited[0]["observed"] == "scan 4", "newest first, not oldest"


# ── the endpoints ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_openapi_lists_the_drift_routes() -> None:
    async with _client() as client:
        paths = (await client.get("/openapi.json")).json()["paths"]
        assert "/api/control-tests/{test_id}/drift" in paths
        assert "/api/control-tests/{test_id}/resources/{resource_id}/timeline" in paths


@pytest.mark.asyncio
async def test_the_drift_endpoint_returns_the_transitions() -> None:
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        await record_result(
            session, test, status="pass", detail="1", evaluated=1, failing=0,
            resources=[_f("r@acme.gov", "pass")],
        )
        await record_result(
            session, test, status="fail", detail="2", evaluated=1, failing=1,
            resources=[_f("r@acme.gov", "fail", "broke")],
        )
    async with _client() as client:
        resp = await client.get(f"/api/control-tests/{test.id}/drift")
        assert resp.status_code == 200, resp.text
        assert resp.json() == [
            {
                "resource_id": "r@acme.gov",
                "kind": "regressed",
                "before": "pass",
                "after": "fail",
                "observed": "broke",
            }
        ]


@pytest.mark.asyncio
async def test_the_timeline_endpoint_returns_entries() -> None:
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        await record_result(
            session, test, status="fail", detail="1", evaluated=1, failing=1,
            resources=[_f("r@acme.gov", "fail", "broke")],
        )
    async with _client() as client:
        resp = await client.get(
            f"/api/control-tests/{test.id}/resources/r@acme.gov/timeline"
        )
        assert resp.status_code == 200, resp.text
        assert [e["verdict"] for e in resp.json()] == ["fail"]


@pytest.mark.asyncio
async def test_an_unknown_test_is_not_found_on_both_endpoints() -> None:
    async with _client() as client:
        assert (await client.get("/api/control-tests/9999999/drift")).status_code == 404
        timeline = await client.get(
            "/api/control-tests/9999999/resources/anything/timeline"
        )
        assert timeline.status_code == 404
