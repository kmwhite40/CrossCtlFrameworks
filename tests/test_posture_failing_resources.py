"""/failing-resources must mean *currently* failing.

It did not: the endpoint selected every fail row across all results, so a
resource fixed weeks ago was still reported, with the stale observed text from
the scan that found it broken.
"""

from __future__ import annotations

import itertools

import pytest
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.db import session_scope
from ccf.governance.control_tests import record_result
from ccf.models import Organization, System
from ccf.models_grc import ControlTest
from ccf.posture.types import ResourceFinding

_SEQ = itertools.count()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://test")


def _f(resource_id: str, verdict: str, observed: str) -> ResourceFinding:
    return ResourceFinding(
        resource_id=resource_id, resource_type="entra_user", verdict=verdict, observed=observed
    )


async def _test_on_new_system(session, *, name: str = "MFA") -> ControlTest:
    org = Organization(name=f"FailingResOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"FailingResSys-{next(_SEQ)}")
    session.add(sys_)
    await session.flush()
    test = ControlTest(
        organization_id=org.id,
        system_id=sys_.id,
        control_id="IA-2",
        name=name,
        method="connector",
        check_key=f"fr.check.{next(_SEQ)}",
    )
    session.add(test)
    await session.flush()
    return test


async def _rows_for(test_id: int) -> list[dict]:
    async with _client() as client:
        resp = await client.get("/api/posture/failing-resources", params={"limit": 1000})
        assert resp.status_code == 200, resp.text
        return [r for r in resp.json() if r["test_id"] == test_id]


@pytest.mark.asyncio
async def test_a_resource_fixed_in_the_latest_scan_is_not_reported_failing() -> None:
    """The bug, as verified against the shipped endpoint before the fix."""
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        await record_result(
            session, test, status="fail", detail="broken", evaluated=1, failing=1,
            resources=[_f("fixed-later@acme.gov", "fail", "first scan: no MFA")],
        )
        await record_result(
            session, test, status="pass", detail="fixed", evaluated=1, failing=0,
            resources=[_f("fixed-later@acme.gov", "pass", "second scan: MFA registered")],
        )
    assert await _rows_for(test.id) == []


@pytest.mark.asyncio
async def test_a_resource_still_failing_in_the_latest_scan_is_reported() -> None:
    """The companion. Without it, "return nothing" passes the test above."""
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        await record_result(
            session, test, status="fail", detail="broken", evaluated=1, failing=1,
            resources=[_f("still-broken@acme.gov", "fail", "first scan: no MFA")],
        )
        await record_result(
            session, test, status="fail", detail="still broken", evaluated=1, failing=1,
            resources=[_f("still-broken@acme.gov", "fail", "second scan: still no MFA")],
        )
    rows = await _rows_for(test.id)
    assert [r["resource_id"] for r in rows] == ["still-broken@acme.gov"]


@pytest.mark.asyncio
async def test_the_observed_text_comes_from_the_latest_scan() -> None:
    """Stale observed text is what makes a stale row actively misleading."""
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        await record_result(
            session, test, status="fail", detail="broken", evaluated=1, failing=1,
            resources=[_f("r@acme.gov", "fail", "first scan: no MFA")],
        )
        await record_result(
            session, test, status="fail", detail="broken differently", evaluated=1, failing=1,
            resources=[_f("r@acme.gov", "fail", "second scan: legacy auth permitted")],
        )
    rows = await _rows_for(test.id)
    assert len(rows) == 1
    assert rows[0]["observed"] == "second scan: legacy auth permitted"


@pytest.mark.asyncio
async def test_a_resource_reported_once_per_failing_scan_is_not_duplicated() -> None:
    """Three failing scans of one resource is one current failure, not three."""
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        for i in range(3):
            await record_result(
                session, test, status="fail", detail=f"scan {i}", evaluated=1, failing=1,
                resources=[_f("r@acme.gov", "fail", f"scan {i}")],
            )
    assert len(await _rows_for(test.id)) == 1


@pytest.mark.asyncio
async def test_latest_is_per_test_not_per_resource() -> None:
    """Two checks on one resource are two independent judgements: a resource
    failing one and passing another must still be reported for the one."""
    async with session_scope() as session:
        failing = await _test_on_new_system(session, name="Still failing")
        passing = await _test_on_new_system(session, name="Now passing")
        await record_result(
            session, failing, status="fail", detail="broken", evaluated=1, failing=1,
            resources=[_f("shared@acme.gov", "fail", "check A: broken")],
        )
        await record_result(
            session, passing, status="pass", detail="fine", evaluated=1, failing=0,
            resources=[_f("shared@acme.gov", "pass", "check B: fine")],
        )
    assert [r["resource_id"] for r in await _rows_for(failing.id)] == ["shared@acme.gov"]
    assert await _rows_for(passing.id) == []


@pytest.mark.asyncio
async def test_a_warn_resource_is_not_reported_as_failing() -> None:
    """The endpoint is about failures; widening it silently would change what
    an operator's queue means."""
    async with session_scope() as session:
        test = await _test_on_new_system(session)
        await record_result(
            session, test, status="warn", detail="warning", evaluated=1, failing=0,
            resources=[_f("warned@acme.gov", "warn", "close to the threshold")],
        )
    assert await _rows_for(test.id) == []
