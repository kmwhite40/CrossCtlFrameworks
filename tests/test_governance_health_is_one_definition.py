"""The governance page reports the shared health number, not a second one.

`/governance` computed its own `scan_pass / scan_total`, while
`analytics.live_scan` divides by the checks that actually judged a control.
A tenant with any `not_applicable` result — an unlicensed Microsoft 365 fleet
produces them by the hundred, and `roll_up_findings` returns it for a fleet of
zero — therefore saw one health percentage on /governance and a different one on
/systems and /ssp, with neither page naming its denominator.

Two implementations of one number is the shape of the complaint this addresses:
components that each compute their own answer instead of reading one.
"""

from __future__ import annotations

import itertools
import os
from datetime import UTC, datetime

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from ccf.analytics.live_scan import live_scan_for_org
from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Control, ControlImplementation, Organization, System, User
from ccf.models_grc import ControlTest, ControlTestResult

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _auth_enabled():
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


async def _scene(statuses: list[str]) -> tuple[int, str]:
    tag = f"{next(_SEQ)}"
    async with session_scope() as s:
        org = Organization(name=f"GovHealth Org {tag}")
        s.add(org)
        await s.flush()
        user = User(
            email=f"g-{tag}@gov.test",
            organization_id=org.id,
            role="admin",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        sys_ = System(organization_id=org.id, name=f"GovHealth Sys {tag}")
        s.add(sys_)
        await s.flush()
        for i, status in enumerate(statuses):
            test = ControlTest(
                organization_id=org.id,
                system_id=sys_.id,
                control_id=f"AC-{i + 1}",
                name=f"check {i}",
                method="connector",
                source="generated",
                check_key=f"gov.{tag}.{i}",
                last_status=status,
            )
            s.add(test)
            await s.flush()
            s.add(
                ControlTestResult(
                    control_test_id=test.id,
                    status=status,
                    run_at=datetime(2026, 9, 29, tzinfo=UTC),
                    evaluated=1,
                    failing=1 if status == "fail" else 0,
                )
            )
        await s.flush()
        return org.id, user.api_token


async def _cleanup(org_id: int) -> None:
    async with session_scope() as s:
        await s.execute(delete(Organization).where(Organization.id == org_id))


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


@pytest.mark.asyncio
async def test_the_page_shows_the_same_percentage_the_shared_rollup_computes() -> None:
    """The scenario the two implementations disagreed on.

    8 passing, 2 out of scope: the shared rollup says 100% of 8 judged; the
    page's own arithmetic said 80% of 10. Both appeared in the product.
    """
    org_id, token = await _scene(["pass"] * 8 + ["not_applicable"] * 2)
    try:
        async with session_scope() as s:
            shared = await live_scan_for_org(s, org_id=org_id)
        assert shared["health_pct"] == 100
        assert shared["assessed"] == 8

        async with _client() as c:
            r = await c.get("/governance", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200, r.text
        assert ">100%" in r.text.replace(" ", "").replace("\n", ""), (
            "the page computed its own percentage instead of the shared one"
        )
        assert "80%" not in r.text, "the old denominator is still in use"
        # And the base is named, so the number can be read.
        assert "8 of 10 live check(s) judged" in r.text
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_a_tenant_whose_checks_all_found_nothing_is_not_reported_as_zero() -> None:
    org_id, token = await _scene(["not_applicable"] * 5)
    try:
        async with _client() as c:
            r = await c.get("/governance", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200, r.text
        assert "not measured" in r.text
        assert "0%" not in r.text, "an unmeasurable tenant was reported at zero health"
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_a_failing_check_is_counted_and_surfaced() -> None:
    org_id, token = await _scene(["pass", "pass", "fail"])
    try:
        async with _client() as c:
            r = await c.get("/governance", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert "67%" in r.text
        assert "1 need review" in r.text
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_a_tenant_with_no_scans_falls_back_to_implementation_health() -> None:
    """The page must not go blank for a tenant that documents rather than scans."""
    org_id, token = await _scene([])
    try:
        async with _client() as c:
            r = await c.get("/governance", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert "implementation(s)" in r.text
        assert "live check(s) judged" not in r.text
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_both_populations_are_reported_when_a_tenant_has_both() -> None:
    """A documented implementation does not vanish because a scan exists.

    The page used to *replace* implementation health with live-scan health, so a
    tenant that both documents and scans saw only whichever branch fired — half
    its control programme missing from the page whose title is "command centre",
    with nothing saying so. Mutation testing found this uncovered: every other
    test here has scans or implementations, never both.
    """
    org_id, token = await _scene(["pass", "fail"])
    try:
        async with session_scope() as s:
            system = (
                await s.execute(select(System).where(System.organization_id == org_id))
            ).scalars().first()
            control = Control(identifier=f"ZG-{next(_SEQ)}")
            s.add(control)
            await s.flush()
            s.add(
                ControlImplementation(
                    system_id=system.id, control_id=control.id, status="implemented"
                )
            )

        async with _client() as c:
            r = await c.get("/governance", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200, r.text
        # The live-scan half still leads, because it is current evidence.
        assert "live check(s) judged" in r.text
        # And the documented half is still on the page.
        assert "documented implementation(s)" in r.text, (
            "implementation health vanished because scans exist"
        )
        assert "plus 1 documented" in r.text
    finally:
        await _cleanup(org_id)
