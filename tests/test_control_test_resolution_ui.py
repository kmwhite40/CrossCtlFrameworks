"""Step 4 of the customer flow: resolving a failing control in place.

The gap report's rows link to a control test, and that page had no actions at
all -- no way to accept a risk, no sight of one already accepted. Every
acceptance on record had to be made over the JSON API, so the flow the product
promises (connect, evaluate, show posture, **correct and remediate**, write the
SSP) stopped dead at step 4.

These routes delegate to the JSON handlers rather than re-implementing them, so
what is pinned here is the wiring and the separation of duties the page has to
respect -- and, above all, that accepting a risk never turns a failing control
into a passing one.
"""

from __future__ import annotations

import itertools
import os
from datetime import UTC, datetime

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.analytics.gaps import compliance_gaps
from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, System, User
from ccf.models_grc import ControlTest, ControlTestResourceResult, ControlTestResult
from ccf.models_waivers import Waiver

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


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _scene() -> dict[str, object]:
    """An org with two admins, a system, and one failing control over 3 resources."""
    tag = f"{next(_SEQ)}-{os.getpid()}"
    async with session_scope() as s:
        org = Organization(name=f"Resolve Org {tag}")
        s.add(org)
        await s.flush()
        users = {}
        for role, label in (("admin", "ao"), ("admin", "second"), ("control_owner", "owner")):
            u = User(
                email=f"{label}-{tag}@resolve.test",
                organization_id=org.id,
                role=role,
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
            s.add(u)
            users[label] = u
        system = System(organization_id=org.id, name=f"Sys {tag}")
        s.add(system)
        await s.flush()
        test = ControlTest(
            organization_id=org.id,
            system_id=system.id,
            control_id="IA-2",
            name="Every user has an MFA method registered",
            method="automated",
            source="generated",
            check_key="m365.identity.mfa_registered",
            last_status="fail",
        )
        s.add(test)
        await s.flush()
        result = ControlTestResult(
            control_test_id=test.id,
            status="fail",
            run_at=datetime.now(UTC),
            evaluated=3,
            failing=3,
        )
        s.add(result)
        await s.flush()
        for i in range(3):
            s.add(
                ControlTestResourceResult(
                    result_id=result.id,
                    resource_id=f"u{i}",
                    resource_type="entra_user",
                    verdict="fail",
                    observed=f"no MFA method registered: user{i}@x.gov",
                )
            )
        await s.flush()
        return {
            "org_id": org.id,
            "system_id": system.id,
            "test_id": test.id,
            "ao": users["ao"].api_token,
            "ao_email": users["ao"].email,
            "second": users["second"].api_token,
            "owner": users["owner"].api_token,
            "owner_email": users["owner"].email,
        }


async def _waivers(test_id: int) -> list[Waiver]:
    async with session_scope() as s:
        return list(
            (
                await s.execute(
                    select(Waiver).join(
                        ControlTest,
                        (ControlTest.system_id == Waiver.system_id)
                        & (ControlTest.check_key == Waiver.check_key),
                    ).where(ControlTest.id == test_id).order_by(Waiver.id)
                )
            ).scalars().all()
        )


# ---------------------------------------------------------------------------
# The page offers the action
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_failing_control_offers_a_resolution_path() -> None:
    sc = await _scene()
    async with _client() as c:
        r = await c.get(f"/control-tests/{sc['test_id']}", headers=_auth(str(sc["ao"])))
    assert r.status_code == 200, r.text
    assert "Request a risk acceptance" in r.text, "the page is still a dead end"
    assert f"/control-tests/{sc['test_id']}/accept" in r.text


@pytest.mark.asyncio
async def test_the_request_form_round_trips_and_suppresses_nothing_yet() -> None:
    """A request is a request. If asking were enough, anyone could clear the queue."""
    sc = await _scene()
    async with _client() as c:
        r = await c.post(
            f"/control-tests/{sc['test_id']}/accept",
            data={
                "rationale": "Conditional access blocks these three.",
                "expires_on": "2027-03-31",
            },
            headers=_auth(str(sc["owner"])),
            follow_redirects=False,
        )
    assert r.status_code == 303, r.text

    filed = await _waivers(int(sc["test_id"]))
    assert len(filed) == 1
    assert filed[0].status == "requested"
    assert filed[0].requested_by == sc["owner_email"]
    assert filed[0].check_key == "m365.identity.mfa_registered"
    assert filed[0].control_id is None, "exactly one target, per ck_waiver_one_target"

    async with session_scope() as s:
        g = await compliance_gaps(s, int(sc["org_id"]))
    assert g["open"] == 1, "a requested acceptance suppressed the finding"
    assert g["accepted"] == 0


@pytest.mark.asyncio
async def test_a_rationale_is_required() -> None:
    """An acceptance with no stated reason is not reviewable."""
    sc = await _scene()
    async with _client() as c:
        r = await c.post(
            f"/control-tests/{sc['test_id']}/accept",
            data={"rationale": "   "},
            headers=_auth(str(sc["owner"])),
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "error=" in r.headers["location"], "the refusal was silent"
    assert await _waivers(int(sc["test_id"])) == []


@pytest.mark.asyncio
async def test_a_malformed_expiry_is_reported_not_swallowed() -> None:
    sc = await _scene()
    async with _client() as c:
        r = await c.post(
            f"/control-tests/{sc['test_id']}/accept",
            data={"rationale": "Accepted.", "expires_on": "31/03/2027"},
            headers=_auth(str(sc["owner"])),
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "error=" in r.headers["location"]
    assert await _waivers(int(sc["test_id"])) == []


# ---------------------------------------------------------------------------
# Approval, and what it does and does not change
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_requester_may_not_approve_their_own_acceptance() -> None:
    """Separation of duties, enforced on the form path as on the API path."""
    sc = await _scene()
    async with _client() as c:
        await c.post(
            f"/control-tests/{sc['test_id']}/accept",
            data={"rationale": "Accepted by the owner."},
            headers=_auth(str(sc["ao"])),
            follow_redirects=False,
        )
        waiver = (await _waivers(int(sc["test_id"])))[0]
        r = await c.post(
            f"/control-tests/{sc['test_id']}/waivers/{waiver.id}/approve",
            headers=_auth(str(sc["ao"])),
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "error=" in r.headers["location"]
    assert (await _waivers(int(sc["test_id"])))[0].status == "requested"


@pytest.mark.asyncio
async def test_a_control_owner_cannot_approve_an_acceptance() -> None:
    sc = await _scene()
    async with _client() as c:
        await c.post(
            f"/control-tests/{sc['test_id']}/accept",
            data={"rationale": "Accepted."},
            headers=_auth(str(sc["ao"])),
            follow_redirects=False,
        )
        waiver = (await _waivers(int(sc["test_id"])))[0]
        r = await c.post(
            f"/control-tests/{sc['test_id']}/waivers/{waiver.id}/approve",
            headers=_auth(str(sc["owner"])),
            follow_redirects=False,
        )
    assert r.status_code == 403
    assert (await _waivers(int(sc["test_id"])))[0].status == "requested"


@pytest.mark.asyncio
async def test_approval_suppresses_the_consequence_and_nothing_else() -> None:
    """The whole design in one assertion: accepted, and still failing."""
    sc = await _scene()
    async with _client() as c:
        await c.post(
            f"/control-tests/{sc['test_id']}/accept",
            data={"rationale": "Conditional access blocks these three."},
            headers=_auth(str(sc["owner"])),
            follow_redirects=False,
        )
        waiver = (await _waivers(int(sc["test_id"])))[0]
        r = await c.post(
            f"/control-tests/{sc['test_id']}/waivers/{waiver.id}/approve",
            headers=_auth(str(sc["ao"])),
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert "error=" not in r.headers["location"], r.headers["location"]
        page = await c.get(f"/control-tests/{sc['test_id']}", headers=_auth(str(sc["ao"])))

    granted = (await _waivers(int(sc["test_id"])))[0]
    assert granted.status == "approved"
    assert granted.approved_by == sc["ao_email"]

    async with session_scope() as s:
        g = await compliance_gaps(s, int(sc["org_id"]))
        test = await s.get(ControlTest, int(sc["test_id"]))
    assert g["accepted"] == 1
    assert g["open"] == 0
    assert g["failing"] == 1, "the finding was erased rather than accepted"
    assert g["passing"] == 0, "an acceptance was counted as a pass"
    assert test.last_status == "fail", "approval rewrote the control's verdict"
    assert "Accepted — and still failing" in page.text


@pytest.mark.asyncio
async def test_revoking_returns_the_finding_to_the_queue() -> None:
    sc = await _scene()
    async with _client() as c:
        await c.post(
            f"/control-tests/{sc['test_id']}/accept",
            data={"rationale": "Accepted."},
            headers=_auth(str(sc["owner"])),
            follow_redirects=False,
        )
        waiver = (await _waivers(int(sc["test_id"])))[0]
        await c.post(
            f"/control-tests/{sc['test_id']}/waivers/{waiver.id}/approve",
            headers=_auth(str(sc["ao"])),
            follow_redirects=False,
        )
        r = await c.post(
            f"/control-tests/{sc['test_id']}/waivers/{waiver.id}/revoke",
            headers=_auth(str(sc["ao"])),
            follow_redirects=False,
        )
    assert r.status_code == 303
    async with session_scope() as s:
        g = await compliance_gaps(s, int(sc["org_id"]))
    assert g["open"] == 1
    assert g["accepted"] == 0


@pytest.mark.asyncio
async def test_another_tenant_cannot_open_or_accept_this_test() -> None:
    mine = await _scene()
    theirs = await _scene()
    async with _client() as c:
        page = await c.get(
            f"/control-tests/{mine['test_id']}", headers=_auth(str(theirs["ao"]))
        )
        post = await c.post(
            f"/control-tests/{mine['test_id']}/accept",
            data={"rationale": "Not mine to accept."},
            headers=_auth(str(theirs["ao"])),
            follow_redirects=False,
        )
    assert page.status_code == 404
    assert post.status_code == 404
    assert await _waivers(int(mine["test_id"])) == []
