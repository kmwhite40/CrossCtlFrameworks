"""The enforcement endpoints -- the only path by which a change reaches an environment."""

from __future__ import annotations

import itertools

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.auth_deps import get_principal
from ccf.api.main import create_app
from ccf.api.routes.enforcement import _require_plan
from ccf.auth import Principal
from ccf.db import session_scope
from ccf.enforcement.types import PROVIDER_REGISTRY, RemediationStep, StepOutcome, register
from ccf.governance.control_tests import record_result
from ccf.models import Organization, System
from ccf.models_enforcement import RemediationPlan
from ccf.models_grc import ControlTest
from ccf.posture.types import ResourceFinding

_SEQ = itertools.count()
CHECK = "api.enforcement.demo"


class _ApiProvider:
    """Registered once for this module's check key."""

    key = "api_demo"
    write_credential_type = "api_demo_write"
    required_permissions = ("Demo.Write.All",)
    handled_checks = (CHECK,)

    def __init__(self, credential: dict | None = None) -> None:
        self.credential = credential

    async def is_write_configured(self) -> bool:
        # No credential store is configured in tests, so the provider declares
        # itself write-capable; what the API tests exercise is the gate above
        # it, and the credential refusal has its own service-level test.
        return True

    async def plan(self, findings) -> list[RemediationStep]:
        return [
            RemediationStep(
                resource_id=f.resource_id,
                resource_type=f.resource_type,
                action="disable_account",
                description=f"disable {f.resource_id}",
                current_state={"enabled": True},
                target_state={"enabled": False},
            )
            for f in findings
        ]

    async def apply(self, step: RemediationStep) -> StepOutcome:
        return StepOutcome(step.resource_id, "applied", "done")

    async def reverse(self, step: RemediationStep) -> StepOutcome:
        return StepOutcome(step.resource_id, "applied", "undone")


if not any(p.key == _ApiProvider.key for p in PROVIDER_REGISTRY):
    register(_ApiProvider)


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://test")


class _Session:
    """A client whose identity can change between calls.

    Separation of duties means one identity cannot drive the whole loop -- a
    single test client requests AND approves, and the service correctly refuses
    it. Overriding ``get_principal`` is how the routes get exercised end to end
    with two people, which is the real deployment shape.
    """

    def __init__(self) -> None:
        self.app = create_app()
        self.email = "isso@acme.gov"
        self.app.dependency_overrides[get_principal] = self._principal

    def _principal(self) -> Principal:
        return Principal(user_id=1, email=self.email, org_id=None, role="admin")

    def as_(self, email: str) -> _Session:
        self.email = email
        return self

    def client(self) -> AsyncClient:
        return AsyncClient(
            transport=ASGITransport(app=self.app), base_url="http://test"
        )


async def _scanned_system(failing: int = 2) -> int:
    async with session_scope() as session:
        org = Organization(name=f"EnfApiOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"EnfApiSys-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        test = ControlTest(
            organization_id=org.id,
            system_id=sys_.id,
            control_id="AC-2",
            name="Demo",
            method="connector",
            check_key=CHECK,
        )
        session.add(test)
        await session.flush()
        await record_result(
            session, test, status="fail", detail="failing", evaluated=failing,
            failing=failing,
            resources=[
                ResourceFinding(f"u{i}@acme.gov", "entra_user", "fail", "stale")
                for i in range(failing)
            ],
        )
        return sys_.id


@pytest.mark.asyncio
async def test_openapi_lists_the_enforcement_routes() -> None:
    async with _client() as client:
        paths = (await client.get("/openapi.json")).json()["paths"]
        assert "/api/systems/{system_id}/remediation-plans" in paths
        assert "/api/remediation-plans" in paths
        assert "/api/remediation-plans/{plan_id}/approve" in paths
        assert "/api/remediation-plans/{plan_id}/apply" in paths
        assert "/api/remediation-plans/{plan_id}/reverse" in paths


@pytest.mark.asyncio
async def test_there_is_no_endpoint_that_plans_and_applies_in_one_call() -> None:
    """The review between them is the control, so it cannot be skipped by
    reaching for a more convenient route."""
    async with _client() as client:
        paths = (await client.get("/openapi.json")).json()["paths"]
    for path in paths:
        assert "remediate-now" not in path
        assert "auto-remediate" not in path


@pytest.mark.asyncio
async def test_the_requester_cannot_approve_their_own_plan_through_the_api() -> None:
    """The service rule, reached through HTTP -- so it cannot be bypassed by
    calling the route instead of the function."""
    system_id = await _scanned_system()
    session = _Session().as_("isso@acme.gov")
    async with session.client() as client:
        plan_id = (
            await client.post(
                f"/api/systems/{system_id}/remediation-plans", json={"check_key": CHECK}
            )
        ).json()["id"]
        resp = await client.post(f"/api/remediation-plans/{plan_id}/approve")
        assert resp.status_code == 409
        assert "may not approve" in resp.json()["detail"]
    async with session_scope() as db:
        plan = (
            await db.execute(select(RemediationPlan).where(RemediationPlan.id == plan_id))
        ).scalar_one()
        assert plan.status == "pending_approval", "a refused approval changes nothing"


@pytest.mark.asyncio
async def test_the_whole_loop_plan_approve_apply_reverse() -> None:
    """Two identities, because one cannot drive this loop -- which is the point."""
    system_id = await _scanned_system()
    session = _Session()

    async with session.as_("isso@acme.gov").client() as client:
        created = await client.post(
            f"/api/systems/{system_id}/remediation-plans", json={"check_key": CHECK}
        )
        assert created.status_code == 201, created.text
        plan = created.json()
        assert plan["status"] == "pending_approval"
        assert plan["resource_count"] == 2
        assert plan["steps"][0]["current_state"] == {"enabled": True}
        assert plan["outcomes"] == [], "planning changes nothing"
        plan_id = plan["id"]

    async with session.as_("ao@acme.gov").client() as client:
        approved = await client.post(f"/api/remediation-plans/{plan_id}/approve")
        assert approved.status_code == 200, approved.text
        assert approved.json()["status"] == "approved"
        assert approved.json()["approved_by"] == "ao@acme.gov"
        assert approved.json()["outcomes"] == [], "approval changes nothing either"

        applied = await client.post(f"/api/remediation-plans/{plan_id}/apply")
        assert applied.status_code == 200, applied.text
        assert applied.json()["status"] == "applied"
        assert {o["status"] for o in applied.json()["outcomes"]} == {"applied"}

        reversed_ = await client.post(f"/api/remediation-plans/{plan_id}/reverse")
        assert reversed_.status_code == 200, reversed_.text
        assert reversed_.json()["status"] == "reversed"


@pytest.mark.asyncio
async def test_apply_without_approval_is_a_conflict() -> None:
    system_id = await _scanned_system()
    async with _client() as client:
        plan_id = (
            await client.post(
                f"/api/systems/{system_id}/remediation-plans", json={"check_key": CHECK}
            )
        ).json()["id"]
        resp = await client.post(f"/api/remediation-plans/{plan_id}/apply")
        assert resp.status_code == 409, resp.text
    async with session_scope() as session:
        plan = (
            await session.execute(
                select(RemediationPlan).where(RemediationPlan.id == plan_id)
            )
        ).scalar_one()
        assert plan.outcomes == [], "nothing was applied"


@pytest.mark.asyncio
async def test_resource_ids_narrow_the_plan() -> None:
    system_id = await _scanned_system(failing=3)
    async with _client() as client:
        created = await client.post(
            f"/api/systems/{system_id}/remediation-plans",
            json={"check_key": CHECK, "resource_ids": ["u1@acme.gov"]},
        )
        assert created.json()["resource_count"] == 1
        assert created.json()["steps"][0]["resource_id"] == "u1@acme.gov"


@pytest.mark.asyncio
async def test_a_refused_plan_is_201_with_its_reason_not_an_error() -> None:
    """The refusal is a stored decision an operator should be able to read, and
    an HTTP error would discard the row's id."""
    system_id = await _scanned_system()
    async with _client() as client:
        created = await client.post(
            f"/api/systems/{system_id}/remediation-plans",
            json={"check_key": CHECK, "resource_ids": ["nobody@acme.gov"]},
        )
        assert created.status_code == 201, created.text
        assert created.json()["status"] == "refused"
        assert created.json()["refusal_reason"] == "no resources to remediate"
        assert created.json()["id"] is not None

    # And it cannot then be approved, even by a different person.
    session = _Session().as_("ao@acme.gov")
    async with session.client() as client:
        resp = await client.post(
            f"/api/remediation-plans/{created.json()['id']}/approve"
        )
        assert resp.status_code == 409
        assert "not awaiting approval" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_a_check_with_no_provider_is_not_found() -> None:
    system_id = await _scanned_system()
    async with _client() as client:
        resp = await client.post(
            f"/api/systems/{system_id}/remediation-plans",
            json={"check_key": "nothing.handles.this"},
        )
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_an_unknown_plan_is_not_found() -> None:
    async with _client() as client:
        for suffix in ("approve", "apply", "reverse"):
            resp = await client.post(f"/api/remediation-plans/9999999/{suffix}")
            assert resp.status_code == 404, suffix
        assert (await client.get("/api/remediation-plans/9999999")).status_code == 404


@pytest.mark.asyncio
async def test_listing_filters_by_system_and_status() -> None:
    """Two systems, so the filter must exclude rather than merely include."""
    mine = await _scanned_system()
    theirs = await _scanned_system()
    async with _client() as client:
        for system_id in (mine, theirs):
            await client.post(
                f"/api/systems/{system_id}/remediation-plans", json={"check_key": CHECK}
            )
        listed = (await client.get("/api/remediation-plans", params={"system_id": mine})).json()
        assert {p["system_id"] for p in listed} == {mine}
        pending = (
            await client.get(
                "/api/remediation-plans",
                params={"system_id": mine, "status": "pending_approval"},
            )
        ).json()
        assert len(pending) == 1
        none = (
            await client.get(
                "/api/remediation-plans", params={"system_id": mine, "status": "applied"}
            )
        ).json()
        assert none == []


@pytest.mark.asyncio
async def test_a_scoped_principal_cannot_reach_another_tenants_plan() -> None:
    """Exercised directly: the HTTP client is a global principal, so the
    cross-tenant branch is unreachable through it."""
    system_id = await _scanned_system()
    async with _client() as client:
        plan_id = (
            await client.post(
                f"/api/systems/{system_id}/remediation-plans", json={"check_key": CHECK}
            )
        ).json()["id"]
    async with session_scope() as session:
        plan = (
            await session.execute(
                select(RemediationPlan).where(RemediationPlan.id == plan_id)
            )
        ).scalar_one()
        owning = plan.organization_id or 0
        intruder = Principal(
            user_id=1, email="other@example.gov", org_id=owning + 1000, role="admin"
        )
        with pytest.raises(HTTPException) as caught:
            await _require_plan(session, plan_id, intruder)
        assert caught.value.status_code == 404
        owner = Principal(user_id=2, email="owner@example.gov", org_id=owning, role="admin")
        assert (await _require_plan(session, plan_id, owner)).id == plan_id
