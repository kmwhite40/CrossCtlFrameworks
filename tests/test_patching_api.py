"""Flaw-remediation endpoints: the report, the policy, and campaigns."""

from __future__ import annotations

import itertools
from datetime import date, timedelta

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.auth_deps import get_principal
from ccf.api.main import create_app
from ccf.api.routes import patching as patching_module
from ccf.api.routes.patching import _owned_campaign
from ccf.auth import Principal
from ccf.db import session_scope
from ccf.models import POAM, Organization, System
from ccf.models_enforcement import RemediationPlan
from ccf.models_patching import PatchWave

_SEQ = itertools.count()
TODAY = date.today()


class _Session:
    """A client whose identity and role can change between calls."""

    def __init__(self, *, org_id: int | None = None, role: str = "admin") -> None:
        self.app = create_app()
        self.email = "isso@acme.gov"
        self.org_id = org_id
        self.role = role
        self.app.dependency_overrides[get_principal] = self._principal

    def _principal(self) -> Principal:
        return Principal(user_id=1, email=self.email, org_id=self.org_id, role=self.role)

    def as_(self, email: str, *, role: str | None = None) -> _Session:
        self.email = email
        if role is not None:
            self.role = role
        return self

    def client(self) -> AsyncClient:
        return AsyncClient(transport=ASGITransport(app=self.app), base_url="http://test")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://test")


async def _system_with_flaws(n: int = 4, *, severity: str = "critical", age: int = 45):
    async with session_scope() as session:
        org = Organization(name=f"PatchApiOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"PatchApiSys-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        for i in range(n):
            session.add(
                POAM(
                    system_id=sys_.id,
                    title=f"flaw-{next(_SEQ)}-{i}",
                    severity=severity,
                    status="open",
                    source="scan",
                    identified_on=TODAY - timedelta(days=age),
                )
            )
        await session.flush()
        return sys_.id, org.id


@pytest.mark.asyncio
async def test_openapi_lists_the_patching_routes() -> None:
    async with _client() as client:
        paths = (await client.get("/openapi.json")).json()["paths"]
        assert "/api/systems/{system_id}/flaw-remediation" in paths
        assert "/api/remediation-policy" in paths
        assert "/api/systems/{system_id}/patch-campaigns" in paths
        assert "/api/patch-campaigns/{campaign_id}" in paths
        assert "/api/patch-waves/{wave_id}/complete" in paths


#: The exact set of (method, path) routes this module registers. A real guard
#: rather than a substring blocklist: the PR #20 review found that asserting
#: ``"apply-patch" not in path`` and ``"install-update" not in path`` is a
#: tautology -- those hyphenations have never existed in this repo, so the
#: assertion passed regardless of what the module actually did, and a future
#: ``/patch-waves/{id}/apply`` or ``/push-updates`` route would pass it
#: unchanged. Pinning the full set means any new route -- including one that
#: would apply a patch -- must be consciously added here, where its name is
#: forced into the open rather than merely not matching two guessed strings.
_EXPECTED_PATCHING_ROUTES = {
    ("GET", "/api/systems/{system_id}/flaw-remediation"),
    ("GET", "/api/remediation-policy"),
    ("PUT", "/api/remediation-policy"),
    ("POST", "/api/systems/{system_id}/patch-campaigns"),
    ("GET", "/api/patch-campaigns"),
    ("GET", "/api/patch-campaigns/{campaign_id}"),
    ("POST", "/api/patch-waves/{wave_id}/complete"),
}


@pytest.mark.asyncio
async def test_the_patching_module_registers_exactly_the_expected_routes() -> None:
    """Concord has no endpoint-management provider, and no route should imply
    otherwise. See ``_EXPECTED_PATCHING_ROUTES`` for why this is a set
    comparison rather than a substring check."""
    actual = {
        (method, route.path)
        for route in patching_module.router.routes
        for method in route.methods  # type: ignore[attr-defined]
    }
    assert actual == _EXPECTED_PATCHING_ROUTES


@pytest.mark.asyncio
async def test_the_report_breaches_on_aged_criticals() -> None:
    system_id, _org = await _system_with_flaws(2, severity="critical", age=45)
    async with _client() as client:
        resp = await client.get(f"/api/systems/{system_id}/flaw-remediation")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["buckets"]["breached"] == 2
        assert body["window"]["critical"] == 30
        assert len(body["breaching_ids"]) == 2


@pytest.mark.asyncio
async def test_a_default_policy_is_reported_as_a_default_not_a_decision() -> None:
    """A caller should know whether it is looking at a decision or a fallback."""
    async with _client() as client:
        body = (await client.get("/api/remediation-policy")).json()
        assert body["explicit"] is False
        assert body["source"] == "fedramp-default"
        assert body["window"]["moderate"] == 90


@pytest.mark.asyncio
async def test_setting_a_tighter_policy_moves_the_buckets() -> None:
    system_id, org_id = await _system_with_flaws(1, severity="moderate", age=45)
    session = _Session(org_id=org_id, role="admin")
    async with session.client() as client:
        before = (await client.get(f"/api/systems/{system_id}/flaw-remediation")).json()
        assert before["buckets"]["within_sla"] == 1

        put = await client.put(
            "/api/remediation-policy",
            json={"moderate_days": 14, "source": "organization policy 4.2"},
        )
        assert put.status_code == 200, put.text
        assert put.json()["window"]["moderate"] == 14
        assert put.json()["explicit"] is True

        after = (await client.get(f"/api/systems/{system_id}/flaw-remediation")).json()
        assert after["buckets"]["breached"] == 1


@pytest.mark.asyncio
async def test_a_zero_day_window_is_rejected() -> None:
    session = _Session(org_id=None, role="admin")
    async with session.client() as client:
        resp = await client.put("/api/remediation-policy", json={"critical_days": 0})
        assert resp.status_code == 400


@pytest.mark.asyncio
async def test_a_partial_policy_put_only_changes_what_was_sent() -> None:
    """IMPORTANT 5 (PR #20 review): ``PolicyIn`` defaults every ``*_days``
    field to the FedRAMP value, so a full ``model_dump()`` on a partial PUT
    would silently reset the fields the caller did not mention -- an org that
    declared 7/7/14/30 and later PUTs only ``{"moderate_days": 45}`` must not
    have critical/high/low reset to 30/30/180 and flaws previously breached
    move to within_sla on the next report.
    """
    _system_id, org_id = await _system_with_flaws(1)
    session = _Session(org_id=org_id, role="admin")
    async with session.client() as client:
        first = await client.put(
            "/api/remediation-policy",
            json={
                "critical_days": 7,
                "high_days": 7,
                "moderate_days": 14,
                "low_days": 30,
            },
        )
        assert first.status_code == 200, first.text
        assert first.json()["window"] == {
            "critical": 7,
            "high": 7,
            "moderate": 14,
            "low": 30,
        }

        second = await client.put(
            "/api/remediation-policy", json={"moderate_days": 45}
        )
        assert second.status_code == 200, second.text
        assert second.json()["window"] == {
            "critical": 7,
            "high": 7,
            "moderate": 45,
            "low": 30,
        }


@pytest.mark.asyncio
async def test_setting_a_policy_is_role_gated() -> None:
    """A scoped viewer cannot redefine the timeframe the organization is
    measured against."""
    _system_id, org_id = await _system_with_flaws(1)
    viewer = _Session(org_id=org_id, role="viewer").as_("viewer@acme.gov")
    async with viewer.client() as client:
        resp = await client.put("/api/remediation-policy", json={"critical_days": 365})
        assert resp.status_code == 403


@pytest.mark.asyncio
async def test_create_a_campaign_and_complete_its_waves_in_order() -> None:
    """``control_owner`` -- the operator who would actually run a wave -- is
    the role exercised here, not ``admin``, so this also proves Important 4's
    fix did not leave it locked out."""
    system_id, org_id = await _system_with_flaws(5)
    session = _Session(org_id=org_id, role="control_owner")
    async with session.client() as client:
        created = await client.post(
            f"/api/systems/{system_id}/patch-campaigns",
            json={
                "name": "September criticals",
                "window_start": str(TODAY),
                "window_end": str(TODAY + timedelta(days=7)),
                "wave_size": 2,
            },
        )
        assert created.status_code == 201, created.text
        body = created.json()
        assert body["status"] == "planned"
        assert [len(w["poam_ids"]) for w in body["waves"]] == [1, 2, 2]
        waves = body["waves"]

        # Out of order is refused.
        out_of_order = await client.post(
            f"/api/patch-waves/{waves[1]['id']}/complete", json={}
        )
        assert out_of_order.status_code == 409
        assert "still pending" in out_of_order.json()["detail"]

        for w in waves:
            done = await client.post(
                f"/api/patch-waves/{w['id']}/complete",
                json={"evidence_ref": f"CHG-{w['sequence']}"},
            )
            assert done.status_code == 200, done.text
            assert done.json()["status"] == "completed"

        final = (await client.get(f"/api/patch-campaigns/{body['id']}")).json()
        assert final["status"] == "completed"


@pytest.mark.asyncio
async def test_creating_a_campaign_is_role_gated() -> None:
    """IMPORTANT 8 (PR #20 review): a bare ``get_principal`` let a ``viewer``
    write campaign and wave rows and, through the overlapping-window
    refusal, block a legitimate maintenance window on any system in their
    org with one POST."""
    system_id, org_id = await _system_with_flaws(2)
    viewer = _Session(org_id=org_id, role="viewer").as_("viewer@acme.gov")
    async with viewer.client() as client:
        resp = await client.post(
            f"/api/systems/{system_id}/patch-campaigns",
            json={"name": "c", "window_start": str(TODAY), "window_end": str(TODAY)},
        )
        assert resp.status_code == 403


@pytest.mark.asyncio
async def test_a_campaign_with_no_open_flaws_is_a_conflict() -> None:
    async with session_scope() as session:
        org = Organization(name=f"PatchApiOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"Bare-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        system_id = sys_.id
    async with _client() as client:
        resp = await client.post(
            f"/api/systems/{system_id}/patch-campaigns",
            json={"name": "empty", "window_start": str(TODAY), "window_end": str(TODAY)},
        )
        assert resp.status_code == 409
        assert "no open scan-sourced findings" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_completing_a_wave_is_role_gated() -> None:
    """Tries both directions, not just a role that was never going to be
    allowed: the PR #20 review found the original version of this test only
    tried "viewer", which 403s identically whether ``PATCHER_ROLES`` is
    correct or is the old ``("admin", "issm", "isso")`` (none of which
    "viewer" is either way) -- so it could not have caught
    ``control_owner``, the role the fix was actually about, being silently
    locked out. "assessor" is a real, distinct role that must also stay
    excluded (see the justification on ``PATCHER_ROLES``), and
    "control_owner" must be let through.
    """
    system_id, org_id = await _system_with_flaws(3)
    author = _Session(org_id=org_id, role="control_owner")
    async with author.client() as client:
        waves = (
            await client.post(
                f"/api/systems/{system_id}/patch-campaigns",
                json={"name": "c", "window_start": str(TODAY), "window_end": str(TODAY)},
            )
        ).json()["waves"]

    for role, wave in (("viewer", waves[0]), ("assessor", waves[0])):
        denied = _Session(org_id=org_id, role=role).as_(f"{role}@acme.gov")
        async with denied.client() as client:
            resp = await client.post(
                f"/api/patch-waves/{wave['id']}/complete", json={"evidence_ref": "CHG-1"}
            )
            assert resp.status_code == 403, (role, resp.text)
        async with session_scope() as db:
            row = (
                await db.execute(select(PatchWave).where(PatchWave.id == wave["id"]))
            ).scalar_one()
            assert row.status == "pending", f"a rejected {role} call changed nothing"

    allowed = _Session(org_id=org_id, role="control_owner").as_("owner@acme.gov")
    async with allowed.client() as client:
        resp = await client.post(
            f"/api/patch-waves/{waves[0]['id']}/complete", json={"evidence_ref": "CHG-1"}
        )
        assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_listing_filters_by_system() -> None:
    """Two systems, so the filter must exclude."""
    mine, _org_id = await _system_with_flaws(2)
    theirs, _ = await _system_with_flaws(2)
    async with _client() as client:
        for system_id in (mine, theirs):
            await client.post(
                f"/api/systems/{system_id}/patch-campaigns",
                json={"name": "c", "window_start": str(TODAY), "window_end": str(TODAY)},
            )
        listed = (
            await client.get("/api/patch-campaigns", params={"system_id": mine})
        ).json()
        assert {c["system_id"] for c in listed} == {mine}


@pytest.mark.asyncio
async def test_an_unknown_system_and_campaign_are_not_found() -> None:
    async with _client() as client:
        assert (
            await client.get("/api/systems/9999999/flaw-remediation")
        ).status_code == 404
        assert (await client.get("/api/patch-campaigns/9999999")).status_code == 404
        assert (
            await client.post("/api/patch-waves/9999999/complete", json={})
        ).status_code == 404


@pytest.mark.asyncio
async def test_a_scoped_principal_cannot_reach_another_tenants_campaign() -> None:
    """Exercised directly: the default client is a global principal, so the
    cross-tenant branch is unreachable through it."""
    system_id, org_id = await _system_with_flaws(2)
    session = _Session(org_id=org_id, role="admin")
    async with session.client() as client:
        campaign_id = (
            await client.post(
                f"/api/systems/{system_id}/patch-campaigns",
                json={"name": "c", "window_start": str(TODAY), "window_end": str(TODAY)},
            )
        ).json()["id"]
    async with session_scope() as db:
        intruder = Principal(
            user_id=1, email="other@example.gov", org_id=org_id + 1000, role="admin"
        )
        with pytest.raises(HTTPException) as caught:
            await _owned_campaign(db, campaign_id, intruder)
        assert caught.value.status_code == 404
        owner = Principal(user_id=2, email="o@example.gov", org_id=org_id, role="admin")
        assert (await _owned_campaign(db, campaign_id, owner)).id == campaign_id


@pytest.mark.asyncio
async def test_completing_a_wave_with_no_evidence_is_refused() -> None:
    """CRITICAL 3 (PR #20 review): ``POST .../complete`` with body ``{}`` used
    to set status=completed, completed_at, completed_by, evidence_ref=None --
    nothing enforced the PR's own claim that a wave records completion "with
    evidence"."""
    system_id, org_id = await _system_with_flaws(2)
    session = _Session(org_id=org_id, role="control_owner")
    async with session.client() as client:
        waves = (
            await client.post(
                f"/api/systems/{system_id}/patch-campaigns",
                json={"name": "c", "window_start": str(TODAY), "window_end": str(TODAY)},
            )
        ).json()["waves"]
        resp = await client.post(f"/api/patch-waves/{waves[0]['id']}/complete", json={})
        assert resp.status_code == 409
        assert "requires evidence_ref" in resp.json()["detail"]
    async with session_scope() as db:
        row = (
            await db.execute(select(PatchWave).where(PatchWave.id == waves[0]["id"]))
        ).scalar_one()
        assert row.status == "pending"


@pytest.mark.asyncio
async def test_completing_a_wave_citing_an_unapplied_plan_is_refused() -> None:
    """CRITICAL 2 (PR #20 review): assigning ``remediation_plan_id`` had no
    validation at all -- no tenant check, no status check -- so a tenant
    could complete a wave citing a ``refused`` plan, or one belonging to
    another organization, and the row would read to an assessor as "applied
    by enforcement plan N" when it never ran."""
    system_id, org_id = await _system_with_flaws(2)
    async with session_scope() as db:
        plan = RemediationPlan(
            organization_id=org_id,
            system_id=system_id,
            check_key="demo.check",
            provider_key="demo",
            status="refused",
        )
        db.add(plan)
        await db.flush()
        plan_id = plan.id
    session = _Session(org_id=org_id, role="control_owner")
    async with session.client() as client:
        waves = (
            await client.post(
                f"/api/systems/{system_id}/patch-campaigns",
                json={"name": "c", "window_start": str(TODAY), "window_end": str(TODAY)},
            )
        ).json()["waves"]
        resp = await client.post(
            f"/api/patch-waves/{waves[0]['id']}/complete",
            json={"remediation_plan_id": plan_id},
        )
        assert resp.status_code == 409
        assert "not an applied plan" in resp.json()["detail"]
    async with session_scope() as db:
        row = (
            await db.execute(select(PatchWave).where(PatchWave.id == waves[0]["id"]))
        ).scalar_one()
        assert row.status == "pending"


@pytest.mark.asyncio
async def test_a_reopened_poam_is_not_reported_as_remediated() -> None:
    """CRITICAL 1 (PR #20 review): ``sla.classify`` branched on
    ``closed_on is not None`` before consulting status, so a POA&M closed
    fast and later reopened (status back to "open") through
    ``PATCH /api/poams/{id}`` -- which, before this fix, set status without
    clearing ``closed_on`` -- still classified as ``closed_on_time`` while
    it sat open and breaching, overstating SI-2 compliance. Demonstrates the
    full human-facing path: close, reopen via PATCH, and confirm the report
    reflects the truth afterward.
    """
    system_id, _org_id = await _system_with_flaws(0)
    async with session_scope() as session:
        poam = POAM(
            system_id=system_id,
            title="reopened-flaw",
            severity="critical",
            status="completed",
            source="scan",
            identified_on=TODAY - timedelta(days=404),
            closed_on=TODAY - timedelta(days=400),  # closed in 4 days -- fast
        )
        session.add(poam)
        await session.flush()
        poam_id = poam.id

    async with _client() as client:
        before = await client.get(f"/api/systems/{system_id}/flaw-remediation")
        assert before.json()["buckets"]["closed_on_time"] == 1

        reopened = await client.patch(f"/api/poams/{poam_id}", json={"status": "open"})
        assert reopened.status_code == 200, reopened.text
        assert reopened.json()["closed_on"] is None, (
            "PATCH /api/poams/{id} must clear a stale closed_on on reopen, "
            "matching ingest/scanners.py's reopen path"
        )

        after = await client.get(f"/api/systems/{system_id}/flaw-remediation")
        body = after.json()
        assert body["buckets"]["closed_on_time"] == 0
        assert body["buckets"]["breached"] == 1
        assert poam_id in body["breaching_ids"]
        assert body["compliance_pct"] == 0.0
