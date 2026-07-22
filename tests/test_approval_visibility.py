"""ISSM-07: approval decisions must be visible on the governed record.

``decide()`` in ccf.governance.approvals writes the Approval sidecar row and,
for ssp_project only, stamped the entity's own status. Approving a poam/risk/
assessment left the decision invisible anywhere except the Approval table.
These tests exercise the real approval flow (submit -> approve/reject via the
HTTP API) and assert the decision now shows up in the entity's own API
payload (``approval_state``), without the visibility mechanism fabricating a
terminal status transition the closure/acceptance gates own.
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance import approvals
from ccf.models import Organization, SSPProject, System

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _make_system(name: str) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"{name} system")
        s.add(sysm)
        await s.flush()
        return org.id, sysm.id


@pytest.mark.asyncio
async def test_poam_starts_with_draft_approval_state() -> None:
    _, sys_id = await _make_system("PoamVisOrg1")
    async with _client() as c:
        created = await c.post("/api/poams", json={"system_id": sys_id, "title": "Weak spot"})
        assert created.json()["approval_state"] == "draft"

        pid = created.json()["id"]
        fetched = await c.get(f"/api/poams/{pid}")
        assert fetched.json()["approval_state"] == "draft"


@pytest.mark.asyncio
async def test_poam_approval_reflects_onto_entity_payload_via_production_flow() -> None:
    """Approve a POA&M through the real /api/approvals flow (single-operator
    mode: no SoD) and confirm the decision surfaces on the POA&M's own record —
    in the single GET, the list endpoint, and the CSV/list-adjacent paths —
    not just in the Approval table."""
    _, sys_id = await _make_system("PoamVisOrg2")
    async with _client() as c:
        created = await c.post("/api/poams", json={"system_id": sys_id, "title": "Weak spot"})
        pid = created.json()["id"]

        submitted = await c.post(f"/api/approvals/poam/{pid}/submit")
        assert submitted.status_code == 200, submitted.text
        after_submit = await c.get(f"/api/poams/{pid}")
        assert after_submit.json()["approval_state"] == "submitted"
        # Not fabricating a terminal transition: status is untouched.
        assert after_submit.json()["status"] == "open"

        approved = await c.post(f"/api/approvals/poam/{pid}/approve")
        assert approved.status_code == 200, approved.text
        assert approved.json()["state"] == "approved"

        after_approve = await c.get(f"/api/poams/{pid}")
        assert after_approve.json()["approval_state"] == "approved"
        # Still just visibility — the closure gate, not this task, owns 'closed'.
        assert after_approve.json()["status"] == "open"

        listed = await c.get("/api/poams", params={"system_id": sys_id})
        by_id = {p["id"]: p for p in listed.json()}
        assert by_id[pid]["approval_state"] == "approved"


@pytest.mark.asyncio
async def test_poam_rejection_reflects_onto_entity_payload() -> None:
    _, sys_id = await _make_system("PoamVisOrg3")
    async with _client() as c:
        created = await c.post("/api/poams", json={"system_id": sys_id, "title": "Weak spot"})
        pid = created.json()["id"]
        await c.post(f"/api/approvals/poam/{pid}/submit")
        rejected = await c.post(f"/api/approvals/poam/{pid}/reject", json={"note": "insufficient"})
        assert rejected.status_code == 200, rejected.text

        fetched = await c.get(f"/api/poams/{pid}")
        assert fetched.json()["approval_state"] == "rejected"
        assert fetched.json()["status"] == "open"  # no fabricated transition


@pytest.mark.asyncio
async def test_risk_approval_reflects_onto_entity_payload_via_production_flow() -> None:
    _, sys_id = await _make_system("RiskVisOrg1")
    async with _client() as c:
        created = await c.post(
            "/api/risks",
            json={
                "title": "Vendor exposure",
                "system_id": sys_id,
                "likelihood": "moderate",
                "impact": "high",
            },
        )
        rid = created.json()["id"]
        assert created.json()["approval_state"] == "draft"

        await c.post(f"/api/approvals/risk/{rid}/submit")
        approved = await c.post(f"/api/approvals/risk/{rid}/approve")
        assert approved.status_code == 200, approved.text

        fetched = await c.get(f"/api/risks/{rid}")
        assert fetched.json()["approval_state"] == "approved"
        # Visibility only: acceptance gate (ISSM-08/09) still owns 'accepted'.
        assert fetched.json()["status"] == "open"

        listed = await c.get("/api/risks", params={"system_id": sys_id})
        by_id = {r["id"]: r for r in listed.json()}
        assert by_id[rid]["approval_state"] == "approved"

        heat = await c.get("/api/risks/heatmap")
        top_by_id = {r["id"]: r for r in heat.json()["top"]}
        assert top_by_id[rid]["approval_state"] == "approved"


@pytest.mark.asyncio
async def test_assessment_approval_reflects_onto_entity_payload() -> None:
    _, sys_id = await _make_system("AssessVisOrg1")
    async with _client() as c:
        created = await c.post(
            "/api/assessments", json={"system_id": sys_id, "kind": "self", "name": "Self assess"}
        )
        aid = created.json()["id"]
        assert created.json()["approval_state"] == "draft"

        await c.post(f"/api/approvals/assessment/{aid}/submit")
        approved = await c.post(f"/api/approvals/assessment/{aid}/approve")
        assert approved.status_code == 200, approved.text

        fetched = await c.get(f"/api/assessments/{aid}")
        assert fetched.json()["assessment"]["approval_state"] == "approved"

        listed = await c.get("/api/assessments")
        by_id = {a["id"]: a for a in listed.json()}
        assert by_id[aid]["approval_state"] == "approved"


@pytest.mark.asyncio
async def test_ssp_project_approval_still_stamps_status_directly() -> None:
    """Existing behavior (ISSM-07 predates this task for ssp_project): approving
    an ssp_project keeps stamping the project's own status, unaffected by the
    new read-time visibility mechanism for poam/risk/assessment."""
    org_id, sys_id = await _make_system("SspVisOrg1")
    async with session_scope() as s:
        proj = SSPProject(
            organization_id=org_id, system_id=sys_id, customer_name="Project A", status="draft"
        )
        s.add(proj)
        await s.flush()
        proj_id = proj.id

    async with session_scope() as s:
        await approvals.submit(s, entity_type="ssp_project", entity_id=str(proj_id), actor="alice")
        await approvals.decide(
            s,
            entity_type="ssp_project",
            entity_id=str(proj_id),
            approve=True,
            actor="bob",
            role="admin",
        )

    async with session_scope() as s:
        refreshed = await s.get(SSPProject, proj_id)
        assert refreshed is not None
        assert refreshed.status == "approved"
