"""Typed AI actions — stub run, citations, approval mutation, guardrails, RLS."""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.ai_actions import run_action, service
from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import (
    POAM,
    Control,
    ControlImplementation,
    Organization,
    System,
    Vendor,
)
from ccf.models_ai_actions import AiActionRun, AiGuardrailViolation
from ccf.models_evidence import EvidenceObject
from ccf.models_tprm import QuestionnaireResponse, VendorQuestionnaire

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _system(name: str) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"{name}-sys", baseline="moderate")
        s.add(sysm)
        await s.flush()
        return org.id, sysm.id


# --- list + stub run + hashes -----------------------------------------------


@pytest.mark.asyncio
async def test_list_and_stub_run_stores_hashes() -> None:
    _org_id, sys_id = await _system("AiOrgA")
    async with _client() as c:
        actions = (await c.get("/api/ai-actions")).json()
        assert any(a["key"] == "explain_failed_ksi" for a in actions)

        r = await c.post(
            "/api/ai-actions/generate_assessor_brief/run",
            json={"entity_type": "system", "entity_id": str(sys_id)},
        )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["status"] == "completed"  # advisory action, no approval needed
        assert body["input_hash"] and body["output_hash"]
        assert body["outputs"][0]["content"].startswith("[generate_assessor_brief]")


# --- citations ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_citations_stored_from_evidence() -> None:
    org_id, sys_id = await _system("AiOrgCite")
    async with session_scope() as s:
        s.add(EvidenceObject(organization_id=org_id, system_id=sys_id, title="IAM export"))
        control = (await s.execute(select(Control).limit(1))).scalar_one_or_none()
        if control is None:
            control = Control(identifier="AC-2", control_name="Account Management")
            s.add(control)
            await s.flush()
        impl = ControlImplementation(system_id=sys_id, control_id=control.id, status="implemented")
        s.add(impl)
        await s.flush()
        impl_id = impl.id
    async with _client() as c:
        r = await c.post(
            "/api/ai-actions/find_evidence_for_control/run",
            json={"entity_type": "control", "entity_id": str(impl_id)},
        )
        assert r.status_code == 201, r.text
        assert len(r.json()["citations"]) >= 1


# --- approval mutation -------------------------------------------------------


@pytest.mark.asyncio
async def test_approval_applies_poam_remediation() -> None:
    _org_id, sys_id = await _system("AiOrgMutate")
    async with session_scope() as s:
        poam = POAM(system_id=sys_id, title="Patch server", severity="high", status="open")
        s.add(poam)
        await s.flush()
        poam_id = poam.id
    async with _client() as c:
        run = (
            await c.post(
                "/api/ai-actions/draft_poam_remediation/run",
                json={"entity_type": "poam", "entity_id": str(poam_id)},
            )
        ).json()
        assert run["status"] == "pending_review"
        approved = await c.post(f"/api/ai-actions/runs/{run['id']}/approve")
        assert approved.status_code == 200, approved.text
        assert approved.json()["status"] == "approved"
        assert approved.json()["mutation_applied"] is True
    async with session_scope() as s:
        poam = await s.get(POAM, poam_id)
        assert poam.remediation_plan is not None


# --- rejection preserves record ---------------------------------------------


@pytest.mark.asyncio
async def test_rejection_preserves_output() -> None:
    _org_id, sys_id = await _system("AiOrgReject")
    async with session_scope() as s:
        poam = POAM(system_id=sys_id, title="X", severity="low", status="open")
        s.add(poam)
        await s.flush()
        poam_id = poam.id
    async with _client() as c:
        run = (
            await c.post(
                "/api/ai-actions/draft_poam_remediation/run",
                json={"entity_type": "poam", "entity_id": str(poam_id)},
            )
        ).json()
        rej = await c.post(f"/api/ai-actions/runs/{run['id']}/reject", json={"note": "wrong"})
        assert rej.json()["status"] == "rejected"
        assert rej.json()["outputs"][0]["content"]  # output preserved
    async with session_scope() as s:
        poam = await s.get(POAM, poam_id)
        assert poam.remediation_plan is None  # rejection applied no mutation


# --- guardrail: uncited citation-required action cannot be approved ----------


@pytest.mark.asyncio
async def test_uncited_action_blocks_approval() -> None:
    org_id, _sys_id = await _system("AiOrgUncited")
    async with session_scope() as s:
        v = Vendor(organization_id=org_id, name="V")
        s.add(v)
        await s.flush()
        q = VendorQuestionnaire(organization_id=org_id, vendor_id=v.id, name="Q", status="sent")
        s.add(q)
        await s.flush()
        resp = QuestionnaireResponse(
            questionnaire_id=q.id, question_id="GOV-01", question_text="Do you?",
            answer="unanswered",
        )
        s.add(resp)
        await s.flush()
        resp_id = resp.id
    async with _client() as c:
        run = (
            await c.post(
                "/api/ai-actions/draft_questionnaire_answer/run",
                json={"entity_type": "questionnaire_response", "entity_id": str(resp_id)},
            )
        ).json()
        assert run["outputs"][0]["uncited"] is True  # no evidence → uncited
        blocked = await c.post(f"/api/ai-actions/runs/{run['id']}/approve")
        assert blocked.status_code == 409
    async with session_scope() as s:
        run_row = await s.get(AiActionRun, run["id"])
        assert run_row.status == "blocked"
        violations = (
            await s.execute(
                select(AiGuardrailViolation).where(AiGuardrailViolation.run_id == run["id"])
            )
        ).scalars().all()
        assert any(v.kind == "unapproved_mutation" for v in violations)


# --- guardrail: cross-tenant retrieval refused ------------------------------


@pytest.mark.asyncio
async def test_cross_tenant_retrieval_refused() -> None:
    org_a, _sa = await _system("AiOrgTenantA")
    _org_b, sys_b = await _system("AiOrgTenantB")
    async with session_scope() as s:
        poam_b = POAM(system_id=sys_b, title="B-only", severity="high", status="open")
        s.add(poam_b)
        await s.flush()
        poam_b_id = poam_b.id
    # Org A tries to run against org B's POA&M → refused + recorded.
    async with session_scope() as s:
        with pytest.raises(service.AiActionError, match="cross-tenant"):
            await run_action(
                s, action_key="draft_poam_remediation", entity_type="poam",
                entity_id=str(poam_b_id), org_id=org_a, actor="attacker",
            )
        await s.commit()
    async with session_scope() as s:
        violations = (
            await s.execute(
                select(AiGuardrailViolation).where(AiGuardrailViolation.kind == "cross_tenant")
            )
        ).scalars().all()
        assert violations


@pytest.mark.asyncio
async def test_ai_disabled_is_default() -> None:
    assert get_settings().ai_enabled is False  # safe default
