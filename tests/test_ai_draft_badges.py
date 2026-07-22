"""CISO-02: AI-drafted/unreviewed content must be visibly distinguishable in
the UI. Assert the "AI-assisted / draft — needs review" badge appears in the
*rendered* SSP and POA&M pages for draft/AI-sourced entries and is absent for
approved/human ones — per entry, not once per page.
"""

from __future__ import annotations

import re

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import POAM, Organization, SSPControlEntry, SSPProject, System
from ccf.ssp.statements import DRAFT_PREFIX

pytestmark = pytest.mark.usefixtures("fresh_engine")

BADGE = "AI-assisted / draft — needs review"


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _org_and_system(name: str) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"{name}-sys", baseline="moderate")
        s.add(sysm)
        await s.flush()
        return org.id, sysm.id


def _entry_segments(html: str, project_id: int) -> list[str]:
    """Split the SSP detail page into one HTML chunk per control entry.

    Each entry's ``<form>`` opens with a unique
    ``action="/ssp/{project_id}/entry/{entry_id}"`` — splitting on that marker
    isolates one entry's control id, narrative, and badge from its neighbors.
    """
    marker = f'action="/ssp/{project_id}/entry/'
    parts = html.split(marker)
    return parts[1:]  # parts[0] is page preamble before the first entry form


# --- SSP: draft narrative shows the badge, approved narrative does not -----


@pytest.mark.asyncio
async def test_ssp_draft_entry_shows_badge_approved_entry_does_not() -> None:
    org_id, sys_id = await _org_and_system("BadgeSspOrg")
    async with session_scope() as s:
        proj = SSPProject(organization_id=org_id, system_id=sys_id, customer_name="Badge Co")
        s.add(proj)
        await s.flush()
        draft = SSPControlEntry(
            project_id=proj.id,
            control_id="AC.L2-DRAFT",
            nist_id="3.1.1",
            domain="AC",
            title="Draft control",
            sort_order=1,
            part_narratives=[
                {"label": "Implementation", "text": DRAFT_PREFIX + "The organization configures X."}
            ],
        )
        approved = SSPControlEntry(
            project_id=proj.id,
            control_id="AC.L2-APPROVED",
            nist_id="3.1.2",
            domain="AC",
            title="Approved control",
            sort_order=2,
            part_narratives=[
                {
                    "label": "Implementation",
                    "text": "The organization implements the control by configuring Y.",
                }
            ],
        )
        s.add_all([draft, approved])
        await s.flush()
        proj_id = proj.id

    async with _client() as c:
        r = await c.get(f"/ssp/{proj_id}")
        assert r.status_code == 200

    segments = _entry_segments(r.text, proj_id)
    assert len(segments) == 2
    draft_seg = next(seg for seg in segments if "AC.L2-DRAFT" in seg.split("</form>")[0])
    approved_seg = next(seg for seg in segments if "AC.L2-APPROVED" in seg.split("</form>")[0])

    assert BADGE in draft_seg
    assert BADGE not in approved_seg
    # per-entry, not once-per-page: exactly one occurrence across the whole page
    assert r.text.count(BADGE) == 1


# --- POA&M: AI-written remediation shows the badge, human-written does not -


@pytest.mark.asyncio
async def test_poam_ai_remediation_shows_badge_human_remediation_does_not() -> None:
    _org_id, sys_id = await _org_and_system("BadgePoamOrg")
    async with session_scope() as s:
        human_poam = POAM(
            system_id=sys_id,
            title="Human-reviewed weakness",
            severity="low",
            status="open",
            remediation_plan="Reviewed manually: patched the service and verified in staging.",
        )
        s.add(human_poam)
        ai_poam = POAM(
            system_id=sys_id, title="AI-drafted weakness", severity="high", status="open"
        )
        s.add(ai_poam)
        await s.flush()
        ai_id = ai_poam.id

    async with _client() as c:
        # Draft + approve a real AI action mutation so the badge is derived
        # from genuine ai_actions provenance, not a fabricated marker.
        run = (
            await c.post(
                "/api/ai-actions/draft_poam_remediation/run",
                json={"entity_type": "poam", "entity_id": str(ai_id)},
            )
        ).json()
        approved = await c.post(f"/api/ai-actions/runs/{run['id']}/approve")
        assert approved.status_code == 200, approved.text
        assert approved.json()["mutation_applied"] is True

        r = await c.get("/poams", params={"system_id": sys_id})
        assert r.status_code == 200

    rows = re.findall(r"<tr>.*?</tr>", r.text, flags=re.S)
    human_row = next(row for row in rows if "Human-reviewed weakness" in row)
    ai_row = next(row for row in rows if "AI-drafted weakness" in row)

    assert BADGE not in human_row
    assert BADGE in ai_row
    assert r.text.count(BADGE) == 1


# --- an AI-drafted remediation plan that's since been hand-edited loses the badge


@pytest.mark.asyncio
async def test_poam_hand_edited_after_ai_draft_loses_badge() -> None:
    _org_id, sys_id = await _org_and_system("BadgePoamEditOrg")
    async with session_scope() as s:
        poam = POAM(system_id=sys_id, title="Edited weakness", severity="moderate", status="open")
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
        approved = await c.post(f"/api/ai-actions/runs/{run['id']}/approve")
        assert approved.json()["mutation_applied"] is True

    async with session_scope() as s:
        poam = await s.get(POAM, poam_id)
        assert poam is not None
        poam.remediation_plan = "Human follow-up: rewrote the plan after review."

    async with _client() as c:
        r = await c.get("/poams", params={"system_id": sys_id})
        assert r.status_code == 200

    rows = re.findall(r"<tr>.*?</tr>", r.text, flags=re.S)
    row = next(row for row in rows if "Edited weakness" in row)
    assert BADGE not in row
    assert "Human follow-up" in row
