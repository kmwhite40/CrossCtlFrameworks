"""A SPRS state records who decided it, and the score says what it rests on.

The profile derivation writes an implementation state for all 110 CMMC
practices from the intake answers plus a vendor shared-responsibility placemat.
Those states earn SPRS credit exactly as an assessed state does, so a score
computed from a questionnaire rendered as though an assessor had produced it --
on the tenant this was found in, 25 of 110 points on the live system, including
the SSP prerequisite that a DoD assessment cannot be scored without.

Provenance also used to live only in the ``notes`` prose, and nothing cleared
it when a person changed the state afterwards: three rows read
``derived: platform:m365_gcc_high`` while holding ``implemented``, a state the
derivation cannot produce. Microsoft was being credited for somebody's claim.
"""

from __future__ import annotations

import os
import uuid
from datetime import date

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.analytics.posture import systems_scorecard
from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance import automation as automation_engine
from ccf.models import (
    Organization,
    ScoringControl,
    ScoringStatus,
    System,
    SystemProfile,
    User,
)
from ccf.scoring.engine import ASSESSED, DERIVED, SSP_CONTROL_ID
from ccf.scoring.seed import seed_scoring_controls
from ccf.scoring.service import (
    record_assessed_state,
    record_derived_state,
    system_score_summary,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _auth():
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _org_admin_system(label: str) -> tuple[int, int, str]:
    """An organization, a system in it, a seeded matrix, and an admin token."""
    async with session_scope() as s:
        await seed_scoring_controls(s)
        org = Organization(name=f"{label} {uuid.uuid4().hex[:6]}")
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name=f"Sys {uuid.uuid4().hex[:6]}")
        s.add(system)
        user = User(
            email=f"a-{uuid.uuid4().hex[:6]}@prov.test",
            organization_id=org.id,
            role="admin",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        await s.flush()
        return org.id, system.id, user.api_token


async def _derive(org_id: int, system_id: int, platform: str = "m365_gcc_high") -> dict:
    async with session_scope() as s:
        profile = SystemProfile(
            system_id=system_id,
            answers={"system_name": "t"},
            environment_type="cloud",
            cloud_platform=platform,
            identity_model="entra",
            connectivity="internet",
        )
        s.add(profile)
        await s.flush()
        return await automation_engine.derive_system(
            s, system_id=system_id, org_id=org_id, profile=profile, create_poams=False
        )


async def _status(system_id: int, control_id: str) -> ScoringStatus:
    async with session_scope() as s:
        return (
            await s.execute(
                select(ScoringStatus)
                .join(ScoringControl, ScoringControl.id == ScoringStatus.scoring_control_id)
                .where(ScoringStatus.system_id == system_id)
                .where(ScoringControl.control_id == control_id)
            )
        ).scalars().one()


# ---------------------------------------------------------------------------
# The derivation labels what it writes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deriving_a_profile_labels_every_state_it_writes_as_derived() -> None:
    org_id, system_id, _ = await _org_admin_system("Prov Derive")
    result = await _derive(org_id, system_id)

    async with session_scope() as s:
        rows = (
            await s.execute(
                select(ScoringStatus.source).where(ScoringStatus.system_id == system_id)
            )
        ).scalars().all()
    assert rows, "the derivation wrote no states at all"
    assert set(rows) == {DERIVED}, "a state nobody assessed is labelled assessed"

    # And the derivation reports what its score rests on, so a caller that
    # renders `sprs_score` has the qualifier in the same payload.
    assert result["sprs_derived_credit"] > 0
    assert result["sprs_derived_controls"] == len(rows)
    assert result["sprs_assessed_controls"] == 0


@pytest.mark.asyncio
async def test_the_m365_placemat_asserts_the_ssp_prerequisite_and_says_so() -> None:
    """CA.L2-3.12.4 is "Shared Coverage" -> `partial` -> `ssp_present` True.

    Answering "Microsoft 365 GCC High" on an intake form therefore satisfied
    the one prerequisite 32 CFR 170.24 will not let an assessment proceed
    without, with no SSP anywhere in the database. The claim is the customer's
    to make; being unable to see where it came from was the defect.
    """
    org_id, system_id, _ = await _org_admin_system("Prov SSP")
    result = await _derive(org_id, system_id)

    assert result["ssp_present"] is True
    assert result["ssp_present_source"] == DERIVED

    summary = None
    async with session_scope() as s:
        summary = await system_score_summary(s, system_id)
    assert summary["ssp_present"] is True
    assert summary["ssp_present_source"] == DERIVED


@pytest.mark.asyncio
async def test_the_derivations_reported_score_matches_the_stored_one() -> None:
    """Two views of the same rows must not disagree.

    `derive_system` scored the states its rules computed, while the database
    kept a human's state where one already stood -- so the SPRS number it
    returned could differ from the one every other surface computes from the
    stored rows.
    """
    org_id, system_id, _ = await _org_admin_system("Prov Agree")
    await _derive(org_id, system_id)

    # A human contradicts the placemat on a physical-protection practice.
    st = await _status(system_id, "PE.L2-3.10.1")
    async with session_scope() as s:
        row = await s.get(ScoringStatus, st.id)
        record_assessed_state(row, "not_implemented")

    # Re-deriving must not clobber that, and must score what is stored.
    async with session_scope() as s:
        profile = (
            await s.execute(select(SystemProfile).where(SystemProfile.system_id == system_id))
        ).scalars().one()
        again = await automation_engine.derive_system(
            s, system_id=system_id, org_id=org_id, profile=profile, create_poams=False
        )
        stored = await system_score_summary(s, system_id)

    assert again["sprs_score"] == stored["score"]
    assert again["sprs_derived_credit"] == stored["derived_credit"]
    after = await _status(system_id, "PE.L2-3.10.1")
    assert after.state == "not_implemented", "the derivation overwrote a human assessment"
    assert after.source == ASSESSED


# ---------------------------------------------------------------------------
# Setting a state takes provenance with it
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_human_state_stops_crediting_the_platform_over_the_api() -> None:
    org_id, system_id, token = await _org_admin_system("Prov Api")
    await _derive(org_id, system_id)
    before = await _status(system_id, "PE.L2-3.10.1")
    assert before.source == DERIVED
    assert before.derived_from == "platform:m365_gcc_high"
    assert (before.notes or "").startswith("derived: ")

    async with _client() as c:
        r = await c.put(
            f"/api/scoring/systems/{system_id}/controls/PE.L2-3.10.1",
            json={"state": "implemented"},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code == 200, r.text

    after = await _status(system_id, "PE.L2-3.10.1")
    assert after.state == "implemented"
    assert after.source == ASSESSED
    assert after.derived_from is None
    assert after.notes is None, "the derivation's label outlived the state it described"


@pytest.mark.asyncio
async def test_a_human_state_stops_crediting_the_platform_over_the_matrix_ui() -> None:
    """The HTMX matrix is a second write path; it was the one nobody guarded."""
    org_id, system_id, token = await _org_admin_system("Prov Ui")
    await _derive(org_id, system_id)

    async with _client() as c:
        r = await c.post(
            f"/scoring/{system_id}/state",
            data={"control_id": "PE.L2-3.10.2", "state": "implemented"},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code == 200, r.text

    after = await _status(system_id, "PE.L2-3.10.2")
    assert after.state == "implemented"
    assert after.source == ASSESSED
    assert after.derived_from is None


@pytest.mark.asyncio
async def test_a_note_the_caller_wrote_is_never_discarded() -> None:
    """Only the derivation's own prose is cleared -- a person's note is theirs."""
    org_id, system_id, token = await _org_admin_system("Prov Note")
    await _derive(org_id, system_id)

    async with _client() as c:
        r = await c.put(
            f"/api/scoring/systems/{system_id}/controls/PE.L2-3.10.3",
            json={"state": "implemented", "notes": "Verified against the CRM on 2026-09-25"},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code == 200, r.text
    after = await _status(system_id, "PE.L2-3.10.3")
    assert after.notes == "Verified against the CRM on 2026-09-25"
    assert after.source == ASSESSED


@pytest.mark.asyncio
async def test_a_derived_state_keeps_its_label_across_a_re_derivation() -> None:
    org_id, system_id, _ = await _org_admin_system("Prov Relabel")
    await _derive(org_id, system_id)
    async with session_scope() as s:
        profile = (
            await s.execute(select(SystemProfile).where(SystemProfile.system_id == system_id))
        ).scalars().one()
        await automation_engine.derive_system(
            s, system_id=system_id, org_id=org_id, profile=profile, create_poams=False
        )
    row = await _status(system_id, SSP_CONTROL_ID)
    assert row.source == DERIVED
    assert row.derived_from == "platform:m365_gcc_high"


# ---------------------------------------------------------------------------
# What the surfaces show
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_scorecard_separates_reviewed_practices_from_derived_ones() -> None:
    """`controls_assessed` counted derived rows, so a questionnaire read 110/110."""
    org_id, system_id, _ = await _org_admin_system("Prov Card")
    await _derive(org_id, system_id)

    async with session_scope() as s:
        cards = await systems_scorecard(s, today=date.today(), org_id=org_id)
    card = next(c for c in cards if c["system_id"] == system_id)

    assert card["controls_assessed"] == 110, "the derivation states a value for every practice"
    assert card["controls_reviewed"] == 0, "nobody assessed anything, and the card said 110"
    assert card["derived_credit"] > 0
    assert card["ssp_present_source"] == DERIVED


@pytest.mark.asyncio
async def test_the_scoring_page_names_the_derived_share_of_the_score() -> None:
    org_id, system_id, token = await _org_admin_system("Prov Page")
    result = await _derive(org_id, system_id)

    async with _client() as c:
        r = await c.get(
            f"/scoring?system_id={system_id}", headers={"Authorization": f"Bearer {token}"}
        )
    assert r.status_code == 200
    assert "Projected from the system profile" in r.text, (
        "a score built entirely from an intake answer rendered as an assessment"
    )
    assert "asserted by the platform profile" in r.text, "the SSP claim is unqualified"
    assert str(result["sprs_derived_credit"]) in r.text


@pytest.mark.asyncio
async def test_record_derived_state_and_record_assessed_state_are_inverses() -> None:
    """The two writers are the only places provenance is set; pin both."""
    _org_id, system_id, _ = await _org_admin_system("Prov Writers")
    async with session_scope() as s:
        ctrl = (
            await s.execute(
                select(ScoringControl).where(ScoringControl.control_id == "PE.L2-3.10.1")
            )
        ).scalars().one()
        row = ScoringStatus(system_id=system_id, scoring_control_id=ctrl.id)
        s.add(row)
        record_derived_state(row, "inherited", derived_from="vendor:Acme")
        assert (row.state, row.source, row.derived_from) == ("inherited", DERIVED, "vendor:Acme")
        assert row.notes == "derived: vendor:Acme"

        record_assessed_state(row, "partial")
        assert (row.state, row.source, row.derived_from) == ("partial", ASSESSED, None)
        assert row.notes is None
