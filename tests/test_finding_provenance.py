"""ISSM-04/05: finding->risk/POA&M provenance, and the risk_accepted-POA&M gate.

Covers:
* accept-finding -> Risk (``POST /api/risks/from-finding/{id}``): the new Risk
  carries ``source_ref`` back to the finding, and the finding's ``risk_id``
  makes it traceable the other way — idempotent on re-accepting.
* promote-to-POA&M (``POST /api/audit/findings/{id}/promote-to-poam``): mirrors
  the assessment->POA&M pattern (ISSM-02) — provenanced via ``source_ref``,
  reachable both ways via ``finding.poam_id`` — idempotent on re-promoting.
* the risk_accepted-POA&M gate: reaching ``status='risk_accepted'`` via create
  or generic PATCH requires the same owner+expiry(+approval) discipline as
  Risk acceptance, closing the parallel-gate bypass.
"""

from __future__ import annotations

import os
from datetime import date, timedelta

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import POAM, Organization, System, User

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


async def _make_finding(
    c: AsyncClient, sys_id: int, title: str = "Weak access control"
) -> tuple[int, int]:
    """Create an engagement + one finding scoped to ``sys_id``.

    Returns ``(engagement_id, finding_id)``.
    """
    eng = await c.post("/api/audit/engagements", json={"name": f"Engagement for {title}"})
    eng_id = eng.json()["id"]
    finding = await c.post(
        f"/api/audit/engagements/{eng_id}/findings",
        json={"title": title, "severity": "high", "system_id": sys_id},
    )
    assert finding.status_code == 201, finding.text
    return eng_id, finding.json()["id"]


# --- accept-finding -> Risk (ISSM-05) ----------------------------------------


@pytest.mark.asyncio
async def test_accept_finding_creates_risk_with_origin() -> None:
    _org_id, sys_id = await _make_system("FindingRiskOrg1")
    async with _client() as c:
        _eng_id, find_id = await _make_finding(c, sys_id)

        r = await c.post(f"/api/risks/from-finding/{find_id}")
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["source"] == "audit_finding"
        assert body["source_ref"] == f"audit_finding:{find_id}"
        assert body["system_id"] == sys_id
        assert body["status"] == "open"  # not silently pre-accepted

        # visible from the finding, the other direction
        got_finding = await c.get(f"/api/audit/findings/{find_id}")
        assert got_finding.json()["risk_id"] == body["id"]


@pytest.mark.asyncio
async def test_accept_finding_missing_system_id_is_rejected() -> None:
    await _make_system("FindingRiskOrg2")
    async with _client() as c:
        eng = await c.post("/api/audit/engagements", json={"name": "Eng no system"})
        eng_id = eng.json()["id"]
        finding = await c.post(
            f"/api/audit/engagements/{eng_id}/findings",
            json={"title": "No system set", "severity": "moderate"},
        )
        find_id = finding.json()["id"]
        assert finding.json()["system_id"] is None

        r = await c.post(f"/api/risks/from-finding/{find_id}")
        assert r.status_code == 400, r.text


@pytest.mark.asyncio
async def test_accept_finding_twice_is_idempotent() -> None:
    _org_id, sys_id = await _make_system("FindingRiskOrg3")
    async with _client() as c:
        _eng_id, find_id = await _make_finding(c, sys_id)

        first = await c.post(f"/api/risks/from-finding/{find_id}")
        second = await c.post(f"/api/risks/from-finding/{find_id}")
        assert first.status_code == 201, first.text
        assert second.status_code == 201, second.text
        assert first.json()["id"] == second.json()["id"]


@pytest.mark.asyncio
async def test_accept_finding_not_found_is_404() -> None:
    async with _client() as c:
        r = await c.post("/api/risks/from-finding/999999")
        assert r.status_code == 404, r.text


# --- promote-to-POA&M (ISSM-04) ----------------------------------------------


@pytest.mark.asyncio
async def test_promote_finding_to_poam_is_provenanced_and_reachable_both_ways() -> None:
    _org_id, sys_id = await _make_system("FindingPoamOrg1")
    async with _client() as c:
        _eng_id, find_id = await _make_finding(c, sys_id, title="Unpatched host")

        r = await c.post(f"/api/audit/findings/{find_id}/promote-to-poam")
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["source"] == "audit_finding"
        assert body["source_ref"] == f"audit_finding:{find_id}"
        assert body["system_id"] == sys_id
        poam_id = body["id"]

        # reachable both ways: finding -> poam, and the poam exists with the
        # matching provenance
        got_finding = await c.get(f"/api/audit/findings/{find_id}")
        assert got_finding.json()["poam_id"] == poam_id

        got_poam = await c.get(f"/api/poams/{poam_id}")
        assert got_poam.status_code == 200, got_poam.text
        assert got_poam.json()["source_ref"] == f"audit_finding:{find_id}"


@pytest.mark.asyncio
async def test_promote_finding_missing_system_id_is_rejected() -> None:
    await _make_system("FindingPoamOrg2")
    async with _client() as c:
        eng = await c.post("/api/audit/engagements", json={"name": "Eng no system 2"})
        eng_id = eng.json()["id"]
        finding = await c.post(
            f"/api/audit/engagements/{eng_id}/findings",
            json={"title": "No system set", "severity": "moderate"},
        )
        find_id = finding.json()["id"]

        r = await c.post(f"/api/audit/findings/{find_id}/promote-to-poam")
        assert r.status_code == 400, r.text


@pytest.mark.asyncio
async def test_promote_finding_twice_does_not_duplicate() -> None:
    _org_id, sys_id = await _make_system("FindingPoamOrg3")
    async with _client() as c:
        _eng_id, find_id = await _make_finding(c, sys_id, title="Repeat me")

        first = await c.post(f"/api/audit/findings/{find_id}/promote-to-poam")
        second = await c.post(f"/api/audit/findings/{find_id}/promote-to-poam")
        assert first.status_code == 201, first.text
        assert second.status_code == 201, second.text
        assert first.json()["id"] == second.json()["id"]


@pytest.mark.asyncio
async def test_close_finding_without_closure_evidence_is_rejected() -> None:
    _org_id, sys_id = await _make_system("FindingCloseOrg1")
    async with _client() as c:
        _eng_id, find_id = await _make_finding(c, sys_id, title="Needs evidence to close")

        r = await c.patch(f"/api/audit/findings/{find_id}", json={"status": "closed"})
        assert r.status_code == 409, r.text

        r2 = await c.patch(
            f"/api/audit/findings/{find_id}",
            json={
                "status": "closed",
                "closure_evidence": "ticket JIRA-123, patched and re-scanned",
            },
        )
        assert r2.status_code == 200, r2.text
        assert r2.json()["status"] == "closed"


# --- risk_accepted-POA&M gate -------------------------------------------------


@pytest.mark.asyncio
async def test_patch_poam_to_risk_accepted_without_owner_or_due_on_is_blocked() -> None:
    _org_id, sys_id = await _make_system("PoamRiskAcceptOrg1")
    async with _client() as c:
        created = await c.post("/api/poams", json={"system_id": sys_id, "title": "Accepted risk"})
        pid = created.json()["id"]

        r = await c.patch(f"/api/poams/{pid}", json={"status": "risk_accepted"})
        assert r.status_code == 409, r.text

        got = await c.get(f"/api/poams/{pid}")
        assert got.json()["status"] == "open"  # unchanged


@pytest.mark.asyncio
async def test_patch_poam_to_risk_accepted_with_owner_but_no_due_on_is_blocked() -> None:
    _org_id, sys_id = await _make_system("PoamRiskAcceptOrg2")
    async with _client() as c:
        created = await c.post("/api/poams", json={"system_id": sys_id, "title": "Accepted risk"})
        pid = created.json()["id"]

        r = await c.patch(
            f"/api/poams/{pid}", json={"status": "risk_accepted", "owner_user_id": 999999}
        )
        assert r.status_code == 409, r.text


@pytest.mark.asyncio
async def test_patch_poam_to_risk_accepted_with_owner_and_due_on_but_no_rationale_is_blocked() -> (
    None
):
    """CR26's `acceptanceRationale` requirement (spec §5, §9.1): owner and due_on alone are not
    enough -- every accepted vulnerability needs a written rationale, and an
    admin who forgets it must be told now rather than have `merge_accepted`
    omit the row from the AVI later with no way to know why.
    """
    org_id, sys_id = await _make_system("PoamRiskAcceptOrg2b")
    async with session_scope() as s:
        u = User(
            organization_id=org_id,
            email="owner@poamriskacceptorg2b.example",
            role="control_owner",
            password_hash=hash_password("pw"),
        )
        s.add(u)
        await s.flush()
        owner_id = u.id

    async with _client() as c:
        created = await c.post("/api/poams", json={"system_id": sys_id, "title": "Accepted risk"})
        pid = created.json()["id"]

        r = await c.patch(
            f"/api/poams/{pid}",
            json={
                "status": "risk_accepted",
                "owner_user_id": owner_id,
                "due_on": str(date.today() + timedelta(days=180)),
            },
        )
        assert r.status_code == 409, r.text

        got = await c.get(f"/api/poams/{pid}")
        assert got.json()["status"] == "open"  # unchanged


@pytest.mark.asyncio
async def test_patch_poam_to_risk_accepted_blank_rationale_is_blocked_too() -> None:
    """Blank-or-missing, never a ``None`` test (mirrors ``ccf.cr26.ver.is_blank``,
    this codebase's established rule): whitespace persists as a "cleared"
    field with no strip, so `"   "` must be refused exactly like an absent
    field.
    """
    org_id, sys_id = await _make_system("PoamRiskAcceptOrg2c")
    async with session_scope() as s:
        u = User(
            organization_id=org_id,
            email="owner@poamriskacceptorg2c.example",
            role="control_owner",
            password_hash=hash_password("pw"),
        )
        s.add(u)
        await s.flush()
        owner_id = u.id

    async with _client() as c:
        created = await c.post("/api/poams", json={"system_id": sys_id, "title": "Accepted risk"})
        pid = created.json()["id"]

        r = await c.patch(
            f"/api/poams/{pid}",
            json={
                "status": "risk_accepted",
                "owner_user_id": owner_id,
                "due_on": str(date.today() + timedelta(days=180)),
                "acceptance_rationale": "   ",
            },
        )
        assert r.status_code == 409, r.text


@pytest.mark.asyncio
async def test_patch_poam_to_risk_accepted_succeeds_with_owner_due_on_and_rationale() -> None:
    org_id, sys_id = await _make_system("PoamRiskAcceptOrg3")
    async with session_scope() as s:
        u = User(
            organization_id=org_id,
            email="owner@poamriskacceptorg3.example",
            role="control_owner",
            password_hash=hash_password("pw"),
        )
        s.add(u)
        await s.flush()
        owner_id = u.id

    async with _client() as c:
        created = await c.post("/api/poams", json={"system_id": sys_id, "title": "Accepted risk"})
        pid = created.json()["id"]

        r = await c.patch(
            f"/api/poams/{pid}",
            json={
                "status": "risk_accepted",
                "owner_user_id": owner_id,
                "due_on": str(date.today() + timedelta(days=180)),
                "acceptance_rationale": "Compensating control: WAF rule 91234.",
            },
        )
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "risk_accepted"
        assert r.json()["acceptance_rationale"] == "Compensating control: WAF rule 91234."


@pytest.mark.asyncio
async def test_patch_poam_already_risk_accepted_with_no_rationale_stays_editable() -> None:
    """Grandfathering (spec §9.1): every ``risk_accepted`` POA&M that predates
    this column has ``acceptance_rationale IS NULL``, and the gate must not
    brick every one of them. The gate fires on the TRANSITION into
    `risk_accepted` -- a PATCH body that does not touch `status` at all must
    keep working exactly as it did before this change, mirroring
    ``test_patch_poam_non_terminal_edit_still_works_without_gate`` for the
    closure gate.
    """
    _org_id, sys_id = await _make_system("PoamRiskAcceptGrandfather")
    async with session_scope() as s:
        row = POAM(
            system_id=sys_id,
            title="Pre-existing accepted risk",
            status="risk_accepted",
            owner_user_id=None,
            due_on=date.today() + timedelta(days=90),
            acceptance_rationale=None,
        )
        s.add(row)
        await s.flush()
        pid = row.id

    async with _client() as c:
        r = await c.patch(f"/api/poams/{pid}", json={"severity": "critical"})
        assert r.status_code == 200, r.text
        assert r.json()["severity"] == "critical"
        assert r.json()["status"] == "risk_accepted"
        assert r.json()["acceptance_rationale"] is None


@pytest.mark.asyncio
async def test_patch_poam_already_risk_accepted_resending_status_also_stays_editable() -> None:
    """The transition-only guard's B case (Critical I2). Measured before the
    fix: `PATCH {"severity": "critical"}` on a legacy row succeeded, but
    `PATCH {"status": "risk_accepted", "severity": "high"}` -- exactly what a
    save-the-whole-form client sends -- was blocked with 409, because the
    gate fired on any write naming `risk_accepted` rather than the actual
    transition into it. The row is ALREADY `risk_accepted`; re-sending the
    same status is not a transition and must not require a rationale.
    """
    _org_id, sys_id = await _make_system("PoamRiskAcceptGrandfatherResend")
    async with session_scope() as s:
        row = POAM(
            system_id=sys_id,
            title="Pre-existing accepted risk",
            status="risk_accepted",
            owner_user_id=None,
            due_on=date.today() + timedelta(days=90),
            acceptance_rationale=None,
        )
        s.add(row)
        await s.flush()
        pid = row.id

    async with _client() as c:
        r = await c.patch(
            f"/api/poams/{pid}", json={"status": "risk_accepted", "severity": "high"}
        )
        assert r.status_code == 200, r.text
        assert r.json()["severity"] == "high"
        assert r.json()["status"] == "risk_accepted"
        assert r.json()["acceptance_rationale"] is None


@pytest.mark.asyncio
async def test_patch_poam_cannot_blank_the_rationale_while_risk_accepted() -> None:
    """Critical I3: the gate refuses a MISSING rationale on the transition in,
    but nothing stopped a later PATCH from blanking one that already existed
    -- `PATCH {"acceptance_rationale": "   "}` on an accepted row succeeded
    (200) and silently invalidated the row for the next AVI/ver_history seed,
    which would omit it with no warning at PATCH time. Refused regardless of
    whether `status` is in the body, since the row is risk_accepted either
    way.
    """
    org_id, sys_id = await _make_system("PoamRiskAcceptBlankOut")
    async with session_scope() as s:
        u = User(
            organization_id=org_id,
            email="owner@poamriskacceptblankout.example",
            role="control_owner",
            password_hash=hash_password("pw"),
        )
        s.add(u)
        await s.flush()
        owner_id = u.id

    async with _client() as c:
        created = await c.post("/api/poams", json={"system_id": sys_id, "title": "Accepted risk"})
        pid = created.json()["id"]
        r = await c.patch(
            f"/api/poams/{pid}",
            json={
                "status": "risk_accepted",
                "owner_user_id": owner_id,
                "due_on": str(date.today() + timedelta(days=180)),
                "acceptance_rationale": "Compensating control: WAF rule 91234.",
            },
        )
        assert r.status_code == 200, r.text

        blanked = await c.patch(f"/api/poams/{pid}", json={"acceptance_rationale": "   "})
        assert blanked.status_code == 409, blanked.text

        got = await c.get(f"/api/poams/{pid}")
        assert got.json()["acceptance_rationale"] == "Compensating control: WAF rule 91234."


@pytest.mark.asyncio
async def test_patch_poam_clears_the_rationale_on_any_transition_out_of_risk_accepted() -> None:
    """m4: reopening then re-accepting must not silently reuse the PREVIOUS
    acceptance's rationale for a NEW decision. Measured before the fix:
    "Reason A (2026 Q1)." survived open -> risk_accepted verbatim and would
    have been filed as the reason for a decision it was never written for --
    well-formed, validating, and untrue.
    """
    org_id, sys_id = await _make_system("PoamRiskAcceptClearOnExit")
    async with session_scope() as s:
        u = User(
            organization_id=org_id,
            email="owner@poamriskacceptclearonexit.example",
            role="control_owner",
            password_hash=hash_password("pw"),
        )
        s.add(u)
        await s.flush()
        owner_id = u.id

    async with _client() as c:
        created = await c.post("/api/poams", json={"system_id": sys_id, "title": "Accepted risk"})
        pid = created.json()["id"]
        accept = await c.patch(
            f"/api/poams/{pid}",
            json={
                "status": "risk_accepted",
                "owner_user_id": owner_id,
                "due_on": str(date.today() + timedelta(days=180)),
                "acceptance_rationale": "Reason A (2026 Q1).",
            },
        )
        assert accept.status_code == 200, accept.text

        reopened = await c.patch(f"/api/poams/{pid}", json={"status": "open"})
        assert reopened.status_code == 200, reopened.text
        assert reopened.json()["acceptance_rationale"] is None

        # Re-accepting without a fresh rationale is blocked -- the old one is
        # truly gone, not merely hidden from the read.
        blocked = await c.patch(
            f"/api/poams/{pid}",
            json={
                "status": "risk_accepted",
                "owner_user_id": owner_id,
                "due_on": str(date.today() + timedelta(days=180)),
            },
        )
        assert blocked.status_code == 409, blocked.text

        reaccepted = await c.patch(
            f"/api/poams/{pid}",
            json={
                "status": "risk_accepted",
                "owner_user_id": owner_id,
                "due_on": str(date.today() + timedelta(days=180)),
                "acceptance_rationale": "Reason B (2026 Q3) -- new finding, new justification.",
            },
        )
        assert reaccepted.status_code == 200, reaccepted.text
        assert (
            reaccepted.json()["acceptance_rationale"]
            == "Reason B (2026 Q3) -- new finding, new justification."
        )


@pytest.mark.asyncio
async def test_create_poam_with_status_risk_accepted_is_gated_too() -> None:
    """A caller cannot skip the PATCH gate by setting status='risk_accepted' at
    creation time — POAMCreate exposes the same field, mirroring risks.py."""
    _org_id, sys_id = await _make_system("PoamRiskAcceptOrg4")
    async with _client() as c:
        r = await c.post(
            "/api/poams",
            json={
                "system_id": sys_id,
                "title": "Born accepted",
                "status": "risk_accepted",
            },
        )
        assert r.status_code == 409, r.text


@pytest.mark.asyncio
async def test_create_poam_born_accepted_with_a_whitespace_rationale_is_gated_too() -> None:
    """N6 (review round 3): the shared gate's `is_blank` check was only
    exercised through PATCH, where I3's separate top-level blank guard fires
    first and can mask whether `create_poam`'s own call into the gate still
    correctly rejects a whitespace-only rationale -- `"   "` is as absent as
    a missing field (`ccf.cr26.ver.is_blank`), and POST has no I3 guard in
    front of it to hide behind.
    """
    org_id, sys_id = await _make_system("PoamRiskAcceptOrg5")
    async with session_scope() as s:
        u = User(
            organization_id=org_id,
            email="owner@poamriskacceptorg5.example",
            role="control_owner",
            password_hash=hash_password("pw"),
        )
        s.add(u)
        await s.flush()
        owner_id = u.id

    async with _client() as c:
        r = await c.post(
            "/api/poams",
            json={
                "system_id": sys_id,
                "title": "Born accepted, blank rationale",
                "status": "risk_accepted",
                "owner_user_id": owner_id,
                "due_on": str(date.today() + timedelta(days=180)),
                "acceptance_rationale": "   ",
            },
        )
        assert r.status_code == 409, r.text


@pytest.mark.asyncio
async def test_patch_poam_to_risk_accepted_blocked_without_approval_when_auth_enabled() -> None:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    try:
        org_id, sys_id = await _make_system("PoamRiskAcceptAuthOrg1")
        async with session_scope() as s:
            preparer = User(
                organization_id=org_id,
                email="prep@poamriskacceptauthorg1.example",
                role="control_owner",
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
            s.add(preparer)
            await s.flush()
            assert preparer.api_token is not None
            token = preparer.api_token

        headers = {"Authorization": f"Bearer {token}"}
        async with _client() as c:
            created = await c.post(
                "/api/poams",
                json={"system_id": sys_id, "title": "Accepted risk auth"},
                headers=headers,
            )
            pid = created.json()["id"]

            r = await c.patch(
                f"/api/poams/{pid}",
                json={
                    "status": "risk_accepted",
                    "owner_user_id": 1,
                    "due_on": str(date.today() + timedelta(days=90)),
                    "acceptance_rationale": "Compensating control: WAF rule 91234.",
                },
                headers=headers,
            )
            assert r.status_code == 409, r.text  # validation OK, but no approval yet
    finally:
        os.environ.pop("CCF_AUTH_ENABLED", None)
        os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_patch_poam_to_risk_accepted_succeeds_with_approval_when_auth_enabled() -> None:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    try:
        org_id, sys_id = await _make_system("PoamRiskAcceptAuthOrg2")
        async with session_scope() as s:
            preparer = User(
                organization_id=org_id,
                email="prep2@poamriskacceptauthorg2.example",
                role="control_owner",
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
            approver = User(
                organization_id=org_id,
                email="appr2@poamriskacceptauthorg2.example",
                role="admin",
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
            owner = User(
                organization_id=org_id,
                email="owner2@poamriskacceptauthorg2.example",
                role="control_owner",
                password_hash=hash_password("pw"),
            )
            s.add_all([preparer, approver, owner])
            await s.flush()
            assert preparer.api_token is not None
            assert approver.api_token is not None
            prep_token = preparer.api_token
            appr_token = approver.api_token
            owner_id = owner.id

        prep_headers = {"Authorization": f"Bearer {prep_token}"}
        appr_headers = {"Authorization": f"Bearer {appr_token}"}
        async with _client() as c:
            created = await c.post(
                "/api/poams",
                json={"system_id": sys_id, "title": "Accepted risk auth ok"},
                headers=prep_headers,
            )
            pid = created.json()["id"]

            await c.post(f"/api/approvals/poam/{pid}/submit", headers=prep_headers)
            approve = await c.post(f"/api/approvals/poam/{pid}/approve", headers=appr_headers)
            assert approve.status_code == 200, approve.text

            r = await c.patch(
                f"/api/poams/{pid}",
                json={
                    "status": "risk_accepted",
                    "owner_user_id": owner_id,
                    "due_on": str(date.today() + timedelta(days=90)),
                    "acceptance_rationale": "Compensating control: WAF rule 91234.",
                },
                headers=prep_headers,
            )
            assert r.status_code == 200, r.text
            assert r.json()["status"] == "risk_accepted"
    finally:
        os.environ.pop("CCF_AUTH_ENABLED", None)
        os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
        get_settings.cache_clear()
