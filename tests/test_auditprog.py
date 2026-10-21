"""Audit and assurance program (workstream D -- auditprog).

Spec: docs/superpowers/specs/2026-10-20-grc-buildout-design.md.

What is pinned here, each the shape of a defect this platform has shipped:

* **Tenant isolation is in the query.** Two organizations, each with one
  distinctively named record of every kind, served through an app whose
  session has RLS cleared (``_unscoped_session``), so only the page's own org
  predicate can keep Bravo's rows off Alpha's page. Every page must show the
  caller's record **and** never the other's or a deleted system's.
* **Writes are role-gated, scoped and audited.** A viewer and a role outside
  each gate get 403; a foreign id is a 404 and changes nothing.
* **Separation of duties.** The preparer cannot finalise a workpaper; the
  proposer cannot approve or reject a compensating control.
* **A final workpaper is read-only.**
* **A ratio over nothing is ``—``.**
"""

from __future__ import annotations

import itertools
import os
from datetime import UTC, date, datetime, timedelta

import pytest
from alembic import command
from alembic.config import Config
from fastapi import HTTPException
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.deps import get_session
from ccf.api.main import create_app
from ccf.api.routes import ui_auditprog
from ccf.auth import Principal, hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import get_session_factory, session_scope, set_session_tenant
from ccf.governance import audit_program
from ccf.models import (
    POAM,
    AuditLog,
    Control,
    ControlImplementation,
    Organization,
    System,
    User,
)
from ccf.models_grc import AuditEngagement, AuditFinding, AuditRequest, ControlTest
from ccf.models_packages import (
    AuthorizationPackage,
    AuthorizationPackageDiff,
    AuthorizationPackageFact,
    AuthorizationPackageReplayRun,
)
from ccf.models_program import AuditWorkpaper, CompensatingControl

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()
ROLES = ("admin", "admin2", "assessor", "assessor2", "control_owner", "viewer")


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


async def _unscoped_session():
    """RLS tenant cleared (bypass): only the page's own org predicate can keep
    Bravo's rows off Alpha's page."""
    factory = get_session_factory()
    async with factory() as session:
        await set_session_tenant(session, None)
        yield session


def _client() -> AsyncClient:
    app = create_app()
    app.dependency_overrides[get_session] = _unscoped_session
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://t")


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _org(label: str, tag: str) -> dict[str, object]:
    """One organization with a record of every kind, named ``<label>-<kind>-<tag>``,
    plus a soft-deleted system carrying records named ``<label>-DELETED-...``."""
    today = date.today()
    m = lambda kind: f"{label}-{kind}-{tag}"  # noqa: E731
    out: dict[str, object] = {"label": label, "tag": tag}
    async with session_scope() as s:
        org = Organization(name=m("org"))
        s.add(org)
        await s.flush()
        users = {}
        for key in ROLES:
            role = key.rstrip("2")
            users[key] = User(
                email=f"{label.lower()}-{key}-{tag}@ap.test",
                organization_id=org.id,
                role=role,
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
        live = System(organization_id=org.id, name=m("system"), baseline="moderate")
        gone = System(
            organization_id=org.id,
            name=f"{label}-DELETED-system-{tag}",
            baseline="moderate",
            deleted_at=datetime.now(UTC),
        )
        ctl = Control(identifier=m("ctl"))
        ctl_gone = Control(identifier=f"{label}-DELETED-ctl-{tag}")
        s.add_all([*users.values(), live, gone, ctl, ctl_gone])
        await s.flush()
        poam = POAM(system_id=live.id, title=m("poam"), severity="high", status="open")
        eng = AuditEngagement(
            organization_id=org.id,
            name=m("audit"),
            status="fieldwork",
            target_on=today + timedelta(days=30),
        )
        s.add_all([poam, eng])
        await s.flush()
        s.add_all(
            [
                AuditRequest(
                    engagement_id=eng.id,
                    title=m("pbc-late"),
                    status="open",
                    owner_user_id=users["control_owner"].id,
                    due_on=today - timedelta(days=2),
                ),
                AuditRequest(
                    engagement_id=eng.id,
                    title=m("pbc-soon"),
                    status="open",
                    due_on=today + timedelta(days=5),
                ),
                AuditRequest(engagement_id=eng.id, title=m("pbc-done"), status="accepted"),
                AuditFinding(
                    engagement_id=eng.id,
                    organization_id=org.id,
                    title=m("finding"),
                    severity="high",
                    status="open",
                    poam_id=poam.id,
                ),
                AuditFinding(
                    engagement_id=eng.id,
                    organization_id=org.id,
                    title=m("finding-closed"),
                    severity="low",
                    status="closed",
                ),
                AuditWorkpaper(
                    organization_id=org.id,
                    engagement_id=eng.id,
                    title=m("workpaper"),
                    status="draft",
                    prepared_by=users["assessor"].email,
                ),
                CompensatingControl(
                    organization_id=org.id,
                    system_id=live.id,
                    control_identifier=m("ctl"),
                    measure=m("cc-approved"),
                    rationale="r",
                    status="approved",
                    proposed_by=users["control_owner"].email,
                    decided_by=users["admin"].email,
                    expires_on=today + timedelta(days=60),
                ),
                CompensatingControl(
                    organization_id=org.id,
                    system_id=live.id,
                    control_identifier=m("ctl"),
                    measure=m("cc-proposed"),
                    rationale="r",
                    status="proposed",
                    proposed_by=users["admin"].email,
                ),
                CompensatingControl(
                    organization_id=org.id,
                    system_id=gone.id,
                    control_identifier=f"{label}-DELETED-ctl-{tag}",
                    measure=f"{label}-DELETED-cc-{tag}",
                    rationale="r",
                    status="approved",
                    proposed_by="x@ap.test",
                ),
                ControlImplementation(
                    system_id=live.id,
                    control_id=ctl.id,
                    status="implemented",
                    next_assessment_due=today - timedelta(days=1),
                ),
                ControlImplementation(
                    system_id=gone.id,
                    control_id=ctl_gone.id,
                    status="implemented",
                    next_assessment_due=today - timedelta(days=1),
                ),
                ControlTest(
                    organization_id=org.id,
                    system_id=live.id,
                    control_id=m("ctl"),
                    name=m("test"),
                    frequency="monthly",
                    last_tested_at=datetime.now(UTC) - timedelta(days=40),
                    last_status="pass",
                ),
                ControlTest(
                    organization_id=org.id,
                    system_id=gone.id,
                    control_id="x",
                    name=f"{label}-DELETED-test-{tag}",
                    frequency="monthly",
                ),
            ]
        )
        pkg = AuthorizationPackage(
            organization_id=org.id,
            system_id=live.id,
            kind="fedramp20x",
            label=m("package"),
            fact_count=2,
        )
        pkg_gone = AuthorizationPackage(
            organization_id=org.id,
            system_id=gone.id,
            kind="fedramp20x",
            label=f"{label}-DELETED-package-{tag}",
        )
        s.add_all([pkg, pkg_gone])
        await s.flush()
        s.add_all(
            [
                AuthorizationPackageFact(package_id=pkg.id, fact_type="ksi", fact_key="a"),
                AuthorizationPackageFact(package_id=pkg.id, fact_type="poam", fact_key="b"),
                AuthorizationPackageReplayRun(
                    organization_id=org.id, package_id=pkg.id, status="drifted"
                ),
            ]
        )
        await s.flush()
        wp_id = (
            await s.execute(select(AuditWorkpaper.id).where(AuditWorkpaper.engagement_id == eng.id))
        ).scalar_one()
        cc_ids = dict(
            (
                await s.execute(
                    select(CompensatingControl.measure, CompensatingControl.id).where(
                        CompensatingControl.organization_id == org.id
                    )
                )
            ).all()
        )
        out.update(
            org_id=org.id,
            system_id=live.id,
            gone_id=gone.id,
            eng_id=eng.id,
            wp_id=wp_id,
            poam_id=poam.id,
            control=m("ctl"),
            cc_proposed=cc_ids[m("cc-proposed")],
            cc_approved=cc_ids[m("cc-approved")],
            pkg_id=pkg.id,
            pkg_gone_id=pkg_gone.id,
            tokens={k: u.api_token for k, u in users.items()},
            emails={k: u.email for k, u in users.items()},
        )
    return out


@pytest.fixture
async def two_orgs() -> tuple[dict[str, object], dict[str, object]]:
    tag = f"ap{next(_SEQ)}q{os.getpid()}{os.urandom(2).hex()}"
    return await _org("Alpha", tag), await _org("Bravo", tag)


def _tok(o: dict[str, object], role: str) -> dict[str, str]:
    return _auth(str(o["tokens"][role]))  # type: ignore[index]


async def _get(model, pk):
    async with session_scope() as s:
        await set_session_tenant(s, None)
        return await s.get(model, pk)


# ── isolation, on every page ─────────────────────────────────────────────────

PAGES = (
    ("/audit/workpapers", "workpaper"),
    ("/audit/findings", "finding"),
    ("/evidence/requests", "pbc-late"),
    ("/evidence/packages", "package"),
    ("/assessments/schedule", "ctl"),
    ("/assessments/schedule", "test"),
    ("/compensating-controls", "cc-proposed"),
    ("/audit/readiness", "audit"),
    ("/exceptions", "cc-approved"),
)


@pytest.mark.parametrize(("path", "kind"), PAGES)
async def test_each_page_shows_its_own_and_never_anothers(two_orgs, path: str, kind: str) -> None:
    a, _ = two_orgs
    async with _client() as c:
        resp = await c.get(path, headers=_tok(a, "viewer"))
    assert resp.status_code == 200, resp.text[:400]
    body = resp.text
    assert f"Alpha-{kind}-{a['tag']}" in body, f"{path} does not show the caller's own {kind}"
    assert "Bravo" not in body, f"{path} shows Bravo's records to Alpha"
    assert "DELETED" not in body, f"{path} shows a soft-deleted system's records"


async def test_a_findings_poam_link_never_names_another_tenants_poam(two_orgs) -> None:
    """A finding whose ``poam_id`` points at another organization's POA&M
    (a stale or crafted link) must not render that POA&M."""
    a, b = two_orgs
    async with session_scope() as s:
        await set_session_tenant(s, None)
        s.add(
            AuditFinding(
                engagement_id=int(a["eng_id"]),
                organization_id=int(a["org_id"]),
                title=f"Alpha-crosslink-{a['tag']}",
                severity="moderate",
                status="open",
                poam_id=int(b["poam_id"]),
            )
        )
    async with _client() as c:
        body = (await c.get("/audit/findings", headers=_tok(a, "viewer"))).text
    assert f"Alpha-crosslink-{a['tag']}" in body
    assert f"Alpha-poam-{a['tag']}" in body
    assert f"Bravo-poam-{b['tag']}" not in body


async def test_findings_filters_by_severity_and_status(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        high = (await c.get("/audit/findings?severity=high", headers=_tok(a, "viewer"))).text
        closed = (await c.get("/audit/findings?status=closed", headers=_tok(a, "viewer"))).text
    assert f"Alpha-finding-{a['tag']}" in high
    assert f"Alpha-finding-closed-{a['tag']}" not in high
    assert f"Alpha-finding-closed-{a['tag']}" in closed
    assert f"Alpha-finding-{a['tag']}<" not in closed


async def test_evidence_requests_list_overdue_first(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        body = (await c.get("/evidence/requests", headers=_tok(a, "viewer"))).text
    late = body.index(f"Alpha-pbc-late-{a['tag']}")
    assert late < body.index(f"Alpha-pbc-soon-{a['tag']}")
    assert late < body.index(f"Alpha-pbc-done-{a['tag']}")
    assert "overdue" in body
    # The owner is named, not numbered.
    assert str(a["emails"]["control_owner"]) in body  # type: ignore[index]


async def test_foreign_ids_are_not_found_and_change_nothing(two_orgs) -> None:
    a, b = two_orgs
    async with _client() as c:
        assert (
            await c.get(f"/audit/workpapers/{b['wp_id']}", headers=_tok(a, "admin"))
        ).status_code == 404
        assert (
            await c.get(f"/audit/workpapers?engagement={b['eng_id']}", headers=_tok(a, "admin"))
        ).status_code == 404
        r = await c.post(
            "/audit/workpapers",
            data={"engagement_id": b["eng_id"], "title": "injected"},
            headers=_tok(a, "admin"),
        )
        assert r.status_code == 404
        for action in ("submit", "return", "finalise"):
            r = await c.post(f"/audit/workpapers/{b['wp_id']}/{action}", headers=_tok(a, "admin"))
            assert r.status_code == 404, action
        r = await c.post(
            f"/audit/workpapers/{b['wp_id']}/edit",
            data={"title": "hijacked"},
            headers=_tok(a, "assessor"),
        )
        assert r.status_code == 404
        r = await c.post(
            "/compensating-controls",
            data={
                "system_id": b["system_id"],
                "control_identifier": str(b["control"]),
                "measure": "m",
                "rationale": "r",
            },
            headers=_tok(a, "admin"),
        )
        assert r.status_code == 404
        for action in ("approve", "reject"):
            r = await c.post(
                f"/compensating-controls/{b['cc_proposed']}/{action}", headers=_tok(a, "admin2")
            )
            assert r.status_code == 404, action
        r = await c.post(
            f"/compensating-controls/{b['cc_approved']}/retire", headers=_tok(a, "admin")
        )
        assert r.status_code == 404
    wp = await _get(AuditWorkpaper, int(b["wp_id"]))
    assert wp.status == "draft" and wp.title == f"Bravo-workpaper-{b['tag']}"
    assert (await _get(CompensatingControl, int(b["cc_proposed"]))).status == "proposed"
    assert (await _get(CompensatingControl, int(b["cc_approved"]))).status == "approved"
    async with session_scope() as s:
        await set_session_tenant(s, None)
        injected = (
            (await s.execute(select(AuditWorkpaper).where(AuditWorkpaper.title == "injected")))
            .scalars()
            .all()
        )
    assert injected == []


async def test_a_compensating_control_cannot_be_proposed_on_a_deleted_system(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        r = await c.post(
            "/compensating-controls",
            data={
                "system_id": a["gone_id"],
                "control_identifier": str(a["control"]),
                "measure": "m",
                "rationale": "r",
            },
            headers=_tok(a, "admin"),
        )
    assert r.status_code == 404


# ── role gates ───────────────────────────────────────────────────────────────


async def test_workpaper_writes_are_admin_or_assessor(two_orgs) -> None:
    a, _ = two_orgs
    wp = int(a["wp_id"])
    async with _client() as c:
        for role in ("viewer", "control_owner"):
            r = await c.post(
                "/audit/workpapers",
                data={"engagement_id": a["eng_id"], "title": f"by-{role}"},
                headers=_tok(a, role),
            )
            assert r.status_code == 403, (role, r.text[:200])
            for action in ("submit", "return", "finalise"):
                r = await c.post(f"/audit/workpapers/{wp}/{action}", headers=_tok(a, role))
                assert r.status_code == 403, (role, action)
            r = await c.post(
                f"/audit/workpapers/{wp}/edit", data={"title": "x"}, headers=_tok(a, role)
            )
            assert r.status_code == 403, role
        for role in ("assessor", "admin"):
            r = await c.post(
                "/audit/workpapers",
                data={"engagement_id": a["eng_id"], "title": f"by-{role}", "sample_size": "25"},
                headers=_tok(a, role),
            )
            assert r.status_code == 303, (role, r.text[:200])
    assert (await _get(AuditWorkpaper, wp)).status == "draft"
    async with session_scope() as s:
        await set_session_tenant(s, None)
        made = dict(
            (
                await s.execute(
                    select(AuditWorkpaper.title, AuditWorkpaper.prepared_by).where(
                        AuditWorkpaper.engagement_id == int(a["eng_id"])
                    )
                )
            ).all()
        )
        events = (
            (
                await s.execute(
                    select(AuditLog).where(
                        AuditLog.entity_type == "audit_workpaper",
                        AuditLog.organization_id == int(a["org_id"]),
                    )
                )
            )
            .scalars()
            .all()
        )
    assert "by-viewer" not in made and "by-control_owner" not in made
    assert made["by-assessor"] == a["emails"]["assessor"]  # type: ignore[index]
    assert len([e for e in events if e.diff.get("event") == "prepared"]) == 2


async def test_compensating_control_gates(two_orgs) -> None:
    a, _ = two_orgs
    data = {
        "system_id": a["system_id"],
        "control_identifier": str(a["control"]),
        "measure": "m",
        "rationale": "r",
    }
    async with _client() as c:
        assert (
            await c.post("/compensating-controls", data=data, headers=_tok(a, "viewer"))
        ).status_code == 403
        for role in ("control_owner", "assessor", "admin"):
            r = await c.post(
                "/compensating-controls",
                data={**data, "measure": f"m-{role}"},
                headers=_tok(a, role),
            )
            assert r.status_code == 303, (role, r.text[:200])
        for role in ("viewer", "control_owner", "assessor"):
            for action in ("approve", "reject"):
                r = await c.post(
                    f"/compensating-controls/{a['cc_proposed']}/{action}", headers=_tok(a, role)
                )
                assert r.status_code == 403, (role, action)
            r = await c.post(
                f"/compensating-controls/{a['cc_approved']}/retire", headers=_tok(a, role)
            )
            assert r.status_code == 403, role
    assert (await _get(CompensatingControl, int(a["cc_proposed"]))).status == "proposed"
    assert (await _get(CompensatingControl, int(a["cc_approved"]))).status == "approved"


async def test_an_unknown_control_cannot_be_compensated(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        r = await c.post(
            "/compensating-controls",
            data={
                "system_id": a["system_id"],
                "control_identifier": f"NOPE-{a['tag']}",
                "measure": "m",
                "rationale": "r",
            },
            headers=_tok(a, "admin"),
        )
    assert r.status_code == 422


# ── separation of duties ─────────────────────────────────────────────────────


async def test_the_preparer_cannot_finalise_a_workpaper(two_orgs) -> None:
    a, _ = two_orgs
    wp = int(a["wp_id"])  # prepared by Alpha's assessor
    async with _client() as c:
        r = await c.post(
            f"/audit/workpapers/{wp}/edit",
            data={"title": "WP", "conclusion": "effective", "sample_size": "10"},
            headers=_tok(a, "assessor"),
        )
        assert r.status_code == 303, r.text[:200]
        assert (
            await c.post(f"/audit/workpapers/{wp}/submit", headers=_tok(a, "assessor"))
        ).status_code == 303
        r = await c.post(f"/audit/workpapers/{wp}/finalise", headers=_tok(a, "assessor"))
        assert r.status_code == 403
        assert "separation of duties" in r.text
        assert (await _get(AuditWorkpaper, wp)).status == "in_review"
        r = await c.post(f"/audit/workpapers/{wp}/finalise", headers=_tok(a, "assessor2"))
        assert r.status_code == 303, r.text[:200]
    row = await _get(AuditWorkpaper, wp)
    assert row.status == "final"
    assert row.reviewed_by == a["emails"]["assessor2"]  # type: ignore[index]
    assert row.reviewed_at is not None


async def test_only_the_preparer_edits_a_draft(two_orgs) -> None:
    """Otherwise a second hand in the draft could then finalise it."""
    a, _ = two_orgs
    wp = int(a["wp_id"])
    async with _client() as c:
        r = await c.post(
            f"/audit/workpapers/{wp}/edit",
            data={"title": "rewritten", "conclusion": "effective"},
            headers=_tok(a, "assessor2"),
        )
    assert r.status_code == 403
    row = await _get(AuditWorkpaper, wp)
    assert row.title == f"Alpha-workpaper-{a['tag']}" and row.conclusion is None


async def test_a_conclusion_is_required_to_finalise(two_orgs) -> None:
    a, _ = two_orgs
    wp = int(a["wp_id"])
    async with _client() as c:
        await c.post(f"/audit/workpapers/{wp}/submit", headers=_tok(a, "assessor"))
        r = await c.post(f"/audit/workpapers/{wp}/finalise", headers=_tok(a, "assessor2"))
    assert r.status_code == 422
    assert (await _get(AuditWorkpaper, wp)).status == "in_review"


async def test_a_draft_cannot_skip_review(two_orgs) -> None:
    a, _ = two_orgs
    wp = int(a["wp_id"])
    async with _client() as c:
        await c.post(
            f"/audit/workpapers/{wp}/edit",
            data={"title": "WP", "conclusion": "effective"},
            headers=_tok(a, "assessor"),
        )
        r = await c.post(f"/audit/workpapers/{wp}/finalise", headers=_tok(a, "assessor2"))
    assert r.status_code == 409
    assert (await _get(AuditWorkpaper, wp)).status == "draft"


async def test_a_final_workpaper_is_read_only(two_orgs) -> None:
    a, _ = two_orgs
    wp = int(a["wp_id"])
    async with session_scope() as s:
        await set_session_tenant(s, None)
        row = await s.get(AuditWorkpaper, wp)
        row.status, row.conclusion, row.reviewed_by = "final", "effective", "rev@ap.test"
    async with _client() as c:
        r = await c.post(
            f"/audit/workpapers/{wp}/edit",
            data={"title": "rewritten", "conclusion": "ineffective"},
            headers=_tok(a, "assessor"),
        )
        assert r.status_code == 409 and "read-only" in r.text
        for action in ("submit", "return", "finalise"):
            r = await c.post(f"/audit/workpapers/{wp}/{action}", headers=_tok(a, "assessor2"))
            assert r.status_code == 409, action
            assert "read-only" in r.text
        page = (await c.get(f"/audit/workpapers/{wp}", headers=_tok(a, "assessor"))).text
    row = await _get(AuditWorkpaper, wp)
    assert (row.status, row.conclusion, row.title) == (
        "final",
        "effective",
        f"Alpha-workpaper-{a['tag']}",
    )
    assert "read-only" in page
    assert f"/audit/workpapers/{wp}/edit" not in page


async def test_a_workpaper_can_be_returned_to_its_preparer(two_orgs) -> None:
    a, _ = two_orgs
    wp = int(a["wp_id"])
    async with _client() as c:
        await c.post(f"/audit/workpapers/{wp}/submit", headers=_tok(a, "assessor"))
        assert (
            await c.post(f"/audit/workpapers/{wp}/return", headers=_tok(a, "assessor2"))
        ).status_code == 303
        assert (
            await c.post(f"/audit/workpapers/{wp}/return", headers=_tok(a, "assessor2"))
        ).status_code == 409
    assert (await _get(AuditWorkpaper, wp)).status == "draft"


async def test_the_proposer_cannot_decide_a_compensating_control(two_orgs) -> None:
    a, _ = two_orgs
    cc = int(a["cc_proposed"])  # proposed by Alpha's admin
    async with _client() as c:
        for action in ("approve", "reject"):
            r = await c.post(f"/compensating-controls/{cc}/{action}", headers=_tok(a, "admin"))
            assert r.status_code == 403, action
            assert "separation of duties" in r.text
        assert (await _get(CompensatingControl, cc)).status == "proposed"
        r = await c.post(f"/compensating-controls/{cc}/approve", headers=_tok(a, "admin2"))
        assert r.status_code == 303, r.text[:200]
        # Decided once: a second decision is refused, not a rewrite.
        r = await c.post(f"/compensating-controls/{cc}/reject", headers=_tok(a, "admin2"))
        assert r.status_code == 409
    row = await _get(CompensatingControl, cc)
    assert row.status == "approved"
    assert row.decided_by == a["emails"]["admin2"]  # type: ignore[index]
    async with session_scope() as s:
        await set_session_tenant(s, None)
        events = (
            (
                await s.execute(
                    select(AuditLog).where(
                        AuditLog.entity_type == "compensating_control",
                        AuditLog.entity_id == str(cc),
                    )
                )
            )
            .scalars()
            .all()
        )
    assert [e.diff.get("event") for e in events if e.diff.get("event")] == ["approved"]
    assert events[0].organization_id == int(a["org_id"])


async def test_approved_compensating_controls_are_exceptions_until_retired(two_orgs) -> None:
    a, _ = two_orgs
    approved, proposed = f"Alpha-cc-approved-{a['tag']}", f"Alpha-cc-proposed-{a['tag']}"
    async with _client() as c:
        body = (await c.get("/exceptions", headers=_tok(a, "viewer"))).text
        in_force, _, pending = body.partition("Awaiting a decision")
        assert approved in in_force
        # Pending items are listed by subject (the control), not counted above.
        assert proposed not in in_force
        assert str(a["control"]) in pending and "proposed" in pending
        assert "Compensating controls" in in_force
        r = await c.post(
            f"/compensating-controls/{a['cc_approved']}/retire", headers=_tok(a, "admin")
        )
        assert r.status_code == 303
        body = (await c.get("/exceptions", headers=_tok(a, "viewer"))).text
    assert approved not in body
    assert (await _get(CompensatingControl, int(a["cc_approved"]))).status == "retired"


def test_sign_off_is_refused_when_the_signer_is_the_preparer_or_unknown() -> None:
    assert audit_program.may_sign_off("a@x", "b@x")
    assert not audit_program.may_sign_off("a@x", "a@x")
    assert not audit_program.may_sign_off("A@x ", "a@X")
    assert not audit_program.may_sign_off("a@x", "")
    assert not audit_program.may_sign_off(None, None)
    assert audit_program.may_sign_off(None, "b@x")


# ── ratios over nothing, and parts that sum ──────────────────────────────────


async def test_readiness_over_nothing_is_a_dash(two_orgs) -> None:
    a, _ = two_orgs
    async with session_scope() as s:
        await set_session_tenant(s, None)
        s.add(
            AuditEngagement(
                organization_id=int(a["org_id"]), name=f"Alpha-empty-{a['tag']}", status="planning"
            )
        )
        s.add(
            AuditEngagement(
                organization_id=int(a["org_id"]), name=f"Alpha-closed-{a['tag']}", status="closed"
            )
        )
    async with session_scope() as s:
        await set_session_tenant(s, None)
        rows = {
            r["e"].name: r for r in await audit_program.readiness(s, int(a["org_id"]), date.today())
        }
    assert f"Alpha-closed-{a['tag']}" not in rows
    empty = rows[f"Alpha-empty-{a['tag']}"]
    assert empty["pbc_pct"] is None and empty["wp_pct"] is None
    full = rows[f"Alpha-audit-{a['tag']}"]
    assert (full["pbc_accepted"], full["pbc_total"], full["pbc_pct"]) == (1, 3, 33)
    assert (full["wp_final"], full["wp_total"], full["wp_pct"]) == (0, 1, 0)
    assert full["findings"]["high"] == 1 and full["findings_open"] == 1
    assert full["pbc_overdue"] == 1
    async with _client() as c:
        body = (await c.get("/audit/readiness", headers=_tok(a, "viewer"))).text
    row = body[body.index(f"Alpha-empty-{a['tag']}") :]
    row = row[: row.index("</tr>")]
    assert row.count('data-metric="pbc">—<') == 1
    assert row.count('data-metric="wp">—<') == 1
    assert "0%" not in row and "100%" not in row
    assert f"Alpha-closed-{a['tag']}" not in body


async def test_the_schedule_windows_sum_to_the_total(two_orgs) -> None:
    a, _ = two_orgs
    today = date.today()
    async with session_scope() as s:
        await set_session_tenant(s, None)
        for offset in (None, 10, 60, 200):
            ctl = Control(identifier=f"Alpha-w{offset}-{a['tag']}")
            s.add(ctl)
            await s.flush()
            s.add(
                ControlImplementation(
                    system_id=int(a["system_id"]),
                    control_id=ctl.id,
                    status="implemented",
                    next_assessment_due=None if offset is None else today + timedelta(days=offset),
                )
            )
    async with session_scope() as s:
        await set_session_tenant(s, None)
        data = await audit_program.assessment_schedule(s, int(a["org_id"]), today)
    assert data["impl_counts"] == {
        "overdue": 1,
        "due_30": 1,
        "due_90": 1,
        "later": 1,
        "unscheduled": 1,
    }
    assert sum(data["impl_counts"].values()) == data["impl_total"] == 5
    (test,) = data["tests"]
    assert test["state"] == "due"  # monthly, last run 40 days ago
    assert data["tests_by_frequency"] == {"monthly": {"due": 1}}


def test_schedule_window_boundaries() -> None:
    today = date(2026, 10, 20)
    w = audit_program.schedule_window
    assert w(None, today) == "unscheduled"
    assert w(today - timedelta(days=1), today) == "overdue"
    assert w(today, today) == "due_30"
    assert w(today + timedelta(days=30), today) == "due_30"
    assert w(today + timedelta(days=31), today) == "due_90"
    assert w(today + timedelta(days=90), today) == "due_90"
    assert w(today + timedelta(days=91), today) == "later"


async def test_a_package_shows_its_contents_and_replay(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        body = (await c.get("/evidence/packages", headers=_tok(a, "viewer"))).text
    assert "1 ksi" in body and "1 poam" in body
    assert "drifted" in body


async def test_the_engagement_page_carries_a_workpapers_section(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        body = (await c.get(f"/audit-workspace/{a['eng_id']}", headers=_tok(a, "viewer"))).text
        listing = (
            await c.get(f"/audit/workpapers?engagement={a['eng_id']}", headers=_tok(a, "viewer"))
        ).text
    assert f'hx-get="/audit/workpapers?engagement={a["eng_id"]}"' in body
    assert 'hx-select="#workpaper-table"' in body
    assert 'id="workpaper-table"' in listing
    assert f"Alpha-workpaper-{a['tag']}" in listing


# ── evidence packages: a workflow over ccf.packages.service ──────────────────


async def _facts(pid: int) -> list[tuple[str, str, str | None]]:
    async with session_scope() as s:
        await set_session_tenant(s, None)
        return sorted(
            (
                await s.execute(
                    select(
                        AuthorizationPackageFact.fact_type,
                        AuthorizationPackageFact.fact_key,
                        AuthorizationPackageFact.value,
                    ).where(AuthorizationPackageFact.package_id == pid)
                )
            ).all()
        )


async def test_a_package_is_exported_through_the_service(two_orgs) -> None:
    a, _ = two_orgs
    label = f"Alpha-exported-{a['tag']}"
    async with _client() as c:
        r = await c.post(
            "/evidence/packages",
            data={"system_id": a["system_id"], "kind": "fedramp20x", "label": label},
            headers=_tok(a, "control_owner"),
        )
        assert r.status_code == 303, r.text[:200]
        body = (await c.get("/evidence/packages", headers=_tok(a, "viewer"))).text
    assert label in body
    async with session_scope() as s:
        await set_session_tenant(s, None)
        pkg = (
            await s.execute(select(AuthorizationPackage).where(AuthorizationPackage.label == label))
        ).scalar_one()
        events = (
            (
                await s.execute(
                    select(AuditLog).where(
                        AuditLog.entity_type == "authorization_package",
                        AuditLog.entity_id == str(pkg.id),
                    )
                )
            )
            .scalars()
            .all()
        )
    assert pkg.organization_id == int(a["org_id"]) and pkg.system_id == int(a["system_id"])
    assert pkg.created_by == a["emails"]["control_owner"]  # type: ignore[index]
    assert len(await _facts(pkg.id)) == pkg.fact_count
    assert [e.diff.get("event") for e in events if e.diff.get("event")] == ["exported"]


async def test_package_actions_are_gated_and_scoped(two_orgs) -> None:
    a, b = two_orgs
    own, other, gone = int(a["pkg_id"]), int(b["pkg_id"]), int(a["pkg_gone_id"])
    async with _client() as c:
        viewer = _tok(a, "viewer")
        assert (
            await c.post("/evidence/packages", data={"system_id": a["system_id"]}, headers=viewer)
        ).status_code == 403
        assert (await c.post(f"/evidence/packages/{own}/replay", headers=viewer)).status_code == 403
        assert (
            await c.post(
                f"/evidence/packages/{own}/compare", data={"other_id": own}, headers=viewer
            )
        ).status_code == 403
        admin = _tok(a, "admin")
        for sid in (b["system_id"], a["gone_id"]):
            r = await c.post("/evidence/packages", data={"system_id": sid}, headers=admin)
            assert r.status_code == 404, sid
        r = await c.post(
            "/evidence/packages",
            data={"system_id": a["system_id"], "kind": "nonsense"},
            headers=admin,
        )
        assert r.status_code == 422
        for pid in (other, gone):
            assert (
                await c.post(f"/evidence/packages/{pid}/replay", headers=admin)
            ).status_code == 404, pid
            assert (
                await c.post(
                    f"/evidence/packages/{own}/compare", data={"other_id": pid}, headers=admin
                )
            ).status_code == 404, pid
        assert (
            await c.post(
                f"/evidence/packages/{other}/compare", data={"other_id": own}, headers=admin
            )
        ).status_code == 404
        assert (
            await c.post(f"/evidence/packages/{own}/compare", data={"other_id": own}, headers=admin)
        ).status_code == 422
    async with session_scope() as s:
        await set_session_tenant(s, None)
        runs = (
            await s.execute(
                select(AuthorizationPackageReplayRun.package_id).where(
                    AuthorizationPackageReplayRun.package_id.in_([other, gone])
                )
            )
        ).all()
        made = (
            (
                await s.execute(
                    select(AuthorizationPackage).where(
                        AuthorizationPackage.organization_id == int(a["org_id"])
                    )
                )
            )
            .scalars()
            .all()
        )
    assert (other,) in runs and len(runs) == 1  # only Bravo's own seeded run
    assert len(made) == 2  # the two seeded; no refused export landed


async def test_an_exported_package_is_fixed_replay_and_compare_change_nothing(two_orgs) -> None:
    """There is no operation that adds to, edits or removes a package: the
    service writes its facts once, at export. Replay and compare record their
    own rows and leave the package exactly as it was."""
    a, _ = two_orgs
    own = int(a["pkg_id"])
    async with _client() as c:
        r = await c.post(
            "/evidence/packages",
            data={"system_id": a["system_id"], "label": f"Alpha-second-{a['tag']}"},
            headers=_tok(a, "assessor"),
        )
        assert r.status_code == 303
    async with session_scope() as s:
        await set_session_tenant(s, None)
        second = (
            await s.execute(
                select(AuthorizationPackage.id).where(
                    AuthorizationPackage.label == f"Alpha-second-{a['tag']}"
                )
            )
        ).scalar_one()
    before = {pid: await _facts(pid) for pid in (own, second)}
    count_before = (await _get(AuthorizationPackage, own)).fact_count
    async with _client() as c:
        for pid in (own, second):
            r = await c.post(f"/evidence/packages/{pid}/replay", headers=_tok(a, "assessor"))
            assert r.status_code == 303, r.text[:200]
        r = await c.post(
            f"/evidence/packages/{own}/compare",
            data={"other_id": second},
            headers=_tok(a, "assessor"),
        )
        assert r.status_code == 303, r.text[:200]
        for path in ("edit", "facts", "seal"):
            assert (
                await c.post(f"/evidence/packages/{own}/{path}", headers=_tok(a, "admin"))
            ).status_code in (404, 405), path
        body = (await c.get("/evidence/packages", headers=_tok(a, "viewer"))).text
    assert {pid: await _facts(pid) for pid in (own, second)} == before
    assert (await _get(AuthorizationPackage, own)).fact_count == count_before
    async with session_scope() as s:
        await set_session_tenant(s, None)
        diffs = (
            (
                await s.execute(
                    select(AuthorizationPackageDiff).where(
                        AuthorizationPackageDiff.from_package_id == own
                    )
                )
            )
            .scalars()
            .all()
        )
    assert len(diffs) == 1 and diffs[0].organization_id == int(a["org_id"])
    assert "Recent comparisons" in body
    assert f"Alpha-second-{a['tag']}" in body


# ── guards a page-level test cannot reach ────────────────────────────────────


async def test_every_write_refuses_a_viewer_at_its_own_gate() -> None:
    """The middleware refuses a viewer's write before the route runs, so an
    HTTP test cannot tell a route's own ``require_role`` from the middleware.
    Call each write route's role dependency directly with a viewer."""
    viewer = Principal(user_id=1, email="v@ap.test", org_id=1, role="viewer")
    writes = [
        r for r in ui_auditprog.router.routes if isinstance(r, APIRoute) and "POST" in r.methods
    ]
    assert len(writes) == 12, [r.path for r in writes]
    for route in writes:
        gates = [
            d.call
            for d in route.dependant.dependencies
            if "require_role" in getattr(d.call, "__qualname__", "")
        ]
        assert len(gates) == 1, route.path
        with pytest.raises(HTTPException) as err:
            await gates[0](principal=viewer)
        assert err.value.status_code == 403, route.path


async def test_a_workpaper_needs_an_engagement_with_an_organization() -> None:
    async with session_scope() as s:
        await set_session_tenant(s, None)
        eng = AuditEngagement(organization_id=None, name="orgless", status="planning")
        s.add(eng)
        await s.flush()
        with pytest.raises(audit_program.RefusalError) as err:
            await audit_program.create_workpaper(
                s,
                eng,
                actor="a@ap.test",
                title="t",
                control_id=None,
                procedure=None,
                sample_size=None,
                exceptions_found=None,
                conclusion=None,
                evidence_refs=None,
            )
        assert err.value.status_code == 409
        await s.rollback()


async def test_recent_comparisons_are_the_callers_own(two_orgs) -> None:
    """The page also drops comparisons of packages it does not list; the
    service's own predicate is pinned here, where that filter cannot mask it."""
    a, b = two_orgs
    async with session_scope() as s:
        await set_session_tenant(s, None)
        s.add(
            AuthorizationPackageDiff(
                organization_id=int(b["org_id"]),
                from_package_id=int(b["pkg_id"]),
                to_package_id=int(b["pkg_id"]),
                summary={},
                changes={},
            )
        )
        await s.flush()
        mine = await audit_program.recent_comparisons(s, int(a["org_id"]))
    assert all(d.organization_id == int(a["org_id"]) for d in mine)


async def test_compensating_control_dates_and_states(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        r = await c.post(
            "/compensating-controls",
            data={
                "system_id": a["system_id"],
                "control_identifier": str(a["control"]),
                "measure": "m",
                "rationale": "r",
                "expires_on": (date.today() - timedelta(days=1)).isoformat(),
            },
            headers=_tok(a, "admin"),
        )
        assert r.status_code == 422
        # Only an approved measure can be retired; a proposal is rejected instead.
        r = await c.post(
            f"/compensating-controls/{a['cc_proposed']}/retire", headers=_tok(a, "admin2")
        )
        assert r.status_code == 409
    assert (await _get(CompensatingControl, int(a["cc_proposed"]))).status == "proposed"
