"""Workstream F -- platform: API tokens, the route-derived RBAC matrix, group
mappings, and the governed AI analysis page.

Spec: docs/superpowers/specs/2026-10-20-grc-buildout-design.md, section F.

Every page is driven through the real auth gate with bearer tokens, on a
session with the RLS tenant cleared (``_unscoped_session``), so the only thing
keeping Bravo's rows off Alpha's page is the page's own org predicate.

No test reaches an AI provider: no organization here has a usable provider
credential, and ``ccf.ai.gateway.build_provider`` -- the one place a provider
adapter is constructed -- is replaced for every test by a recorder that the
test asserts was never called.
"""

from __future__ import annotations

import itertools
import os
import re
from datetime import UTC, date, datetime

import pytest
from alembic import command
from alembic.config import Config
from fastapi import Depends
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.ai import gateway
from ccf.ai_actions import run_action
from ccf.api.auth_deps import get_principal, require_role, viewer_may_write
from ccf.api.deps import get_session
from ccf.api.main import create_app
from ccf.api.routes import ui_platform
from ccf.auth import Principal, hash_password, hash_token, new_api_token
from ccf.config import get_settings
from ccf.db import get_session_factory, session_scope, set_session_tenant
from ccf.governance import rbac_matrix
from ccf.models import (
    POAM,
    AuditLog,
    Control,
    ControlImplementation,
    Organization,
    Policy,
    Risk,
    System,
    User,
    Vendor,
)
from ccf.models_ai_actions import AiActionRun, AiApprovedMutation, AiProviderConfig
from ccf.models_evidence import EvidenceObject
from ccf.models_identity import GroupRoleMapping

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()
_PROBE = "/api/ai-actions/runs"  # any authenticated API GET: 200 or 401


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


@pytest.fixture(autouse=True)
def _no_ai_provider(monkeypatch):
    """Record any attempt to build a provider adapter; the test asserts none."""
    calls: list[tuple[object, ...]] = []

    def _refuse(*args: object, **kwargs: object) -> None:
        calls.append(args)
        raise RuntimeError("tests never call a real AI provider")

    monkeypatch.setattr(gateway, "build_provider", _refuse)
    yield
    assert not calls, f"an AI provider was constructed: {calls}"


async def _unscoped_session():
    factory = get_session_factory()
    async with factory() as session:
        await set_session_tenant(session, None)
        yield session


def _client(app=None) -> AsyncClient:
    app = app or create_app()
    app.dependency_overrides[get_session] = _unscoped_session
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://t")


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


_ROLES = ("admin", "control_owner", "assessor", "viewer")


async def _org(label: str, tag: str) -> dict[str, object]:
    """One organization: a user per role (each with a token) and one record of
    every type the AI page runs on, each named ``<label>-<kind>-<tag>``. Also a
    soft-deleted system with a POA&M, and a risk with no system at all."""
    m = lambda kind: f"{label}-{kind}-{tag}"  # noqa: E731
    async with session_scope() as s:
        org = Organization(name=m("org"))
        s.add(org)
        await s.flush()
        users = {
            role: User(
                email=f"{label.lower()}-{role}-{tag}@pf.test",
                organization_id=org.id,
                role=role,
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
            for role in _ROLES
        }
        live = System(organization_id=org.id, name=m("system"), baseline="moderate")
        gone = System(
            organization_id=org.id,
            name=f"{label}-DELETED-system-{tag}",
            baseline="moderate",
            deleted_at=datetime.now(UTC),
        )
        control = Control(identifier=m("ctl"), sequence_control=m("ctl"))
        s.add_all([*users.values(), live, gone, control])
        await s.flush()
        poam = POAM(
            system_id=live.id,
            title=m("poam"),
            severity="high",
            status="open",
            identified_on=date.today(),
        )
        gone_poam = POAM(
            system_id=gone.id,
            title=f"{label}-DELETED-poam-{tag}",
            severity="high",
            status="open",
            identified_on=date.today(),
        )
        risk = Risk(system_id=live.id, title=m("risk"), status="open")
        orphan = Risk(system_id=None, title=f"{label}-ORPHAN-risk-{tag}", status="open")
        impl = ControlImplementation(system_id=live.id, control_id=control.id)
        vendor = Vendor(organization_id=org.id, name=m("vendor"))
        policy = Policy(organization_id=org.id, name=m("policy"), status="active")
        evidence = EvidenceObject(
            organization_id=org.id, title=m("evidence"), source_type="upload", status="approved"
        )
        mapping = GroupRoleMapping(organization_id=org.id, group=m("group"), role="assessor")
        s.add_all([poam, gone_poam, risk, orphan, impl, vendor, policy, evidence, mapping])
        await s.flush()
        return {
            "org_id": org.id,
            "tag": tag,
            "label": label,
            "tokens": {r: u.api_token for r, u in users.items()},
            "user_ids": {r: u.id for r, u in users.items()},
            "system_id": live.id,
            "poam_id": poam.id,
            "gone_poam_id": gone_poam.id,
            "orphan_risk_id": orphan.id,
            "mapping_id": mapping.id,
        }


@pytest.fixture
async def two_orgs() -> tuple[dict, dict]:
    tag = f"{next(_SEQ)}x{os.getpid()}"
    return await _org("Alpha", tag), await _org("Bravo", tag)


async def _user(user_id: int) -> User:
    async with session_scope() as s:
        return (await s.execute(select(User).where(User.id == user_id))).scalar_one()


async def _events(entity_type: str, entity_id: str) -> list[AuditLog]:
    async with session_scope() as s:
        stmt = select(AuditLog).where(
            AuditLog.entity_type == entity_type, AuditLog.entity_id == entity_id
        )
        return list((await s.execute(stmt)).scalars().all())


# ── API tokens ───────────────────────────────────────────────────────────────


async def test_a_rotated_token_is_shown_once_and_stored_only_as_its_digest(two_orgs) -> None:
    a, _ = two_orgs
    old = a["tokens"]["assessor"]
    uid = a["user_ids"]["assessor"]
    async with _client() as c:
        resp = await c.post("/settings/api-tokens/rotate", headers=_auth(old))
        assert resp.status_code == 200, resp.text
        assert resp.headers["cache-control"] == "no-store"
        new = re.search(r'id="issued-token">([^<]+)<', resp.text).group(1)
        assert new and new != old

        user = await _user(uid)
        assert user.api_token_hash == hash_token(new)
        assert new not in (user.api_token_hash or "")

        # The old token stopped authenticating; the new one works.
        assert (await c.get(_PROBE, headers=_auth(old))).status_code == 401
        assert (await c.get(_PROBE, headers=_auth(new))).status_code == 200

        # Shown once: the next render of the page does not carry it.
        again = await c.get("/settings/api-tokens", headers=_auth(new))
        assert again.status_code == 200
        assert new not in again.text
        assert "issued-token" not in again.text

    events = await _events("api_token", str(uid))
    assert [e.diff.get("change") for e in events] == ["rotated"]
    assert events[0].organization_id == a["org_id"]
    assert new not in str(events[0].diff) and hash_token(new) not in str(events[0].diff)


async def test_revoking_your_own_token_stops_it_at_once(two_orgs) -> None:
    a, _ = two_orgs
    token = a["tokens"]["control_owner"]
    async with _client() as c:
        assert (await c.get(_PROBE, headers=_auth(token))).status_code == 200
        resp = await c.post("/settings/api-tokens/revoke", headers=_auth(token))
        assert resp.status_code == 303
        assert (await c.get(_PROBE, headers=_auth(token))).status_code == 401
    assert (await _user(a["user_ids"]["control_owner"])).api_token_hash is None
    events = await _events("api_token", str(a["user_ids"]["control_owner"]))
    assert [e.diff.get("change") for e in events] == ["revoked"]


async def test_an_admin_revokes_a_user_of_their_own_organization(two_orgs) -> None:
    a, _ = two_orgs
    victim = a["tokens"]["viewer"]
    async with _client() as c:
        assert (await c.get(_PROBE, headers=_auth(victim))).status_code == 200
        resp = await c.post(
            f"/settings/api-tokens/users/{a['user_ids']['viewer']}/revoke",
            headers=_auth(a["tokens"]["admin"]),
        )
        assert resp.status_code == 303
        assert (await c.get(_PROBE, headers=_auth(victim))).status_code == 401
    events = await _events("api_token", str(a["user_ids"]["viewer"]))
    assert [e.diff.get("change") for e in events] == ["revoked_by_admin"]
    assert events[0].organization_id == a["org_id"]


async def test_an_admin_cannot_revoke_a_user_of_another_organization(two_orgs) -> None:
    a, b = two_orgs
    target = b["tokens"]["assessor"]
    async with _client() as c:
        resp = await c.post(
            f"/settings/api-tokens/users/{b['user_ids']['assessor']}/revoke",
            headers=_auth(a["tokens"]["admin"]),
        )
        assert resp.status_code == 404
        assert (await c.get(_PROBE, headers=_auth(target))).status_code == 200
    assert (await _user(b["user_ids"]["assessor"])).api_token_hash == hash_token(target)


@pytest.mark.parametrize("role", ["assessor", "control_owner", "viewer"])
async def test_only_an_admin_revokes_someone_elses_token(two_orgs, role: str) -> None:
    a, _ = two_orgs
    target = a["tokens"]["admin"]
    async with _client() as c:
        resp = await c.post(
            f"/settings/api-tokens/users/{a['user_ids']['admin']}/revoke",
            headers=_auth(a["tokens"][role]),
        )
        assert resp.status_code == 403
        assert (await c.get(_PROBE, headers=_auth(target))).status_code == 200


async def test_a_viewer_cannot_rotate_or_revoke(two_orgs) -> None:
    a, _ = two_orgs
    token = a["tokens"]["viewer"]
    async with _client() as c:
        assert (
            await c.post("/settings/api-tokens/rotate", headers=_auth(token))
        ).status_code == 403
        assert (
            await c.post("/settings/api-tokens/revoke", headers=_auth(token))
        ).status_code == 403
        page = await c.get("/settings/api-tokens", headers=_auth(token))
        assert page.status_code == 200
        assert 'action="/settings/api-tokens/rotate"' not in page.text
    assert (await _user(a["user_ids"]["viewer"])).api_token_hash == hash_token(token)
    for path in ("/settings/api-tokens/rotate", "/settings/api-tokens/revoke"):
        assert not viewer_may_write(path, "POST")


def test_the_token_routes_gate_on_their_own_not_only_through_the_middleware() -> None:
    """The middleware refuses a viewer's write anyway, so an HTTP test cannot
    tell a route gated by ``require_role`` from one gated by nothing. The
    matrix reads the route's own dependency, so it can."""
    rows = {(r.path, r.method): r for r in rbac_matrix.route_matrix(create_app())}
    for path in ("/settings/api-tokens/rotate", "/settings/api-tokens/revoke", "/ai/analysis/run"):
        row = rows[(path, "POST")]
        assert row.gate == rbac_matrix.GATE_ROLE, path
        assert set(row.roles) == {"admin", "control_owner", "assessor"}, path
    for path in (
        "/settings/api-tokens/users/{user_id}/revoke",
        "/admin/rbac/mappings",
        "/admin/rbac/mappings/{mapping_id}/delete",
    ):
        assert rows[(path, "POST")].roles == ("admin",), path


async def test_the_token_holder_list_is_the_admins_organization_only(two_orgs) -> None:
    a, b = two_orgs
    async with _client() as c:
        admin_page = (await c.get("/settings/api-tokens", headers=_auth(a["tokens"]["admin"]))).text
        assessor_page = (
            await c.get("/settings/api-tokens", headers=_auth(a["tokens"]["assessor"]))
        ).text
    assert f"alpha-viewer-{a['tag']}@pf.test" in admin_page
    assert f"bravo-viewer-{b['tag']}@pf.test" not in admin_page
    assert "Users holding a token" not in assessor_page
    assert f"alpha-viewer-{a['tag']}@pf.test" not in assessor_page


async def test_own_user_lookup_is_confined_to_the_principals_organization(two_orgs) -> None:
    """Defence in depth: a principal naming a user id from another organization
    (a stale or forged principal) resolves to no user at all."""
    a, b = two_orgs
    forged = Principal(
        user_id=int(b["user_ids"]["admin"]), email="x", org_id=int(a["org_id"]), role="admin"
    )
    async with session_scope() as s:
        assert await ui_platform._own_user(s, forged) is None


# ── RBAC matrix ──────────────────────────────────────────────────────────────


def test_the_matrix_reads_the_live_route_dependencies() -> None:
    rows = rbac_matrix.route_matrix(create_app())
    by = {(r.path, r.method): r for r in rows}
    assert len(rows) > 300, f"only {len(rows)} routes found -- route walk drift?"

    integrity = by[("/catalog/integrity", "GET")]
    assert integrity.gate == rbac_matrix.GATE_ROLE
    assert integrity.roles == ("admin",)
    assert integrity.admits == {
        "admin": True,
        "control_owner": False,
        "assessor": False,
        "viewer": False,
    }
    assert by[("/admin/self-assurance", "GET")].gate == rbac_matrix.GATE_PLATFORM
    assert not any(by[("/admin/self-assurance", "GET")].admits.values())
    assert by[("/healthz", "GET")].gate == rbac_matrix.GATE_PUBLIC
    assert by[("/ai/analysis", "GET")].gate == rbac_matrix.GATE_SIGNED_IN

    # A viewer is admitted by a signed-in-only write route's own gate, but the
    # auth middleware refuses it -- unless the path is on the allowlist.
    run = by[("/api/ai-actions/{action_key}/run", "POST")]
    assert run.gate == rbac_matrix.GATE_SIGNED_IN
    assert run.admits["viewer"] is False and run.viewer_refused_by_middleware
    assert by[("/api/notifications/read-all", "POST")].admits["viewer"] is True

    summary = rbac_matrix.summarize(rows)
    assert sum(summary[g] for g in rbac_matrix.GATES) == summary["total"] == len(rows)


def test_the_matrix_follows_a_route_it_has_never_seen() -> None:
    """Not a written table: a route added at runtime appears with its gate."""
    app = create_app()

    @app.post("/zz-probe/{thing_id}")
    async def _probe(
        thing_id: int, _p: Principal = Depends(require_role("assessor", "control_owner"))
    ) -> dict:
        return {}

    @app.get("/zz-open")
    async def _open(_p: Principal = Depends(get_principal)) -> dict:
        return {}

    by = {(r.path, r.method): r for r in rbac_matrix.route_matrix(app)}
    probe = by[("/zz-probe/{thing_id}", "POST")]
    assert probe.roles == ("assessor", "control_owner")
    assert probe.admits == {
        "admin": False,
        "control_owner": True,
        "assessor": True,
        "viewer": False,
    }
    assert by[("/zz-open", "GET")].gate == rbac_matrix.GATE_SIGNED_IN
    assert all(by[("/zz-open", "GET")].admits.values())


def test_two_role_gates_on_one_route_admit_only_their_intersection() -> None:
    app = create_app()

    @app.get("/zz-both")
    async def _both(
        _a: Principal = Depends(require_role("admin", "assessor")),
        _b: Principal = Depends(require_role("assessor", "viewer")),
    ) -> dict:
        return {}

    both = {(r.path, r.method): r for r in rbac_matrix.route_matrix(app)}[("/zz-both", "GET")]
    assert both.roles == ("assessor",)
    assert [r for r, ok in both.admits.items() if ok] == ["assessor"]


@pytest.mark.parametrize("role", ["assessor", "control_owner", "viewer"])
async def test_the_rbac_page_is_for_admins(two_orgs, role: str) -> None:
    a, _ = two_orgs
    async with _client() as c:
        assert (await c.get("/admin/rbac", headers=_auth(a["tokens"][role]))).status_code == 403


async def test_the_rbac_page_renders_the_derived_matrix(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        page = await c.get("/admin/rbac?q=/catalog/integrity", headers=_auth(a["tokens"]["admin"]))
    assert page.status_code == 200
    assert "/catalog/integrity" in page.text
    assert "require_role(admin)" in page.text


async def test_group_mappings_are_listed_per_organization(two_orgs) -> None:
    a, b = two_orgs
    async with _client() as c:
        page = (await c.get("/admin/rbac", headers=_auth(a["tokens"]["admin"]))).text
    assert f"Alpha-group-{a['tag']}" in page
    assert f"Bravo-group-{b['tag']}" not in page


async def test_an_admin_adds_and_removes_a_mapping_in_their_own_organization(two_orgs) -> None:
    a, _ = two_orgs
    group = f"Alpha-new-group-{a['tag']}"
    async with _client() as c:
        resp = await c.post(
            "/admin/rbac/mappings",
            data={"group": group, "role": "control_owner", "priority": "5"},
            headers=_auth(a["tokens"]["admin"]),
        )
        assert resp.status_code == 303
        async with session_scope() as s:
            m = (
                await s.execute(select(GroupRoleMapping).where(GroupRoleMapping.group == group))
            ).scalar_one()
        assert (m.organization_id, m.role, m.priority) == (a["org_id"], "control_owner", 5)
        assert [e.action for e in await _events("group_role_mapping", str(m.id))] == ["create"]

        dup = await c.post(
            "/admin/rbac/mappings",
            data={"group": group, "role": "viewer"},
            headers=_auth(a["tokens"]["admin"]),
        )
        assert dup.status_code == 303 and "already" in dup.headers["location"]

        bad = await c.post(
            "/admin/rbac/mappings",
            data={"group": group + "x", "role": "superuser"},
            headers=_auth(a["tokens"]["admin"]),
        )
        assert bad.status_code == 422

        gone = await c.post(
            f"/admin/rbac/mappings/{m.id}/delete", headers=_auth(a["tokens"]["admin"])
        )
        assert gone.status_code == 303
    async with session_scope() as s:
        assert await s.get(GroupRoleMapping, m.id) is None
    assert [e.action for e in await _events("group_role_mapping", str(m.id))] == [
        "create",
        "delete",
    ]


async def test_an_admin_cannot_remove_another_organizations_mapping(two_orgs) -> None:
    a, b = two_orgs
    async with _client() as c:
        resp = await c.post(
            f"/admin/rbac/mappings/{b['mapping_id']}/delete", headers=_auth(a["tokens"]["admin"])
        )
    assert resp.status_code == 404
    async with session_scope() as s:
        assert await s.get(GroupRoleMapping, int(b["mapping_id"])) is not None


@pytest.mark.parametrize("role", ["assessor", "control_owner", "viewer"])
async def test_only_an_admin_edits_mappings(two_orgs, role: str) -> None:
    a, _ = two_orgs
    async with _client() as c:
        add = await c.post(
            "/admin/rbac/mappings",
            data={"group": f"nope-{role}-{a['tag']}", "role": "admin"},
            headers=_auth(a["tokens"][role]),
        )
        rm = await c.post(
            f"/admin/rbac/mappings/{a['mapping_id']}/delete", headers=_auth(a["tokens"][role])
        )
    assert (add.status_code, rm.status_code) == (403, 403)
    async with session_scope() as s:
        assert await s.get(GroupRoleMapping, int(a["mapping_id"])) is not None
        stmt = select(GroupRoleMapping).where(GroupRoleMapping.group == f"nope-{role}-{a['tag']}")
        assert (await s.execute(stmt)).first() is None


# ── Governed AI analysis ─────────────────────────────────────────────────────


async def test_without_a_provider_the_page_says_so_and_links_the_settings(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        for role in _ROLES:
            page = await c.get("/ai/analysis", headers=_auth(a["tokens"][role]))
            assert page.status_code == 200, role
            assert "No AI provider is configured" in page.text, role
            assert 'href="/admin/ai-settings"' in page.text, role
            assert "No runs yet" in page.text, role


async def test_a_configured_provider_is_not_reported_missing(two_orgs) -> None:
    a, b = two_orgs
    async with session_scope() as s:
        s.add(
            AiProviderConfig(
                organization_id=int(b["org_id"]),
                provider="anthropic",
                enabled=True,
                encrypted_credential="not-a-real-credential",
            )
        )
    async with _client() as c:
        alpha = (await c.get("/ai/analysis", headers=_auth(a["tokens"]["admin"]))).text
        bravo = (await c.get("/ai/analysis", headers=_auth(b["tokens"]["admin"]))).text
    assert "No AI provider is configured" in alpha  # Bravo's provider is not Alpha's
    assert "No AI provider is configured" not in bravo


async def test_a_run_is_recorded_as_a_draft_and_applies_nothing(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        resp = await c.post(
            "/ai/analysis/run",
            data={"action_key": "draft_poam_remediation", "target": f"poam:{a['poam_id']}"},
            headers=_auth(a["tokens"]["assessor"]),
        )
        assert resp.status_code == 303, resp.text
        run_id = int(resp.headers["location"].split("run=")[1])
        page = await c.get(f"/ai/analysis?run={run_id}", headers=_auth(a["tokens"]["viewer"]))
    assert page.status_code == 200
    assert "Draft, not applied" in page.text
    assert "Awaiting review" in page.text
    async with session_scope() as s:
        run = await s.get(AiActionRun, run_id)
        assert run.organization_id == a["org_id"]
        assert run.provider == "stub" and run.model is None
        assert run.status == "pending_review" and not run.mutation_applied
        poam = await s.get(POAM, int(a["poam_id"]))
        assert poam.remediation_plan is None
        applied = await s.execute(
            select(AiApprovedMutation).where(AiApprovedMutation.run_id == run_id)
        )
        assert applied.first() is None
    assert [e.action for e in await _events("ai_action", str(run_id))] == ["create"]


@pytest.mark.parametrize(
    "target",
    ["bravo_poam", "alpha_deleted_poam", "alpha_orphan_risk", "bravo_system"],
)
async def test_a_run_is_refused_on_a_record_the_caller_cannot_see(two_orgs, target: str) -> None:
    a, b = two_orgs
    value = {
        "bravo_poam": ("draft_poam_remediation", f"poam:{b['poam_id']}"),
        "alpha_deleted_poam": ("draft_poam_remediation", f"poam:{a['gone_poam_id']}"),
        "alpha_orphan_risk": ("open_task_with_owner_due_date", f"risk:{a['orphan_risk_id']}"),
        "bravo_system": ("generate_assessor_brief", f"system:{b['system_id']}"),
    }[target]
    async with _client() as c:
        resp = await c.post(
            "/ai/analysis/run",
            data={"action_key": value[0], "target": value[1]},
            headers=_auth(a["tokens"]["admin"]),
        )
    assert resp.status_code == 404
    async with session_scope() as s:
        stmt = select(AiActionRun).where(AiActionRun.organization_id == a["org_id"])
        assert (await s.execute(stmt)).first() is None


async def test_an_action_is_refused_on_a_type_it_does_not_accept(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        resp = await c.post(
            "/ai/analysis/run",
            data={"action_key": "draft_poam_remediation", "target": f"system:{a['system_id']}"},
            headers=_auth(a["tokens"]["admin"]),
        )
    assert resp.status_code == 303
    assert "cannot%20run%20on%20system" in resp.headers["location"]


async def test_a_viewer_cannot_start_a_run(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        resp = await c.post(
            "/ai/analysis/run",
            data={"action_key": "generate_assessor_brief", "target": f"system:{a['system_id']}"},
            headers=_auth(a["tokens"]["viewer"]),
        )
        page = await c.get("/ai/analysis", headers=_auth(a["tokens"]["viewer"]))
    assert resp.status_code == 403
    assert 'action="/ai/analysis/run"' not in page.text


async def test_the_record_picker_offers_only_the_callers_live_records(two_orgs) -> None:
    a, b = two_orgs
    async with _client() as c:
        page = (await c.get("/ai/analysis", headers=_auth(a["tokens"]["control_owner"]))).text
    for kind in ("system", "poam", "risk", "ctl", "vendor", "policy", "evidence"):
        assert f"Alpha-{kind}-{a['tag']}" in page, kind
        assert f"Bravo-{kind}-{b['tag']}" not in page, kind
    assert "DELETED" not in page
    assert "ORPHAN" not in page


async def test_runs_are_listed_and_opened_for_the_callers_organization_only(two_orgs) -> None:
    a, b = two_orgs
    async with session_scope() as s:
        mine = await run_action(
            s,
            action_key="generate_assessor_brief",
            entity_type="system",
            entity_id=str(a["system_id"]),
            org_id=int(a["org_id"]),
            actor="t",
        )
        theirs = await run_action(
            s,
            action_key="generate_assessor_brief",
            entity_type="system",
            entity_id=str(b["system_id"]),
            org_id=int(b["org_id"]),
            actor="t",
        )
        mine_id, theirs_id = mine.id, theirs.id
    async with _client() as c:
        page = (await c.get("/ai/analysis", headers=_auth(a["tokens"]["viewer"]))).text
        foreign = await c.get(f"/ai/analysis?run={theirs_id}", headers=_auth(a["tokens"]["admin"]))
    assert f'href="/ai/analysis?run={mine_id}#run"' in page
    assert f'href="/ai/analysis?run={theirs_id}#run"' not in page
    assert foreign.status_code == 404


async def test_writes_without_an_organization_are_refused() -> None:
    """With auth off the caller is the unscoped system principal. A run or a
    mapping written for it would carry a NULL org, which RLS shows everyone."""
    os.environ["CCF_AUTH_ENABLED"] = "false"
    get_settings.cache_clear()
    async with _client() as c:
        run = await c.post(
            "/ai/analysis/run", data={"action_key": "generate_assessor_brief", "target": "system:1"}
        )
        mapping = await c.post("/admin/rbac/mappings", data={"group": "g", "role": "viewer"})
        page = await c.get("/ai/analysis")
    assert run.status_code == 400
    assert mapping.status_code == 400
    assert page.status_code == 200 and "No organization in this session" in page.text
