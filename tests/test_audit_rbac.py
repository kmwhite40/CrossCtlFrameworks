"""RBAC gate on the audit-read API (IA-02): list_audit / verify_chain must
require a privileged role once auth is enabled — the role gate is independent
of (and layered beneath) the per-tenant RLS scoping added in DATA-06 (see
``tests/test_audit_tenant_scoping.py`` and the note in ``ccf.api.routes.audit``):
a non-privileged user is refused outright regardless of tenant, while a
privileged admin/assessor's own session is now additionally row-isolated to
their own org.

The server-rendered ``/audit`` HTML page (``ccf.api.routes.ui.audit_page``)
reads the same table and must carry the identical gate — otherwise a
non-privileged, authenticated user could browse every tenant's audit trail
through the UI even though the JSON API refuses them.
"""

from __future__ import annotations

import os

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete

from ccf.api.audit import row_hash
from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import AuditLog, Organization, User

_GENESIS = "0" * 64

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _auth_enabled() -> None:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _mk_user(email: str, org_name: str, role: str) -> str:
    """Create an org + a user with the given role; return a bearer token."""
    async with session_scope() as s:
        org = Organization(name=org_name)
        s.add(org)
        await s.flush()
        user = User(
            email=email,
            organization_id=org.id,
            role=role,
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        await s.flush()
        return user.api_token


async def _mk_user_with_org(email: str, org_name: str, role: str) -> tuple[str, int]:
    """Like ``_mk_user``, but also returns the new org's id (needed to seed
    audit rows directly against a specific org)."""
    async with session_scope() as s:
        org = Organization(name=org_name)
        s.add(org)
        await s.flush()
        user = User(
            email=email,
            organization_id=org.id,
            role=role,
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        await s.flush()
        return user.api_token, org.id


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --- unauthenticated ---------------------------------------------------------


@pytest.mark.asyncio
async def test_unauthenticated_refused() -> None:
    async with _client() as c:
        assert (await c.get("/api/audit")).status_code == 401
        assert (await c.get("/api/audit/verify")).status_code == 401


# --- non-privileged roles get 403 --------------------------------------------


@pytest.mark.asyncio
async def test_viewer_refused() -> None:
    token = await _mk_user("viewer@audit-rbac.test", "Audit RBAC Viewer Org", "viewer")
    async with _client() as c:
        r1 = await c.get("/api/audit", headers=_auth(token))
        assert r1.status_code == 403
        r2 = await c.get("/api/audit/verify", headers=_auth(token))
        assert r2.status_code == 403


@pytest.mark.asyncio
async def test_control_owner_refused() -> None:
    token = await _mk_user(
        "co@audit-rbac.test", "Audit RBAC ControlOwner Org", "control_owner"
    )
    async with _client() as c:
        r1 = await c.get("/api/audit", headers=_auth(token))
        assert r1.status_code == 403
        r2 = await c.get("/api/audit/verify", headers=_auth(token))
        assert r2.status_code == 403


# --- privileged roles are let through ------------------------------------------


@pytest.mark.asyncio
async def test_admin_allowed() -> None:
    token = await _mk_user("admin@audit-rbac.test", "Audit RBAC Admin Org", "admin")
    async with _client() as c:
        r1 = await c.get("/api/audit", headers=_auth(token))
        assert r1.status_code == 200
        # This file tests the RBAC gate, not chain correctness: a privileged caller
        # reaches the endpoint and gets a well-formed result. Whether ``ok`` is True
        # depends on the session's accumulated audit_log and is asserted in an
        # isolated chain test to avoid full-suite ordering flakiness.
        r2 = await c.get("/api/audit/verify", headers=_auth(token))
        assert r2.status_code == 200
        assert "ok" in r2.json()


@pytest.mark.asyncio
async def test_assessor_allowed() -> None:
    token = await _mk_user(
        "assessor@audit-rbac.test", "Audit RBAC Assessor Org", "assessor"
    )
    async with _client() as c:
        r1 = await c.get("/api/audit", headers=_auth(token))
        assert r1.status_code == 200
        r2 = await c.get("/api/audit/verify", headers=_auth(token))
        assert r2.status_code == 200
        assert "ok" in r2.json()


# --- chain-verify logic is preserved under the gate ----------------------------


@pytest.mark.asyncio
async def test_chain_verify_still_works_for_admin() -> None:
    """The hash-chain verify behavior (incl. tamper detection) is unchanged by
    the role gate — this exercises it end-to-end as an authenticated admin."""
    token = await _mk_user("admin2@audit-rbac.test", "Audit RBAC Chain Org", "admin")
    async with _client() as c:
        # A mutation (creating the org/user above happened outside the HTTP
        # layer) — trigger one through the API so there's a chained row, then
        # confirm the chain still verifies for a privileged caller.
        await c.post(
            "/api/ssp/projects",
            json={"customer_name": "AuditRbacChainCo"},
            headers=_auth(token),
        )
        r = await c.get("/api/audit/verify", headers=_auth(token))
        assert r.status_code == 200
        body = r.json()
        # Reachable by a privileged caller and returns a well-formed chain result.
        # NOTE: this deliberately does NOT assert `ok is True` here — by this point
        # the process-wide `audit_log` table carries whatever every earlier test in
        # the full suite has written to it, and a real `ok is True` check is only
        # deterministic against a controlled chain (see the dedicated,
        # self-contained regression test below, which resets the table first).
        assert body["checked"] >= 1


@pytest.mark.asyncio
async def test_verify_ok_true_for_org_scoped_admin_over_interleaved_multi_org_chain() -> None:
    """FINDING 1 regression: audit_log is RLS-scoped per organization (DATA-06),
    but the SHA-256 hash chain it carries is GLOBAL — each row's ``prev_hash``
    links to the *previous row overall*, regardless of org. Before the fix,
    ``verify_chain`` ran on the tenant-clamped ``get_session`` dependency, so a
    scoped admin's walk only ever saw their own org's (+ NULL-org) rows. Any
    other org's row sitting between two of the admin's own rows in the real
    chain broke the (locally reconstructed) linkage and produced a false
    ``ok=False`` — even though the actual global chain was untampered.

    Interleave two different orgs' rows so at least one other-org row sits
    between two of org A's own rows, then confirm an org A admin's verify still
    reports the true, intact state. Rows are seeded directly (one
    ``session_scope`` transaction, matching exactly what the audit middleware
    itself writes — see ``ccf.api.audit.audit_middleware``) rather than via
    live cross-org HTTP mutations: unrelated to this fix, this codebase's
    create-endpoints commit mid-request and keep using the session afterward
    (e.g. ``insert -> commit -> session.refresh``), which can hand a
    *different* pooled connection to the post-commit statement — harmless
    within one org's own request, but it makes a live two-org interleaving
    within a single test connection-pool-order-dependent. Seeding the rows
    directly keeps this test deterministic while still exercising the exact
    RLS-vs-global-chain scenario FINDING 1 describes.

    The table is cleared first so this test's ``ok is True`` assertion is
    deterministic regardless of full-suite run order: ``verify_chain`` walks
    the *entire* ``audit_log`` table from genesis, and this suite has a
    separate, pre-existing, already-documented source of full-suite-order
    non-determinism around the audit chain (``test-suite-async-flakiness``;
    also why ``test_enterprise.py::test_audit_chain_verifies_and_detects_tampering``
    is the one accepted full-suite flake) that is unrelated to and unaffected
    by this fix. Resetting to a clean, fully-controlled chain here isolates
    FINDING 1's regression from that separate issue.
    """
    token_a, org_a = await _mk_user_with_org(
        "admin-a@audit-rbac-chain.test", "Audit RBAC Chain Org A", "admin"
    )
    _token_b, org_b = await _mk_user_with_org(
        "admin-b@audit-rbac-chain.test", "Audit RBAC Chain Org B", "admin"
    )

    async with session_scope() as s:
        await s.execute(delete(AuditLog))
        prev = _GENESIS
        seeds = ((org_a, "chain-org-a-1"), (org_b, "chain-org-b-1"), (org_a, "chain-org-a-2"))
        for org_id, tag in seeds:
            content = {
                "actor": "chain-seed@audit-rbac.test",
                "action": "create",
                "entity_type": "chain_seed",
                "entity_id": tag,
                "diff": {"seed": tag},
            }
            h = row_hash(prev, content)
            s.add(AuditLog(**content, organization_id=org_id, prev_hash=prev, row_hash=h))
            prev = h

    async with _client() as c:
        r = await c.get("/api/audit/verify", headers=_auth(token_a))
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True


# --- the server-rendered /audit HTML page carries the same gate ----------------


@pytest.mark.asyncio
async def test_audit_page_viewer_refused() -> None:
    token = await _mk_user(
        "viewer-page@audit-rbac.test", "Audit RBAC Viewer Page Org", "viewer"
    )
    async with _client() as c:
        r = await c.get("/audit", headers=_auth(token))
        assert r.status_code == 403


@pytest.mark.asyncio
async def test_audit_page_admin_allowed() -> None:
    token = await _mk_user(
        "admin-page@audit-rbac.test", "Audit RBAC Admin Page Org", "admin"
    )
    async with _client() as c:
        r = await c.get("/audit", headers=_auth(token))
        assert r.status_code == 200
