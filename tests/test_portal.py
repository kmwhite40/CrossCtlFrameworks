"""External collaboration portal — grants, token resolution, scope, audit, RLS.

The portal gives customers/assessors/vendors scoped, expiring, token-based access
to shared packages/evidence — with no internal account and every access audited.
The security-critical invariants live here: expired/revoked tokens don't resolve,
a grant only exposes what was explicitly shared, and nothing crosses tenants.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError

from ccf.api.auth_deps import SESSION_COOKIE
from ccf.api.main import create_app
from ccf.api.routes.portal import PORTAL_SESSION_COOKIE, _portal_cookie_ttl_hours
from ccf.auth import hash_token, sign_session
from ccf.config import get_settings
from ccf.db import session_scope, set_session_tenant
from ccf.evidence import service as ev_service
from ccf.models import Organization, System, User
from ccf.models_portal import (
    ExternalAccessGrant,
    ExternalComment,
    ExternalPackageShare,
    ExternalPortalAuditEvent,
)
from ccf.packages import service as pkg_service
from ccf.portal import service as portal
from ccf.reliability.checks import (
    _check_external_access_scope_integrity,
    _check_external_grant_expiration,
    _check_external_portal_audit_completeness,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name, description="portal test")
        s.add(org)
        await s.flush()
        return org.id


async def _system(org_id: int, name: str) -> int:
    async with session_scope() as s:
        sysm = System(organization_id=org_id, name=name, baseline="moderate")
        s.add(sysm)
        await s.flush()
        return sysm.id


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


@pytest.mark.asyncio
async def test_create_and_resolve_grant() -> None:
    org = await _org("PortalCreate")
    async with session_scope() as s:
        grant = await portal.create_grant(
            s, org_id=org, principal_name="Auditor A", kind="assessor", ttl_days=14
        )
        token = grant.token
        assert token and len(token) <= 64
    async with session_scope() as s:
        resolved = await portal.resolve_grant(s, token)
        assert resolved is not None
        assert resolved.organization_id == org
        assert resolved.kind == "assessor"


@pytest.mark.asyncio
async def test_grant_token_persisted_as_hash_not_plaintext() -> None:
    """IA-09: the DB holds no reversible grant token; resolution works off the hash."""
    org = await _org("PortalHashCheck")
    async with session_scope() as s:
        grant = await portal.create_grant(s, org_id=org, principal_name="Hash Check")
        gid, token = grant.id, grant.token
    async with session_scope() as s:
        row = await s.get(ExternalAccessGrant, gid)
        assert row is not None
        assert row.token_hash is not None
        assert row.token_hash != token
        assert row.token_hash == hash_token(token)
        # A freshly loaded instance never carries the plaintext.
        assert row.token is None
    async with session_scope() as s:
        resolved = await portal.resolve_grant(s, token)
        assert resolved is not None and resolved.id == gid
        assert await portal.resolve_grant(s, "not-the-token") is None


def test_token_setter_guards_empty_value_like_user_api_token() -> None:
    """Symmetry with ``User.api_token``: assigning a falsy token must not clobber
    (or attempt to null out) ``token_hash`` — it's a non-nullable column, so
    setting it to ``None`` would be both wrong behavior and a type violation.
    """
    grant = ExternalAccessGrant(kind="customer")
    grant.token = "a-real-token-value"
    real_hash = grant.token_hash
    assert real_hash == hash_token("a-real-token-value")

    # Re-assigning an empty value leaves the persisted hash untouched.
    grant.token = ""
    assert grant.token_hash == real_hash
    # ...but the in-memory plaintext reflects the last assignment, matching
    # ``User.api_token``'s behavior of always mirroring the last set value.
    assert grant.token == ""


@pytest.mark.asyncio
async def test_resolve_rejects_expired_grant() -> None:
    org = await _org("PortalExpired")
    async with session_scope() as s:
        grant = await portal.create_grant(s, org_id=org, principal_name="Late", ttl_days=1)
        grant.expires_at = datetime.now(UTC) - timedelta(days=1)  # force expiry
        token = grant.token
    async with session_scope() as s:
        assert await portal.resolve_grant(s, token) is None


@pytest.mark.asyncio
async def test_resolve_rejects_revoked_grant() -> None:
    org = await _org("PortalRevoked")
    async with session_scope() as s:
        grant = await portal.create_grant(s, org_id=org, principal_name="Gone", ttl_days=30)
        gid, token = grant.id, grant.token
    async with session_scope() as s:
        assert await portal.revoke_grant(s, gid, actor="admin@x") is True
    async with session_scope() as s:
        assert await portal.resolve_grant(s, token) is None


@pytest.mark.asyncio
async def test_grant_contents_only_returns_shared_artifacts() -> None:
    org = await _org("PortalScope")
    system = await _system(org, "ScopeSys")
    async with session_scope() as s:
        shared = await pkg_service.create_package(
            s, org_id=org, system_id=system, kind="json", label="Shared pkg"
        )
        private = await pkg_service.create_package(
            s, org_id=org, system_id=system, kind="json", label="Private pkg"
        )
        ev = await ev_service.create_object(
            s, org_id=org, title="Shared evidence", system_id=system
        )
        shared_id, private_id, ev_id = shared.id, private.id, ev.id
    async with session_scope() as s:
        grant = await portal.create_grant(
            s, org_id=org, principal_name="Cust", package_ids=[shared_id], evidence_ids=[ev_id]
        )
        token = grant.token
    async with session_scope() as s:
        grant = await portal.resolve_grant(s, token)
        contents = await portal.grant_contents(s, grant)
        pkg_ids = {p["id"] for p in contents["packages"]}
        ev_ids = {e["id"] for e in contents["evidence"]}
        assert pkg_ids == {shared_id}
        assert private_id not in pkg_ids  # not shared → never exposed
        assert ev_ids == {ev_id}


@pytest.mark.asyncio
async def test_access_and_comment_write_audit_events() -> None:
    org = await _org("PortalAudit")
    async with session_scope() as s:
        grant = await portal.create_grant(s, org_id=org, principal_name="Talker")
        gid, token = grant.id, grant.token
    async with session_scope() as s:
        grant = await portal.resolve_grant(s, token)
        await portal.record_access(s, grant, action="view", target_type="package", target_id="1")
        await portal.add_comment(
            s, grant, target_type="evidence", target_id="9", author="Talker", body="Looks good"
        )
    async with session_scope() as s:
        comments = (
            await s.execute(select(func.count()).select_from(ExternalComment).where(
                ExternalComment.grant_id == gid))
        ).scalar_one()
        events = (
            await s.execute(select(ExternalPortalAuditEvent).where(
                ExternalPortalAuditEvent.grant_id == gid))
        ).scalars().all()
        actions = {e.action for e in events}
        assert comments == 1
        assert "view" in actions and "comment" in actions  # both access and comment audited


@pytest.mark.asyncio
async def test_rls_blocks_cross_tenant_grants() -> None:
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    org_a = await _org("PortalRlsA")
    org_b = await _org("PortalRlsB")
    async with session_scope() as s:
        await portal.create_grant(s, org_id=org_a, principal_name="A")
        await portal.create_grant(s, org_id=org_b, principal_name="B")
    async with session_scope() as s:
        await set_session_tenant(s, org_a)
        orgs = {
            g.organization_id
            for g in (await s.execute(select(ExternalAccessGrant))).scalars().all()
        }
        assert orgs == {org_a}  # tenant A cannot see tenant B's grants


@pytest.mark.asyncio
async def test_admin_and_portal_api_end_to_end() -> None:
    org = await _org("PortalApi")
    system = await _system(org, "ApiSys")
    async with session_scope() as s:
        pkg = await pkg_service.create_package(
            s, org_id=org, system_id=system, kind="json", label="API pkg"
        )
        pkg_id = pkg.id
    async with _client() as c:
        created = await c.post(
            "/api/admin/portal/grants",
            json={"organization_id": org, "principal_name": "Ext Auditor",
                  "kind": "assessor", "package_ids": [pkg_id], "ttl_days": 30},
        )
        assert created.status_code == 200
        token = created.json()["token"]
        assert token

        # Issuance is the only place the plaintext token is ever returned — the
        # list endpoint must not re-expose it (IA-09: no reversible token at rest).
        listed = await c.get("/api/admin/portal/grants", params={"organization_id": org})
        assert listed.status_code == 200
        rows = listed.json()
        assert any(g["id"] == created.json()["id"] for g in rows)
        assert all("token" not in g for g in rows)

        # Portal session resolves with the bearer token and returns the shared package.
        sess = await c.get("/api/portal/session", headers={"Authorization": f"Bearer {token}"})
        assert sess.status_code == 200
        assert any(p["id"] == pkg_id for p in sess.json()["packages"])

        # A bogus token is denied.
        bad = await c.get("/api/portal/session", headers={"Authorization": "Bearer nope"})
        assert bad.status_code == 401


# --- reliability checks -----------------------------------------------------


@pytest.mark.asyncio
async def test_scope_integrity_check_flags_cross_tenant_share() -> None:
    org_a = await _org("ScopeChkA")
    org_b = await _org("ScopeChkB")
    system_b = await _system(org_b, "BSys")
    async with session_scope() as s:
        pkg_b = await pkg_service.create_package(
            s, org_id=org_b, system_id=system_b, kind="json", label="B pkg"
        )
        grant_a = await portal.create_grant(s, org_id=org_a, principal_name="A")
        grant_a_id, pkg_b_id = grant_a.id, pkg_b.id
    # Clean state → PASS.
    async with session_scope() as s:
        await set_session_tenant(s, None)
        assert (await _check_external_access_scope_integrity(s)).status == "pass"
    # Craft a cross-tenant leak: A's grant referencing B's package.
    async with session_scope() as s:
        bad = ExternalPackageShare(grant_id=grant_a_id, package_id=pkg_b_id)
        s.add(bad)
        await s.flush()
        bad_id = bad.id
    try:
        async with session_scope() as s:
            await set_session_tenant(s, None)
            assert (await _check_external_access_scope_integrity(s)).status == "fail"
    finally:
        async with session_scope() as s:  # clean up so global reliability stays green
            leak = await s.get(ExternalPackageShare, bad_id)
            if leak is not None:
                await s.delete(leak)


@pytest.mark.asyncio
async def test_scope_integrity_failure_alerts_but_does_not_gate_readyz() -> None:
    """A cross-tenant data leak is a global condition: it must surface in the
    full reliability suite (so it gets fixed) but must NOT pull every container
    out of rotation via /readyz — that would be a fleet-wide outage that can't
    self-heal, since the admin UI needed to fix the leak would itself be down."""
    org_a = await _org("ScopeGateA")
    org_b = await _org("ScopeGateB")
    system_b = await _system(org_b, "GateBSys")
    async with session_scope() as s:
        pkg_b = await pkg_service.create_package(
            s, org_id=org_b, system_id=system_b, kind="json", label="Gate B pkg"
        )
        grant_a = await portal.create_grant(s, org_id=org_a, principal_name="GateA")
        grant_a_id, pkg_b_id = grant_a.id, pkg_b.id
    async with session_scope() as s:
        bad = ExternalPackageShare(grant_id=grant_a_id, package_id=pkg_b_id)
        s.add(bad)
        await s.flush()
        bad_id = bad.id
    try:
        async with session_scope() as s:
            await set_session_tenant(s, None)
            assert (await _check_external_access_scope_integrity(s)).status == "fail"
        async with _client() as c:
            # /readyz stays 200: this check is not in the readiness-gating subset.
            ready = await c.get("/readyz")
            assert ready.status_code == 200
            assert ready.json()["status"] == "ready"
            names = {chk["name"] for chk in ready.json()["checks"]}
            assert "external_access_scope_integrity" not in names

            # The full reliability suite still surfaces the failure.
            report = await c.get("/api/admin/reliability")
            assert report.status_code == 503  # overall FAIL because this check FAILed
            body = report.json()
            flagged = next(
                chk for chk in body["checks"] if chk["name"] == "external_access_scope_integrity"
            )
            assert flagged["status"] == "fail"
    finally:
        async with session_scope() as s:  # clean up so global reliability stays green
            leak = await s.get(ExternalPackageShare, bad_id)
            if leak is not None:
                await s.delete(leak)


@pytest.mark.asyncio
async def test_grant_expiration_check_warns_on_stale_live_grant() -> None:
    org = await _org("ExpChk")
    async with session_scope() as s:
        grant = await portal.create_grant(s, org_id=org, principal_name="Stale", ttl_days=1)
        grant.expires_at = datetime.now(UTC) - timedelta(days=2)  # expired, not revoked
    async with session_scope() as s:
        await set_session_tenant(s, None)
        chk = await _check_external_grant_expiration(s)
        assert chk.status == "warn"
        assert "expired" in chk.message.lower()


@pytest.mark.asyncio
async def test_audit_completeness_check_warns_on_grant_without_audit() -> None:
    org = await _org("AuditChk")
    # A grant inserted directly (bypassing the service) has no audit trail.
    async with session_scope() as s:
        bare = ExternalAccessGrant(organization_id=org, kind="customer", token="bare-" + "x" * 20)
        s.add(bare)
        await s.flush()
        bare_id = bare.id
    try:
        async with session_scope() as s:
            await set_session_tenant(s, None)
            assert (await _check_external_portal_audit_completeness(s)).status == "warn"
    finally:
        async with session_scope() as s:
            g = await s.get(ExternalAccessGrant, bare_id)
            if g is not None:
                await s.delete(g)


# --- internal admin UI ------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_portal_ui_lists_shareable_artifacts_and_issues_grant() -> None:
    org = await _org("PortalAdminUI")
    system = await _system(org, "AdminUISys")
    async with session_scope() as s:
        pkg = await pkg_service.create_package(
            s, org_id=org, system_id=system, kind="json", label="AdminUI package"
        )
        pkg_id = pkg.id
    async with _client() as c:
        # The page renders and offers the org's package to share.
        page = await c.get("/admin/portal", params={"organization_id": org})
        assert page.status_code == 200
        assert "AdminUI package" in page.text
        # Issue a grant via the form. The response renders the admin page
        # directly (no redirect) so the one-time plaintext token never
        # transits a URL/query param — see the finding-4 fix note in
        # ui_grc.py's portal_admin_create.
        issued = await c.post(
            "/admin/portal/grants",
            data={"organization_id": org, "principal_name": "UI Assessor",
                  "kind": "assessor", "ttl_days": "30", "package_ids": str(pkg_id)},
            follow_redirects=False,
        )
        assert issued.status_code == 200
        assert issued.url == "http://t/admin/portal/grants"
        assert "issued_token" not in str(issued.url)
        assert "token=" not in str(issued.url)
        assert "UI Assessor" in issued.text
        # The one-time share link (which embeds the plaintext token) is shown
        # in the response body, not the URL.
        assert "portal?token=" in issued.text
    # The new grant now appears on the page on a plain reload too.
    async with _client() as c:
        page2 = await c.get("/admin/portal", params={"organization_id": org})
        assert "UI Assessor" in page2.text


# --- portal UI: token→cookie session exchange (magic-link hardening) -------
#
# The external link is `…/portal?token=<plaintext>`. Leaving the token in the
# URL after first use means it lands in browser history and portal access
# logs on every subsequent navigation. The UI route now exchanges a valid
# link token for a short-lived signed session cookie (scoped to the grant,
# reusing ``ccf.auth.sign_session``/``verify_session``) on first use, and
# redirects to the same path with the token stripped — later requests
# authenticate off the cookie, which is re-validated against the live grant
# (not just its own signature/exp) on every request.


@pytest.mark.asyncio
async def test_portal_ui_token_exchanges_for_cookie_and_strips_token_from_url() -> None:
    org = await _org("PortalCookieExchange")
    system = await _system(org, "CookieSys")
    async with session_scope() as s:
        pkg = await pkg_service.create_package(
            s, org_id=org, system_id=system, kind="json", label="Cookie pkg"
        )
        grant = await portal.create_grant(
            s, org_id=org, principal_name="Cookie Cust", package_ids=[pkg.id], ttl_days=30
        )
        token = grant.token

    async with _client() as c:
        first = await c.get("/portal", params={"token": token}, follow_redirects=False)
        assert first.status_code == 303
        location = first.headers["location"]
        assert "token=" not in location
        assert location.split("?")[0].endswith("/portal")
        assert PORTAL_SESSION_COOKIE in first.cookies

        # Following the redirect (same client → cookie jar carries the new
        # session cookie, no token in the URL) authenticates and renders.
        second = await c.get(location)
        assert second.status_code == 200
        assert "Cookie pkg" in second.text
        assert "This link is invalid" not in second.text

        # A follow-up request with no token at all, just the cookie already
        # in the jar, also authenticates — the cookie, not the URL, now
        # carries the session.
        third = await c.get("/portal")
        assert third.status_code == 200
        assert "Cookie pkg" in third.text


@pytest.mark.asyncio
async def test_portal_ui_revoked_grant_rejected_even_with_valid_cookie() -> None:
    org = await _org("PortalCookieRevoke")
    async with session_scope() as s:
        grant = await portal.create_grant(s, org_id=org, principal_name="Revoke Me", ttl_days=30)
        gid, token = grant.id, grant.token

    async with _client() as c:
        first = await c.get("/portal", params={"token": token}, follow_redirects=False)
        assert first.status_code == 303
        assert PORTAL_SESSION_COOKIE in first.cookies

        # The freshly issued cookie currently authenticates.
        ok = await c.get("/portal")
        assert ok.status_code == 200
        assert "This link is invalid" not in ok.text

        # Revoke the grant out-of-band (e.g. an admin action). The
        # previously-issued cookie's signature/exp are still perfectly
        # valid, but the per-request re-check against the live grant row
        # must catch the revocation immediately.
        async with session_scope() as s:
            assert await portal.revoke_grant(s, gid, actor="admin@x") is True

        after_revoke = await c.get("/portal")
        assert after_revoke.status_code == 200
        assert "This link is invalid" in after_revoke.text


@pytest.mark.asyncio
async def test_portal_ui_invalid_token_does_not_authenticate() -> None:
    async with _client() as c:
        resp = await c.get("/portal", params={"token": "not-a-real-token"})
        assert resp.status_code == 200
        assert "This link is invalid" in resp.text
        assert PORTAL_SESSION_COOKIE not in resp.cookies


@pytest.mark.asyncio
async def test_portal_ui_no_token_no_cookie_shows_gate() -> None:
    async with _client() as c:
        resp = await c.get("/portal")
        assert resp.status_code == 200
        assert "This link is invalid" in resp.text


# --- DATA-07/11: grant_id FKs on external_comments / questionnaire requests /
# audit events (0049_portal_grant_ref_fks) -----------------------------------


@pytest.mark.asyncio
async def test_comment_with_nonexistent_grant_id_raises_integrity_error() -> None:
    org = await _org("PortalGrantFkBadComment")
    with pytest.raises(IntegrityError):
        async with session_scope() as s:
            s.add(
                ExternalComment(
                    organization_id=org,
                    grant_id=999_999_999,
                    target_type="evidence",
                    target_id="1",
                    author="Ghost",
                    body="orphaned reference",
                )
            )
            await s.flush()


@pytest.mark.asyncio
async def test_audit_event_with_nonexistent_grant_id_raises_integrity_error() -> None:
    org = await _org("PortalGrantFkBadAudit")
    with pytest.raises(IntegrityError):
        async with session_scope() as s:
            s.add(
                ExternalPortalAuditEvent(
                    organization_id=org,
                    grant_id=999_999_999,
                    action="view",
                )
            )
            await s.flush()


@pytest.mark.asyncio
async def test_deleting_grant_nulls_comment_and_audit_event_reference() -> None:
    org = await _org("PortalGrantFkCascade")
    async with session_scope() as s:
        grant = await portal.create_grant(s, org_id=org, principal_name="ToBeDeleted")
        gid, token = grant.id, grant.token
    async with session_scope() as s:
        grant = await portal.resolve_grant(s, token)
        await portal.record_access(s, grant, action="view", target_type="package", target_id="1")
        await portal.add_comment(
            s, grant, target_type="evidence", target_id="9", author="Talker", body="hi"
        )

    async with session_scope() as s:
        await s.execute(delete(ExternalAccessGrant).where(ExternalAccessGrant.id == gid))

    async with session_scope() as s:
        comment = (
            await s.execute(select(ExternalComment).where(ExternalComment.organization_id == org))
        ).scalar_one()
        event = (
            await s.execute(
                select(ExternalPortalAuditEvent).where(
                    ExternalPortalAuditEvent.organization_id == org,
                    ExternalPortalAuditEvent.action == "view",
                )
            )
        ).scalar_one()
        # The rows survive the grant's deletion; only the reference is cleared.
        assert comment.grant_id is None
        assert event.grant_id is None


# --- C1: portal cookie / internal session domain separation ----------------
#
# ``sign_session``/``verify_session`` (ccf.auth) carry no audience/type claim.
# Before the fix, the portal cookie (``concord_portal_session``) and the
# internal login cookie (``concord_session``) were signed with the *same*
# secret and the *same* payload shape (``{"uid": <int>, "exp": ...}``) — a
# value minted for one verified as valid for the other. Grant ids and user
# ids are independent serial sequences that both start from 1, so a real
# collision is entirely plausible in production. These tests force an exact
# id collision to prove the fix (a distinct, HMAC-derived portal signing key)
# closes the hole regardless of any such collision, not just avoids it by luck.


@pytest.fixture
async def auth_on() -> AsyncIterator[None]:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_portal_cookie_cannot_authenticate_internal_session(auth_on: None) -> None:
    """A value minted as a portal session cookie must not authenticate the
    internal ``concord_session`` cookie — even for a colliding user id."""
    org = await _org("TokenConfusionA")
    fake_id = 900_000_101  # arbitrary, far outside any sequence's natural range
    async with session_scope() as s:
        s.add(User(id=fake_id, email="confuse-a@x.test", organization_id=org,
                    role="admin", active=True))
        # Force the exact collision the finding describes: a grant sharing
        # the internal user's id.
        grant = ExternalAccessGrant(
            id=fake_id, organization_id=org, kind="customer",
            expires_at=datetime.now(UTC) + timedelta(days=1), revoked=False, scope={},
        )
        grant.token = "confuse-a-token-" + "z" * 10
        s.add(grant)
        await s.flush()
        token = grant.token

    async with _client() as c:
        mint = await c.get("/portal", params={"token": token}, follow_redirects=False)
        assert mint.status_code == 303
        portal_cookie_value = mint.cookies[PORTAL_SESSION_COOKIE]

        # Attacker replays the portal cookie's raw value under the INTERNAL
        # cookie name against an internal-only route.
        c.cookies.set(SESSION_COOKIE, portal_cookie_value)
        resp = await c.get("/api/auth/me")
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_internal_session_cannot_authenticate_portal_grant(auth_on: None) -> None:
    """Conversely, a value minted as the internal login session cookie must
    not authenticate a portal grant when replayed as
    ``concord_portal_session`` — even for a colliding grant id."""
    org = await _org("TokenConfusionB")
    system = await _system(org, "ConfusionBSys")
    fake_id = 900_000_202  # arbitrary, far outside any sequence's natural range
    async with session_scope() as s:
        pkg = await pkg_service.create_package(
            s, org_id=org, system_id=system, kind="json", label="Confusion B secret pkg"
        )
        # A real, live, shared-content grant sharing the internal user's id.
        grant = ExternalAccessGrant(
            id=fake_id, organization_id=org, kind="customer",
            expires_at=datetime.now(UTC) + timedelta(days=30), revoked=False,
            scope={"package_ids": [pkg.id], "evidence_ids": []},
        )
        grant.token = "confuse-b-token-" + "y" * 10
        s.add(grant)
        await s.flush()
        s.add(ExternalPackageShare(grant_id=grant.id, package_id=pkg.id))
        s.add(User(id=fake_id, email="confuse-b@x.test", organization_id=org,
                    role="admin", active=True))
        await s.flush()

    settings = get_settings()
    # Exactly what an internal login would mint for this user id.
    internal_cookie_value = sign_session(fake_id, settings.auth_session_secret, ttl_hours=1)

    async with _client() as c:
        c.cookies.set(PORTAL_SESSION_COOKIE, internal_cookie_value)
        resp = await c.get("/portal")
        assert resp.status_code == 200
        assert "This link is invalid" in resp.text
        assert "Confusion B secret pkg" not in resp.text


@pytest.mark.asyncio
async def test_portal_cookie_ttl_never_exceeds_grant_expiry() -> None:
    """M1: the cookie's own signed lifetime must not exceed the grant's
    expiry by rounding up to the next whole hour."""

    class _Grant:
        def __init__(self, expires_at: datetime | None) -> None:
            self.expires_at = expires_at

    # No expiry at all → capped at the max TTL.
    assert _portal_cookie_ttl_hours(_Grant(None)) == 24

    # 90 minutes left: flooring to 1 hour keeps the cookie inside the grant's
    # remaining lifetime (the old ``// 3600 + 1`` formula rounded up to 2).
    ninety_min = datetime.now(UTC) + timedelta(minutes=90)
    assert _portal_cookie_ttl_hours(_Grant(ninety_min)) == 1

    # 5 hours left → floors to 5, still well inside the grant's lifetime.
    five_hours = datetime.now(UTC) + timedelta(hours=5, minutes=30)
    assert _portal_cookie_ttl_hours(_Grant(five_hours)) == 5

    # Far in the future → capped at the 24h ceiling.
    far_future = datetime.now(UTC) + timedelta(days=10)
    assert _portal_cookie_ttl_hours(_Grant(far_future)) == 24
