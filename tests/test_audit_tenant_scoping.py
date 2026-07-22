"""DATA-06: per-tenant audit-log isolation, exercised through the real HTTP
mutation + read path (as opposed to ``tests/test_rls_coverage.py``'s direct-DB
RLS predicate check).

Covers the three acceptance criteria from the task brief:

1. A mutation by an org-A principal writes an ``audit_log`` row with
   ``organization_id = A`` (written by ``ccf.api.audit.audit_middleware``,
   resolved from the request principal — never a manual/synthetic insert).
2. Under tenant A, the audit-read path (``ccf.api.deps.get_session`` ->
   ``set_session_tenant`` -> RLS) returns A's + system (NULL-org) rows only,
   never B's — even though both callers pass the same ``require_role``
   admin/assessor gate.
3. ``organization_id`` never entered the hash payload: recomputing
   ``row_hash`` from the persisted content (sans ``organization_id``) for a
   row written by a real mutation still matches — i.e. the chain guardrail
   holds for production-written rows, not just synthetic test rows.
"""

from __future__ import annotations

import os

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.audit import _GENESIS, record_event, row_hash
from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import AuditLog, Organization, User

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


async def _mk_admin(email: str, org_name: str) -> tuple[str, int]:
    """Create an org + an admin user in it; return (bearer token, org id)."""
    async with session_scope() as s:
        org = Organization(name=org_name)
        s.add(org)
        await s.flush()
        user = User(
            email=email,
            organization_id=org.id,
            role="admin",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        await s.flush()
        return user.api_token, org.id


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_mutation_writes_organization_id_from_principal() -> None:
    """A mutation by an org-A admin lands in audit_log with organization_id = A."""
    token, org_id = await _mk_admin("mutator@audit-scope.test", "Audit Scope Mutator Org")
    async with _client() as c:
        r = await c.post(
            "/api/ssp/projects",
            json={"customer_name": "AuditScopeMutatorCo"},
            headers=_auth(token),
        )
        assert r.status_code == 201

    async with session_scope() as s:
        row = (
            await s.execute(
                select(AuditLog)
                .where(AuditLog.actor == "mutator@audit-scope.test")
                .order_by(AuditLog.id.desc())
                .limit(1)
            )
        ).scalar_one()
        assert row.organization_id == org_id

        # Guardrail: organization_id never entered the hash payload — recomputing
        # row_hash from the persisted content (sans organization_id) still matches
        # the value the (production) middleware actually wrote.
        content = {
            "actor": row.actor,
            "action": row.action,
            "entity_type": row.entity_type,
            "entity_id": row.entity_id,
            "diff": row.diff,
        }
        assert row.row_hash == row_hash(row.prev_hash or _GENESIS, content)


@pytest.mark.asyncio
async def test_audit_list_row_isolates_by_tenant_but_shows_system_rows() -> None:
    """Under tenant A, GET /api/audit returns A's + system rows only, not B's —
    even though both admins pass the identical require_role gate.

    The org-A/org-B rows here are seeded directly (chained, mirroring what the
    middleware writes) rather than via two live cross-tenant HTTP mutations:
    ``test_mutation_writes_organization_id_from_principal`` above already
    proves the middleware writes organization_id correctly for a real
    mutation, so this test isolates exactly what its name says — the READ
    path's tenant scoping — without depending on that separate concern.
    """
    token_a, org_a = await _mk_admin("scope-a@audit-scope.test", "Audit Scope Org A")
    token_b, org_b = await _mk_admin("scope-b@audit-scope.test", "Audit Scope Org B")

    async with session_scope() as s:
        for org_id, actor, entity_id in (
            (org_a, "scope-a@audit-scope.test", "AuditScopeRowA"),
            (org_b, "scope-b@audit-scope.test", "AuditScopeRowB"),
        ):
            content = {
                "actor": actor,
                "action": "create",
                "entity_type": "ssp",
                "entity_id": entity_id,
                "diff": {},
            }
            prev = (
                await s.execute(
                    select(AuditLog.row_hash).order_by(AuditLog.id.desc()).limit(1)
                )
            ).scalar_one_or_none() or _GENESIS
            s.add(
                AuditLog(
                    **content,
                    organization_id=org_id,
                    prev_hash=prev,
                    row_hash=row_hash(prev, content),
                )
            )
            await s.flush()

        # A system/global event (organization_id stays NULL — mirrors the
        # non-HTTP-mutation callers of record_event, e.g. OIDC JIT provisioning).
        await record_event(
            s,
            actor="system-marker@audit-scope.test",
            action="create",
            entity_type="rls-cov-audit",
            entity_id="AuditScopeSystemMarker",
            diff={},
        )

    async def _by_actor(c: AsyncClient, token: str, actor: str) -> list[dict[str, object]]:
        r = await c.get("/api/audit", params={"actor": actor}, headers=_auth(token))
        assert r.status_code == 200
        return r.json()  # type: ignore[no-any-return]

    async with _client() as c:
        # Admin A can see their own mutation...
        own = await _by_actor(c, token_a, "scope-a@audit-scope.test")
        assert any(e["actor"] == "scope-a@audit-scope.test" for e in own)

        # ...and the system row (NULL org visible to every scoped tenant)...
        system_rows = await _by_actor(c, token_a, "system-marker@audit-scope.test")
        assert any(e["actor"] == "system-marker@audit-scope.test" for e in system_rows)

        # ...but never admin B's mutation, even filtering explicitly for it — RLS
        # hides the row at the DB layer regardless of the query-param filter.
        leaked = await _by_actor(c, token_a, "scope-b@audit-scope.test")
        assert leaked == [], "tenant A must not see tenant B's audit rows"

        # And the reverse holds for admin B.
        leaked_b = await _by_actor(c, token_b, "scope-a@audit-scope.test")
        assert leaked_b == [], "tenant B must not see tenant A's audit rows"
        system_rows_b = await _by_actor(c, token_b, "system-marker@audit-scope.test")
        assert any(e["actor"] == "system-marker@audit-scope.test" for e in system_rows_b)
