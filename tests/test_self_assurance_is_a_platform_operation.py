"""Self-assurance acts on Concord's own boundary, not on the caller's tenant.

Found by exercising every GET the live app serves. One returned 500:

    GET /api/admin/self-assurance/package
    -> InsufficientPrivilegeError: new row violates row-level security policy
       for table "organizations"
    [SQL: INSERT INTO ccf.organizations ... ('Concord Platform', ...)]

Two defects behind one status code.

**A GET performed a write.** `export_package` called `_self_ids`, a lazy
get-or-create, and the route committed. A read that creates an organization and
a system is not a read.

**The read it depended on was RLS-blind to the row it needed, and a tenant admin
should not have been asking.** The platform org is on file -- `Concord Platform`
-- but the request session is bound to the caller's tenant, so
`select(Organization).where(name == SELF_ORG)` returns nothing for an admin
scoped to some customer. The code concludes it is absent and tries to create it.
`organizations.name` is UNIQUE, so the attempt could only ever fail -- as an RLS
refusal here, as a unique violation if the policy were ever relaxed. Either way
the endpoint is unusable, and `require_role("admin")` admitted any tenant admin
to an operation on the vendor's own authorization boundary.

`status` shared the blindness and answered `{"initialized": false}` to a
tenant-scoped admin regardless of what was on file -- a false answer rather than
a refusal.

**Why the existing suite missed it, and why the first draft of this file did
too.** `test_self_assurance.py` calls the service functions directly on
`session_scope()`, which is unscoped and bypasses RLS, and the API test client is
a single *global* principal. Neither can produce a tenant-scoped request.

The subtlety that caught the first draft of these tests is worth recording:
`require_role` resolves `get_principal`, while `get_session` binds the RLS tenant
from **`get_principal_optional`**. Overriding only the former authorizes as a
tenant admin while leaving the session unscoped, so the endpoint passed. Both
have to be overridden for a request to be scoped the way a real one is.
"""

from __future__ import annotations

import itertools

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select

from ccf.api.auth_deps import get_principal, get_principal_optional
from ccf.api.main import create_app
from ccf.auth import Principal
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, System
from ccf.self_assurance.service import SELF_ORG

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


class _Caller:
    """A request as a specific principal, scoped the way a real one is.

    Both principal dependencies are overridden on purpose. `require_role` reads
    `get_principal`; `get_session` reads `get_principal_optional` to bind the
    RLS tenant. Override one and the route authorizes as a tenant admin over an
    unscoped session, which is not a state any real request can be in.
    """

    def __init__(self, *, org_id: int | None, role: str = "admin") -> None:
        self.app = create_app()
        self.org_id = org_id
        self.role = role
        self.app.dependency_overrides[get_principal] = self._principal
        self.app.dependency_overrides[get_principal_optional] = self._principal

    def _principal(self) -> Principal:
        return Principal(
            user_id=1, email="tenant-admin@customer.gov", org_id=self.org_id, role=self.role
        )

    def client(self) -> AsyncClient:
        return AsyncClient(transport=ASGITransport(app=self.app), base_url="http://test")


async def _count(model: type, **where: object) -> int:
    async with session_scope() as session:
        stmt = select(func.count()).select_from(model)
        for column, value in where.items():
            stmt = stmt.where(getattr(model, column) == value)
        return int((await session.execute(stmt)).scalar_one())


async def _a_customer_org() -> int:
    """A tenant that is NOT the platform boundary. Uniquely named per test."""
    async with session_scope() as session:
        org = Organization(name=f"Customer Of Concord {next(_SEQ)}")
        session.add(org)
        await session.flush()
        return int(org.id)


@pytest.fixture
async def platform_boundary() -> int:
    """The platform org on file, created the way the CLI creates it: unscoped."""
    async with session_scope() as session:
        existing = (
            await session.execute(select(Organization).where(Organization.name == SELF_ORG))
        ).scalar_one_or_none()
        if existing is None:
            existing = Organization(
                name=SELF_ORG, description="Concord's own assurance boundary."
            )
            session.add(existing)
            await session.flush()
        return int(existing.id)


@pytest.mark.asyncio
async def test_package_refuses_a_tenant_scoped_admin_instead_of_erroring(
    platform_boundary: int,
) -> None:
    """The reported failure, through the real request path."""
    tenant = await _a_customer_org()
    async with _Caller(org_id=tenant).client() as c:
        resp = await c.get("/api/admin/self-assurance/package")
    assert resp.status_code != 500, (
        f"a tenant-scoped admin still gets a server error: {resp.text[:300]}"
    )
    assert resp.status_code == 403, (
        "self-assurance is a platform operation; a tenant-scoped caller must be "
        f"refused explicitly, got {resp.status_code}: {resp.text[:200]}"
    )


@pytest.mark.asyncio
async def test_a_read_endpoint_creates_nothing(platform_boundary: int) -> None:
    """GET must not write, for any caller.

    Checked over organizations *and* systems, because `_self_ids` lazily created
    either. Driven as a global admin so the assertion is about the endpoint being
    a read, not about RLS stopping it.
    """
    orgs_before = await _count(Organization, name=SELF_ORG)
    systems_before = await _count(System, name=SELF_ORG)

    async with _Caller(org_id=None).client() as c:
        resp = await c.get("/api/admin/self-assurance/package")
    assert resp.status_code != 500, resp.text[:300]

    assert await _count(Organization, name=SELF_ORG) == orgs_before, (
        "a GET created an organization"
    )
    assert await _count(System, name=SELF_ORG) == systems_before, "a GET created a system"


@pytest.mark.asyncio
async def test_status_refuses_rather_than_answering_falsely(
    platform_boundary: int,
) -> None:
    """`initialized: false` to a caller who cannot see it is a wrong answer.

    The platform boundary is on file. A tenant-scoped admin asking about it must
    be told it is not theirs to ask about, not handed a negative that reads as
    fact.
    """
    tenant = await _a_customer_org()
    async with _Caller(org_id=tenant).client() as c:
        resp = await c.get("/api/admin/self-assurance/status")
    assert resp.status_code == 403, (
        f"expected a refusal, got {resp.status_code}: {resp.text[:200]}"
    )
    assert "initialized" not in resp.text, (
        "a refusal must not also report an initialisation state"
    )


@pytest.mark.asyncio
async def test_a_tenant_admin_cannot_initialise_or_assess_the_platform(
    platform_boundary: int,
) -> None:
    """The authorization half, on the two mutating endpoints.

    A customer's administrator triggering writes against the vendor's own
    assurance boundary is a tenant-isolation failure, independent of whether the
    write happens to succeed.
    """
    tenant = await _a_customer_org()
    async with _Caller(org_id=tenant).client() as c:
        for path in ("/api/admin/self-assurance/init", "/api/admin/self-assurance/run"):
            resp = await c.post(path)
            assert resp.status_code == 403, (
                f"{path} admitted a tenant-scoped admin: {resp.status_code} "
                f"{resp.text[:160]}"
            )


@pytest.mark.asyncio
async def test_a_global_admin_is_still_allowed(platform_boundary: int) -> None:
    """The refusal is about scope, not a blanket lockout.

    Without this, returning 403 everywhere would satisfy every test above while
    removing the feature.
    """
    async with _Caller(org_id=None).client() as c:
        resp = await c.get("/api/admin/self-assurance/status")
    assert resp.status_code == 200, resp.text[:200]
    assert "initialized" in resp.text


@pytest.mark.asyncio
async def test_the_ui_page_and_run_button_are_gated_too(platform_boundary: int) -> None:
    """The server-rendered twin had no role gate at all.

    `GET /admin/self-assurance` and `POST /admin/self-assurance/run` in
    `ui_grc.py` take only a session -- no `require_role`, no scope check -- while
    the POST executes a platform self-assessment and commits it. The API gate is
    worth nothing if the page beside it does the same work ungated.
    """
    tenant = await _a_customer_org()
    async with _Caller(org_id=tenant, role="viewer").client() as c:
        page = await c.get("/admin/self-assurance")
        assert page.status_code == 403, (
            f"the self-assurance page rendered for a tenant viewer: {page.status_code}"
        )
        run = await c.post("/admin/self-assurance/run", follow_redirects=False)
        assert run.status_code == 403, (
            "a tenant viewer could run a platform self-assessment: "
            f"{run.status_code} {run.text[:160]}"
        )


@pytest.mark.asyncio
async def test_the_ui_page_still_renders_for_a_platform_admin(
    platform_boundary: int,
) -> None:
    """Again, the refusal is about scope rather than a lockout."""
    async with _Caller(org_id=None).client() as c:
        page = await c.get("/admin/self-assurance")
    assert page.status_code == 200, page.text[:200]
