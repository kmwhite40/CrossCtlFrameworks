"""``POST /api/import/{dataset}`` keeps what it reports.

The route answered ``{"created": 1}`` and never committed: the request session
closed and rolled the rows back, so the register was unchanged while the
response said otherwise. The service-level tests share one session with their
assertions, so they could not see it.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import POAM, Organization, Policy, Risk, System, User

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture
def _auth_enabled() -> Iterator[None]:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_an_imported_row_is_still_there_after_the_request(_auth_enabled: None) -> None:
    tag = uuid.uuid4().hex[:8]
    async with session_scope() as s:
        org = Organization(name=f"imp-{tag}")
        s.add(org)
        await s.flush()
        s.add(System(organization_id=org.id, name=f"imp {tag}"))
        user = User(
            email=f"admin-{tag}@imp.example",
            organization_id=org.id,
            role="admin",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        token, org_id = user.api_token, org.id
    title = f"Imported risk {tag}"
    csv = f"title,category,likelihood,impact,status\n{title},technical,moderate,high,open\n"
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        r = await c.post(
            "/api/import/risks",
            files={"file": ("risks.csv", csv.encode(), "text/csv")},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code == 200, r.text
    assert r.json()["created"] == 1
    async with session_scope() as s:
        saved = (
            (await s.execute(select(Risk.organization_id).where(Risk.title == title)))
            .scalars()
            .all()
        )
    assert saved == [org_id]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("held", "imported"),
    [("retired", "active"), ("active", "retired"), ("draft", "active")],
    ids=["unretire", "retire", "activate"],
)
async def test_an_import_does_not_change_a_policys_status(
    _auth_enabled: None, held: str, imported: str
) -> None:
    """A policy goes in force only through an approved version and retires only
    by an admin (``ccf.policies.service``). Once imports were saved, a CSV
    could do either: re-activating a retired policy put its old version back
    in force with no review."""
    tag = uuid.uuid4().hex[:8]
    async with session_scope() as s:
        org = Organization(name=f"impp-{tag}")
        s.add(org)
        await s.flush()
        user = User(
            email=f"editor-{tag}@imp.example",
            organization_id=org.id,
            role="control_owner",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        policy = Policy(organization_id=org.id, name=f"Access {tag}", status=held)
        s.add_all([user, policy])
        await s.flush()
        token, pid = user.api_token, policy.id
    csv = f"id,name,status\n{pid},Access {tag},{imported}\nnew,Fresh {tag},active\n"
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        r = await c.post(
            "/api/import/policies",
            files={"file": ("p.csv", csv.encode(), "text/csv")},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["updated"], body["created"], body["skipped"]) == (0, 0, 2), body
    async with session_scope() as s:
        status = (await s.execute(select(Policy.status).where(Policy.id == pid))).scalar_one()
        fresh = (
            await s.execute(select(Policy.id).where(Policy.name == f"Fresh {tag}"))
        ).scalar_one_or_none()
    assert status == held and fresh is None


@pytest.mark.asyncio
async def test_an_import_may_create_a_draft_policy_and_keep_a_status_unchanged(
    _auth_enabled: None,
) -> None:
    tag = uuid.uuid4().hex[:8]
    async with session_scope() as s:
        org = Organization(name=f"impd-{tag}")
        s.add(org)
        await s.flush()
        user = User(
            email=f"editor-{tag}@imp.example",
            organization_id=org.id,
            role="control_owner",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        policy = Policy(organization_id=org.id, name=f"Keep {tag}", status="active")
        s.add_all([user, policy])
        await s.flush()
        token, pid, org_id = user.api_token, policy.id, org.id
    csv = (
        f"id,name,status,review_frequency\n{pid},Keep {tag},active,annual\n"
        f"new,Draft {tag},draft,annual\nnew,Blank {tag},,annual\n"
    )
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        r = await c.post(
            "/api/import/policies",
            files={"file": ("p.csv", csv.encode(), "text/csv")},
            headers={"Authorization": f"Bearer {token}"},
        )
    body = r.json()
    assert (body["updated"], body["created"], body["skipped"]) == (1, 2, 0), body
    async with session_scope() as s:
        statuses = dict(
            (
                await s.execute(
                    select(Policy.name, Policy.status).where(Policy.organization_id == org_id)
                )
            ).all()
        )
    # A blank cell leaves the status as it is -- for a new row, a draft.
    assert statuses == {f"Keep {tag}": "active", f"Draft {tag}": "draft", f"Blank {tag}": "draft"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("dataset", "bad"),
    [("risks", "likelihood_score=x"), ("poams", "identified_on=not-a-date")],
    ids=["bad-score", "bad-date"],
)
async def test_a_row_refused_halfway_changes_nothing(
    _auth_enabled: None, dataset: str, bad: str
) -> None:
    """The fields are applied in order, so a row that failed on a later field
    used to leave the earlier ones changed -- and saved, once imports were
    committed -- while the response called it skipped."""
    tag = uuid.uuid4().hex[:8]
    async with session_scope() as s:
        org = Organization(name=f"imph-{tag}")
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"imph {tag}")
        s.add(sysm)
        await s.flush()
        user = User(
            email=f"editor-{tag}@imp.example",
            organization_id=org.id,
            role="control_owner",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        model = Risk if dataset == "risks" else POAM
        row = model(system_id=sysm.id, title=f"Before {tag}", status="open")
        s.add_all([user, row])
        await s.flush()
        token, rid = user.api_token, row.id
    field, value = bad.split("=")
    csv = f"id,title,{field}\n{rid},After {tag},{value}\n"
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        r = await c.post(
            f"/api/import/{dataset}",
            files={"file": ("x.csv", csv.encode(), "text/csv")},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code == 200, r.text
    assert (r.json()["updated"], r.json()["skipped"]) == (0, 1), r.json()
    async with session_scope() as s:
        title = (await s.execute(select(model.title).where(model.id == rid))).scalar_one()
    assert title == f"Before {tag}"
