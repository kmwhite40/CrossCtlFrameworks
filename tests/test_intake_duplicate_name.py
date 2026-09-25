"""Submitting system intake: duplicate names, deleted names, and no organization.

All three were found by a real submission returning ``Internal Server Error``.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, System, User

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


async def _org_admin(name: str) -> tuple[int, str]:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        user = User(
            email=f"a-{uuid.uuid4().hex[:6]}@intake.test",
            organization_id=org.id,
            role="admin",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        await s.flush()
        return org.id, user.api_token


def _form(name: str) -> dict[str, str]:
    return {
        "system_name": name,
        "environment_type": "cloud",
        "cloud_platform": "m365",
        "identity_model": "entra",
        "connectivity": "internet",
    }


@pytest.mark.asyncio
async def test_a_duplicate_system_name_is_a_form_error_not_a_500() -> None:
    """`uq_system_org_name_live` is UNIQUE (organization_id, name) over live
    rows. The route never caught the IntegrityError, so a real submission
    answered `Internal Server Error` and said nothing actionable."""
    _org_id, token = await _org_admin(f"Intake Dup {uuid.uuid4().hex[:6]}")
    name = f"Federal {uuid.uuid4().hex[:6]}"

    async with _client() as c:
        first = await c.post("/intake", data=_form(name), headers={"Authorization": f"Bearer {token}"})
        assert first.status_code == 200, "the first submission must succeed"

        second = await c.post("/intake", data=_form(name), headers={"Authorization": f"Bearer {token}"})

    assert second.status_code == 409
    assert "already has a system named" in second.text
    assert name in second.text


@pytest.mark.asyncio
async def test_a_deleted_systems_name_can_be_used_again() -> None:
    """The old constraint ignored `deleted_at`, so deleting a system reserved
    its name in that organization forever -- and the attempt to reuse it was
    the 500 above. Ten systems across six organizations were holding names
    this way when this was written."""
    org_id, token = await _org_admin(f"Intake Reuse {uuid.uuid4().hex[:6]}")
    name = f"Nexus {uuid.uuid4().hex[:6]}"

    async with _client() as c:
        created = await c.post("/intake", data=_form(name), headers={"Authorization": f"Bearer {token}"})
    assert created.status_code == 200

    async with session_scope() as s:
        system = (
            await s.execute(
                select(System).where(System.organization_id == org_id, System.name == name)
            )
        ).scalars().one()
        system.deleted_at = datetime.now(UTC)

    async with _client() as c:
        again = await c.post("/intake", data=_form(name), headers={"Authorization": f"Bearer {token}"})
    assert again.status_code == 200, "a deleted system is still holding its name"

    async with session_scope() as s:
        rows = (
            await s.execute(
                select(System).where(
                    System.organization_id == org_id, System.name == name
                )
            )
        ).scalars().all()
        live = [r for r in rows if r.deleted_at is None]
        assert len(live) == 1

        # Removed, not left behind. This pair -- one live and one deleted
        # sharing a name -- is precisely what the migration's downgrade cannot
        # reverse, and `conftest` cycles migrations down and up between
        # modules. Left in place it fails an unrelated module's setup with
        # "could not create unique index uq_system_org_name" and nothing
        # pointing back here.
        for row in rows:
            await s.delete(row)


@pytest.mark.asyncio
async def test_intake_without_an_organization_does_not_guess_one() -> None:
    """It used to fall back to the most recently created organization, or make
    a "Default Organization" -- writing a system, its derived baseline and a
    generated SSP into whichever tenant happened to sort last."""
    before = await _org_admin(f"Intake NoOrg {uuid.uuid4().hex[:6]}")
    name = f"Orphan {uuid.uuid4().hex[:6]}"

    os.environ["CCF_AUTH_ENABLED"] = "false"
    get_settings.cache_clear()
    try:
        async with _client() as c:
            r = await c.post("/intake", data=_form(name))
    finally:
        os.environ["CCF_AUTH_ENABLED"] = "true"
        get_settings.cache_clear()

    assert r.status_code == 400
    assert "No organization in this session" in r.text

    async with session_scope() as s:
        assert (
            await s.execute(select(System).where(System.name == name))
        ).scalars().first() is None
        assert (
            await s.execute(
                select(Organization).where(Organization.name == "Default Organization")
            )
        ).scalars().first() is None
