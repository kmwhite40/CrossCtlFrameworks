"""/graph serves only the caller's own systems (auth enabled)."""

from __future__ import annotations

import itertools
import os
from collections.abc import Iterator

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.assurance import builder
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, System, User

pytestmark = pytest.mark.usefixtures("fresh_engine")
_SEQ = itertools.count()


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _auth_enabled() -> Iterator[None]:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


async def _tenant() -> tuple[str, int, str]:
    """``(api token, system id, system name)`` for a fresh org with a built graph."""
    async with session_scope() as s:
        org = Organization(name=f"Graph Tenant {next(_SEQ)}")
        s.add(org)
        await s.flush()
        name = f"Secret System {next(_SEQ)}"
        sysm = System(organization_id=org.id, name=name)
        user = User(email=f"u{next(_SEQ)}@graph.test", organization_id=org.id,
                    role="control_owner", active=True, password_hash=hash_password("pw"),
                    api_token=new_api_token())
        s.add_all([sysm, user])
        await s.flush()
        await builder.rebuild_org(s, org.id)
        return user.api_token, sysm.id, name


async def test_another_tenants_system_is_a_404_and_is_not_listed() -> None:
    token_a, sid_a, name_a = await _tenant()
    _token_b, sid_b, name_b = await _tenant()
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t",
                           headers={"Authorization": f"Bearer {token_a}"}) as c:
        own = await c.get(f"/graph?system_id={sid_a}")
        foreign = await c.get(f"/graph?system_id={sid_b}")
        own_page = await c.get("/graph")
    assert own.status_code == 200 and name_a in own.text  # the positive counterpart
    assert foreign.status_code == 404 and name_b not in foreign.text
    assert name_a in own_page.text and name_b not in own_page.text


async def test_the_handler_itself_refuses_a_foreign_system_on_an_unscoped_session() -> None:
    """RLS 404s the HTTP test before the route's own org predicate is reached, so
    delete the predicate and the test above still passes. Call the handler on an
    unscoped session (RLS bypassed) with a foreign principal instead."""
    from types import SimpleNamespace  # noqa: PLC0415

    from fastapi import HTTPException  # noqa: PLC0415

    from ccf.api.routes.ui_grc import graph_page  # noqa: PLC0415

    token_a, sid_a, _ = await _tenant()
    _tb, sid_b, _ = await _tenant()
    async with session_scope() as s:
        org_a = (await s.get(System, sid_a)).organization_id

    def request_of(org: int) -> SimpleNamespace:
        return SimpleNamespace(state=SimpleNamespace(principal=SimpleNamespace(org_id=org)))

    assert token_a
    async with session_scope() as s:
        # the owning org succeeds, so the refusal below is the org check
        own = await graph_page(request_of(org_a), sid_a, s)  # type: ignore[arg-type]
        assert own.status_code == 200
    async with session_scope() as s:
        with pytest.raises(HTTPException) as err:
            await graph_page(request_of(org_a), sid_b, s)  # type: ignore[arg-type]
    assert err.value.status_code == 404
