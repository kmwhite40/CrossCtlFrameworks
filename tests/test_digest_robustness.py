"""One hidden dedupe collision costs one alert, not an org's whole digest."""

from __future__ import annotations

import itertools
from datetime import UTC, datetime

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text

from ccf.api.auth_deps import get_principal
from ccf.api.main import create_app
from ccf.auth import Principal
from ccf.db import session_scope, set_session_tenant
from ccf.governance import bus, digest
from ccf.models import Notification, Organization

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


async def _org(name: str, *, deleted: bool = False) -> int:
    async with session_scope() as s:
        org = Organization(name=f"{name} {next(_SEQ)}")
        if deleted:
            org.deleted_at = datetime.now(UTC)
        s.add(org)
        await s.flush()
        return org.id


async def test_a_hidden_collision_is_contained() -> None:
    org = await _org("Collide")
    key = f"collide-{next(_SEQ)}"
    async with session_scope() as s:
        s.add(Notification(organization_id=None, category="x", title="orphan", dedupe_key=key))
    async with session_scope() as s:
        await set_session_tenant(s, org)
        out = await bus.notify(s, category="x", title="mine", org_id=org, dedupe_key=key)
        # Hidden by RLS, so not found, so inserted, so the unique index fires --
        # contained: no exception, and the session is still usable afterwards.
        assert out is None
        assert (await s.execute(text("SELECT 1"))).scalar_one() == 1
    async with session_scope() as s:
        await s.execute(Notification.__table__.delete().where(Notification.dedupe_key == key))


async def test_run_all_skips_deleted_organizations(monkeypatch: pytest.MonkeyPatch) -> None:
    live = await _org("Live")
    gone = await _org("Gone", deleted=True)
    seen: list[int] = []

    async def fake_run(session: object, *, today: object, org_id: int | None = None) -> dict:
        seen.append(org_id)  # type: ignore[arg-type]
        return {}

    monkeypatch.setattr(digest, "run", fake_run)
    async with session_scope() as s:
        await digest.run_all(s, today=datetime.now(UTC).date())
    assert live in seen and gone not in seen


async def test_an_unscoped_non_admin_cannot_scan_every_tenant() -> None:
    app = create_app()
    app.dependency_overrides[get_principal] = lambda: Principal(
        user_id=None, email="u@t", org_id=None, role="control_owner"
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post("/api/notifications/scan")
    assert r.status_code == 403
    async with session_scope() as s:
        assert (await s.execute(select(Notification.id).limit(1))) is not None
