"""The push endpoint: who may call it, and how each refusal reaches the caller.

The three failure modes are deliberately different status codes because they
need different actions from whoever sees them: configure Jira, read Jira's
complaint, or retry unchanged. Collapsing them into one 500 is the defect
these pin against.
"""

from __future__ import annotations

import os
import uuid

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.integrations import service as integrations_service
from ccf.integrations.types import (
    IntegrationNotConfigured,
    IntegrationRefused,
    IntegrationUnavailable,
    PushResult,
)
from ccf.models import POAM, Organization, System, User

pytestmark = pytest.mark.usefixtures("fresh_engine")


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


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _org_poam_and_user(name: str, *, role: str = "admin") -> tuple[int, str]:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name=f"{name} System")
        s.add(system)
        await s.flush()
        poam = POAM(system_id=system.id, title="Weak spot", severity="high", status="open")
        s.add(poam)
        user = User(
            email=f"{role}-{uuid.uuid4().hex[:6]}@{name.lower().replace(' ', '-')}.test",
            organization_id=org.id,
            role=role,
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        await s.flush()
        return poam.id, user.api_token


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.parametrize(
    ("raised", "expected"),
    [
        (IntegrationNotConfigured("no Jira credential is stored"), 409),
        (IntegrationRefused("Jira returned 400 -- issuetype: invalid", status=400), 502),
        (IntegrationUnavailable("could not reach Jira"), 504),
    ],
)
@pytest.mark.asyncio
async def test_each_refusal_reaches_the_caller_as_its_own_status(
    monkeypatch: pytest.MonkeyPatch, raised: Exception, expected: int
) -> None:
    """Configure / read the complaint / retry -- three actions, three codes."""
    poam_id, token = await _org_poam_and_user(f"Jira Api {uuid.uuid4().hex[:6]}")

    async def _boom(*args, **kwargs):
        raise raised

    monkeypatch.setattr(integrations_service, "push_poam", _boom)
    async with _client() as c:
        r = await c.post(f"/api/poams/{poam_id}/push/jira", headers=_auth(token))

    assert r.status_code == expected
    # Jira's own words survive the trip; a generic message would not be actionable.
    assert str(raised) in r.json()["detail"]


@pytest.mark.asyncio
async def test_a_successful_push_returns_where_the_ticket_now_lives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    poam_id, token = await _org_poam_and_user(f"Jira Ok {uuid.uuid4().hex[:6]}")

    async def _ok(session, org_id, pid, **kwargs):
        assert org_id is not None, "the route must pass the caller's own org"
        return PushResult(
            external_id="SEC-9", url="https://acme.atlassian.net/browse/SEC-9", created=True
        )

    monkeypatch.setattr(integrations_service, "push_poam", _ok)
    async with _client() as c:
        r = await c.post(f"/api/poams/{poam_id}/push/jira", headers=_auth(token))

    assert r.status_code == 200
    assert r.json() == {
        "poam_id": poam_id,
        "provider": "jira",
        "external_id": "SEC-9",
        "url": "https://acme.atlassian.net/browse/SEC-9",
        "created": True,
    }


@pytest.mark.asyncio
async def test_a_viewer_cannot_send_a_poam_out_to_jira() -> None:
    """A POA&M's text can name an unremediated weakness in a federal system.

    Who may read it here and who may publish it into a project every engineer
    can see are different questions, so this is admin-only rather than
    inheriting the read role.
    """
    poam_id, token = await _org_poam_and_user(
        f"Jira Viewer {uuid.uuid4().hex[:6]}", role="viewer"
    )
    async with _client() as c:
        r = await c.post(f"/api/poams/{poam_id}/push/jira", headers=_auth(token))
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_an_unauthenticated_caller_cannot_push() -> None:
    poam_id, _token = await _org_poam_and_user(f"Jira Anon {uuid.uuid4().hex[:6]}")
    async with _client() as c:
        r = await c.post(f"/api/poams/{poam_id}/push/jira")
    assert r.status_code == 401


async def _link(org_id: int, poam_id: int, key: str) -> None:
    from ccf.models_grc import ExternalIssueLink

    async with session_scope() as s:
        s.add(
            ExternalIssueLink(
                organization_id=org_id,
                entity_type="poam",
                entity_id=poam_id,
                provider="jira",
                external_id=key,
                external_url=f"https://acme.atlassian.net/browse/{key}",
            )
        )


async def _org_id_of(poam_id: int) -> int:
    from sqlalchemy import select as _select

    async with session_scope() as s:
        return (
            await s.execute(
                _select(System.organization_id)
                .join(POAM, POAM.system_id == System.id)
                .where(POAM.id == poam_id)
            )
        ).scalar_one()


@pytest.mark.asyncio
async def test_the_poam_page_never_shows_another_tenants_issue_key() -> None:
    """End-to-end: the caller's own link renders, another tenant's never does.

    This proves the *observable* behaviour, not which control produces it.
    The session here is tenant-bound, so RLS refuses the other row whether or
    not the query carries an organization predicate -- deleting that predicate
    leaves this test green. The predicate itself is pinned separately, on an
    unscoped session, by
    ``test_the_link_lookup_refuses_another_tenants_row_on_its_own``.

    The viewer's own link is asserted present first, so a page that rendered
    no links at all would fail here too.
    """
    mine_poam, token = await _org_poam_and_user(f"Jira Mine {uuid.uuid4().hex[:6]}")
    theirs_poam, _ = await _org_poam_and_user(f"Jira Theirs {uuid.uuid4().hex[:6]}")

    await _link(await _org_id_of(mine_poam), mine_poam, "SEC-100")
    await _link(await _org_id_of(theirs_poam), theirs_poam, "OTHER-999")

    async with _client() as c:
        r = await c.get("/poams", headers=_auth(token))

    assert r.status_code == 200
    assert "SEC-100" in r.text, "the caller's own link must be shown"
    assert "OTHER-999" not in r.text


@pytest.mark.asyncio
async def test_the_button_is_withheld_until_jira_is_configured() -> None:
    """A push with nothing configured is a 409 the operator cannot act on here.

    Both directions are asserted: absent without a credential, present once one
    exists -- a page that never rendered the button would pass the first half
    alone.
    """
    from ccf.connectors.credentials import set_credential
    from ccf.models_grc import ConnectorConfig

    poam_id, token = await _org_poam_and_user(f"Jira Button {uuid.uuid4().hex[:6]}")
    org_id = await _org_id_of(poam_id)

    async with _client() as c:
        before = await c.get("/poams", headers=_auth(token))
    # Matched on the button's own marker, not the selector string: the script
    # block mentions `[data-jira-push]` too, so the looser assertion passed
    # whether or not a button had rendered.
    assert f'data-poam="{poam_id}"' not in before.text

    os.environ["CCF_AI_CREDENTIAL_MASTER_KEY"] = "unit-test-master-key-32-chars-xx"
    get_settings.cache_clear()
    try:
        async with session_scope() as s:
            cfg = await set_credential(
                s,
                org_id,
                "jira",
                {
                    "base_url": "https://acme.atlassian.net",
                    "email": "svc@acme.test",
                    "api_token": "ATATT-secret",
                },
            )
            cfg_id = cfg.id
        async with _client() as c:
            after = await c.get("/poams", headers=_auth(token))
    finally:
        # The credential is removed rather than left behind: it is wrapped
        # under a master key no other module configures, so every later
        # rotation sweep would report it unreadable for the rest of the run.
        async with session_scope() as s:
            row = await s.get(ConnectorConfig, cfg_id)
            if row is not None:
                await s.delete(row)
        os.environ.pop("CCF_AI_CREDENTIAL_MASTER_KEY", None)
        get_settings.cache_clear()

    assert "data-jira-push" in after.text
    assert f'data-poam="{poam_id}"' in after.text
