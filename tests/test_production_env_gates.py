"""Every ``is_dev_env`` gate, exercised on its **production** side.

``tests/conftest.py`` sets ``CCF_ENV=test`` process-wide and
``config._DEV_ENVS`` counts ``test`` as a development environment, so the whole
suite runs on the permissive branch of every gate in ``config.is_dev_env``.
Nothing proved that the strict branch does anything at all: a test of the
``Secure`` cookie attribute or the HSTS header written the ordinary way passes
with the gate deleted, because in the test environment the gate is never on.

``tests/test_cookie_security.py`` is adjacent but is not this: it asserts
properties of ``is_dev_env`` and of ``Settings.env``'s declared default, i.e.
that the *predicate* is right. It never asks any cookie-setting site whether it
calls that predicate, so deleting ``secure=not is_dev_env(...)`` from all five
sites leaves it green. These tests read the header the client would actually
receive.

Every cookie here carries SC-8/SC-23 weight in a FedRAMP deployment: without
``Secure`` a session cookie travels over plaintext HTTP, and without HSTS the
browser will make that first plaintext request at all.

The ``production_env`` fixture lives in ``conftest.py`` -- see its docstring
for why ``CCF_ENV`` alone is not enough.
"""

from __future__ import annotations

import itertools
import os
from collections.abc import AsyncIterator, Iterator
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, User
from ccf.models_portal import ExternalAccessGrant, ExternalPrincipal
from ccf.portal import service as portal_service

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


def _tag() -> str:
    return f"{next(_SEQ)}-{os.urandom(3).hex()}"


def _client() -> AsyncClient:
    """A client over a **freshly built** app.

    ``create_app`` reads settings once, at build time -- the HSTS flag is
    baked into the middleware there -- so the app must be constructed inside
    the ``production_env`` fixture's window, never module-scoped.
    """
    return AsyncClient(
        transport=ASGITransport(app=create_app()), base_url="http://t", follow_redirects=False
    )


def _set_cookie_headers(response: Any, name: str) -> list[str]:
    """Every ``set-cookie`` header for ``name`` (there should be exactly one)."""
    return [
        v
        for v in response.headers.get_list("set-cookie")
        if v.split("=", 1)[0].strip() == name
    ]


def _assert_secure(response: Any, name: str) -> None:
    """The named cookie was set, and it carries ``Secure``.

    Asserts the cookie was set *first*: without that, a route that stopped
    setting a cookie at all -- or a redirect chain that swallowed it -- would
    satisfy an "all cookies are Secure" assertion vacuously, which is how a
    gate test comes to pass with its gate deleted.
    """
    headers = _set_cookie_headers(response, name)
    assert headers, (
        f"{name} was never set (status {response.status_code}); this test cannot "
        f"say anything about Secure until it is"
    )
    for header in headers:
        attrs = {a.strip().lower() for a in header.split(";")[1:]}
        assert "secure" in attrs, f"{name} set without Secure: {header}"


# --- Seed helpers ------------------------------------------------------------


async def _mk_user(tag: str, password: str = "pw") -> tuple[int, int, str]:
    """An org + an active admin user in it. Returns ``(org_id, user_id, email)``."""
    async with session_scope() as s:
        org = Organization(name=f"ProdGate Org {tag}")
        s.add(org)
        await s.flush()
        user = User(
            email=f"prodgate-{tag}@gates.test",
            organization_id=org.id,
            role="admin",
            active=True,
            password_hash=hash_password(password),
            api_token=new_api_token(),
        )
        s.add(user)
        await s.flush()
        return org.id, user.id, user.email


async def _cleanup(*org_ids: int) -> None:
    async with session_scope() as s:
        await s.execute(
            delete(ExternalAccessGrant).where(ExternalAccessGrant.organization_id.in_(org_ids))
        )
        await s.execute(
            delete(ExternalPrincipal).where(ExternalPrincipal.organization_id.in_(org_ids))
        )
        await s.execute(delete(User).where(User.organization_id.in_(org_ids)))
        await s.execute(delete(Organization).where(Organization.id.in_(org_ids)))


@pytest.fixture
async def seeded_user() -> AsyncIterator[tuple[int, int, str]]:
    tag = _tag()
    org_id, user_id, email = await _mk_user(tag)
    try:
        yield org_id, user_id, email
    finally:
        await _cleanup(org_id)


# --- api/main.py:179 -- HSTS on the security middleware ----------------------


@pytest.mark.asyncio
async def test_hsts_is_sent_in_production(production_env: None) -> None:
    """SC-8/SC-23. Without HSTS the browser's *first* request to a Concord
    deployment is plaintext HTTP, and the session cookie's ``Secure`` flag
    cannot protect a request the cookie is not yet on."""
    async with _client() as c:
        response = await c.get("/healthz")
    assert response.status_code == 200
    hsts = response.headers.get("strict-transport-security")
    assert hsts is not None, "no Strict-Transport-Security header in production"
    assert "max-age=" in hsts
    assert int(hsts.split("max-age=")[1].split(";")[0]) > 0


@pytest.mark.asyncio
async def test_hsts_is_not_sent_in_development() -> None:
    """The other half of the gate, asserted separately so "always on" cannot
    pass as a fix: dev/test serve plaintext HTTP, and an HSTS header there
    would pin a developer's browser to https://localhost for a year."""
    async with _client() as c:
        response = await c.get("/healthz")
    assert response.status_code == 200
    assert response.headers.get("strict-transport-security") is None


# --- api/routes/auth.py:40 -- the API login session cookie -------------------


@pytest.mark.asyncio
async def test_api_login_session_cookie_is_secure_in_production(
    production_env: None, seeded_user: tuple[int, int, str]
) -> None:
    _org_id, _user_id, email = seeded_user
    async with _client() as c:
        response = await c.post("/api/auth/login", json={"email": email, "password": "pw"})
    assert response.status_code == 200, response.text
    _assert_secure(response, "concord_session")


# --- api/routes/ui.py:1697 -- the server-rendered login form's cookie --------


@pytest.mark.asyncio
async def test_ui_login_session_cookie_is_secure_in_production(
    production_env: None, seeded_user: tuple[int, int, str]
) -> None:
    """The browser path mints the same cookie from a different call site --
    the one an actual federal user's session comes from."""
    _org_id, _user_id, email = seeded_user
    async with _client() as c:
        response = await c.post("/login", data={"email": email, "password": "pw"})
    assert response.status_code == 303, response.text
    _assert_secure(response, "concord_session")


# --- api/routes/portal.py:445 -- the external portal grant cookie ------------


@pytest.mark.asyncio
async def test_portal_session_cookie_is_secure_in_production(
    production_env: None,
) -> None:
    """The portal cookie is the credential an *external* assessor's browser
    holds for a federal evidence package, exchanged for the one-time link
    token -- so it is the one most likely to cross an untrusted network."""
    tag = _tag()
    async with session_scope() as s:
        org = Organization(name=f"ProdGate Portal Org {tag}")
        s.add(org)
        await s.flush()
        org_id = org.id
        grant = await portal_service.create_grant(
            s, org_id=org_id, principal_name=f"Assessor {tag}", kind="assessor", ttl_days=7
        )
        token = grant.token
    try:
        async with _client() as c:
            response = await c.get("/portal", params={"token": token})
        assert response.status_code == 303, response.text
        _assert_secure(response, "concord_portal_session")
    finally:
        await _cleanup(org_id)


# --- api/routes/identity.py:77 and :45 -- the two SSO cookies ----------------


@pytest.fixture
def oidc_enabled() -> Iterator[None]:
    previous = os.environ.get("CCF_OIDC_ENABLED")
    os.environ["CCF_OIDC_ENABLED"] = "true"
    get_settings.cache_clear()
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("CCF_OIDC_ENABLED", None)
        else:
            os.environ["CCF_OIDC_ENABLED"] = previous
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_sso_state_cookie_is_secure_in_production(
    production_env: None, oidc_enabled: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``identity.py:77``. The OIDC ``state`` cookie is the CSRF defence for
    the whole SSO handshake: ``sso_callback`` compares the IdP's ``state``
    against it, so a value readable off a plaintext hop is a forgeable login."""
    from ccf.api.routes import identity as identity_routes  # noqa: PLC0415

    async def _url(state: str) -> str:
        return f"https://idp.example/authorize?state={state}"

    monkeypatch.setattr(identity_routes, "authorization_url", _url)

    async with _client() as c:
        response = await c.get("/auth/login")
    assert response.status_code == 303, response.text
    assert response.headers["location"].startswith("https://idp.example/")
    _assert_secure(response, "concord_oidc_state")


@pytest.mark.asyncio
async def test_sso_callback_session_cookie_is_secure_in_production(
    production_env: None, oidc_enabled: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``identity.py:45``. The third site that mints ``concord_session`` --
    and the one a real SSO deployment uses, so leaving it ungated would mean
    the cookie was ``Secure`` on the two login paths nobody uses."""
    from ccf.api.routes import identity as identity_routes  # noqa: PLC0415

    tag = _tag()
    email = f"sso-{tag}@gates.test"

    async def _exchange(code: str) -> dict[str, Any]:
        return {"email": email, "sub": f"sub-{tag}"}

    monkeypatch.setattr(identity_routes, "exchange_code", _exchange)

    try:
        async with _client() as c:
            response = await c.get(
                "/auth/callback",
                params={"code": "any-code", "state": "s"},
                cookies={"concord_oidc_state": "s"},
            )
        assert response.status_code == 303, response.text
        _assert_secure(response, "concord_session")
    finally:
        # ``_default_org_id`` reuses the lowest-id existing organization
        # rather than creating one, so only the JIT-provisioned user is ours
        # to remove.
        async with session_scope() as s:
            await s.execute(delete(User).where(User.email == email))


# --- reliability/checks.py -- the go-live gate must agree with is_dev_env ----


@pytest.mark.asyncio
@pytest.mark.parametrize("env", ["", "production", "prod", "staging", "gov-prod"])
async def test_auth_posture_check_agrees_with_is_dev_env(
    env: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``_check_auth_posture`` had its own copy of the dev-env list.

    The copy defaulted a missing ``env`` to ``"dev"`` where ``is_dev_env``
    defaults it to ``""`` -- the production side. So with ``CCF_ENV=""`` and
    auth off, the readiness check that gates go-live reported
    ``pass: Dev environment`` while every cookie, HSTS and
    ``enforce_secure_config`` treated the same deployment as production.
    Parametrized over ``""`` *and* the ordinary production spellings so the
    fix cannot be special-cased to the empty string.
    """
    from ccf.config import Settings, is_dev_env  # noqa: PLC0415
    from ccf.reliability.checks import _check_auth_posture  # noqa: PLC0415

    settings = Settings(env=env, auth_enabled=False)
    assert not is_dev_env(settings), f"{env!r} must be the production side"
    monkeypatch.setattr("ccf.reliability.checks.get_settings", lambda: settings)

    check = await _check_auth_posture(None)  # type: ignore[arg-type]
    assert check.status == "fail", (
        f"auth is disabled and env={env!r} is not a dev env, but the go-live "
        f"check said {check.status}: {check.detail}"
    )
