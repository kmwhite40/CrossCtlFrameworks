"""A viewer changes nothing -- enforced once, in the auth gate, for every route.

docs/HANDBOOK.md: viewer = "Read everything in your organization. Change
nothing." docs/THREAT_MODEL.md: "Reads only." 165 of 246 write routes carried
no role check, so a viewer could write through most of the API and UI.

The exhaustive test walks every mutating route the app registers and sends it
as a viewer through the real auth gate, so a write route added later is
refused without anyone remembering to gate it.
"""

from __future__ import annotations

import itertools
import os
import re
from collections.abc import Iterator

import pytest
from alembic import command
from alembic.config import Config
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.auth_deps import is_public_path, viewer_may_write
from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, Task, User

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()
_READ_ONLY = "the viewer role is read-only"


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


async def _token(role: str) -> tuple[str, int]:
    async with session_scope() as s:
        org = Organization(name=f"Viewer RO {next(_SEQ)}")
        s.add(org)
        await s.flush()
        user = User(
            email=f"{role}-{next(_SEQ)}@viewer.test",
            organization_id=org.id,
            role=role,
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        await s.flush()
        return user.api_token, org.id


def _client(token: str) -> AsyncClient:
    # A handler that raises is still a handler the viewer REACHED; report it
    # as a status, not as an exception that stops the walk.
    return AsyncClient(
        transport=ASGITransport(app=create_app(), raise_app_exceptions=False),
        base_url="http://t",
        headers={"Authorization": f"Bearer {token}"},
    )


def _walk(routes: list[object], prefix: str = "") -> Iterator[tuple[str, str]]:
    """Every (method, path) under ``routes``, through FastAPI's lazy wrappers.

    This FastAPI wraps each ``include_router`` in an ``_IncludedRouter`` that is
    not an ``APIRoute``; a flat walk of ``app.routes`` finds nothing and the
    exhaustive test below would pass over an empty list.
    """
    for route in routes:
        ctx = getattr(route, "include_context", None)
        inner = getattr(route, "original_router", None)
        if ctx is not None and inner is not None:
            yield from _walk(list(inner.routes), prefix + (ctx.prefix or ""))
        elif isinstance(route, APIRoute):
            for method in route.methods or ():
                yield method, prefix + route.path


def _mutating_routes() -> list[tuple[str, str]]:
    return sorted(
        {
            (method, re.sub(r"\{[^}]+\}", "1", path))
            for method, path in _walk(list(create_app().routes))
            if method in {"POST", "PUT", "PATCH", "DELETE"}
        }
    )


#: Literal, so a widened allowlist or public prefix fails here instead of being
#: trusted: deriving the expectation from ``viewer_may_write`` itself would let
#: ``^/api/risks`` slip in with every test still green (review of 764e87e, M2).
VIEWER_ALLOWED = {
    ("POST", "/api/oscal/validate"),
    ("POST", "/api/packs/validate"),
    ("POST", "/api/queries/{key}/export"),
    ("POST", "/api/queries/{key}/run"),
    ("POST", "/api/trust/access-requests"),
    ("POST", "/settings/security/activate"),
    ("POST", "/settings/security/disable"),
    ("POST", "/settings/security/enroll"),
    ("POST", "/trust/access-requests"),
}
PUBLIC_MUTATING = {
    ("DELETE", "/api/auth/mfa"),
    ("DELETE", "/api/scim/v2/Users/{user_id}"),
    ("PATCH", "/api/scim/v2/Users/{user_id}"),
    ("POST", "/api/auth/login"),
    ("POST", "/api/auth/logout"),
    ("POST", "/api/auth/mfa/activate"),
    ("POST", "/api/auth/mfa/enroll"),
    ("POST", "/api/auth/mfa/verify"),
    ("POST", "/api/portal/comments"),
    ("POST", "/api/scim/v2/Users"),
    ("POST", "/auth/logout"),
    ("POST", "/login"),
    ("POST", "/login/mfa"),
    ("PUT", "/api/scim/v2/Users/{user_id}"),
}


def _raw_mutating_routes() -> set[tuple[str, str]]:
    return {
        (method, path)
        for method, path in _walk(list(create_app().routes))
        if method in {"POST", "PUT", "PATCH", "DELETE"}
    }


def _concrete(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "1", path)


def test_the_app_has_the_write_surface_this_test_assumes() -> None:
    routes = _mutating_routes()
    assert len(routes) > 200  # if this collapses, the walk below proves nothing


def test_the_viewer_exceptions_are_exactly_the_reviewed_set() -> None:
    raw = _raw_mutating_routes()
    public = {r for r in raw if is_public_path(_concrete(r[1]))}
    allowed = {r for r in raw if r not in public and viewer_may_write(_concrete(r[1]), r[0])}
    assert public == PUBLIC_MUTATING
    assert allowed == VIEWER_ALLOWED


async def test_every_write_route_refuses_a_viewer_unless_allowlisted() -> None:
    token, _org = await _token("viewer")
    leaked: list[str] = []
    wrongly_refused: list[str] = []
    reached: list[str] = []
    async with _client(token) as c:
        for method, path in _mutating_routes():
            if is_public_path(path):
                continue  # never reaches the gate: login, SCIM, portal, ...
            r = await c.request(method, path, json={})
            refused_by_gate = r.status_code == 403 and _READ_ONLY in r.text
            if viewer_may_write(path, method):
                reached.append(f"{method} {path} -> {r.status_code}")
                if refused_by_gate:
                    wrongly_refused.append(f"{method} {path}")
            elif not refused_by_gate:
                leaked.append(f"{method} {path} -> {r.status_code}")
    assert leaked == [], leaked
    assert wrongly_refused == [], wrongly_refused
    # The allowlist is not dead code: every entry is a route the app serves.
    assert len(reached) == len(VIEWER_ALLOWED), reached


async def test_a_refused_write_writes_nothing_and_a_control_owner_still_can() -> None:
    viewer, org_id = await _token("viewer")
    owner, _ = await _token("control_owner")
    body = {"title": f"viewer task {next(_SEQ)}", "organization_id": org_id}
    async with _client(viewer) as c:
        r = await c.post("/api/tasks", json=body)
    assert r.status_code == 403 and _READ_ONLY in r.text
    async with session_scope() as s:
        assert (
            await s.execute(select(Task).where(Task.title == body["title"]))
        ).scalar_one_or_none() is None
    async with _client(owner) as c:
        r = await c.post("/api/tasks", json={"title": f"owner task {next(_SEQ)}"})
    assert _READ_ONLY not in r.text


async def test_a_viewer_still_reads_and_uses_its_read_only_posts() -> None:
    token, _ = await _token("viewer")
    async with _client(token) as c:
        assert (await c.get("/api/tasks")).status_code == 200
        r = await c.post("/api/packs/validate", json={})
        assert r.status_code == 200 and "valid" in r.json()
        # Read-state is one column per org-wide notification: a viewer marking
        # it would silence every user's alerts (review of 764e87e, H1).
        r = await c.post("/api/notifications/read-all")
        assert r.status_code == 403 and _READ_ONLY in r.text
        # Registering a pack source starts scheduled server-side fetches.
        r = await c.post("/api/packs/x/sources", json={"url": "https://example.test/p.json"})
        assert r.status_code == 403 and _READ_ONLY in r.text


async def test_a_refusal_is_logged() -> None:
    from structlog.testing import capture_logs  # noqa: PLC0415

    token, _ = await _token("viewer")
    with capture_logs() as logs:
        async with _client(token) as c:
            await c.post("/api/tasks", json={"title": "x"})
    refused = [e for e in logs if e.get("event") == "auth.viewer_write_refused"]
    assert refused and refused[0]["path"] == "/api/tasks" and refused[0]["method"] == "POST"


async def test_a_ui_form_post_is_refused_in_plain_text() -> None:
    token, _ = await _token("viewer")
    async with _client(token) as c:
        r = await c.post("/fedramp20x/1/profile", data={"service_name": "x"})
    assert r.status_code == 403
    assert r.headers["content-type"].startswith("text/plain")
    assert _READ_ONLY in r.text


@pytest.mark.parametrize(
    ("method", "path", "allowed"),
    [
        ("POST", "/api/queries/open_poams/run", True),
        ("DELETE", "/api/queries/open_poams/run", False),  # method matters
        ("POST", "/api/queries/open_poams/delete", False),
        ("POST", "/api/oscal/validate", True),
        ("POST", "/api/oscal/validate\n", False),  # \\Z, not $
        ("POST", "/api/oscal/validate-and-store", False),
        ("POST", "/settings/security/enroll", True),
        ("POST", "/settings/security/anything-new", False),  # exact, not a prefix
        ("POST", "/trust/access-requests", True),
        ("POST", "/trust/access-requests/4/decide", False),
        ("POST", "/api/trust/access-requests/4/decide", False),
        ("POST", "/api/notifications/12/read", False),
        ("POST", "/api/notifications/read-all", False),
        ("POST", "/api/packs/ai-agent-governance/sources", False),
        ("POST", "/api/tasks", False),
    ],
)
def test_the_allowlist_matches_exact_shapes(method: str, path: str, allowed: bool) -> None:
    assert viewer_may_write(path, method) is allowed
