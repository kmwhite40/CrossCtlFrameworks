"""Nothing can be written to a deleted system either.

The companion to ``test_deleted_systems_are_not_readable``. Fourteen reads served
a soft-deleted system's data; this covers the twenty-eight endpoints that would
*add* to one. Writing is the worse half: a read exposes what the customer thought
was gone, a write attaches new records to it -- a scan result, a seeded CR26
document, a remediation plan, an authorization decision -- so the system quietly
comes back as a thing with recent activity.

``org_systems_subq`` already states the intent: a deleted system's id "can no
longer be used to scope in new risks/scans/evidence/POA&Ms". This asserts it for
every mutating endpoint that takes a ``system_id``.

**The invariant is deliberately "never 2xx" rather than "always 404".** Most of
these endpoints need a request body, and without one they answer 422 before any
scope check runs. A 422 is not a refusal on the grounds that matter, but it does
establish that nothing was written, which is the property worth guarding across
all twenty-eight. The two cases that take no body are asserted the strong way --
live succeeds, deleted 404s -- so the broad test cannot pass merely because every
endpoint rejected a missing body.
"""

from __future__ import annotations

import itertools
import re
from datetime import UTC, datetime

import pytest
from alembic import command
from alembic.config import Config
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient

from ccf.api.auth_deps import get_principal, get_principal_optional
from ccf.api.main import create_app
from ccf.auth import Principal
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, System, SystemProfile

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _mutating_system_routes() -> list[tuple[str, str]]:
    """(method, path-template) for every mutating route keyed on a system id.

    Discovered from the app rather than listed, so a new one is covered the day
    it ships. The read-side companion lists its routes because it also asserts
    the live side answers; here the invariant holds for any such route without
    needing to know what it does.
    """
    app = create_app()

    def flatten(obj: object, depth: int = 0):
        if depth > 6:
            return
        for attr in (
            "routes",
            "original_router",
            "effective_candidates",
            "effective_low_priority_routes",
        ):
            val = getattr(obj, attr, None)
            if val is None:
                continue
            items = val if isinstance(val, (list, tuple)) else getattr(val, "routes", None)
            if not items:
                continue
            for it in items:
                if isinstance(it, APIRoute):
                    yield it
                else:
                    yield from flatten(it, depth + 1)

    out: set[tuple[str, str]] = set()
    for r in app.routes:
        for route in [r, *flatten(r)]:
            if not isinstance(route, APIRoute):
                continue
            if "{system_id}" not in route.path or not route.path.startswith("/api"):
                continue
            if re.search(r"\{(?!system_id)[^}]+\}", route.path):
                continue
            for method in route.methods:
                if method in ("POST", "PUT", "PATCH", "DELETE"):
                    out.add((method, route.path))
    return sorted(out)


MUTATING = _mutating_system_routes()

#: Endpoints that need no request body, so the strong form of the assertion is
#: available: the live system must succeed and the deleted one must 404.
#: ``scan``/``scan-all``/``provider-readiness`` are excluded on purpose -- they
#: reach a provider API, and the suite blocks outbound network.
NO_BODY_POSTS = [
    "/api/systems/{system_id}/derive",
    "/api/systems/{system_id}/cr26-documents/cpo/seed",
]


class _Caller:
    def __init__(self, *, org_id: int | None, role: str = "admin") -> None:
        self.app = create_app()
        self.org_id = org_id
        self.role = role
        self.app.dependency_overrides[get_principal] = self._principal
        self.app.dependency_overrides[get_principal_optional] = self._principal

    def _principal(self) -> Principal:
        return Principal(user_id=1, email="owner@customer.gov", org_id=self.org_id, role=self.role)

    def client(self) -> AsyncClient:
        return AsyncClient(transport=ASGITransport(app=self.app), base_url="http://test")


@pytest.fixture
async def one_live_and_one_deleted() -> tuple[int, int, int]:
    tag = next(_SEQ)
    async with session_scope() as session:
        org = Organization(name=f"Write Scope Org {tag}")
        session.add(org)
        await session.flush()
        live = System(organization_id=org.id, name=f"wlive-{tag}", baseline="moderate")
        gone = System(organization_id=org.id, name=f"wgone-{tag}", baseline="moderate")
        session.add_all([live, gone])
        await session.flush()
        gone.deleted_at = datetime.now(UTC)
        for system in (live, gone):
            session.add(
                SystemProfile(
                    system_id=system.id,
                    answers={},
                    environment_type="cloud",
                    cloud_platform="m365_gcc_high",
                    frameworks=["NIST_800_171"],
                    derivation={},
                )
            )
        await session.flush()
        return int(org.id), int(live.id), int(gone.id)


def test_the_route_discovery_found_the_endpoints() -> None:
    """A discovery function that returns nothing makes every case below vacuous."""
    assert len(MUTATING) >= 25, (
        f"only {len(MUTATING)} mutating system routes discovered; the parametrised "
        "cases below would be testing almost nothing"
    )
    paths = {p for _m, p in MUTATING}
    # Spot-check the ones whose misuse would matter most.
    for expected in (
        "/api/systems/{system_id}/authorize",
        "/api/systems/{system_id}/scan-all",
        "/api/systems/{system_id}/derive",
    ):
        assert expected in paths, f"{expected} was not discovered"


@pytest.mark.parametrize(("method", "path"), MUTATING, ids=str)
@pytest.mark.asyncio
async def test_no_write_succeeds_against_a_deleted_system(
    method: str, path: str, one_live_and_one_deleted: tuple[int, int, int]
) -> None:
    """Never a 2xx. A 422 is acceptable here only because it proves no write ran."""
    org_id, _live_id, gone_id = one_live_and_one_deleted
    url = path.replace("{system_id}", str(gone_id))
    async with _Caller(org_id=org_id).client() as c:
        resp = await c.request(method, url, json={})
    assert not (200 <= resp.status_code < 300), (
        f"{method} {path} succeeded against a soft-deleted system: "
        f"{resp.status_code} {resp.text[:200]}"
    )


@pytest.mark.parametrize("path", NO_BODY_POSTS)
@pytest.mark.asyncio
async def test_a_bodyless_write_refuses_the_deleted_system_and_accepts_the_live_one(
    path: str, one_live_and_one_deleted: tuple[int, int, int]
) -> None:
    """The strong form, where it is available.

    Without this the broad test above could pass because every endpoint rejected
    an empty body, having never consulted the system at all.
    """
    org_id, live_id, gone_id = one_live_and_one_deleted
    async with _Caller(org_id=org_id).client() as c:
        live = await c.post(path.replace("{system_id}", str(live_id)))
        gone = await c.post(path.replace("{system_id}", str(gone_id)))

    assert 200 <= live.status_code < 300, (
        f"{path} does not accept a LIVE system either ({live.status_code}: "
        f"{live.text[:200]}), so a refusal on the deleted one proves nothing"
    )
    assert gone.status_code == 404, (
        f"{path} accepted a write to a soft-deleted system: {gone.status_code}"
    )
