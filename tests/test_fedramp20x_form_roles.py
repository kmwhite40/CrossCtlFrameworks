"""The 20x UI forms enforce the same roles as the API routes they mirror.

The assessor-review and exception forms wrote with no role check at all, so a
viewer could record an "accepted" 3PAO review through the page that
``POST /api/fedramp/20x/assessor-reviews`` refuses them.
"""

from __future__ import annotations

import itertools

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.auth_deps import get_principal
from ccf.api.main import create_app
from ccf.auth import Principal
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.fedramp20x import catalog
from ccf.models import KSI, KSIAssessorReview, KSIException, Organization, System

pytestmark = pytest.mark.usefixtures("fresh_engine", "isolate_ksi_rows")

_SEQ = itertools.count()


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _setup() -> tuple[int, int, int]:
    async with session_scope() as s:
        await catalog.seed_ksis(s)
        org = Organization(name=f"Form Roles {next(_SEQ)}")
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"Form Roles {next(_SEQ)}")
        s.add(sysm)
        await s.flush()
        ksi_id = (
            await s.execute(select(KSI.id).where(KSI.identifier == "KSI-CED-RAT"))
        ).scalar_one()
        return org.id, sysm.id, ksi_id


def _client(org_id: int, role: str) -> AsyncClient:
    app = create_app()
    app.dependency_overrides[get_principal] = lambda: Principal(
        user_id=1, email=f"{role}@tenant.example", org_id=org_id, role=role
    )
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://t")


async def _rows(model: type, system_id: int) -> int:
    async with session_scope() as s:
        return len(
            (await s.execute(select(model).where(model.system_id == system_id))).scalars().all()
        )


@pytest.mark.parametrize(
    ("role", "review_allowed", "exception_allowed"),
    [
        ("viewer", False, False),
        ("control_owner", False, False),
        ("assessor", True, False),
        ("admin", True, True),
    ],
)
async def test_form_roles_match_the_api(
    role: str, review_allowed: bool, exception_allowed: bool
) -> None:
    org_id, sid, ksi_id = await _setup()
    async with _client(org_id, role) as c:
        review = await c.post(
            f"/fedramp20x/{sid}/assessor-review",
            data={"ksi_id": str(ksi_id), "status": "accepted", "assessor": "3PAO"},
            follow_redirects=False,
        )
        exception = await c.post(
            f"/fedramp20x/{sid}/exception",
            data={"ksi_id": str(ksi_id), "rationale": "compensating control"},
            follow_redirects=False,
        )
        api_review = await c.post(
            "/api/fedramp/20x/assessor-reviews",
            json={"system_id": sid, "ksi_id": ksi_id, "status": "accepted"},
        )
        api_exception = await c.post(
            "/api/fedramp/20x/exceptions",
            json={"system_id": sid, "ksi_id": ksi_id, "rationale": "api"},
        )

    assert (review.status_code == 303) is review_allowed
    assert (exception.status_code == 303) is exception_allowed
    # The form and the API agree, role for role.
    assert (api_review.status_code == 201) is review_allowed
    assert (api_exception.status_code == 201) is exception_allowed
    assert await _rows(KSIAssessorReview, sid) == (2 if review_allowed else 0)
    assert await _rows(KSIException, sid) == (2 if exception_allowed else 0)
