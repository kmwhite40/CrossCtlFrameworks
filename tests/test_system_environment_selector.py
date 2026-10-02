"""A system's environment can be chosen -- and changed -- from its own page.

``SystemProfile.cloud_platform`` decides which connector a system is measured
against (``ccf.posture.scope``), but it could be set only at intake and never
changed; a system created any other way had no profile at all. These pin the
route that sets it and the refusals around it.
"""

from __future__ import annotations

import itertools
from datetime import UTC, datetime

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.auth_deps import get_principal, get_principal_optional
from ccf.api.main import create_app
from ccf.api.routes.ui import ENVIRONMENT_OPTIONS
from ccf.auth import Principal
from ccf.db import session_scope
from ccf.governance.automation import QUESTIONNAIRE
from ccf.models import AuditLog, Organization, System, SystemProfile
from ccf.posture.scope import provider_scope

_SEQ = itertools.count()


def _client(*, org_id: int | None, role: str = "admin") -> AsyncClient:
    app = create_app()

    def _principal() -> Principal:
        return Principal(user_id=1, email="owner@customer.gov", org_id=org_id, role=role)

    app.dependency_overrides[get_principal] = _principal
    app.dependency_overrides[get_principal_optional] = _principal
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Origin": "http://test"},
    )


async def _system(*, cloud_platform: str | None = None, deleted: bool = False) -> tuple[int, int]:
    async with session_scope() as session:
        org = Organization(name=f"EnvOrg{next(_SEQ)}")
        session.add(org)
        await session.flush()
        system = System(organization_id=org.id, name=f"env-{next(_SEQ)}", baseline="moderate")
        session.add(system)
        await session.flush()
        if cloud_platform is not None:
            session.add(
                SystemProfile(system_id=system.id, answers={}, cloud_platform=cloud_platform)
            )
        if deleted:
            system.deleted_at = datetime.now(UTC)
        return org.id, system.id


async def _declared(system_id: int) -> str | None:
    async with session_scope() as session:
        profile = (
            await session.execute(
                select(SystemProfile).where(SystemProfile.system_id == system_id)
            )
        ).scalars().first()
        return profile.cloud_platform if profile is not None else None


def test_the_choices_are_the_questionnaires() -> None:
    """One list, read from intake, so the page and the questionnaire cannot drift."""
    intake = next(q for q in QUESTIONNAIRE if q["id"] == "cloud_platform")["options"]
    assert [code for code, _ in ENVIRONMENT_OPTIONS] == intake
    assert {"m365_gcc_high", "azure_gov", "aws_govcloud", "gcp"} <= set(intake)


async def test_a_system_with_no_profile_gets_one() -> None:
    """The live system 33 state: created outside intake, no profile row."""
    org_id, system_id = await _system()
    async with _client(org_id=org_id) as c:
        r = await c.post(f"/systems/{system_id}/environment", data={"cloud_platform": "azure_gov"})
    assert r.status_code == 303, r.text
    assert await _declared(system_id) == "azure_gov"


async def test_changing_the_environment_changes_what_is_measured() -> None:
    """The point of the control, asserted through scope rather than the column."""
    org_id, system_id = await _system(cloud_platform="aws_govcloud")
    async with _client(org_id=org_id) as c:
        r = await c.post(
            f"/systems/{system_id}/environment", data={"cloud_platform": "m365_gcc_high"}
        )
    assert r.status_code == 303, r.text
    async with session_scope() as session:
        system = await session.get(System, system_id)
        scope = await provider_scope(session, system=system)
    assert scope["msgraph"].in_scope is True
    assert scope["aws_govcloud"].in_scope is False


async def test_the_change_is_audited_with_before_and_after() -> None:
    org_id, system_id = await _system(cloud_platform="aws_govcloud")
    async with _client(org_id=org_id) as c:
        await c.post(f"/systems/{system_id}/environment", data={"cloud_platform": "gcp"})
    async with session_scope() as session:
        rows = (
            await session.execute(
                select(AuditLog).where(
                    AuditLog.action == "system_environment_set",
                    AuditLog.entity_id == str(system_id),
                )
            )
        ).scalars().all()
    assert len(rows) == 1
    assert rows[0].diff["cloud_platform"] == {"from": "aws_govcloud", "to": "gcp"}


@pytest.mark.parametrize("value", ["aws", "M365_GCC_HIGH", "", "azure_commercial"])
async def test_an_unknown_environment_is_refused_and_nothing_changes(value: str) -> None:
    """An unrecognised code resolves to no platform, which would fall back to org
    configuration -- a typo silently changing what is measured."""
    org_id, system_id = await _system(cloud_platform="m365_gcc_high")
    async with _client(org_id=org_id) as c:
        r = await c.post(f"/systems/{system_id}/environment", data={"cloud_platform": value})
    assert r.status_code in (400, 422), r.status_code
    assert await _declared(system_id) == "m365_gcc_high"


@pytest.mark.parametrize("role", ["viewer", "assessor", "control_owner"])
async def test_only_an_administrator_can_choose(role: str) -> None:
    org_id, system_id = await _system(cloud_platform="m365_gcc_high")
    async with _client(org_id=org_id, role=role) as c:
        r = await c.post(f"/systems/{system_id}/environment", data={"cloud_platform": "gcp"})
    assert r.status_code == 403, r.status_code
    assert await _declared(system_id) == "m365_gcc_high"


async def test_another_organizations_system_is_404() -> None:
    _org_id, system_id = await _system(cloud_platform="m365_gcc_high")
    other_org, _ = await _system()
    async with _client(org_id=other_org) as c:
        r = await c.post(f"/systems/{system_id}/environment", data={"cloud_platform": "gcp"})
    assert r.status_code == 404, r.status_code
    assert await _declared(system_id) == "m365_gcc_high"


async def test_a_deleted_system_is_404() -> None:
    org_id, system_id = await _system(cloud_platform="m365_gcc_high", deleted=True)
    async with _client(org_id=org_id) as c:
        r = await c.post(f"/systems/{system_id}/environment", data={"cloud_platform": "gcp"})
    assert r.status_code == 404, r.status_code
    assert await _declared(system_id) == "m365_gcc_high"


async def test_the_page_shows_the_choice_and_offers_the_form_to_an_admin() -> None:
    org_id, system_id = await _system(cloud_platform="azure_gov")
    async with _client(org_id=org_id) as c:
        r = await c.get(f"/systems/{system_id}")
    assert r.status_code == 200, r.text
    assert "Measured as <strong>Azure Government</strong>" in r.text
    assert f'action="/systems/{system_id}/environment"' in r.text
    assert '<option value="azure_gov" selected>' in r.text


async def test_a_viewer_sees_the_choice_but_not_the_form() -> None:
    org_id, system_id = await _system(cloud_platform="azure_gov")
    async with _client(org_id=org_id, role="viewer") as c:
        r = await c.get(f"/systems/{system_id}")
    assert r.status_code == 200, r.text
    assert "Measured as <strong>Azure Government</strong>" in r.text
    assert f'action="/systems/{system_id}/environment"' not in r.text


async def test_an_unchosen_environment_is_stated_as_unchosen() -> None:
    """Not defaulted to a platform on the page either."""
    org_id, system_id = await _system()
    async with _client(org_id=org_id) as c:
        r = await c.get(f"/systems/{system_id}")
    assert r.status_code == 200, r.text
    assert "Not chosen." in r.text
    assert "Measured as" not in r.text
