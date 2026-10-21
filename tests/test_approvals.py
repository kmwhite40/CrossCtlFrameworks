"""The approval workflow's authority and separation-of-duties rules, against the
real ``approvals.decide``.

These tests used to re-implement the guard in the test file and assert on the
copy, so no change to ``decide`` could ever fail them. They now call the code.

Authority is per system: an ``admin``, or the holder of a system role that
``APPROVAL_AUTHORITY`` names for the entity type. ``authorizing_official`` used
to be checked as a *user* role, which the ``user_role`` enum cannot hold, so an
AO could never approve anything.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from alembic import command
from alembic.config import Config

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance import approvals
from ccf.governance.approvals import ENTITY_TYPES, EntityNotFoundError, WorkflowError
from ccf.models import POAM, Organization, Risk, System, User
from ccf.models_ato import SystemRoleAssignment

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


def test_entity_types_have_authority() -> None:
    assert {"ssp_project", "poam", "risk", "assessment"} <= ENTITY_TYPES
    assert approvals.APPROVAL_AUTHORITY["risk"] == ("authorizing_official",)


async def _world(name: str) -> dict[str, int]:
    """An org with a system, a POA&M, a risk, and four control owners."""
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"{name} sys")
        s.add(sysm)
        await s.flush()
        poam = POAM(system_id=sysm.id, title="weakness")
        risk = Risk(system_id=sysm.id, title="risk")
        s.add_all([poam, risk])
        ids: dict[str, int] = {"org": org.id, "system": sysm.id}
        for key in ("prep", "isso", "ao", "other"):
            u = User(
                email=f"{key}@{name.lower()}.example", organization_id=org.id,
                role="control_owner", active=True,
            )
            s.add(u)
            await s.flush()
            ids[key] = u.id
        await s.flush()
        ids["poam"], ids["risk"] = poam.id, risk.id
        for role, key in (("isso", "isso"), ("authorizing_official", "ao")):
            s.add(SystemRoleAssignment(
                organization_id=org.id, system_id=sysm.id, role=role, user_id=ids[key]
            ))
        return ids


def _email(key: str, name: str) -> str:
    return f"{key}@{name.lower()}.example"


async def _submit(kind: str, eid: int, name: str, org: int) -> None:
    async with session_scope() as s:
        await approvals.submit(
            s, entity_type=kind, entity_id=str(eid), actor=_email("prep", name), org_id=org
        )


async def _decide(kind: str, eid: int, name: str, key: str, ids: dict[str, int]) -> None:
    async with session_scope() as s:
        await approvals.decide(
            s, entity_type=kind, entity_id=str(eid), approve=True,
            actor=_email(key, name), role="control_owner", org_id=ids["org"],
            user_id=ids[key],
        )


@pytest.mark.asyncio
async def test_the_systems_ao_can_approve_a_risk(_auth_enabled: None) -> None:
    ids = await _world("ApprAuthA")
    await _submit("risk", ids["risk"], "ApprAuthA", ids["org"])
    await _decide("risk", ids["risk"], "ApprAuthA", "ao", ids)  # no raise


@pytest.mark.asyncio
async def test_an_isso_cannot_approve_a_risk(_auth_enabled: None) -> None:
    ids = await _world("ApprAuthB")
    await _submit("risk", ids["risk"], "ApprAuthB", ids["org"])
    with pytest.raises(WorkflowError, match="authorizing role"):
        await _decide("risk", ids["risk"], "ApprAuthB", "isso", ids)


@pytest.mark.asyncio
async def test_a_user_with_no_system_role_cannot_approve(_auth_enabled: None) -> None:
    ids = await _world("ApprAuthC")
    await _submit("poam", ids["poam"], "ApprAuthC", ids["org"])
    with pytest.raises(WorkflowError, match="authorizing role"):
        await _decide("poam", ids["poam"], "ApprAuthC", "other", ids)


@pytest.mark.asyncio
async def test_the_ao_of_another_system_cannot_approve(_auth_enabled: None) -> None:
    ids = await _world("ApprAuthD")
    other = await _world("ApprAuthD2")
    await _submit("risk", other["risk"], "ApprAuthD2", other["org"])
    async with session_scope() as s:
        with pytest.raises(EntityNotFoundError):
            await approvals.decide(
                s, entity_type="risk", entity_id=str(other["risk"]), approve=True,
                actor=_email("ao", "ApprAuthD"), role="control_owner", org_id=ids["org"],
                user_id=ids["ao"],
            )


@pytest.mark.asyncio
async def test_separation_of_duties_binds_the_ao_too(_auth_enabled: None) -> None:
    name = "ApprAuthE"
    ids = await _world(name)
    async with session_scope() as s:
        await approvals.submit(
            s, entity_type="risk", entity_id=str(ids["risk"]),
            actor=_email("ao", name), org_id=ids["org"],
        )
    with pytest.raises(WorkflowError, match="separation of duties"):
        await _decide("risk", ids["risk"], name, "ao", ids)


@pytest.mark.asyncio
async def test_a_missing_entity_cannot_be_submitted() -> None:
    async with session_scope() as s:
        with pytest.raises(EntityNotFoundError):
            await approvals.submit(
                s, entity_type="poam", entity_id="999999999", actor="a", org_id=None
            )


@pytest.mark.asyncio
async def test_single_operator_mode_skips_authority_and_sod() -> None:
    name = "ApprAuthF"
    ids = await _world(name)
    async with session_scope() as s:
        await approvals.submit(
            s, entity_type="risk", entity_id=str(ids["risk"]), actor="system", org_id=None
        )
        a = await approvals.decide(
            s, entity_type="risk", entity_id=str(ids["risk"]), approve=True,
            actor="system", role="viewer", org_id=None,
        )
        assert a.state == "approved"


@pytest.mark.asyncio
async def test_granted_as_reports_the_reviewers_capacity(_auth_enabled: None) -> None:
    name = "ApprAuthG"
    ids = await _world(name)
    await _submit("poam", ids["poam"], name, ids["org"])
    await _decide("poam", ids["poam"], name, "isso", ids)
    async with session_scope() as s:
        assert await approvals.granted_as(s, "poam", ids["poam"], ("isso",)) == "isso"
        assert await approvals.granted_as(
            s, "poam", ids["poam"], approvals.RISK_ACCEPTANCE_AUTHORITY
        ) is None
