"""Assurance query layer — deterministic, parameterized templates over the data.

Phase 9: auditors/AOs ask canned questions ("systems with expired evidence",
"grants expiring in 7 days", "controls failing across N systems") and get an
exportable answer table — no AI, reusable templates, tenant-scoped results.
"""

from __future__ import annotations

from datetime import date, timedelta

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.evidence import service as ev_service
from ccf.models import Control, ControlImplementation, Organization, System
from ccf.portal import service as portal
from ccf.queries import service as queries
from ccf.reliability.checks import _check_query_templates_health

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name, description="queries test")
        s.add(org)
        await s.flush()
        return org.id


async def _system(org_id: int, name: str) -> int:
    async with session_scope() as s:
        sysm = System(organization_id=org_id, name=name, baseline="moderate")
        s.add(sysm)
        await s.flush()
        return sysm.id


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


def test_list_templates_exposes_registry_with_param_schemas() -> None:
    templates = queries.list_templates()
    keys = {t["key"] for t in templates}
    assert {"expired-evidence", "expiring-grants", "controls-failing-across-systems"} <= keys
    grants = next(t for t in templates if t["key"] == "expiring-grants")
    assert grants["columns"]  # declares its output columns
    assert any(p["name"] == "days" for p in grants["params"])  # typed, discoverable params


@pytest.mark.asyncio
async def test_expired_evidence_returns_only_expired() -> None:
    org = await _org("QExpEv")
    system = await _system(org, "QExpSys")
    async with session_scope() as s:
        await ev_service.create_object(
            s, org_id=org, title="Old SOC2", system_id=system, control_id="AC-2",
            expires_on=date(2020, 1, 1),
        )
        await ev_service.create_object(
            s, org_id=org, title="Fresh pentest", system_id=system, control_id="CA-8",
            expires_on=date.today() + timedelta(days=365),
        )
    async with session_scope() as s:
        result = await queries.run_query(s, "expired-evidence", {}, org_id=org)
        titles = {r["title"] for r in result["rows"]}
        assert "Old SOC2" in titles
        assert "Fresh pentest" not in titles
        assert result["count"] == len(result["rows"])


@pytest.mark.asyncio
async def test_expiring_grants_respects_days_param() -> None:
    org = await _org("QGrants")
    async with session_scope() as s:
        await portal.create_grant(
            s, org_id=org, principal_name="X", ttl_days=3, label="soon-grant"
        )
        await portal.create_grant(
            s, org_id=org, principal_name="Y", ttl_days=60, label="later-grant"
        )
    async with session_scope() as s:
        result = await queries.run_query(s, "expiring-grants", {"days": 7}, org_id=org)
        labels = {r["label"] for r in result["rows"]}
        assert "soon-grant" in labels
        assert "later-grant" not in labels  # outside the 7-day window
        wide = await queries.run_query(s, "expiring-grants", {"days": 90}, org_id=org)
        assert {"soon-grant", "later-grant"} <= {r["label"] for r in wide["rows"]}


@pytest.mark.asyncio
async def test_controls_failing_across_systems_counts_distinct_systems() -> None:
    org = await _org("QFail")
    sys_a = await _system(org, "QFailA")
    sys_b = await _system(org, "QFailB")
    async with session_scope() as s:
        ctrl = Control(identifier="AC-99", control_name="Test control")
        s.add(ctrl)
        await s.flush()
        for sid in (sys_a, sys_b):
            s.add(ControlImplementation(
                system_id=sid, control_id=ctrl.id, status="not_implemented"))
    async with session_scope() as s:
        result = await queries.run_query(
            s, "controls-failing-across-systems", {"min_systems": 2}, org_id=org
        )
        row = next((r for r in result["rows"] if r["control"] == "AC-99"), None)
        assert row is not None
        assert row["systems_affected"] == 2


@pytest.mark.asyncio
async def test_query_is_org_scoped() -> None:
    org_a = await _org("QScopeA")
    org_b = await _org("QScopeB")
    sys_a = await _system(org_a, "QScopeSysA")
    sys_b = await _system(org_b, "QScopeSysB")
    async with session_scope() as s:
        await ev_service.create_object(
            s, org_id=org_a, title="A-only expired", system_id=sys_a, expires_on=date(2019, 1, 1)
        )
        await ev_service.create_object(
            s, org_id=org_b, title="B-only expired", system_id=sys_b, expires_on=date(2019, 1, 1)
        )
    async with session_scope() as s:
        result = await queries.run_query(s, "expired-evidence", {}, org_id=org_a)
        titles = {r["title"] for r in result["rows"]}
        assert "A-only expired" in titles
        assert "B-only expired" not in titles  # never leaks another tenant's data


@pytest.mark.asyncio
async def test_unknown_template_raises() -> None:
    async with session_scope() as s:
        with pytest.raises(KeyError):
            await queries.run_query(s, "no-such-template", {}, org_id=None)


@pytest.mark.asyncio
async def test_reliability_check_runs_every_template() -> None:
    async with session_scope() as s:
        chk = await _check_query_templates_health(s)
        assert chk.status == "pass"  # every registered template executes cleanly


@pytest.mark.asyncio
async def test_query_api_list_run_and_csv() -> None:
    org = await _org("QApi")
    system = await _system(org, "QApiSys")
    async with session_scope() as s:
        await ev_service.create_object(
            s, org_id=org, title="API expired", system_id=system, expires_on=date(2018, 6, 1)
        )
    async with _client() as c:
        listed = await c.get("/api/queries")
        assert listed.status_code == 200
        assert any(t["key"] == "expired-evidence" for t in listed.json())

        run = await c.post(
            "/api/queries/expired-evidence/run", json={"organization_id": org, "params": {}}
        )
        assert run.status_code == 200
        assert any(r["title"] == "API expired" for r in run.json()["rows"])

        csv = await c.post(
            "/api/queries/expired-evidence/export", json={"organization_id": org, "params": {}}
        )
        assert csv.status_code == 200
        assert "text/csv" in csv.headers["content-type"]
        assert "API expired" in csv.text
