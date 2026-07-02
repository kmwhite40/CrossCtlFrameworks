"""Assertion-based control tests: evaluator logic + on-demand evaluate endpoint."""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance.control_tests import evaluate_assertion
from ccf.models import CaptureSnapshot, Organization
from ccf.models_grc import ControlTestResult

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


# --- evaluator unit tests ----------------------------------------------------


def test_assertion_equals_coerces_bool_words() -> None:
    a = {"odp_key": "mfa_enforced", "operator": "equals", "value": "true"}
    ok, _ = evaluate_assertion(a, "enabled")
    assert ok is True
    ok2, _ = evaluate_assertion(a, "disabled")
    assert ok2 is False


def test_assertion_numeric_operators() -> None:
    a = {"odp_key": "retention_days", "operator": "gte", "value": "90"}
    assert evaluate_assertion(a, ["365", "days"][0])[0] is True
    assert evaluate_assertion(a, "30")[0] is False
    bad_ok, bad_detail = evaluate_assertion(a, "not-a-number")
    assert bad_ok is False
    assert "non-numeric" in bad_detail


def test_assertion_contains_and_unknown_operator() -> None:
    assert evaluate_assertion(
        {"operator": "contains", "value": "AES"}, "AES-256 at rest"
    )[0] is True
    ok, detail = evaluate_assertion({"operator": "bogus", "value": "x"}, "y")
    assert ok is False and "unknown assertion operator" in detail


# --- integration: evaluate endpoint against a capture snapshot ---------------


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _org(name: str = "AssertOrg") -> int:
    async with session_scope() as s:
        org = (
            await s.execute(select(Organization).where(Organization.name == name))
        ).scalar_one_or_none()
        if org is None:
            org = Organization(name=name)
            s.add(org)
            await s.flush()
        return org.id


async def _set_capture(org_id: int, odp_key: str, value: str) -> None:
    async with session_scope() as s:
        await s.execute(
            delete(CaptureSnapshot).where(
                CaptureSnapshot.organization_id == org_id,
                CaptureSnapshot.connector == "msgraph",
                CaptureSnapshot.odp_key == odp_key,
            )
        )
        s.add(
            CaptureSnapshot(
                organization_id=org_id,
                connector="msgraph",
                odp_key=odp_key,
                value=value,
                nist_id="IA-2",
            )
        )


@pytest.mark.asyncio
async def test_evaluate_endpoint_passes_then_fails_on_drift() -> None:
    org_id = await _org()
    await _set_capture(org_id, "mfa_enforced", "true")

    async with _client() as c:
        created = await c.post(
            "/api/control-tests",
            json={
                "control_id": "IA.L2-3.5.3",
                "name": "MFA enforced for all users",
                "method": "connector",
                "connector_type": "msgraph",
                "frequency": "daily",
                "assertion": {
                    "odp_key": "mfa_enforced",
                    "operator": "equals",
                    "value": "true",
                },
            },
        )
        assert created.status_code == 201, created.text
        tid = created.json()["id"]
        assert created.json()["assertion"]["odp_key"] == "mfa_enforced"

        # Captured value satisfies the assertion → pass.
        r_pass = await c.post(f"/api/control-tests/{tid}/evaluate")
        assert r_pass.status_code == 200, r_pass.text
        assert r_pass.json()["status"] == "pass"
        assert "mfa_enforced" in r_pass.json()["evidence_ref"]

        # Config drifts to non-compliant → fail on the next evaluation.
        await _set_capture(org_id, "mfa_enforced", "false")
        r_fail = await c.post(f"/api/control-tests/{tid}/evaluate")
        assert r_fail.json()["status"] == "fail"

    # Two results recorded; a fail opens a remediation task via record_result.
    async with session_scope() as s:
        results = (
            await s.execute(
                select(ControlTestResult).where(ControlTestResult.control_test_id == tid)
            )
        ).scalars().all()
        assert len(results) == 2
        assert {r.status for r in results} == {"pass", "fail"}


@pytest.mark.asyncio
async def test_evaluate_warns_when_no_capture_present() -> None:
    org_id = await _org("AssertOrg2")
    async with session_scope() as s:
        await s.execute(
            delete(CaptureSnapshot).where(
                CaptureSnapshot.organization_id == org_id,
                CaptureSnapshot.odp_key == "encryption_at_rest",
            )
        )
    async with _client() as c:
        created = await c.post(
            "/api/control-tests",
            json={
                "control_id": "SC.L2-3.13.11",
                "name": "Encryption at rest enabled",
                "method": "connector",
                "connector_type": "msgraph",
                "frequency": "weekly",
                "assertion": {
                    "odp_key": "encryption_at_rest",
                    "operator": "equals",
                    "value": "true",
                },
            },
        )
        tid = created.json()["id"]
        r = await c.post(f"/api/control-tests/{tid}/evaluate")
        assert r.json()["status"] == "warn"
        assert "run collection first" in r.json()["detail"]
