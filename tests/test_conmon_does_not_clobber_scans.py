"""ConMon must not overwrite a posture scan's finding with a connector heartbeat.

A posture-scan test carries a ``check_key`` and no ``assertion``, so it fell
through to the connector-freshness heuristic -- which answers "is the
connector healthy", not "does the control pass". A healthy connector therefore
overwrote a real finding with a pass, recorded it with ``evaluated=0,
failing=0``, and raised a "Control test recovered" alert claiming a failure had
been fixed.

Seen live: IA-2 (6 of 78 users without MFA), AC-3 and AC-6 all reported
recovered while still failing.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime

import pytest

from ccf.db import session_scope
from ccf.governance.control_tests import evaluate_test
from ccf.models import Organization, System
from ccf.models_grc import ConnectorConfig, ControlTest

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(autouse=True)
async def _remove_connectors_afterwards():
    """Delete the connectors this module creates.

    Each carries an `encrypted_credential` -- deliberately, because the whole
    subject is a *healthy* connector overwriting a scan result -- which puts
    its organization into `orgs_with_bound_credentials`. The scheduled
    collection path in `test_connectors.py` then tries to capture from it and
    fails in another module with nothing pointing back here.
    """
    from sqlalchemy import delete, select

    yield
    async with session_scope() as s:
        await s.execute(
            delete(ConnectorConfig).where(
                ConnectorConfig.organization_id.in_(
                    select(Organization.id).where(Organization.name.like("ConMon Org %"))
                )
            )
        )


async def _seed(*, check_key: str | None, last_status: str) -> tuple[int, int]:
    tag = uuid.uuid4().hex[:8]
    async with session_scope() as s:
        org = Organization(name=f"ConMon Org {tag}")
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name=f"Sys {tag}")
        s.add(system)
        # A perfectly healthy connector: recent sync, objects discovered.
        # This is exactly the state that made the heuristic answer "pass".
        s.add(
            ConnectorConfig(
                organization_id=org.id,
                name="msgraph",
                connector_type="msgraph",
                status="configured",
                last_sync=datetime.now(UTC),
                objects_discovered=100,
                encrypted_credential="ciphertext",
            )
        )
        await s.flush()
        test = ControlTest(
            organization_id=org.id,
            system_id=system.id,
            control_id="IA-2",
            name="Every user has an MFA method registered",
            method="automated",
            connector_type="msgraph",
            check_key=check_key,
            last_status=last_status,
        )
        s.add(test)
        await s.flush()
        return org.id, test.id


@pytest.mark.asyncio
async def test_a_failing_scan_result_is_not_flipped_to_pass() -> None:
    _org_id, test_id = await _seed(
        check_key="m365.identity.mfa_registered", last_status="fail"
    )
    async with session_scope() as s:
        test = await s.get(ControlTest, test_id)
        status, detail, _ref = await evaluate_test(s, test, date.today())

    assert status == "fail", "a healthy connector overwrote a real finding"
    assert "posture scan" in detail
    assert "m365.identity.mfa_registered" in detail


@pytest.mark.asyncio
async def test_a_passing_scan_result_is_also_left_alone() -> None:
    """Both directions: a heuristic that only preserved failures would still
    be inventing a verdict half the time."""
    _org_id, test_id = await _seed(
        check_key="m365.policy.legacy_auth_blocked", last_status="pass"
    )
    async with session_scope() as s:
        test = await s.get(ControlTest, test_id)
        status, _detail, _ref = await evaluate_test(s, test, date.today())
    assert status == "pass"


@pytest.mark.asyncio
async def test_a_connector_test_with_no_check_key_still_uses_the_heuristic() -> None:
    """The heuristic is right for what it was written for -- a hand-created
    connector-backed test with no scan behind it. Disabling it entirely would
    break those."""
    _org_id, test_id = await _seed(check_key=None, last_status="warn")
    async with session_scope() as s:
        test = await s.get(ControlTest, test_id)
        status, detail, _ref = await evaluate_test(s, test, date.today())

    assert status == "pass", "the freshness heuristic no longer runs at all"
    assert "current" in detail


@pytest.mark.asyncio
async def test_a_scan_test_that_has_never_run_does_not_report_a_verdict() -> None:
    """`last_status` of None must not become a pass by omission."""
    _org_id, test_id = await _seed(check_key="m365.audit.signin_records_current", last_status=None)
    async with session_scope() as s:
        test = await s.get(ControlTest, test_id)
        status, _detail, _ref = await evaluate_test(s, test, date.today())
    assert status == "warn"
