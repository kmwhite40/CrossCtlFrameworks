"""Scheduler per-tenant fan-out isolation (IA-06).

``_run_per_tenant_cycle`` clamps the session to each organization's own RLS
tenant in turn (:func:`ccf.db.set_session_tenant`) before running that org's
collection/ConMon/control-test slice, so one organization's per-tenant work
can never be attributed to another. This exercises the real production path —
two organizations, each with its own bound connector credential (IA-05) — and
asserts the resulting ``CaptureSnapshot`` rows carry the correct
``organization_id`` and value, with no cross-org leak.
"""

from __future__ import annotations

from datetime import date

import pytest
from sqlalchemy import delete, select

from ccf.config import get_settings
from ccf.connectors import CapturedParameter
from ccf.connectors import credentials as connector_credentials
from ccf.connectors.msgraph import MsGraphConnector
from ccf.db import session_scope
from ccf.governance.scheduler import _run_per_tenant_cycle
from ccf.models import CaptureSnapshot, Organization
from ccf.models_grc import ConnectorConfig

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(autouse=True)
def _master_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CCF_AI_CREDENTIAL_MASTER_KEY", "unit-test-master-key-32-chars-xx")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return org.id


async def _cleanup(*org_ids: int) -> None:
    """Deterministic + self-cleaning: leave no global rows behind."""
    async with session_scope() as s:
        await s.execute(
            delete(CaptureSnapshot).where(CaptureSnapshot.organization_id.in_(org_ids))
        )
        await s.execute(
            delete(ConnectorConfig).where(ConnectorConfig.organization_id.in_(org_ids))
        )


async def test_run_per_tenant_cycle_attributes_captures_without_cross_org_leak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_a = await _org("scheduler-tenant-org-a")
    org_b = await _org("scheduler-tenant-org-b")

    # Distinct per-org credential, mirroring the Slice-7 IA-05 model — each
    # org binds its own msgraph credential via credentials.set_credential.
    cred_a = {"tenant_id": "tenant-a", "client_id": "client-a", "client_secret": "secret-a"}
    cred_b = {"tenant_id": "tenant-b", "client_id": "client-b", "client_secret": "secret-b"}

    # Mocked capture — never hits real cloud. Returns a value derived from
    # *this connector instance's own credential* so org A's and org B's
    # captures are distinguishable, exactly mirroring how the scheduler
    # resolves and binds a per-org credential before calling capture().
    async def fake_capture(self: MsGraphConnector) -> list[CapturedParameter]:
        tenant = (self.credential or {}).get("tenant_id", "unknown")
        return [
            CapturedParameter(
                odp_key="mfa_enforced",
                value=f"required-by-{tenant}",
                nist_id="3.5.3",
                source="mock",
            )
        ]

    monkeypatch.setattr(MsGraphConnector, "capture", fake_capture)

    try:
        async with session_scope() as s:
            await connector_credentials.set_credential(s, org_a, "msgraph", cred_a)
            await connector_credentials.set_credential(s, org_b, "msgraph", cred_b)

        async with session_scope() as s:
            await _run_per_tenant_cycle(s, [org_a, org_b], today=date(2026, 7, 21))

        # Query CaptureSnapshot directly, unscoped — one row per org, each
        # carrying the correct organization_id and that org's own value.
        async with session_scope() as s:
            snap_a = (
                await s.execute(
                    select(CaptureSnapshot).where(
                        CaptureSnapshot.organization_id == org_a,
                        CaptureSnapshot.connector == "msgraph",
                        CaptureSnapshot.odp_key == "mfa_enforced",
                    )
                )
            ).scalar_one()
            snap_b = (
                await s.execute(
                    select(CaptureSnapshot).where(
                        CaptureSnapshot.organization_id == org_b,
                        CaptureSnapshot.connector == "msgraph",
                        CaptureSnapshot.odp_key == "mfa_enforced",
                    )
                )
            ).scalar_one()

        assert snap_a.organization_id == org_a
        assert snap_a.value == "required-by-tenant-a"
        assert snap_b.organization_id == org_b
        assert snap_b.value == "required-by-tenant-b"

        # No cross-org leak: org A's value never lands on org B's row (or a
        # different row entirely) and vice versa.
        assert snap_a.value != snap_b.value
        assert snap_a.organization_id != snap_b.organization_id
    finally:
        await _cleanup(org_a, org_b)
