"""Unit + integration tests for config-capture connectors.

Covers the interface + Graph mapping (pure unit tests, no DB) and the
per-organization credential model (IA-05): credentials are envelope-encrypted
on ``connector_configs``, resolved strictly per-org (no global/env fallback),
and ``collection.collect_for_org``/``collect_all`` attribute captures only to
the org whose own credential produced them. The provider network calls are
always mocked — no real cloud calls.
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import delete, select

from ccf.config import get_settings
from ccf.connectors import (
    CapturedParameter,
    connector_keys,
    credentials,
    get_connector,
    list_connectors,
)
from ccf.connectors.aws import AwsGovCloudConnector
from ccf.connectors.msgraph import MsGraphConnector
from ccf.db import session_scope
from ccf.governance import collection
from ccf.models import CaptureSnapshot, Organization
from ccf.models_grc import ConnectorConfig


def test_registry_resolves_both_providers() -> None:
    keys = {c.key for c in list_connectors()}
    assert keys == {"msgraph", "aws_govcloud"}
    assert set(connector_keys()) == keys
    assert get_connector("nope") is None


def test_connectors_report_not_configured_by_default() -> None:
    # No credential bound (the org-scoped equivalent of the old "no env creds")
    # -> capture is a safe no-op, never raises.
    for c in list_connectors():
        assert c.is_configured() is False
        assert asyncio.run(c.capture()) == []


def test_graph_maps_signin_frequency_to_session_lock_odp() -> None:
    payload = {
        "value": [
            {
                "displayName": "Require re-auth",
                "state": "enabled",
                "sessionControls": {
                    "signInFrequency": {"isEnabled": True, "value": 15, "type": "minutes"}
                },
            }
        ]
    }
    caps = MsGraphConnector()._map_conditional_access(payload)
    assert len(caps) == 1
    assert caps[0].odp_key == "inactivity_period"
    assert caps[0].value == "15 minutes"
    assert caps[0].nist_id == "3.1.10"


def test_graph_ignores_disabled_policies() -> None:
    payload = {"value": [{"state": "disabled", "sessionControls": {}}]}
    assert MsGraphConnector()._map_conditional_access(payload) == []


# ── Per-org credential resolution (IA-05) ────────────────────────────────────

_MSGRAPH_SECRET = {"tenant_id": "tenant-1", "client_id": "client-1", "client_secret": "topsecret"}


def test_msgraph_is_configured_requires_full_credential() -> None:
    assert MsGraphConnector(credential=None).is_configured() is False
    assert MsGraphConnector(credential={"tenant_id": "t"}).is_configured() is False
    assert MsGraphConnector(credential=_MSGRAPH_SECRET).is_configured() is True


def test_aws_is_configured_requires_credential_and_feature_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # boto3 may not be installed in this environment; isolate the credential
    # logic under test from that separate concern.
    monkeypatch.setattr(AwsGovCloudConnector, "_boto3_available", lambda self: True)

    monkeypatch.delenv("CCF_AWS_CAPTURE_ENABLED", raising=False)
    get_settings.cache_clear()
    cred = {"access_key_id": "AKIA...", "secret_access_key": "shh"}
    assert AwsGovCloudConnector(credential=cred).is_configured() is False  # feature flag off

    monkeypatch.setenv("CCF_AWS_CAPTURE_ENABLED", "true")
    get_settings.cache_clear()
    try:
        assert AwsGovCloudConnector(credential=None).is_configured() is False
        assert AwsGovCloudConnector(credential={}).is_configured() is False
        assert AwsGovCloudConnector(credential=cred).is_configured() is True
        assert AwsGovCloudConnector(credential={"profile": "org-profile"}).is_configured() is True
    finally:
        monkeypatch.delenv("CCF_AWS_CAPTURE_ENABLED", raising=False)
        get_settings.cache_clear()


# ── DB-backed: encrypted storage + collection attribution ───────────────────

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
    """Deterministic suite: don't leak bound credentials / snapshots across tests."""
    async with session_scope() as s:
        await s.execute(delete(CaptureSnapshot).where(CaptureSnapshot.organization_id.in_(org_ids)))
        await s.execute(delete(ConnectorConfig).where(ConnectorConfig.organization_id.in_(org_ids)))


async def test_set_credential_encrypts_and_masks() -> None:
    org_id = await _org("connector-cipher-org")
    try:
        async with session_scope() as s:
            cfg = await credentials.set_credential(s, org_id, "msgraph", _MSGRAPH_SECRET)
            assert cfg.encrypted_credential
            assert "topsecret" not in cfg.encrypted_credential
            assert cfg.key_last4
        # persisted as ciphertext
        async with session_scope() as s:
            row = (
                await s.execute(
                    select(ConnectorConfig).where(
                        ConnectorConfig.organization_id == org_id,
                        ConnectorConfig.connector_type == "msgraph",
                    )
                )
            ).scalar_one()
            assert "topsecret" not in (row.encrypted_credential or "")
    finally:
        await _cleanup(org_id)


async def test_resolve_credential_roundtrips() -> None:
    org_id = await _org("connector-roundtrip-org")
    try:
        async with session_scope() as s:
            await credentials.set_credential(s, org_id, "msgraph", _MSGRAPH_SECRET)
        async with session_scope() as s:
            cred = await credentials.resolve_credential(s, org_id, "msgraph")
        assert cred == _MSGRAPH_SECRET
    finally:
        await _cleanup(org_id)


async def test_resolve_credential_refuses_without_org_binding() -> None:
    org_id = await _org("connector-unbound-org")
    try:
        async with session_scope() as s:
            assert await credentials.resolve_credential(s, org_id, "msgraph") is None
            assert await credentials.resolve_credential(s, None, "msgraph") is None
    finally:
        await _cleanup(org_id)


async def test_resolve_credential_never_leaks_across_orgs() -> None:
    org_a = await _org("connector-org-a")
    org_b = await _org("connector-org-b")
    try:
        async with session_scope() as s:
            await credentials.set_credential(s, org_a, "msgraph", _MSGRAPH_SECRET)
        async with session_scope() as s:
            assert await credentials.resolve_credential(s, org_a, "msgraph") == _MSGRAPH_SECRET
            # org_b has no bound row -> None, never org_a's credential.
            assert await credentials.resolve_credential(s, org_b, "msgraph") is None
    finally:
        await _cleanup(org_a, org_b)


async def test_collect_for_org_refuses_and_writes_nothing_without_credential() -> None:
    org_id = await _org("connector-noconfig-org")
    try:
        async with session_scope() as s:
            result = await collection.collect_for_org(s, org_id)
        assert result["connectors_run"] == []
        assert set(result["not_configured"]) == {"msgraph", "aws_govcloud"}
        assert result["captured"] == 0
        async with session_scope() as s:
            rows = (
                await s.execute(
                    select(CaptureSnapshot).where(CaptureSnapshot.organization_id == org_id)
                )
            ).scalars().all()
        assert rows == []
    finally:
        await _cleanup(org_id)


async def test_collect_for_org_attributes_snapshot_to_credentialed_org(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_a = await _org("connector-capture-org-a")
    org_b = await _org("connector-capture-org-b")

    async def fake_capture(self: MsGraphConnector) -> list[CapturedParameter]:
        return [
            CapturedParameter(
                odp_key="mfa_enforced", value="required", nist_id="3.5.3", source="mock"
            )
        ]

    monkeypatch.setattr(MsGraphConnector, "capture", fake_capture)

    try:
        async with session_scope() as s:
            await credentials.set_credential(s, org_a, "msgraph", _MSGRAPH_SECRET)

        # org_a: has its own bound credential -> captures, snapshot attributed to org_a.
        async with session_scope() as s:
            result_a = await collection.collect_for_org(s, org_a)
        assert result_a["captured"] == 1
        assert "msgraph" in result_a["connectors_run"]
        async with session_scope() as s:
            snap = (
                await s.execute(
                    select(CaptureSnapshot).where(
                        CaptureSnapshot.organization_id == org_a,
                        CaptureSnapshot.connector == "msgraph",
                    )
                )
            ).scalar_one()
            assert snap.value == "required"

        # org_b: no bound credential -> refused, nothing written under its identity.
        async with session_scope() as s:
            result_b = await collection.collect_for_org(s, org_b)
        assert result_b["captured"] == 0
        assert "msgraph" in result_b["not_configured"]
        async with session_scope() as s:
            rows_b = (
                await s.execute(
                    select(CaptureSnapshot).where(CaptureSnapshot.organization_id == org_b)
                )
            ).scalars().all()
        assert rows_b == []
    finally:
        await _cleanup(org_a, org_b)


async def test_collect_all_scheduler_path_only_touches_orgs_with_bound_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_a = await _org("connector-scheduler-org-a")
    org_b = await _org("connector-scheduler-org-b")

    async def fake_capture(self: MsGraphConnector) -> list[CapturedParameter]:
        return [
            CapturedParameter(
                odp_key="mfa_enforced", value="required", nist_id="3.5.3", source="mock"
            )
        ]

    monkeypatch.setattr(MsGraphConnector, "capture", fake_capture)

    try:
        async with session_scope() as s:
            await credentials.set_credential(s, org_a, "msgraph", _MSGRAPH_SECRET)

        # Scheduler path: no org_id -> fan out only to orgs with a bound credential.
        async with session_scope() as s:
            result = await collection.collect_all(s)

        assert org_a in result["organizations_processed"]
        assert org_b not in result["organizations_processed"]
        assert any(entry == f"{org_a}:msgraph" for entry in result["connectors_run"])

        async with session_scope() as s:
            snap = (
                await s.execute(
                    select(CaptureSnapshot).where(
                        CaptureSnapshot.organization_id == org_a,
                        CaptureSnapshot.connector == "msgraph",
                    )
                )
            ).scalar_one()
            assert snap.value == "required"
            # never attributed to org_b or to no org at all (a "global" identity).
            rows_b = (
                await s.execute(
                    select(CaptureSnapshot).where(CaptureSnapshot.organization_id == org_b)
                )
            ).scalars().all()
            assert rows_b == []
    finally:
        await _cleanup(org_a, org_b)
