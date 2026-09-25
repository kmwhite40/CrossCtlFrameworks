"""Real capture has to write the columns the mock used to fabricate.

Only the development mock ever set ``objects_discovered``,
``evidence_produced``, ``last_sync`` and ``controls_impacted``. Removing its
invented values left the genuine path unable to set them at all, so a
connector that really captured showed "0 objects discovered" forever.

That matters beyond the tile: ``connector_backing_state`` requires
``objects_discovered > 0`` to return ``current``, and ``current`` is what
permits an SSP statement to claim evidence from automated capture. A number
that lied had been replaced with one that could never be true.
"""

from __future__ import annotations

import uuid
from datetime import date

import pytest
from sqlalchemy import select

from ccf.connectors.base import CapturedParameter
from ccf.db import session_scope
from ccf.governance.collection import collect_for_org
from ccf.governance.control_tests import connector_backing_state
from ccf.models import Organization
from ccf.models_grc import ConnectorConfig

pytestmark = pytest.mark.usefixtures("fresh_engine")


async def _org_with_connector() -> tuple[int, int]:
    tag = uuid.uuid4().hex[:8]
    async with session_scope() as s:
        org = Organization(name=f"Capture Org {tag}")
        s.add(org)
        await s.flush()
        cfg = ConnectorConfig(
            organization_id=org.id,
            name="msgraph",
            connector_type="msgraph",
            status="pending",
            encrypted_credential="ciphertext-placeholder",
        )
        s.add(cfg)
        await s.flush()
        return org.id, cfg.id


@pytest.fixture
def _capturing_connector(monkeypatch: pytest.MonkeyPatch):
    """A msgraph connector that is configured and returns two parameters."""
    from ccf.connectors.msgraph import MsGraphConnector

    async def _capture(self):
        return [
            CapturedParameter(
                odp_key="inactivity_period", value="8 hours", nist_id="3.1.10"
            ),
            CapturedParameter(odp_key="mfa_enforced", value="required", nist_id="3.5.3"),
        ]

    # Credential resolution is stubbed rather than exercised: these assertions
    # are about what `collect_for_org` records after a capture, and decrypting
    # a real envelope would need a master key this module has no reason to
    # configure. `tests/test_connector_credential_ui.py` covers the cipher.
    async def _resolve(session, org_id, connector_type):
        return {"tenant_id": "t", "client_id": "c", "client_secret": "s"}

    import ccf.governance.collection as collection

    monkeypatch.setattr(collection, "resolve_credential", _resolve)
    monkeypatch.setattr(MsGraphConnector, "is_configured", lambda self: True)
    monkeypatch.setattr(MsGraphConnector, "capture", _capture)
    yield


@pytest.mark.asyncio
async def test_capture_records_what_it_produced(_capturing_connector) -> None:
    org_id, cfg_id = await _org_with_connector()
    async with session_scope() as s:
        out = await collect_for_org(s, org_id)
    assert out["captured"] == 2

    async with session_scope() as s:
        cfg = await s.get(ConnectorConfig, cfg_id)
        assert cfg.objects_discovered == 2, "a real capture still reported nothing"
        assert cfg.evidence_produced == 2
        assert cfg.last_sync is not None
        assert cfg.status == "configured"


@pytest.mark.asyncio
async def test_controls_impacted_comes_from_the_parameters_actually_returned(
    _capturing_connector,
) -> None:
    """The page says "sync populates these as captures map to controls", and
    nothing in the codebase wrote the column at all."""
    org_id, cfg_id = await _org_with_connector()
    async with session_scope() as s:
        await collect_for_org(s, org_id)

    async with session_scope() as s:
        cfg = await s.get(ConnectorConfig, cfg_id)
        assert cfg.controls_impacted == ["3.1.10", "3.5.3"]


@pytest.mark.asyncio
async def test_a_real_capture_earns_the_backing_state_an_ssp_claim_needs(
    _capturing_connector,
) -> None:
    """`current` is the only rung that permits "evidenced by automated
    capture". Before this it was reachable only by the mock."""
    org_id, cfg_id = await _org_with_connector()
    async with session_scope() as s:
        cfg = await s.get(ConnectorConfig, cfg_id)
        assert connector_backing_state(cfg, date.today(), 7) != "current"

    async with session_scope() as s:
        await collect_for_org(s, org_id)

    async with session_scope() as s:
        cfg = await s.get(ConnectorConfig, cfg_id)
        assert connector_backing_state(cfg, date.today(), 7) == "current"


@pytest.mark.asyncio
async def test_a_connector_with_no_credential_records_nothing() -> None:
    """The guard is about what capture produced, not about writing regardless.

    Without this, setting the columns unconditionally would pass every
    assertion above while reinstating the defect the mock had.
    """
    tag = uuid.uuid4().hex[:8]
    async with session_scope() as s:
        org = Organization(name=f"No Cred Org {tag}")
        s.add(org)
        await s.flush()
        cfg = ConnectorConfig(
            organization_id=org.id,
            name="msgraph",
            connector_type="msgraph",
            status="pending",
        )
        s.add(cfg)
        await s.flush()
        org_id, cfg_id = org.id, cfg.id

    async with session_scope() as s:
        out = await collect_for_org(s, org_id)
    assert "msgraph" in out["not_configured"]

    async with session_scope() as s:
        cfg = await s.get(ConnectorConfig, cfg_id)
        assert cfg.objects_discovered == 0
        assert cfg.last_sync is None
        assert cfg.controls_impacted == []
