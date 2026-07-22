"""Unit tests for the GRC operating-system layer (module wiring + constants),
plus production-path org-scoping tests for the audit-findings route.
"""

from __future__ import annotations

import os

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.api.routes.grc import _MOCK_DISCOVERY, CONNECTOR_TYPES
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, User
from ccf.models_grc import (
    AuditEngagement,
    ConnectorConfig,
    ControlTest,
    RegulatoryUpdate,
    TrustProfile,
)


def test_ten_connector_types_all_have_mock_volumes() -> None:
    assert len(CONNECTOR_TYPES) == 10
    for t in CONNECTOR_TYPES:
        assert t in _MOCK_DISCOVERY
        assert _MOCK_DISCOVERY[t] > 0
    # Government clouds are represented.
    assert {"azure_gov", "m365_gcc_high", "aws_govcloud"} <= set(CONNECTOR_TYPES)


def test_models_map_to_expected_tables() -> None:
    assert TrustProfile.__tablename__ == "trust_profiles"
    assert AuditEngagement.__tablename__ == "audit_engagements"
    assert ConnectorConfig.__tablename__ == "connector_configs"
    assert ControlTest.__tablename__ == "control_tests"
    assert RegulatoryUpdate.__tablename__ == "regulatory_updates"


def test_engagement_has_request_and_finding_relationships() -> None:
    assert hasattr(AuditEngagement, "requests")
    assert hasattr(AuditEngagement, "findings")


# --- add_finding org-scoping (production HTTP path) --------------------------
#
# Org B's engagement id must not be attachable to a finding attributed to org A
# just because the caller happens to know the id: add_finding previously only
# null-checked the engagement before stamping the finding's organization_id
# from it, so a scoped caller who guessed/discovered another org's engagement
# id could attach a finding with mismatched org attribution.


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _mk_admin(email: str, org_name: str) -> tuple[str, int]:
    async with session_scope() as s:
        org = Organization(name=org_name)
        s.add(org)
        await s.flush()
        user = User(
            email=email,
            organization_id=org.id,
            role="admin",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        await s.flush()
        return user.api_token, org.id


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
@pytest.mark.usefixtures("fresh_engine")
async def test_add_finding_rejects_cross_org_engagement() -> None:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    try:
        token_a, _org_a = await _mk_admin("a@grc-findings-org-a.example", "GRC Findings Org A")
        token_b, _org_b = await _mk_admin("b@grc-findings-org-b.example", "GRC Findings Org B")

        async with _client() as c:
            eng_b = await c.post(
                "/api/audit/engagements",
                json={"name": "Org B engagement"},
                headers=_auth(token_b),
            )
            assert eng_b.status_code == 201, eng_b.text
            eng_b_id = eng_b.json()["id"]

            # Org A tries to attach a finding to org B's engagement.
            r = await c.post(
                f"/api/audit/engagements/{eng_b_id}/findings",
                json={"title": "Cross-org attempt", "severity": "high"},
                headers=_auth(token_a),
            )
            assert r.status_code == 404, r.text

            # Org A's own engagement still works.
            eng_a = await c.post(
                "/api/audit/engagements",
                json={"name": "Org A engagement"},
                headers=_auth(token_a),
            )
            eng_a_id = eng_a.json()["id"]
            ok = await c.post(
                f"/api/audit/engagements/{eng_a_id}/findings",
                json={"title": "Legit finding", "severity": "high"},
                headers=_auth(token_a),
            )
            assert ok.status_code == 201, ok.text
    finally:
        os.environ.pop("CCF_AUTH_ENABLED", None)
        os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
        get_settings.cache_clear()
