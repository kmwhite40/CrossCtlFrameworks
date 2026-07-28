"""Integration tests for the enterprise layer: posture, audit trail, OSCAL SSP."""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from ccf.api.audit import _redact, row_hash
from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import AuditLog, Organization, ScoringStatus, System

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _fresh_system(name: str = "PostureSys") -> int:
    async with session_scope() as s:
        org = (
            await s.execute(select(Organization).where(Organization.name == "PostureOrg"))
        ).scalar_one_or_none()
        if org is None:
            org = Organization(name="PostureOrg")
            s.add(org)
            await s.flush()
        sys = (
            await s.execute(
                select(System).where(System.organization_id == org.id, System.name == name)
            )
        ).scalar_one_or_none()
        if sys is None:
            sys = System(organization_id=org.id, name=name, baseline="moderate")
            s.add(sys)
            await s.flush()
        await s.execute(delete(ScoringStatus).where(ScoringStatus.system_id == sys.id))
        return sys.id


@pytest.mark.asyncio
async def test_posture_summary_reflects_live_sprs() -> None:
    async with _client() as c:
        await c.post("/api/scoring/seed")
        sid = await _fresh_system()
        matrix = (await c.get(f"/api/scoring/systems/{sid}/matrix")).json()
        for row in matrix["controls"]:
            await c.put(
                f"/api/scoring/systems/{sid}/controls/{row['control_id']}",
                json={"state": "implemented"},
            )

        summary = (await c.get("/api/posture/summary")).json()
        assert summary["systems_total"] >= 1
        assert summary["avg_sprs_score"] is not None
        # The fully-implemented system should score 110 and surface in the scorecard.
        card = next(c for c in summary["systems"] if c["system_id"] == sid)
        assert card["sprs_score"] == 110
        assert card["controls_assessed"] == 110
        assert set(summary["evidence"]) >= {"fresh", "expiring_soon", "expired"}
        assert set(summary["poam_aging"]["buckets"]) == {
            "0-30",
            "31-60",
            "61-90",
            "90+",
            "unknown",
        }


@pytest.mark.asyncio
async def test_audit_trail_records_mutations() -> None:
    async with _client() as c:
        r = await c.post(
            "/api/ssp/projects",
            json={"customer_name": "AuditCo"},
            headers={"X-Actor": "tester@example.com"},
        )
        assert r.status_code == 201
        # The mutation is the most recent audit entry, attributed to the actor.
        latest = (await c.get("/api/audit")).json()[0]
        assert latest["actor"] == "tester@example.com"
        assert latest["action"] == "create"
        assert latest["entity_type"] == "ssp"
        assert latest["diff"]["method"] == "POST"
        assert latest["diff"]["path"] == "/api/ssp/projects"

        # Read requests are never audited — the latest entry is unchanged after a GET.
        await c.get("/api/posture/summary")
        assert (await c.get("/api/audit")).json()[0]["diff"]["path"] == "/api/ssp/projects"


def test_audit_redaction_and_hash_chain_helpers() -> None:
    # Sensitive keys are redacted recursively.
    red = _redact(
        {"password": "p", "nested": {"api_token": "t", "ok": 1}, "list": [{"secret": "s"}]}
    )
    assert red["password"] == "***"
    assert red["nested"]["api_token"] == "***" and red["nested"]["ok"] == 1
    assert red["list"][0]["secret"] == "***"
    # row_hash is deterministic and chains on the previous hash.
    payload = {"actor": "a", "action": "create", "entity_type": "x"}
    assert row_hash("0" * 64, payload) == row_hash("0" * 64, payload)
    assert row_hash("0" * 64, payload) != row_hash("f" * 64, payload)


@pytest.mark.asyncio
async def test_audit_chain_verifies_and_detects_tampering() -> None:
    async with _client() as c:
        await c.post("/api/scoring/seed")
        await c.post("/api/ssp/projects", json={"customer_name": "ChainCo"})

        assert (await c.get("/api/audit/verify")).json()["ok"] is True
        # Request body is captured into the audit diff.
        latest = (await c.get("/api/audit")).json()[0]
        assert latest["diff"].get("body", {}).get("customer_name") == "ChainCo"

        # Tamper with a chained row's content → the chain no longer verifies.
        async with session_scope() as s:
            row = (
                await s.execute(
                    select(AuditLog)
                    .where(AuditLog.row_hash.is_not(None))
                    .order_by(AuditLog.id.desc())
                    .limit(1)
                )
            ).scalar_one()
            row_id, original_actor = row.id, row.actor
            row.actor = "evil@attacker.test"
        try:
            verdict = (await c.get("/api/audit/verify")).json()
            assert verdict["ok"] is False and verdict["broken_at_id"] is not None
        finally:
            # Restore original content so the chain (and the next run) stays valid.
            async with session_scope() as s:
                row = (
                    await s.execute(select(AuditLog).where(AuditLog.id == row_id))
                ).scalar_one()
                row.actor = original_actor


@pytest.mark.asyncio
async def test_oscal_ssp_export_shape() -> None:
    async with _client() as c:
        await c.post("/api/scoring/seed")
        pid = (
            await c.post(
                "/api/ssp/projects",
                json={"customer_name": "OscalCo", "platform": "aws_govcloud"},
            )
        ).json()["id"]

        # security-sensitivity-level is sourced from the project's own
        # fips199.overall metadata (the same field the docx SSP's "Security
        # Categorization" section renders) — not a hardcoded constant. Set it
        # so the assertion below is meaningful.
        meta_resp = await c.put(
            f"/api/ssp/projects/{pid}/metadata",
            json={
                "metadata_json": {"fips199": {"overall": "moderate"}},
                "autofill": False,
            },
        )
        assert meta_resp.status_code == 200, meta_resp.text

        doc = (await c.get(f"/api/oscal/ssp/{pid}")).json()
        ssp = doc["system-security-plan"]
        assert ssp["metadata"]["oscal-version"].startswith("1.1")
        assert ssp["system-characteristics"]["security-sensitivity-level"] == "moderate"
        reqs = ssp["control-implementation"]["implemented-requirements"]
        assert len(reqs) == 110
        # OSCAL control-id/statement-id are the `token` datatype (must start
        # with a letter/underscore) — the bare NIST SP 800-171 requirement
        # number "3.1.1" starts with a digit, so it is sanitized to "_3.1.1"
        # rather than emitted verbatim (which would be schema-invalid).
        assert reqs[0]["control-id"] == "_3.1.1"
        assert reqs[0]["statements"]
        assert (await c.get("/api/oscal/ssp/999999")).status_code == 404

        # A project with no fips199 metadata gets a clearly-marked placeholder,
        # never the old false "cui" constant.
        pid2 = (
            await c.post("/api/ssp/projects", json={"customer_name": "NoMetaCo"})
        ).json()["id"]
        doc2 = (await c.get(f"/api/oscal/ssp/{pid2}")).json()
        sysc2 = doc2["system-security-plan"]["system-characteristics"]
        level2 = sysc2["security-sensitivity-level"]
        assert level2 != "cui"
        assert "UNSPECIFIED" in level2
