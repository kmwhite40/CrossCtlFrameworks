"""Snapshots of Certification Data aligned to Ongoing Certification Reports (CDS-CSO-HAD).

Filing a valid OCR snapshots every valid deliverable as it stands; the snapshot
outlives later overwrites, cannot be altered or removed, and is served to
grant holders as JSON and Markdown with one digest.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from datetime import UTC, date, datetime
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select, text, update
from sqlalchemy.exc import DBAPIError

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.cr26 import snapshots
from ccf.cr26.ocr import seed_ocr
from ccf.cr26.store import put_document
from ccf.db import session_scope
from ccf.models import Organization, System, User
from ccf.models_cr26 import (
    CertificationSnapshot,
    CertificationSnapshotDocument,
    CertificationSnapshotFiling,
    Cr26Document,
)
from ccf.models_portal import ExternalAccessGrant, ExternalPortalAuditEvent
from ccf.portal import certification

pytestmark = pytest.mark.usefixtures("fresh_engine")

S = CertificationSnapshot
SD = CertificationSnapshotDocument
SF = CertificationSnapshotFiling
Q3 = (date(2026, 7, 1), date(2026, 9, 30))
Q4 = (date(2026, 10, 1), date(2026, 12, 31))
TODAY = date(2026, 11, 5)
SDR_V1 = {"securityDecisions": [{"practiceId": "KSI-IAM-MFA", "decision": "v1"}]}
SDR_V2 = {"securityDecisions": [{"practiceId": "KSI-IAM-MFA", "decision": "v2"}]}


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


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


class World:
    def __init__(self) -> None:
        self.ids: dict[str, int] = {}
        self.admin: dict[str, str] = {}


async def _world() -> World:
    w = World()
    tag = uuid.uuid4().hex[:8]
    async with session_scope() as s:
        org = Organization(name=f"had-{tag}")
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"Snap {tag}", baseline="moderate")
        other = System(organization_id=org.id, name=f"Other {tag}", baseline="moderate")
        s.add_all([sysm, other])
        await s.flush()
        admin = User(
            email=f"admin-{tag}@csp.example",
            organization_id=org.id,
            role="admin",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(admin)
        await s.flush()
        w.ids.update(org=org.id, system=sysm.id, other=other.id)
        w.admin = {"Authorization": f"Bearer {admin.api_token}"}
    return w


async def _live(org: int, system: int, kind: str, document: dict[str, Any], *, valid: bool) -> None:
    """A deliverable written directly, as step 1's tests do, so its validity is
    the test's choice rather than the schema's."""
    async with session_scope() as s:
        row = (
            await s.execute(
                select(Cr26Document).where(
                    Cr26Document.system_id == system,
                    Cr26Document.kind == kind,
                    Cr26Document.document_key.is_(None),
                )
            )
        ).scalar_one_or_none()
        if row is None:
            row = Cr26Document(organization_id=org, system_id=system, kind=kind)
            s.add(row)
        row.document = document
        row.ruleset_version = "2026.10.13.01"
        row.schema_version = "0.1.1"
        row.is_valid = valid
        row.validation_errors = [] if valid else ["<root>: draft"]


async def _file_ocr(
    system: int, period: tuple[date, date], *, changes: list[str] | None = None
) -> None:
    """Author the OCR's human fields, then seed it for the period: valid."""
    async with session_scope() as s:
        await put_document(
            s,
            system_id=system,
            kind="ocr",
            document={
                "certificationPackageOverviewUri": "https://example.gov/cpo.json",
                "certificationDataChanges": changes or [],
                "plannedCertificationDataChanges": {
                    "planningHorizonThrough": "2027-06-01",
                    "changes": [],
                },
                "transformativeChanges": [],
                "updatedRecommendations": [],
                "activeAgencies": [],
                "reportableIncidents": {"incidents": []},
            },
            updated_by="isso@csp.example",
        )
    async with session_scope() as s:
        result = await seed_ocr(
            s, system_id=system, period_from=period[0], period_to=period[1], today=TODAY
        )
        assert result.document.is_valid, result.document.validation_errors


async def _snaps(system: int) -> list[CertificationSnapshot]:
    async with session_scope() as s:
        return list(
            (await s.execute(select(S).where(S.system_id == system).order_by(S.id))).scalars()
        )


async def _docs(snapshot_id: int) -> dict[str, dict[str, Any]]:
    async with session_scope() as s:
        rows = (await s.execute(select(SD).where(SD.snapshot_id == snapshot_id))).scalars()
        return {r.kind: r.document for r in rows}


# ── taking snapshots ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_valid_ocr_snapshots_the_valid_deliverables_and_names_the_rest() -> None:
    w = await _world()
    await _live(w.ids["org"], w.ids["system"], "sdr", SDR_V1, valid=True)
    await _live(w.ids["org"], w.ids["system"], "cpo", {"draft": True}, valid=False)
    await _file_ocr(w.ids["system"], Q3)
    snaps = await _snaps(w.ids["system"])
    assert len(snaps) == 1
    snap = snaps[0]
    assert (snap.ocr_period_from, snap.ocr_period_to) == Q3
    assert snap.basis == "ocr_filed"
    assert snap.withheld_invalid == [{"kind": "cpo", "document_key": None}]
    docs = await _docs(snap.id)
    assert set(docs) == {"sdr", "ocr"}
    assert docs["sdr"] == SDR_V1
    async with session_scope() as s:
        ocr = (
            await s.execute(select(SD).where(SD.snapshot_id == snap.id, SD.kind == "ocr"))
        ).scalar_one()
    assert ocr.sha256 == certification.digest(ocr.document) == snap.ocr_sha256


@pytest.mark.asyncio
async def test_an_invalid_ocr_takes_no_snapshot() -> None:
    w = await _world()
    async with session_scope() as s:
        await put_document(s, system_id=w.ids["system"], kind="ocr", document={"partial": True})
    assert await _snaps(w.ids["system"]) == []


@pytest.mark.asyncio
async def test_storing_the_same_ocr_again_adds_nothing() -> None:
    w = await _world()
    await _file_ocr(w.ids["system"], Q3)
    async with session_scope() as s:
        live = (
            await s.execute(
                select(Cr26Document).where(
                    Cr26Document.system_id == w.ids["system"], Cr26Document.kind == "ocr"
                )
            )
        ).scalar_one()
        document = dict(live.document)
    async with session_scope() as s:
        await put_document(s, system_id=w.ids["system"], kind="ocr", document=document)
    (snap,) = await _snaps(w.ids["system"])
    async with session_scope() as s:
        filings = (await s.execute(select(SF).where(SF.snapshot_id == snap.id))).scalars().all()
    assert len(filings) == 2  # filed twice, copied once


@pytest.mark.asyncio
async def test_an_earlier_quarter_survives_the_live_documents_changing() -> None:
    w = await _world()
    await _live(w.ids["org"], w.ids["system"], "sdr", SDR_V1, valid=True)
    await _file_ocr(w.ids["system"], Q3)
    await _live(w.ids["org"], w.ids["system"], "sdr", SDR_V2, valid=True)
    await _file_ocr(w.ids["system"], Q4)
    first, second = await _snaps(w.ids["system"])
    assert (await _docs(first.id))["sdr"] == SDR_V1
    assert (await _docs(second.id))["sdr"] == SDR_V2
    assert (second.ocr_period_from, second.ocr_period_to) == Q4


# ── kept for the duration of certification ───────────────────────────────


@pytest.mark.asyncio
async def test_no_role_can_alter_or_remove_a_snapshot() -> None:
    """On an unscoped (superuser) session: the trigger refuses, not a REVOKE."""
    w = await _world()
    await _live(w.ids["org"], w.ids["system"], "sdr", SDR_V1, valid=True)
    await _file_ocr(w.ids["system"], Q3)
    (snap,) = await _snaps(w.ids["system"])
    attempts = [
        update(S).where(S.id == snap.id).values(basis="backfill"),
        delete(S).where(S.id == snap.id),
        update(SD).where(SD.snapshot_id == snap.id).values(document={"rewritten": True}),
        delete(SD).where(SD.snapshot_id == snap.id),
        update(SF).where(SF.snapshot_id == snap.id).values(filed_by="someone else"),
        delete(SF).where(SF.snapshot_id == snap.id),
        text("TRUNCATE ccf.certification_snapshot_filings"),
        text("TRUNCATE ccf.certification_snapshot_documents"),
        text("TRUNCATE ccf.certification_snapshots CASCADE"),
    ]
    for stmt in attempts:
        with pytest.raises(DBAPIError, match="append-only"):
            async with session_scope() as s:
                await s.execute(stmt)


@pytest.mark.asyncio
async def test_the_application_role_may_only_read_and_add() -> None:
    async with session_scope() as s:
        for table in (
            "certification_snapshots",
            "certification_snapshot_documents",
            "certification_snapshot_filings",
        ):
            privs = {
                p: (
                    await s.execute(
                        text("SELECT has_table_privilege('ccf_app', :t, :p)"),
                        {"t": f"ccf.{table}", "p": p},
                    )
                ).scalar_one()
                for p in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")
            }
            assert privs == {
                "SELECT": True,
                "INSERT": True,
                "UPDATE": False,
                "DELETE": False,
                "TRUNCATE": False,
            }, table


# ── serving them ─────────────────────────────────────────────────────────


async def _grant(c: AsyncClient, w: World, systems: list[int]) -> str:
    r = await c.post(
        "/api/admin/portal/grants",
        json={
            "organization_id": w.ids["org"],
            "principal_name": "Department of Examples",
            "kind": "agency",
            "certification_system_ids": systems,
        },
        headers=w.admin,
    )
    assert r.status_code == 200, r.text
    return str(r.json()["token"])


@pytest.mark.asyncio
async def test_a_grant_holder_gets_each_quarter_and_corrections_are_marked(
    _auth_enabled: None,
) -> None:
    w = await _world()
    await _live(w.ids["org"], w.ids["system"], "sdr", SDR_V1, valid=True)
    await _file_ocr(w.ids["system"], Q3)
    await _file_ocr(w.ids["system"], Q3, changes=["Corrected after filing."])
    await _file_ocr(w.ids["other"], Q3)  # not shared
    async with _client() as c:
        token = await _grant(c, w, [w.ids["system"]])
        bearer = {"Authorization": f"Bearer {token}"}
        listing = (await c.get("/api/portal/certification-data/snapshots", headers=bearer)).json()
        snaps = listing["snapshots"]
        assert {s["system_id"] for s in snaps} == {w.ids["system"]}
        newest, original = snaps
        assert (newest["current"], original["current"]) == (True, False)
        assert (newest["superseded"], original["superseded"]) == (False, True)
        sdr = next(d for d in original["documents"] if d["kind"] == "sdr")
        as_json = await c.get(sdr["json_url"], headers=bearer)
        as_md = await c.get(sdr["markdown_url"], headers=bearer)
        session = await c.get("/api/portal/session", headers=bearer)
    assert as_json.status_code == 200
    assert as_json.json()["document"] == SDR_V1
    assert as_json.headers["x-content-sha256"] == sdr["sha256"] == certification.digest(SDR_V1)
    assert as_md.headers["x-content-sha256"] == sdr["sha256"]
    assert f"Snapshot:** {original['id']}" in as_md.text
    assert sdr["sha256"] in as_md.text
    assert "2026-07-01 to 2026-09-30" in as_md.text
    assert session.json()["certification_data"]["snapshots"]["total"] == 2


@pytest.mark.asyncio
async def test_a_snapshot_outside_the_grant_is_refused_and_logged(_auth_enabled: None) -> None:
    w = await _world()
    await _file_ocr(w.ids["other"], Q3)
    (other_snap,) = await _snaps(w.ids["other"])
    async with _client() as c:
        token = await _grant(c, w, [w.ids["system"]])
        bearer = {"Authorization": f"Bearer {token}"}
        r = await c.get(
            f"/api/portal/certification-data/snapshots/{other_snap.id}/ocr", headers=bearer
        )
        fmt = await c.get(
            f"/api/portal/certification-data/snapshots/{other_snap.id}/ocr",
            params={"format": "pdf"},
            headers=bearer,
        )
    assert r.status_code == 404
    assert fmt.status_code == 422
    async with session_scope() as s:
        denied = (
            (
                await s.execute(
                    select(ExternalPortalAuditEvent.target_id).where(
                        ExternalPortalAuditEvent.organization_id == w.ids["org"],
                        ExternalPortalAuditEvent.action == "denied",
                    )
                )
            )
            .scalars()
            .all()
        )
    assert f"snapshot/{other_snap.id}/ocr" in denied


@pytest.mark.asyncio
async def test_a_deleted_systems_snapshots_are_withheld(_auth_enabled: None) -> None:
    w = await _world()
    await _file_ocr(w.ids["system"], Q3)
    (snap,) = await _snaps(w.ids["system"])
    async with _client() as c:
        token = await _grant(c, w, [w.ids["system"]])
        bearer = {"Authorization": f"Bearer {token}"}
        async with session_scope() as s:
            sysm = await s.get(System, w.ids["system"])
            assert sysm is not None
            sysm.deleted_at = datetime.now(UTC)
        listing = await c.get("/api/portal/certification-data/snapshots", headers=bearer)
        one = await c.get(f"/api/portal/certification-data/snapshots/{snap.id}/ocr", headers=bearer)
    assert listing.json()["snapshots"] == []
    assert one.status_code == 404


@pytest.mark.asyncio
async def test_a_grant_naming_another_tenants_system_sees_none_of_its_snapshots() -> None:
    """A grant whose scope was written to name another tenant's system.

    This proves the behaviour, not the ``organization_id`` pins in
    ``list_for_grant``/``get_document``: both bind the session to the grant's
    tenant first, so RLS already hides the other tenant's rows, and deleting
    either pin leaves this test green (verified by mutation). The pins stay as
    defence in depth behind RLS, like step 1's in ``certification.get_document``.
    """
    mine, theirs = await _world(), await _world()
    await _file_ocr(theirs.ids["system"], Q3)
    (snap,) = await _snaps(theirs.ids["system"])
    grant = ExternalAccessGrant(
        organization_id=mine.ids["org"],
        kind="agency",
        token=uuid.uuid4().hex,
        scope={"certification_system_ids": [theirs.ids["system"]]},
    )
    async with session_scope() as s:
        found = await snapshots.get_document(
            s, grant, snapshot_id=snap.id, kind="ocr", document_key=None
        )
        listed = await snapshots.list_for_grant(s, grant)
    assert found is None
    assert listed["snapshots"] == [] and listed["total"] == 0


# ── the independent review's findings ────────────────────────────────────


async def _listing(c: AsyncClient, token: str, **params: Any) -> dict[str, Any]:
    r = await c.get(
        "/api/portal/certification-data/snapshots",
        params=params,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text
    out: dict[str, Any] = r.json()
    return out


@pytest.mark.asyncio
async def test_a_reverted_report_reads_as_current_again(_auth_enabled: None) -> None:
    """A, then a corrected B, then A again: A is current, B is superseded."""
    w = await _world()
    await _file_ocr(w.ids["system"], Q3)
    await _file_ocr(w.ids["system"], Q3, changes=["Corrected."])
    await _file_ocr(w.ids["system"], Q3)
    a, b = await _snaps(w.ids["system"])
    async with _client() as c:
        token = await _grant(c, w, [w.ids["system"]])
        listed = {x["id"]: x for x in (await _listing(c, token))["snapshots"]}
    assert len(listed) == 2  # A was not copied twice
    assert listed[a.id]["current"] is True and listed[b.id]["superseded"] is True


@pytest.mark.asyncio
async def test_changed_deliverables_under_an_unchanged_report_are_snapshotted() -> None:
    w = await _world()
    await _live(w.ids["org"], w.ids["system"], "sdr", SDR_V1, valid=True)
    await _file_ocr(w.ids["system"], Q3)
    await _live(w.ids["org"], w.ids["system"], "sdr", SDR_V2, valid=True)
    await _file_ocr(w.ids["system"], Q3)  # byte-identical OCR
    first, second = await _snaps(w.ids["system"])
    assert first.ocr_sha256 == second.ocr_sha256
    assert (await _docs(first.id))["sdr"] == SDR_V1
    assert (await _docs(second.id))["sdr"] == SDR_V2
    assert first.content_sha256 != second.content_sha256


@pytest.mark.asyncio
async def test_the_listing_is_paginated(_auth_enabled: None) -> None:
    w = await _world()
    await _file_ocr(w.ids["system"], Q3)
    await _file_ocr(w.ids["system"], Q4)
    async with _client() as c:
        token = await _grant(c, w, [w.ids["system"]])
        first = await _listing(c, token, limit=1)
        second = await _listing(c, token, limit=1, offset=1)
        huge = await _listing(c, token, limit=100000)
    assert first["total"] == second["total"] == 2
    assert len(first["snapshots"]) == len(second["snapshots"]) == 1
    assert first["snapshots"][0]["id"] != second["snapshots"][0]["id"]
    assert huge["limit"] == snapshots.MAX_PAGE


@pytest.mark.asyncio
async def test_a_system_with_snapshots_cannot_be_hard_deleted(_auth_enabled: None) -> None:
    w = await _world()
    await _file_ocr(w.ids["system"], Q3)
    async with _client() as c:
        r = await c.delete(
            f"/api/systems/{w.ids['system']}", params={"hard": "true"}, headers=w.admin
        )
        soft = await c.delete(f"/api/systems/{w.ids['system']}", headers=w.admin)
    assert r.status_code == 409 and "snapshots" in r.json()["detail"]
    assert soft.status_code == 204
    assert len(await _snaps(w.ids["system"])) == 1


@pytest.mark.asyncio
async def test_a_grantee_learns_how_many_drafts_were_withheld_not_which(
    _auth_enabled: None,
) -> None:
    """Parity with the live listing: a count. A withheld incident report's key
    would tell an agency an incident exists that the provider has not filed."""
    w = await _world()
    async with session_scope() as s:
        s.add(
            Cr26Document(
                organization_id=w.ids["org"],
                system_id=w.ids["system"],
                kind="incident",
                document_key="INC-7/initial",
                document={"draft": True},
                ruleset_version="2026.10.13.01",
                schema_version="0.1.1",
                is_valid=False,
                validation_errors=["<root>: draft"],
            )
        )
    await _file_ocr(w.ids["system"], Q3)
    async with _client() as c:
        token = await _grant(c, w, [w.ids["system"]])
        listing = await _listing(c, token)
        page = await c.get("/api/portal/session", headers={"Authorization": f"Bearer {token}"})
    (snap,) = listing["snapshots"]
    assert snap["withheld_invalid"] == 1
    assert "INC-7" not in str(listing) and "INC-7" not in page.text
