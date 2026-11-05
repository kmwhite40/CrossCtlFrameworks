"""FedRAMP Certification Data through the portal (CDS-TRC-PAC, -HMR, -CBF).

An agency grant covering a system can list and fetch that system's CR26
deliverables by token, as JSON or as Markdown generated from the same JSON.
Drafts that fail FedRAMP's schema, other systems, and deleted systems are
not served, and every attempt is logged.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf import portal
from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, System, User
from ccf.models_cr26 import Cr26Document
from ccf.models_portal import ExternalPortalAuditEvent
from ccf.portal import certification

pytestmark = pytest.mark.usefixtures("fresh_engine")

SDR = {
    "certificationPackageOverviewUri": "https://csp.example/cpo.json",
    "securityDecisions": [
        {"practiceId": "KSI-IAM-MFA", "decision": "Phishing-resistant MFA everywhere"},
        {"practiceId": "KSI-CNA-RNT", "decision": "Default-deny egress", "verified": True},
    ],
    "summary": {"owner": "ISSO", "nested": {"depth": 3}},
}


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


async def _doc(
    org: int,
    system: int,
    kind: str,
    *,
    valid: bool = True,
    key: str | None = None,
    document: dict[str, Any] | None = None,
) -> None:
    async with session_scope() as s:
        s.add(
            Cr26Document(
                organization_id=org,
                system_id=system,
                kind=kind,
                document_key=key,
                document=document if document is not None else {"kind": kind, "key": key},
                ruleset_version="2026.10.13.01",
                schema_version="0.1.1",
                is_valid=valid,
                validation_errors=[] if valid else ["<root>: draft"],
            )
        )


class World:
    def __init__(self) -> None:
        self.ids: dict[str, int] = {}
        self.admin: dict[str, str] = {}


async def _world() -> World:
    w = World()
    tag = uuid.uuid4().hex[:8]
    async with session_scope() as s:
        org = Organization(name=f"cds-{tag}")
        s.add(org)
        await s.flush()
        shared = System(organization_id=org.id, name=f"Shared {tag}", certification_class="C")
        other = System(organization_id=org.id, name=f"Other {tag}")
        s.add_all([shared, other])
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
        w.ids.update(org=org.id, shared=shared.id, other=other.id)
        w.admin = {"Authorization": f"Bearer {admin.api_token}"}
    await _doc(w.ids["org"], w.ids["shared"], "sdr", document=SDR)
    await _doc(w.ids["org"], w.ids["shared"], "vdr", valid=False)
    await _doc(w.ids["org"], w.ids["shared"], "incident", key="INC-1/initial")
    await _doc(w.ids["org"], w.ids["other"], "sdr")
    return w


async def _grant(c: AsyncClient, w: World, **kw: Any) -> str:
    body = {
        "organization_id": w.ids["org"],
        "principal_name": "Department of Examples",
        "kind": "agency",
        "certification_system_ids": [w.ids["shared"]],
        **kw,
    }
    r = await c.post("/api/admin/portal/grants", json=body, headers=w.admin)
    assert r.status_code == 200, r.text
    return str(r.json()["token"])


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _events(org: int) -> list[tuple[str, str | None]]:
    async with session_scope() as s:
        rows = (
            (
                await s.execute(
                    select(ExternalPortalAuditEvent)
                    .where(
                        ExternalPortalAuditEvent.organization_id == org,
                        ExternalPortalAuditEvent.target_type == "certification_data",
                    )
                    .order_by(ExternalPortalAuditEvent.id)
                )
            )
            .scalars()
            .all()
        )
    return [(e.action, e.target_id) for e in rows]


# ── listing ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_an_agency_lists_only_valid_documents_of_its_systems(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        token = await _grant(c, w)
        r = await c.get("/api/portal/certification-data", headers=_bearer(token))
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["systems"] == [w.ids["shared"]]
    assert sorted((d["kind"], d["document_key"]) for d in out["documents"]) == [
        ("incident", "INC-1/initial"),
        ("sdr", None),
    ]
    assert out["withheld_invalid"] == 1  # the draft VDR, said out loud
    sdr = next(d for d in out["documents"] if d["kind"] == "sdr")
    assert sdr["title"] == "Security Decision Record"
    assert sdr["sha256"] == certification.digest(SDR)
    assert sdr["json_url"] == f"/api/portal/certification-data/{w.ids['shared']}/sdr"


@pytest.mark.asyncio
async def test_the_session_and_the_page_carry_the_same_listing(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        token = await _grant(c, w)
        sess = await c.get("/api/portal/session", headers=_bearer(token))
        mint = await c.get("/portal", params={"token": token}, follow_redirects=False)
        page = await c.get(mint.headers["location"], cookies=mint.cookies)
    kinds = {d["kind"] for d in sess.json()["certification_data"]["documents"]}
    assert kinds == {"sdr", "incident"}
    assert "FedRAMP Certification Data" in page.text
    assert "Security Decision Record" in page.text
    assert "1 draft document not yet valid" in page.text


@pytest.mark.asyncio
async def test_a_grant_without_certification_scope_lists_nothing(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        token = await _grant(c, w, certification_system_ids=[])
        r = await c.get("/api/portal/certification-data", headers=_bearer(token))
    assert r.json() == {"systems": [], "documents": [], "withheld_invalid": 0}


# ── one document ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_json_is_the_stored_document_with_its_digest(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        token = await _grant(c, w)
        r = await c.get(
            f"/api/portal/certification-data/{w.ids['shared']}/sdr", headers=_bearer(token)
        )
    assert r.status_code == 200, r.text
    assert r.json()["document"] == SDR
    assert r.headers["x-content-sha256"] == certification.digest(SDR)
    assert ("download", f"{w.ids['shared']}/sdr") in await _events(w.ids["org"])


def _leaves(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [x for v in value.values() for x in _leaves(v)]
    if isinstance(value, list):
        return [x for v in value for x in _leaves(v)]
    if isinstance(value, bool):
        return ["Yes" if value else "No"]
    return [str(value)]


@pytest.mark.asyncio
async def test_markdown_says_everything_the_json_does_and_names_its_digest(
    _auth_enabled: None,
) -> None:
    w = await _world()
    async with _client() as c:
        token = await _grant(c, w)
        r = await c.get(
            f"/api/portal/certification-data/{w.ids['shared']}/sdr",
            params={"format": "md"},
            headers=_bearer(token),
        )
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/markdown")
    md = r.text
    assert md.startswith("# Security Decision Record: Shared ")
    assert certification.digest(SDR) in md
    assert r.headers["x-content-sha256"] == certification.digest(SDR)
    for leaf in _leaves(SDR):
        assert leaf in md, leaf
    for label in ("Security Decisions 1", "Security Decisions 2", "Practice Id", "Nested"):
        assert label in md, label


@pytest.mark.asyncio
async def test_a_keyed_document_needs_its_key(_auth_enabled: None) -> None:
    w = await _world()
    path = f"/api/portal/certification-data/{w.ids['shared']}/incident"
    async with _client() as c:
        token = await _grant(c, w)
        keyed = await c.get(path, params={"key": "INC-1/initial"}, headers=_bearer(token))
        bare = await c.get(path, headers=_bearer(token))
    assert keyed.status_code == 200
    assert keyed.json()["document_key"] == "INC-1/initial"
    assert bare.status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("which", "kind"),
    [("shared", "vdr"), ("other", "sdr"), ("shared", "common"), ("shared", "nonsense")],
)
async def test_out_of_scope_invalid_or_unknown_answers_404_and_is_logged(
    _auth_enabled: None, which: str, kind: str
) -> None:
    w = await _world()
    async with _client() as c:
        token = await _grant(c, w)
        r = await c.get(
            f"/api/portal/certification-data/{w.ids[which]}/{kind}", headers=_bearer(token)
        )
    assert r.status_code == 404
    assert ("denied", f"{w.ids[which]}/{kind}") in await _events(w.ids["org"])


@pytest.mark.asyncio
async def test_an_unknown_format_is_refused(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        token = await _grant(c, w)
        r = await c.get(
            f"/api/portal/certification-data/{w.ids['shared']}/sdr",
            params={"format": "xml"},
            headers=_bearer(token),
        )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_no_token_or_a_revoked_one_gets_nothing(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        token = await _grant(c, w)
        assert (await c.get("/api/portal/certification-data")).status_code == 401
        grants = await c.get(
            "/api/admin/portal/grants", params={"organization_id": w.ids["org"]}, headers=w.admin
        )
        gid = grants.json()[0]["id"]
        r = await c.post(f"/api/admin/portal/grants/{gid}/revoke", headers=w.admin)
        assert r.status_code == 200, r.text
        after = await c.get("/api/portal/certification-data", headers=_bearer(token))
    assert after.status_code == 401


@pytest.mark.asyncio
async def test_a_system_deleted_after_issue_stops_being_served(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        token = await _grant(c, w)
        async with session_scope() as s:
            sysm = await s.get(System, w.ids["shared"])
            assert sysm is not None
            sysm.deleted_at = datetime.now(UTC)
        listing = await c.get("/api/portal/certification-data", headers=_bearer(token))
        one = await c.get(
            f"/api/portal/certification-data/{w.ids['shared']}/sdr", headers=_bearer(token)
        )
    assert listing.json()["documents"] == []
    assert listing.json()["withheld_invalid"] == 0
    assert one.status_code == 404


# ── issuing ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_grant_cannot_name_another_organizations_system() -> None:
    """The service's own org check, on an unscoped session where RLS cannot mask it."""
    mine, theirs = await _world(), await _world()
    async with session_scope() as s:
        with pytest.raises(ValueError, match="not found in organization"):
            await portal.create_grant(
                s,
                org_id=mine.ids["org"],
                principal_name="Agency",
                kind="agency",
                certification_system_ids=[theirs.ids["shared"]],
            )


@pytest.mark.asyncio
async def test_a_grant_cannot_name_a_deleted_system() -> None:
    w = await _world()
    async with session_scope() as s:
        sysm = await s.get(System, w.ids["shared"])
        assert sysm is not None
        sysm.deleted_at = datetime.now(UTC)
    async with session_scope() as s:
        with pytest.raises(ValueError, match="not found in organization"):
            await portal.create_grant(
                s,
                org_id=w.ids["org"],
                principal_name="Agency",
                kind="agency",
                certification_system_ids=[w.ids["shared"]],
            )


@pytest.mark.asyncio
async def test_an_assessment_credential_shares_only_its_own_systems_data() -> None:
    w = await _world()
    now = datetime.now(UTC)
    async with session_scope() as s:
        firm = await portal.create_principal(
            s, org_id=w.ids["org"], kind="assessor", name="Example 3PAO"
        )
        engagement = await portal.create_engagement(
            s,
            org_id=w.ids["org"],
            system_id=w.ids["shared"],
            assessor_principal_id=firm.id,
            period_from=now,
            period_to=now + timedelta(days=30),
        )
        with pytest.raises(ValueError, match="only its own system"):
            await portal.create_grant(
                s,
                org_id=w.ids["org"],
                principal_name="",
                principal_id=firm.id,
                kind="assessor",
                engagement_id=engagement.id,
                ttl_days=10,
                certification_system_ids=[w.ids["other"]],
            )
        ok = await portal.create_grant(
            s,
            org_id=w.ids["org"],
            principal_name="",
            principal_id=firm.id,
            kind="assessor",
            engagement_id=engagement.id,
            ttl_days=10,
            certification_system_ids=[w.ids["shared"]],
        )
    assert certification.shared_system_ids(ok) == [w.ids["shared"]]


@pytest.mark.asyncio
async def test_the_admin_form_issues_a_certification_grant(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        page = await c.get("/admin/portal", headers=w.admin)
        assert 'name="certification_system_ids"' in page.text
        r = await c.post(
            "/admin/portal/grants",
            data={
                "organization_id": str(w.ids["org"]),
                "principal_name": "Dept of Examples",
                "kind": "agency",
                "ttl_days": "30",
                "certification_system_ids": str(w.ids["shared"]),
            },
            headers=w.admin,
        )
    assert r.status_code == 200, r.text
    async with session_scope() as s:
        from ccf.models_portal import ExternalAccessGrant  # noqa: PLC0415

        grant = (
            (
                await s.execute(
                    select(ExternalAccessGrant)
                    .where(ExternalAccessGrant.organization_id == w.ids["org"])
                    .order_by(ExternalAccessGrant.id.desc())
                )
            )
            .scalars()
            .first()
        )
    assert grant is not None and grant.kind == "agency"
    assert certification.shared_system_ids(grant) == [w.ids["shared"]]


def test_every_deliverable_kind_has_a_title() -> None:
    from ccf.cr26.store import DELIVERABLE_KINDS  # noqa: PLC0415

    assert set(DELIVERABLE_KINDS) <= set(certification.KIND_TITLES)


def test_the_digest_ignores_key_order() -> None:
    assert certification.digest({"a": 1, "b": 2}) == certification.digest({"b": 2, "a": 1})


@pytest.mark.asyncio
async def test_a_stored_non_deliverable_kind_is_never_served(_auth_enabled: None) -> None:
    """``common`` is FedRAMP's shared definitions, not a filing; a row of it that
    reached the table anyway is not certification data."""
    w = await _world()
    await _doc(w.ids["org"], w.ids["shared"], "common")
    async with _client() as c:
        token = await _grant(c, w)
        listing = await c.get("/api/portal/certification-data", headers=_bearer(token))
        one = await c.get(
            f"/api/portal/certification-data/{w.ids['shared']}/common", headers=_bearer(token)
        )
    assert "common" not in {d["kind"] for d in listing.json()["documents"]}
    assert one.status_code == 404


@pytest.mark.asyncio
async def test_a_document_filed_under_another_organization_is_not_served(
    _auth_enabled: None,
) -> None:
    """A row naming the shared system but another tenant: the grant's tenant pins it."""
    w, stranger = await _world(), await _world()
    await _doc(stranger.ids["org"], w.ids["shared"], "ocr")
    async with _client() as c:
        token = await _grant(c, w)
        listing = await c.get("/api/portal/certification-data", headers=_bearer(token))
        one = await c.get(
            f"/api/portal/certification-data/{w.ids['shared']}/ocr", headers=_bearer(token)
        )
    assert "ocr" not in {d["kind"] for d in listing.json()["documents"]}
    assert one.status_code == 404
