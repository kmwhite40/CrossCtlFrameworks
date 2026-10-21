"""Workstream G -- intel: KEV, the analytics studio, and the cross-system views.

What is pinned here, each the shape of a defect this platform has shipped:

* **Tenant isolation is in the query.** Two organizations, each with a
  distinctively named record of every kind, plus records on a soft-deleted
  system named ``...DELETED...``. Pages are driven through the real auth gate
  on an RLS-bypass session (``_unscoped_session``), so only the page's own
  predicates can keep Bravo's rows off Alpha's page; each page must also show
  Alpha's own record, or an empty page would pass.
* **The studio is an allowlist.** An unknown register or dimension is a 400,
  never an identifier in SQL; every register counts exactly the caller's
  records.
* **KEV failure is loud.** Parsing and fetching use fixtures and
  ``httpx.MockTransport``; nothing here touches the network. A bad feed raises,
  and a failed sync leaves the catalog as it was.
* **The sync is admin-only and audited.**
"""

from __future__ import annotations

import copy
import itertools
import json
import os
from datetime import UTC, date, datetime, timedelta

import httpx
import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.analytics import studio
from ccf.api.deps import get_session
from ccf.api.main import create_app
from ccf.api.routes.ui_intel import collect_issues, norm_control
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import get_session_factory, session_scope, set_session_tenant
from ccf.intel import kev
from ccf.models import (
    POAM,
    AuditLog,
    Control,
    ControlImplementation,
    FedRAMPDependency,
    Organization,
    Risk,
    System,
    Task,
    User,
    Vendor,
)
from ccf.models_enforcement import RemediationPlan
from ccf.models_evidence import EvidenceObject
from ccf.models_grc import AuditEngagement, AuditFinding, ControlTest, ControlTestResult
from ccf.models_program import KevEntry, VendorFinding

pytestmark = pytest.mark.usefixtures("fresh_engine")

#: The one check a remediation provider (m365) handles today.
STALE_KEY = "m365.identity.stale_accounts"

_SEQ = itertools.count()

#: CISA's feed shape (field names as published), with ids that cannot collide
#: with a real CVE.
KEV_FIXTURE: dict = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2099.01.02",
    "dateReleased": "2099-01-02T15:00:00.0000Z",
    "count": 3,
    "vulnerabilities": [
        {
            "cveID": "CVE-2099-0001",
            "vendorProject": "Acme",
            "product": "Gateway",
            "vulnerabilityName": "Acme Gateway Remote Code Execution",
            "dateAdded": "2099-01-01",
            "shortDescription": "An RCE.",
            "requiredAction": "Apply updates.",
            "dueDate": "2099-01-22",
            "knownRansomwareCampaignUse": "Known",
            "notes": "",
            "cwes": ["CWE-94"],
        },
        {
            "cveID": "CVE-2099-0002",
            "vendorProject": "Acme",
            "product": "Portal",
            "vulnerabilityName": "Acme Portal Auth Bypass",
            "dateAdded": "2099-01-02",
            "shortDescription": "A bypass.",
            "requiredAction": "Apply updates.",
            "dueDate": "2099-01-23",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "",
            "cwes": [],
        },
        {
            "cveID": "CVE-2099-0003",
            "vendorProject": "Acme",
            "product": "Agent",
            "vulnerabilityName": "Acme Agent Privilege Escalation",
            "dateAdded": "2099-01-02",
            "shortDescription": "A PE.",
            "requiredAction": "Apply updates.",
            "dueDate": "2099-01-23",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "",
            "cwes": [],
        },
    ],
}


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _auth_enabled():
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


async def _unscoped_session():
    """RLS tenant cleared (bypass): only the page's own predicates scope it."""
    factory = get_session_factory()
    async with factory() as session:
        await set_session_tenant(session, None)
        yield session


def _client() -> AsyncClient:
    app = create_app()
    app.dependency_overrides[get_session] = _unscoped_session
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://t")


def _auth(token: object) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _org(label: str, tag: str) -> dict[str, object]:
    """One organization with a record of every kind, named ``<label>-<kind>-<tag>``,
    and a soft-deleted system carrying the same kinds, named ``...DELETED...``.

    Records whose system is optional (control tests, evidence, tasks) are
    org-wide on the live side, so the org predicate alone must exclude the
    other org's, and on the deleted system, so the live-system predicate must
    exclude them."""
    today = date.today()
    m = lambda kind: f"{label}-{kind}-{tag}"  # noqa: E731
    d = lambda kind: f"{label}-DELETED-{kind}-{tag}"  # noqa: E731
    async with session_scope() as s:
        org = Organization(name=m("org"))
        s.add(org)
        await s.flush()
        users = {
            role: User(
                email=f"{label.lower()}-{role}-{tag}@intel.test",
                organization_id=org.id,
                role=role,
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
            for role in ("admin", "control_owner", "viewer")
        }
        users["admin2"] = User(
            email=f"{label.lower()}-admin2-{tag}@intel.test",
            organization_id=org.id,
            role="admin",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        live = System(organization_id=org.id, name=m("system"), baseline="moderate")
        gone = System(
            organization_id=org.id,
            name=d("system"),
            baseline="moderate",
            deleted_at=datetime.now(UTC),
        )
        ctl_impl = Control(identifier=f"{label}-IMPL-{tag}", control_name="impl")
        ctl_inh = Control(identifier=f"{label}-INH-{tag}", control_name="inherited")
        ctl_gone = Control(identifier=f"{label}-DELETED-CTL-{tag}", control_name="gone")
        vendor = Vendor(organization_id=org.id, name=m("vendor"))
        eng = AuditEngagement(organization_id=org.id, name=m("engagement"), status="fieldwork")
        s.add_all([*users.values(), live, gone, ctl_impl, ctl_inh, ctl_gone, vendor, eng])
        await s.flush()
        ct_live = ControlTest(
            organization_id=org.id,
            system_id=None,
            control_id="AC-2",
            name=m("test"),
            active=True,
            last_status="fail",
        )
        ct_gone = ControlTest(
            organization_id=org.id,
            system_id=gone.id,
            control_id="AC-2",
            name=d("test"),
            active=True,
            last_status="fail",
        )
        s.add_all(
            [
                POAM(
                    system_id=live.id,
                    title=m("poam-kev"),
                    weakness="Remote code execution.\nRefs: CVE-2099-0001, CVE-1999-9999",
                    severity="critical",
                    status="open",
                    source="scan",
                    scanner="nessus",
                    identified_on=today - timedelta(days=5),
                    due_on=today + timedelta(days=30),
                ),
                POAM(
                    system_id=live.id,
                    title=m("poam-plain"),
                    severity="low",
                    status="in_progress",
                    identified_on=today - timedelta(days=50),
                ),
                POAM(
                    system_id=gone.id,
                    title=d("poam"),
                    weakness="Refs: CVE-2099-0001",
                    severity="critical",
                    status="open",
                    source="scan",
                ),
                Risk(system_id=live.id, title=m("risk"), status="open", category="technical"),
                Risk(system_id=gone.id, title=d("risk"), status="open"),
                # 0100: a system-less enterprise risk belongs to its org directly.
                Risk(
                    organization_id=org.id,
                    system_id=None,
                    register="enterprise",
                    title=m("enterprise-risk"),
                    status="open",
                ),
                ControlImplementation(
                    system_id=live.id,
                    control_id=ctl_impl.id,
                    status="implemented",
                    responsibility="customer",
                    owner_user_id=users["admin"].id,
                ),
                ControlImplementation(
                    system_id=live.id,
                    control_id=ctl_inh.id,
                    status="inherited",
                    responsibility="provider",
                ),
                ControlImplementation(
                    system_id=gone.id,
                    control_id=ctl_gone.id,
                    status="inherited",
                    responsibility="inherited",
                ),
                FedRAMPDependency(
                    system_id=live.id,
                    name=m("dep"),
                    provider=m("provider"),
                    fedramp_status="authorized",
                    inherited_controls=[ctl_inh.identifier.lower(), f"{label}-UNREC-{tag}"],
                ),
                FedRAMPDependency(
                    system_id=gone.id,
                    name=d("dep"),
                    inherited_controls=[ctl_gone.identifier],
                ),
                ct_live,
                ct_gone,
                EvidenceObject(organization_id=org.id, title=m("evidence"), status="approved"),
                EvidenceObject(
                    organization_id=org.id, system_id=gone.id, title=d("evidence"), status="draft"
                ),
                Task(organization_id=org.id, title=m("task"), status="open"),
                Task(organization_id=org.id, system_id=gone.id, title=d("task"), status="open"),
                VendorFinding(
                    organization_id=org.id,
                    vendor_id=vendor.id,
                    title=m("vendor-finding"),
                    severity="high",
                    status="open",
                ),
                AuditFinding(
                    engagement_id=eng.id,
                    organization_id=org.id,
                    title=m("audit-finding"),
                    severity="moderate",
                    status="open",
                ),
                AuditFinding(
                    engagement_id=eng.id,
                    organization_id=org.id,
                    system_id=gone.id,
                    title=d("audit-finding"),
                    status="open",
                ),
                RemediationPlan(
                    organization_id=org.id,
                    system_id=live.id,
                    check_key=m("plan"),
                    provider_key="aws",
                    status="pending_approval",
                    requested_by=users["admin"].email,
                ),
                ControlTest(
                    organization_id=org.id,
                    system_id=live.id,
                    control_id="AC-2",
                    name=m("stale-accounts-test"),
                    source="generated",
                    check_key=STALE_KEY,
                    active=True,
                    last_status="fail",
                ),
                RemediationPlan(
                    organization_id=org.id,
                    system_id=gone.id,
                    check_key=d("plan"),
                    provider_key="aws",
                    status="draft",
                ),
            ]
        )
        await s.flush()
        now = datetime.now(UTC)
        s.add_all(
            [
                ControlTestResult(
                    control_test_id=ct_live.id, status="fail", run_at=now - timedelta(days=20)
                ),
                ControlTestResult(
                    control_test_id=ct_live.id, status="pass", run_at=now - timedelta(days=10)
                ),
                ControlTestResult(
                    control_test_id=ct_live.id, status="fail", run_at=now - timedelta(days=7)
                ),
                ControlTestResult(
                    control_test_id=ct_live.id, status="fail", run_at=now - timedelta(days=1)
                ),
                ControlTestResult(control_test_id=ct_gone.id, status="fail"),
            ]
        )
        await s.flush()
        return {
            "org_id": org.id,
            "label": label,
            "tag": tag,
            "live": live.id,
            "token": users["admin"].api_token,
            "owner_token": users["control_owner"].api_token,
            "viewer_token": users["viewer"].api_token,
            "admin2_token": users["admin2"].api_token,
            "admin_email": users["admin"].email,
            "admin2_email": users["admin2"].email,
        }


@pytest.fixture
async def two_orgs() -> tuple[dict[str, object], dict[str, object]]:
    tag = f"{next(_SEQ)}x{os.getpid()}"
    a, b = await _org("Alpha", tag), await _org("Bravo", tag)
    # Defence in depth on remediation plans: a plan that says it is Bravo's is
    # not Alpha's to see, even if it points at Alpha's system.
    async with session_scope() as s:
        s.add(
            RemediationPlan(
                organization_id=b["org_id"],
                system_id=a["live"],
                check_key=f"Bravo-crossed-plan-{tag}",
                provider_key="aws",
                status="draft",
            )
        )
    return a, b


@pytest.fixture
async def kev_catalog():
    async with session_scope() as s:
        await kev.sync_kev(s, copy.deepcopy(KEV_FIXTURE))
    yield


# ── KEV: parsing, fetching (no network), syncing ─────────────────────────────


def test_the_fixture_feed_parses_into_rows() -> None:
    parsed = kev.normalise(kev.parse_kev(json.dumps(KEV_FIXTURE).encode()))
    assert parsed.catalog_version == "2099.01.02"
    assert [r["cve_id"] for r in parsed.rows] == ["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"]
    first = parsed.rows[0]
    assert first["vendor"] == "Acme" and first["product"] == "Gateway"
    assert first["due_date"] == date(2099, 1, 22) and first["date_added"] == date(2099, 1, 1)
    assert first["known_ransomware"] == "Known"
    assert parsed.skipped == []


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda d: d.update(vulnerabilities=[], count=0), "no vulnerabilities"),
        (lambda d: d.pop("vulnerabilities"), "no 'vulnerabilities'"),
        (lambda d: d.update(count=99), "count=99"),
        (lambda d: d.pop("catalogVersion"), "catalogVersion"),
        (lambda d: d.update(vulnerabilities=["x", "y", "z"]), "not an object"),
    ],
)
def test_a_feed_that_is_not_the_schema_is_refused(mutate, message: str) -> None:
    doc = copy.deepcopy(KEV_FIXTURE)
    mutate(doc)
    with pytest.raises(kev.KevFormatError, match=message):
        kev.normalise(doc)


def test_non_json_is_refused() -> None:
    with pytest.raises(kev.KevFormatError, match="not JSON"):
        kev.parse_kev(b"<html>maintenance</html>")


def test_a_malformed_record_is_named_and_the_rest_kept() -> None:
    doc = copy.deepcopy(KEV_FIXTURE)
    doc["vulnerabilities"][1]["cveID"] = "not-a-cve"
    doc["vulnerabilities"][2]["dueDate"] = "soon"
    parsed = kev.normalise(doc)
    assert [r["cve_id"] for r in parsed.rows] == ["CVE-2099-0001"]
    assert any("not a CVE id" in s for s in parsed.skipped)
    assert any("CVE-2099-0003: unreadable date" in s for s in parsed.skipped)


def test_cve_ids_are_read_out_of_text() -> None:
    assert kev.cve_ids("cve-2099-0001 and CVE-2099-0001", "Refs: CVE-2021-44228, x") == [
        "CVE-2099-0001",
        "CVE-2021-44228",
    ]
    assert kev.cve_ids(None, "CVE-21-1", "XCVE-2021-44228") == []


def _transport(handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


async def test_fetch_returns_the_parsed_feed() -> None:
    body = json.dumps(KEV_FIXTURE).encode()
    doc = await kev.fetch_kev(transport=_transport(lambda req: httpx.Response(200, content=body)))
    assert doc["catalogVersion"] == "2099.01.02"


@pytest.mark.parametrize(
    ("handler", "kwargs", "message"),
    [
        (lambda req: httpx.Response(503, content=b"down"), {}, "HTTP 503"),
        (
            lambda req: httpx.Response(200, content=b"x" * 2048),
            {"max_bytes": 1024},
            "byte cap",
        ),
        (
            lambda req: httpx.Response(200, content=b"{}", headers={"content-length": "999999"}),
            {"max_bytes": 1024},
            "byte cap",
        ),
        (
            lambda req: (_ for _ in ()).throw(httpx.ReadTimeout("slow", request=req)),
            {},
            "timed out",
        ),
        (
            lambda req: (_ for _ in ()).throw(httpx.ConnectError("refused", request=req)),
            {},
            "failed",
        ),
    ],
)
async def test_a_failed_fetch_raises_with_its_reason(handler, kwargs, message: str) -> None:
    with pytest.raises(kev.KevFetchError, match=message):
        await kev.fetch_kev(transport=_transport(handler), **kwargs)


async def test_a_redirect_off_cisa_is_refused() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.host == "www.cisa.gov":
            return httpx.Response(302, headers={"location": "https://evil.example/kev.json"})
        return httpx.Response(200, content=json.dumps(KEV_FIXTURE).encode())

    with pytest.raises(kev.KevFetchError, match="not CISA"):
        await kev.fetch_kev(transport=_transport(handler))


async def test_an_empty_feed_from_the_server_is_an_error_not_an_empty_catalog() -> None:
    empty = json.dumps({"catalogVersion": "x", "count": 0, "vulnerabilities": []}).encode()
    with pytest.raises(kev.KevFormatError):
        await kev.fetch_kev(transport=_transport(lambda req: httpx.Response(200, content=empty)))


async def test_sync_upserts_and_drops_what_cisa_withdrew() -> None:
    async with session_scope() as s:
        first = await kev.sync_kev(s, copy.deepcopy(KEV_FIXTURE))
    assert first["total"] == 3
    doc = copy.deepcopy(KEV_FIXTURE)
    doc["catalogVersion"] = "2099.01.03"
    doc["vulnerabilities"] = doc["vulnerabilities"][:2]
    doc["vulnerabilities"][1]["knownRansomwareCampaignUse"] = "Known"
    doc["count"] = 2
    async with session_scope() as s:
        second = await kev.sync_kev(s, doc)
    assert second["removed"] == 1 and second["total"] == 2 and second["added"] == 0
    async with session_scope() as s:
        rows = {e.cve_id: e for e in (await s.execute(select(KevEntry))).scalars()}
        status = await kev.catalog_status(s)
    assert set(rows) == {"CVE-2099-0001", "CVE-2099-0002"}
    assert rows["CVE-2099-0002"].known_ransomware == "Known"
    assert {r.catalog_version for r in rows.values()} == {"2099.01.03"}
    assert status["entries"] == 2 and status["catalog_version"] == "2099.01.03"


async def test_a_skipped_record_is_not_taken_as_withdrawn() -> None:
    async with session_scope() as s:
        await kev.sync_kev(s, copy.deepcopy(KEV_FIXTURE))
    doc = copy.deepcopy(KEV_FIXTURE)
    doc["vulnerabilities"][2]["dueDate"] = "garbled"
    async with session_scope() as s:
        result = await kev.sync_kev(s, doc)
        still = await s.get(KevEntry, "CVE-2099-0003")
    assert result["removed"] == 0 and result["skipped"] == 1
    assert still is not None


# ── KEV: the page, the match, the sync route ─────────────────────────────────


async def test_the_intel_page_shows_the_callers_kev_matches_only(two_orgs, kev_catalog) -> None:
    a, _ = two_orgs
    async with _client() as c:
        resp = await c.get("/intel", headers=_auth(a["token"]))
    assert resp.status_code == 200, resp.text[:400]
    body = resp.text
    assert f"Alpha-poam-kev-{a['tag']}" in body
    assert "CVE-2099-0001" in body and "Known" in body
    assert "CVE-1999-9999" not in body  # named, but not in the catalog
    assert "Bravo" not in body and "DELETED" not in body


async def test_the_match_counts_name_their_denominators(two_orgs, kev_catalog) -> None:
    a, _ = two_orgs
    async with session_scope() as s:
        found = await kev.kev_matches(s, int(a["org_id"]))
    assert found["examined"] == 2  # two open POA&Ms on the live system
    assert found["scan_examined"] == 1
    assert found["with_cve"] == 1
    assert found["poams_matched"] == 1 and found["ransomware"] == 1
    assert [m.entry.cve_id for m in found["matches"]] == ["CVE-2099-0001"]
    # Due 30 days out; CISA's date (2099) is later, so not past it.
    assert found["past_due"] == 0


async def test_without_a_catalog_the_page_does_not_claim_no_matches(two_orgs) -> None:
    a, _ = two_orgs
    async with session_scope() as s:
        await s.execute(KevEntry.__table__.delete())
    async with _client() as c:
        body = (await c.get("/intel", headers=_auth(a["token"]))).text
    assert "No KEV catalog to match against" in body


PLATFORM_ADMIN = "platform-admin@concord.test"


def _platform_client(monkeypatch, *, org_id: int | None = None) -> AsyncClient:
    """A request as an unscoped (platform-wide) admin, or as ``org_id``'s admin.

    A user row always has an organization, so a global principal exists only
    with auth off or as the system; both principal dependencies are overridden
    (``require_*`` reads ``get_principal``, ``get_session`` reads
    ``get_principal_optional``), as ``test_self_assurance_is_a_platform_operation``
    does."""
    from ccf.api.auth_deps import get_principal, get_principal_optional  # noqa: PLC0415
    from ccf.auth import Principal  # noqa: PLC0415

    monkeypatch.setenv("CCF_AUTH_ENABLED", "false")
    get_settings.cache_clear()
    who = Principal(user_id=None, email=PLATFORM_ADMIN, org_id=org_id, role="admin")
    app = create_app()
    app.dependency_overrides[get_principal] = lambda: who
    app.dependency_overrides[get_principal_optional] = lambda: who
    app.dependency_overrides[get_session] = _unscoped_session
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://t")


@pytest.mark.parametrize("who", ["viewer_token", "owner_token", "token"])
async def test_no_tenant_user_may_sync_the_global_catalog(two_orgs, who: str, monkeypatch) -> None:
    """``kev_entries`` is shared by every tenant: a tenant's admin included is refused."""
    a, _ = two_orgs
    called = []

    async def fake_fetch(**_kw):
        called.append(1)
        doc = copy.deepcopy(KEV_FIXTURE)
        doc["vulnerabilities"] = doc["vulnerabilities"][:1]
        doc["count"] = 1
        return doc

    monkeypatch.setattr(kev, "fetch_kev", fake_fetch)
    async with session_scope() as s:
        await kev.sync_kev(s, copy.deepcopy(KEV_FIXTURE))
    async with _client() as c:
        resp = await c.post("/intel/kev/sync", headers=_auth(a[who]))
        page = (await c.get("/intel", headers=_auth(a[who]))).text
    assert resp.status_code == 403
    assert not called
    async with session_scope() as s:
        assert (await kev.catalog_status(s))["entries"] == 3  # unchanged
    assert 'action="/intel/kev/sync"' not in page  # no control offered


async def test_a_tenant_admin_principal_is_refused_too(two_orgs, monkeypatch) -> None:
    """The same refusal for a scoped admin principal reached by the override path."""
    a, _ = two_orgs
    monkeypatch.setattr(kev, "fetch_kev", lambda **_kw: pytest.fail("fetched"))
    async with _platform_client(monkeypatch, org_id=int(a["org_id"])) as c:
        resp = await c.post("/intel/kev/sync")
    assert resp.status_code == 403


async def test_a_platform_admin_sync_writes_the_catalog_and_an_event(monkeypatch) -> None:
    async def fake_fetch(**_kw):
        return copy.deepcopy(KEV_FIXTURE)

    monkeypatch.setattr(kev, "fetch_kev", fake_fetch)
    async with session_scope() as s:
        await s.execute(KevEntry.__table__.delete())
    async with _platform_client(monkeypatch) as c:
        page = (await c.get("/intel")).text
        resp = await c.post("/intel/kev/sync")
    assert 'action="/intel/kev/sync"' in page
    assert resp.status_code == 303 and resp.headers["location"] == "/intel?synced=3"
    async with session_scope() as s:
        assert (await kev.catalog_status(s))["entries"] == 3
        ev = (
            await s.execute(
                select(AuditLog)
                .where(AuditLog.action == "kev_sync", AuditLog.entity_type == "kev_catalog")
                .order_by(AuditLog.id.desc())
                .limit(1)
            )
        ).scalar_one()
    assert ev.actor == PLATFORM_ADMIN
    assert ev.entity_id == "2099.01.02"
    assert ev.organization_id is None


async def test_a_failed_sync_is_surfaced_and_leaves_the_catalog(monkeypatch) -> None:
    async with session_scope() as s:
        await kev.sync_kev(s, copy.deepcopy(KEV_FIXTURE))

    async def broken_fetch(**_kw):
        raise kev.KevFetchError("CISA answered HTTP 503 for the KEV feed")

    monkeypatch.setattr(kev, "fetch_kev", broken_fetch)
    async with _platform_client(monkeypatch) as c:
        resp = await c.post("/intel/kev/sync")
    assert resp.status_code == 502
    assert "The KEV catalog was not refreshed." in resp.text
    assert "HTTP 503" in resp.text
    async with session_scope() as s:
        assert (await kev.catalog_status(s))["entries"] == 3
        failed = (
            await s.execute(select(AuditLog).where(AuditLog.action == "kev_sync_failed").limit(1))
        ).scalar_one_or_none()
    assert failed is not None


# ── the analytics studio ─────────────────────────────────────────────────────

#: Alpha's records in scope per register: live-system or org-wide ones only.
EXPECTED = {
    "poams": 2,
    "risks": 2,
    "test_results": 4,
    "evidence": 1,
    "vendors": 1,
    "tasks": 1,
}


def test_every_register_is_covered_by_the_isolation_test() -> None:
    assert set(EXPECTED) == set(studio.REGISTERS)


@pytest.mark.parametrize("register", sorted(EXPECTED))
async def test_each_register_counts_only_the_callers_live_records(two_orgs, register) -> None:
    a, _ = two_orgs
    reg = studio.REGISTERS[register]
    async with session_scope() as s:
        for d in reg.dimensions:
            result = await studio.run(s, int(a["org_id"]), register, [d.key])
            assert result["total"] == EXPECTED[register], (register, d.key, result["rows"])
        two = await studio.run(
            s, int(a["org_id"]), register, [reg.dimensions[0].key, reg.dimensions[1].key]
        )
    assert two["total"] == EXPECTED[register]
    assert sum(n for _, n in two["by_first"]) == two["total"]


async def test_the_studio_page_shows_the_callers_system_and_not_anothers(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        resp = await c.get(
            "/analytics?register=poams&by=system&then=severity", headers=_auth(a["token"])
        )
    assert resp.status_code == 200, resp.text[:400]
    assert f"Alpha-system-{a['tag']}" in resp.text
    assert "Bravo" not in resp.text and "DELETED" not in resp.text


@pytest.mark.parametrize(
    "query",
    [
        "register=users&by=status",
        "register=poams&by=title",
        "register=poams&by=status;DROP TABLE ccf.poams",
        "register=poams&by=status&then=status",
        "register=vendors&by=system",
        "register=poams&by=",
        "register=poams&by=organization_id",
    ],
)
async def test_an_unknown_register_or_dimension_is_refused(two_orgs, query: str) -> None:
    a, _ = two_orgs
    async with _client() as c:
        resp = await c.get(f"/analytics?{query}", headers=_auth(a["token"]))
    assert resp.status_code == 400, (query, resp.status_code)


def test_resolve_never_returns_anything_outside_the_allowlist() -> None:
    for bad in ("poams.title", "1=1", "status OR 1=1", "System.name"):
        with pytest.raises(studio.StudioError):
            studio.resolve("poams", [bad])


def test_the_chart_names_what_it_leaves_out() -> None:
    reg, dims = studio.resolve("poams", ["system", "status"])
    rows = [{"values": (f"s{i}", f"v{i % 6}"), "n": 1} for i in range(20)]
    result = {
        "register": reg,
        "dimensions": dims,
        "rows": rows,
        "total": 20,
        "by_first": [(f"s{i}", 1) for i in range(20)],
    }
    ch = studio.chart(result)
    assert len(ch["labels"]) == studio.CHART_MAX_COLUMNS
    assert any("12 largest of 20" in n for n in ch["notes"])
    assert any("6 values" in n for n in ch["notes"])
    assert not ch["stacked"]


# ── implementations, inheritance, remediation, issues ────────────────────────

PAGES = (
    "/intel",
    "/analytics",
    "/analytics?register=poams&by=system",
    "/analytics?register=test_results&by=system",
    "/analytics?register=evidence&by=system",
    "/analytics?register=tasks&by=system",
    "/analytics?register=risks&by=system",
    "/implementations",
    "/inheritance",
    "/remediation",
    "/issues",
)


@pytest.mark.parametrize("path", PAGES)
async def test_no_page_shows_another_organizations_records(two_orgs, kev_catalog, path) -> None:
    a, _ = two_orgs
    async with _client() as c:
        resp = await c.get(path, headers=_auth(a["token"]))
    assert resp.status_code == 200, resp.text[:400]
    assert "Bravo" not in resp.text, f"{path} shows Bravo's records to Alpha"
    assert "DELETED" not in resp.text, f"{path} shows a soft-deleted system's records"


@pytest.mark.parametrize(
    ("path", "kind"),
    [
        ("/implementations", "IMPL"),
        ("/implementations", "INH"),
        ("/inheritance", "INH"),
        ("/inheritance", "dep"),
        ("/inheritance", "UNREC"),
        ("/remediation", "plan"),
        ("/issues", "poam-kev"),
        ("/issues", "audit-finding"),
        ("/issues", "vendor-finding"),
        ("/issues", "test"),
    ],
)
async def test_each_page_shows_its_own_organizations_record(two_orgs, path, kind) -> None:
    a, _ = two_orgs
    async with _client() as c:
        body = (await c.get(path, headers=_auth(a["token"]))).text
    assert f"Alpha-{kind}-{a['tag']}" in body, f"{path} does not show the caller's {kind}"


async def test_filtering_by_another_orgs_system_shows_nothing_of_it(two_orgs) -> None:
    a, b = two_orgs
    async with _client() as c:
        impl = (await c.get(f"/implementations?system={b['live']}", headers=_auth(a["token"]))).text
        inh = (await c.get(f"/inheritance?system={b['live']}", headers=_auth(a["token"]))).text
    assert "Bravo" not in impl and "Bravo" not in inh
    assert "No implementation matches these filters" in impl


async def test_implementation_filters_apply(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        body = (await c.get("/implementations?status=inherited", headers=_auth(a["token"]))).text
        unknown = (await c.get("/implementations?status=nonsense", headers=_auth(a["token"]))).text
    assert f"Alpha-INH-{a['tag']}" in body and f"Alpha-IMPL-{a['tag']}" not in body
    # An unknown filter value is ignored, not passed to SQL.
    assert f"Alpha-INH-{a['tag']}" in unknown and f"Alpha-IMPL-{a['tag']}" in unknown


async def test_inheritance_links_a_dependency_by_normalised_control(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        body = (await c.get("/inheritance", headers=_auth(a["token"]))).text
    # The dependency lists the control in lower case; it still provides it.
    assert f"Alpha-provider-{a['tag']}" in body
    assert "No dependency on this system lists this control" not in body


def test_control_identifiers_normalise() -> None:
    assert norm_control("ac-02") == norm_control("AC-2") == "AC-2"
    assert norm_control("AC-2(1)") == "AC-2(1)"
    assert norm_control(" sc-7 ") == "SC-7"
    assert norm_control("AC-0") == "AC-0"


async def test_issues_are_ordered_by_severity_then_age(two_orgs) -> None:
    a, _ = two_orgs
    async with session_scope() as s:
        issues = await collect_issues(s, int(a["org_id"]), date.today())
    titles = [i["title"] for i in issues]
    assert all("Bravo" not in t and "DELETED" not in t for t in titles)
    assert {i["kind"] for i in issues} == {
        "poam",
        "audit_finding",
        "vendor_finding",
        "control_test",
    }
    sevs = [i["severity"] for i in issues]
    assert sevs == ["critical", "high", "moderate", "low", "unrated", "unrated"]
    test = next(i for i in issues if i["kind"] == "control_test")
    # The current failure began 7 days ago (the run after the last pass),
    # not 20 days ago and not at the latest run.
    # (the run timestamps are UTC; ``today`` is the local date the scene used)
    assert test["age"] == (date.today() - (datetime.now(UTC) - timedelta(days=7)).date()).days
    poam = next(i for i in issues if i["title"].endswith(f"poam-plain-{a['tag']}"))
    assert poam["age"] == 50


# ── the CLI and the scheduler step ───────────────────────────────────────────


def test_the_kev_sync_command_is_registered() -> None:
    from typer.testing import CliRunner  # noqa: PLC0415

    from ccf.cli import app  # noqa: PLC0415

    result = CliRunner().invoke(app, ["kev-sync", "--help"])
    assert result.exit_code == 0
    assert "--file" in result.stdout


def test_the_kev_sync_command_fails_loudly_on_a_bad_feed(tmp_path) -> None:
    from typer.testing import CliRunner  # noqa: PLC0415

    from ccf.cli import app  # noqa: PLC0415

    bad = tmp_path / "kev.json"
    bad.write_text(json.dumps({"catalogVersion": "x", "count": 0, "vulnerabilities": []}))
    result = CliRunner().invoke(app, ["kev-sync", "--file", str(bad)])
    assert result.exit_code == 1
    assert "KEV sync failed" in result.stdout


async def test_the_scheduler_step_syncs_once_a_day(monkeypatch) -> None:
    calls = []

    async def fake_fetch(**_kw):
        calls.append(1)
        return copy.deepcopy(KEV_FIXTURE)

    monkeypatch.setattr(kev, "fetch_kev", fake_fetch)
    async with session_scope() as s:
        await s.execute(KevEntry.__table__.delete())
        first = await kev.refresh_kev(s, today=date.today())
    async with session_scope() as s:
        second = await kev.refresh_kev(s, today=date.today())
    assert first["status"] == "synced" and first["total"] == 3
    assert second["status"] == "skipped"
    assert len(calls) == 1


# ── risks after 0100: owned directly or through a live system ────────────────


async def test_the_risk_register_counts_enterprise_risks_by_owner(two_orgs) -> None:
    a, _ = two_orgs
    async with session_scope() as s:
        result = await studio.run(s, int(a["org_id"]), "risks", ["register"])
    assert dict(result["by_first"]) == {"cyber": 1, "enterprise": 1}


# ── /remediation: the plan workflow through the enforcement service ──────────


async def _plan(tag: object, label: str = "Alpha") -> RemediationPlan:
    async with session_scope() as s:
        return (
            await s.execute(
                select(RemediationPlan).where(RemediationPlan.check_key == f"{label}-plan-{tag}")
            )
        ).scalar_one()


async def _set_status(plan_id: int, status: str) -> None:
    async with session_scope() as s:
        plan = await s.get(RemediationPlan, plan_id)
        plan.status = status


@pytest.mark.parametrize("who", ["viewer_token", "owner_token"])
@pytest.mark.parametrize("action", ["approve", "apply", "reverse"])
async def test_only_an_enforcer_may_move_a_plan(two_orgs, who, action) -> None:
    a, _ = two_orgs
    plan = await _plan(a["tag"])
    async with _client() as c:
        resp = await c.post(f"/remediation/{plan.id}/{action}", headers=_auth(a[who]))
    assert resp.status_code == 403
    assert (await _plan(a["tag"])).status == "pending_approval"


@pytest.mark.parametrize("who", ["viewer_token", "owner_token"])
async def test_only_an_enforcer_may_plan(two_orgs, who) -> None:
    a, _ = two_orgs
    async with _client() as c:
        resp = await c.post(
            "/remediation/plans",
            data={"system_id": a["live"], "check_key": STALE_KEY},
            headers=_auth(a[who]),
        )
    assert resp.status_code == 403


@pytest.mark.parametrize("action", ["approve", "apply", "reverse"])
async def test_another_orgs_plan_is_not_found(two_orgs, action) -> None:
    a, b = two_orgs
    theirs = await _plan(b["tag"], "Bravo")
    async with _client() as c:
        resp = await c.post(f"/remediation/{theirs.id}/{action}", headers=_auth(a["token"]))
    assert resp.status_code == 404
    assert (await _plan(b["tag"], "Bravo")).status == "pending_approval"


async def test_the_requester_cannot_approve_and_another_admin_can(two_orgs) -> None:
    a, _ = two_orgs
    plan = await _plan(a["tag"])
    async with _client() as c:
        own = await c.post(f"/remediation/{plan.id}/approve", headers=_auth(a["token"]))
        assert own.status_code == 409
        assert "the requester may not approve their own remediation plan" in own.text
        assert (await _plan(a["tag"])).status == "pending_approval"
        other = await c.post(f"/remediation/{plan.id}/approve", headers=_auth(a["admin2_token"]))
    assert other.status_code == 303
    after = await _plan(a["tag"])
    assert after.status == "approved" and after.approved_by == a["admin2_email"]
    async with session_scope() as s:
        ev = (
            await s.execute(
                select(AuditLog)
                .where(
                    AuditLog.entity_type == "remediation_plan",
                    AuditLog.entity_id == str(plan.id),
                )
                .order_by(AuditLog.id.desc())
                .limit(1)
            )
        ).scalar_one()
    assert ev.actor == a["admin2_email"] and ev.organization_id == a["org_id"]


async def test_the_page_withholds_approval_from_the_requester(two_orgs) -> None:
    a, _ = two_orgs
    plan = await _plan(a["tag"])
    async with _client() as c:
        mine = (await c.get("/remediation", headers=_auth(a["token"]))).text
        theirs = (await c.get("/remediation", headers=_auth(a["admin2_token"]))).text
        owner = (await c.get("/remediation", headers=_auth(a["owner_token"]))).text
    assert f'action="/remediation/{plan.id}/approve"' not in mine
    assert "another administrator must approve" in mine
    assert f'action="/remediation/{plan.id}/approve"' in theirs
    assert "/remediation/plans" not in owner and "/approve" not in owner


async def test_a_refused_apply_is_shown_and_changes_nothing(two_orgs) -> None:
    """No provider handles the scene's check, so the service refuses at apply."""
    a, _ = two_orgs
    plan = await _plan(a["tag"])
    await _set_status(plan.id, "approved")
    async with _client() as c:
        resp = await c.post(f"/remediation/{plan.id}/apply", headers=_auth(a["admin2_token"]))
    assert resp.status_code == 409
    assert "no remediation provider handles check" in resp.text
    assert (await _plan(a["tag"])).status == "approved"


async def test_reversing_a_plan_that_was_not_applied_is_refused(two_orgs) -> None:
    a, _ = two_orgs
    plan = await _plan(a["tag"])
    async with _client() as c:
        resp = await c.post(f"/remediation/{plan.id}/reverse", headers=_auth(a["token"]))
    assert resp.status_code == 409
    assert "plan is not applied" in resp.text


async def test_planning_a_failing_check_stores_the_plan_or_its_refusal(two_orgs) -> None:
    """No write credential exists in the test database, so the service stores
    the plan as refused, with its reason -- through the page as through the API."""
    a, _ = two_orgs
    async with _client() as c:
        page = (await c.get("/remediation", headers=_auth(a["token"]))).text
        resp = await c.post(
            "/remediation/plans",
            data={"system_id": a["live"], "check_key": STALE_KEY},
            headers=_auth(a["token"]),
        )
    assert f"Alpha-stale-accounts-test-{a['tag']}" in page and "Bravo" not in page
    assert resp.status_code == 303
    async with session_scope() as s:
        plan = (
            await s.execute(
                select(RemediationPlan)
                .where(
                    RemediationPlan.system_id == a["live"],
                    RemediationPlan.check_key == STALE_KEY,
                )
                .order_by(RemediationPlan.id.desc())
                .limit(1)
            )
        ).scalar_one()
    assert plan.organization_id == a["org_id"]
    assert plan.requested_by == a["admin_email"]
    assert plan.status == "refused" and "write credential" in (plan.refusal_reason or "")


async def test_planning_on_another_orgs_system_is_not_found(two_orgs) -> None:
    a, b = two_orgs
    async with _client() as c:
        resp = await c.post(
            "/remediation/plans",
            data={"system_id": b["live"], "check_key": STALE_KEY},
            headers=_auth(a["token"]),
        )
    assert resp.status_code == 404
    async with session_scope() as s:
        n = (
            await s.execute(
                select(RemediationPlan).where(
                    RemediationPlan.system_id == b["live"],
                    RemediationPlan.check_key == STALE_KEY,
                )
            )
        ).first()
    assert n is None


async def test_a_check_no_provider_handles_is_refused_with_its_reason(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        resp = await c.post(
            "/remediation/plans",
            data={"system_id": a["live"], "check_key": "nothing.handles.this"},
            headers=_auth(a["token"]),
        )
    assert resp.status_code == 409
    assert "no remediation provider handles check" in resp.text
