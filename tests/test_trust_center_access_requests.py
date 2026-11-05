"""Agency self-service access requests (CDS-TRC-SSM) and denial notice (CDS-UTC-AAD).

A provider publishes a request link; an agency submits through it and gets a
one-time receipt; the provider approves or denies; an approval is claimed once
with the receipt, issuing an ordinary agency grant whose token is shown once;
a denial starts a five-business-day FedRAMP notice clock that reads overdue
when missed.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text, update
from sqlalchemy.exc import IntegrityError

from ccf.api.limiter import limiter
from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, System, User
from ccf.models_cr26 import Cr26Document
from ccf.models_portal import (
    CertificationAccessRequest,
    ExternalAccessGrant,
    ExternalPrincipal,
)
from ccf.portal import requests as svc
from ccf.portal.inventory import access_inventory

pytestmark = pytest.mark.usefixtures("fresh_engine")

R = CertificationAccessRequest


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _fresh_limits() -> Iterator[None]:
    limiter.reset()
    yield
    limiter.reset()


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
        self.h: dict[str, dict[str, str]] = {}
        self.email: dict[str, str] = {}


async def _world() -> World:
    w = World()
    tag = uuid.uuid4().hex[:8]
    async with session_scope() as s:
        org = Organization(name=f"ssm-{tag}")
        s.add(org)
        await s.flush()
        a = System(organization_id=org.id, name=f"Alpha {tag}", certification_class="C")
        b = System(organization_id=org.id, name=f"Beta {tag}", certification_class="C")
        s.add_all([a, b])
        await s.flush()
        for role in ("admin", "viewer", "control_owner"):
            u = User(
                email=f"{role}-{tag}@csp.example",
                organization_id=org.id,
                role=role,
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
            s.add(u)
            w.h[role] = {"Authorization": f"Bearer {u.api_token}"}
            w.email[role] = u.email
        s.add(
            Cr26Document(
                organization_id=org.id,
                system_id=a.id,
                kind="sdr",
                document_key=None,
                document={"kind": "sdr"},
                ruleset_version="2026.10.13.01",
                schema_version="0.1.1",
                is_valid=True,
                validation_errors=[],
            )
        )
        w.ids.update(org=org.id, a=a.id, b=b.id)
    return w


async def _link(c: AsyncClient, w: World, systems: list[str] | None = None) -> str:
    r = await c.post(
        "/api/admin/portal/request-links",
        json={"system_ids": [w.ids[x] for x in (systems or ["a", "b"])], "label": "onboarding"},
        headers=w.h["admin"],
    )
    assert r.status_code == 200, r.text
    url = r.json()["url"]
    return str(url.split("link=", 1)[1])


async def _submit(c: AsyncClient, link: str, **kw: Any) -> Any:
    body = {
        "link": link,
        "agency_name": "Department of Examples",
        "requester_name": "Pat Example",
        "email": "pat@agency.gov",
        "reason": "ATO review",
        **kw,
    }
    return await c.post("/api/portal/access-requests", json=body)


async def _request(c: AsyncClient, w: World, **kw: Any) -> tuple[int, str]:
    link = await _link(c, w)
    r = await _submit(c, link, **kw)
    assert r.status_code == 201, r.text
    receipt = r.json()["receipt"]
    async with session_scope() as s:
        rid = (
            (
                await s.execute(
                    select(R.id).where(R.organization_id == w.ids["org"]).order_by(R.id.desc())
                )
            )
            .scalars()
            .first()
        )
    assert rid is not None
    return int(rid), str(receipt)


def _admin(w: World, path: str) -> str:
    return f"/api/admin/portal/access-requests/{path}"


# ── the pinned rule and the business-day count ────────────────────────────


def test_the_window_and_target_come_from_the_pinned_rule() -> None:
    assert svc.notice_window() == 5
    target = svc.notice_target()
    assert target["name"] == "[CSP] Agency Access Denial"
    assert target["url"].startswith("https://help.fedramp.gov/")


@pytest.mark.parametrize(
    ("start", "due"),
    [
        (date(2026, 11, 6), date(2026, 11, 13)),  # Fri -> next Fri
        (date(2026, 11, 4), date(2026, 11, 11)),  # Wed -> next Wed
        (date(2026, 11, 7), date(2026, 11, 13)),  # Sat -> Fri
        (date(2026, 11, 8), date(2026, 11, 13)),  # Sun -> Fri
    ],
)
def test_business_days_skip_weekends(start: date, due: date) -> None:
    assert svc.add_business_days(start, 5) == due


# ── links ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_link_names_only_this_organizations_live_systems(_auth_enabled: None) -> None:
    w, other = await _world(), await _world()
    async with _client() as c:
        foreign = await c.post(
            "/api/admin/portal/request-links",
            json={"system_ids": [other.ids["a"]]},
            headers=w.h["admin"],
        )
        empty = await c.post(
            "/api/admin/portal/request-links", json={"system_ids": []}, headers=w.h["admin"]
        )
        viewer = await c.post(
            "/api/admin/portal/request-links",
            json={"system_ids": [w.ids["a"]]},
            headers=w.h["viewer"],
        )
    assert (foreign.status_code, empty.status_code, viewer.status_code) == (422, 422, 403)


@pytest.mark.asyncio
async def test_a_withdrawn_link_takes_no_more_requests(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        link = await _link(c, w)
        links = await c.get("/api/admin/portal/request-links", headers=w.h["admin"])
        lid = links.json()[0]["id"]
        r = await c.post(f"/api/admin/portal/request-links/{lid}/revoke", headers=w.h["admin"])
        assert r.status_code == 200
        refused = await _submit(c, link)
        page = await c.get("/portal/request", params={"link": link})
    assert refused.status_code == 404
    assert "not valid" in page.text


# ── submitting ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_request_is_bounded_by_its_link(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        link = await _link(c, w, ["a"])
        outside = await _submit(c, link, system_ids=[w.ids["b"]])
        blank = await _submit(c, link, agency_name="  ")
        bad_mail = await _submit(c, link, email="not-an-address")
        default = await _submit(c, link)
    assert (outside.status_code, blank.status_code, bad_mail.status_code) == (422, 422, 422)
    assert default.status_code == 201
    async with session_scope() as s:
        req = (await s.execute(select(R).where(R.organization_id == w.ids["org"]))).scalar_one()
    assert req.system_ids == [w.ids["a"]]  # defaults to what the link offers


@pytest.mark.asyncio
async def test_one_link_holds_a_bounded_number_of_pending_requests(
    _auth_enabled: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(svc, "MAX_PENDING_PER_LINK", 2)
    w = await _world()
    async with _client() as c:
        link = await _link(c, w)
        codes = [(await _submit(c, link)).status_code for _ in range(3)]
    assert codes == [201, 201, 429]


@pytest.mark.asyncio
async def test_submission_is_audited_as_the_requester(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        rid, _ = await _request(c, w)
    async with session_scope() as s:
        actor = (
            await s.execute(
                text(
                    "SELECT actor FROM ccf.audit_log WHERE entity_type = "
                    "'certification_access_request' AND entity_id = :id AND action = 'create'"
                ),
                {"id": str(rid)},
            )
        ).scalar_one()
    assert actor == "external:pat@agency.gov"


# ── approving and claiming ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_approval_is_claimed_once_and_issues_an_agency_grant(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        rid, receipt = await _request(c, w)
        early = await c.post("/api/portal/access-requests/claim", json={"receipt": receipt})
        ok = await c.post(_admin(w, f"{rid}/approve"), json={"ttl_days": 90}, headers=w.h["admin"])
        again = await c.post(
            _admin(w, f"{rid}/approve"), json={"ttl_days": 90}, headers=w.h["admin"]
        )
        claimed = await c.post("/api/portal/access-requests/claim", json={"receipt": receipt})
        twice = await c.post("/api/portal/access-requests/claim", json={"receipt": receipt})
        status = await c.post("/api/portal/access-requests/status", json={"receipt": receipt})
        token = claimed.json()["token"]
        docs = await c.get(
            "/api/portal/certification-data", headers={"Authorization": f"Bearer {token}"}
        )
    assert early.status_code == 409
    assert "pending, not approved" in early.json()["detail"]
    assert ok.status_code == 200 and ok.json()["status"] == "approved"
    assert again.status_code == 409
    assert claimed.status_code == 200, claimed.text
    assert twice.status_code == 409
    assert status.json()["claimed"] is True and status.json()["claimable"] is False
    assert docs.status_code == 200
    assert set(docs.json()["systems"]) == {w.ids["a"], w.ids["b"]}
    async with session_scope() as s:
        req = await s.get(R, rid)
        assert req is not None and req.grant_id is not None
        grant = await s.get(ExternalAccessGrant, req.grant_id)
        assert grant is not None
        principal = await s.get(ExternalPrincipal, grant.principal_id)
        rows = await access_inventory(s, org_id=w.ids["org"], kind="agency")
    assert grant.kind == "agency"
    assert grant.issued_by == w.email["admin"]  # the approver, not the claimant
    assert principal is not None and principal.organization_name == "Department of Examples"
    assert [r["grant_id"] for r in rows] == [grant.id]


@pytest.mark.asyncio
async def test_approval_can_narrow_but_not_widen(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        link = await _link(c, w, ["a"])
        r = await _submit(c, link)
        receipt = r.json()["receipt"]
        async with session_scope() as s:
            rid = (
                await s.execute(select(R.id).where(R.organization_id == w.ids["org"]))
            ).scalar_one()
        wider = await c.post(
            _admin(w, f"{rid}/approve"),
            json={"ttl_days": 30, "system_ids": [w.ids["a"], w.ids["b"]]},
            headers=w.h["admin"],
        )
        bad_ttl = await c.post(
            _admin(w, f"{rid}/approve"), json={"ttl_days": 0}, headers=w.h["admin"]
        )
        long_ttl = await c.post(
            _admin(w, f"{rid}/approve"), json={"ttl_days": 5000}, headers=w.h["admin"]
        )
        no_ttl = await c.post(_admin(w, f"{rid}/approve"), json={}, headers=w.h["admin"])
    assert (wider.status_code, bad_ttl.status_code, long_ttl.status_code) == (422, 422, 422)
    assert no_ttl.status_code == 422  # Concord does not choose how long access lasts
    assert receipt


@pytest.mark.asyncio
async def test_a_system_deleted_after_approval_issues_nothing(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        rid, receipt = await _request(c, w)
        await c.post(_admin(w, f"{rid}/approve"), json={"ttl_days": 30}, headers=w.h["admin"])
        async with session_scope() as s:
            sysm = await s.get(System, w.ids["b"])
            assert sysm is not None
            sysm.deleted_at = datetime.now(UTC)
        r = await c.post("/api/portal/access-requests/claim", json={"receipt": receipt})
    assert r.status_code == 409
    async with session_scope() as s:
        req = await s.get(R, rid)
    assert req is not None and req.grant_id is None and req.claimed_at is None


@pytest.mark.asyncio
async def test_only_an_admin_of_that_organization_decides(_auth_enabled: None) -> None:
    w, other = await _world(), await _world()
    async with _client() as c:
        rid, _ = await _request(c, w)
        viewer = await c.post(
            _admin(w, f"{rid}/approve"), json={"ttl_days": 30}, headers=w.h["viewer"]
        )
        owner = await c.post(
            _admin(w, f"{rid}/approve"), json={"ttl_days": 30}, headers=w.h["control_owner"]
        )
        foreign = await c.post(
            _admin(w, f"{rid}/deny"), json={"reason": "x"}, headers=other.h["admin"]
        )
    assert (viewer.status_code, owner.status_code, foreign.status_code) == (403, 403, 404)


@pytest.mark.asyncio
async def test_the_service_refuses_another_organizations_request(_auth_enabled: None) -> None:
    """The org predicate itself, on an unscoped session where RLS cannot mask it."""
    w, other = await _world(), await _world()
    async with _client() as c:
        rid, _ = await _request(c, w)
    async with session_scope() as s:
        with pytest.raises(svc.RequestError) as exc:
            await svc.deny(s, rid, org_id=other.ids["org"], actor="x", reason="no")
    assert exc.value.status == 404


# ── denying and the FedRAMP notice ────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_denial_needs_a_reason_and_starts_the_notice_clock(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        rid, receipt = await _request(c, w)
        blank = await c.post(_admin(w, f"{rid}/deny"), json={"reason": " "}, headers=w.h["admin"])
        r = await c.post(
            _admin(w, f"{rid}/deny"), json={"reason": "not a federal agency"}, headers=w.h["admin"]
        )
        status = await c.post("/api/portal/access-requests/status", json={"receipt": receipt})
        claim = await c.post("/api/portal/access-requests/claim", json={"receipt": receipt})
    assert blank.status_code == 422
    assert r.status_code == 200, r.text
    out = r.json()
    decided = datetime.fromisoformat(out["decided_at"])
    assert out["fedramp_notice"] == "due"
    assert out["fedramp_notify_due"] == svc.notice_due(decided).isoformat()
    assert status.json()["decision_reason"] == "not a federal agency"
    assert "decided_by" not in status.json()
    assert claim.status_code == 409


@pytest.mark.asyncio
async def test_an_unfiled_notice_past_its_date_reads_overdue_and_a_late_one_says_so(
    _auth_enabled: None,
) -> None:
    w = await _world()
    async with _client() as c:
        rid, _ = await _request(c, w)
        await c.post(_admin(w, f"{rid}/deny"), json={"reason": "no"}, headers=w.h["admin"])
        async with session_scope() as s:
            await s.execute(
                update(R)
                .where(R.id == rid)
                .values(
                    decided_at=datetime.now(UTC) - timedelta(days=20),
                    fedramp_notify_due=datetime.now(UTC).date() - timedelta(days=10),
                )
            )
        listed = await c.get("/api/admin/portal/access-requests", headers=w.h["admin"])
        page = await c.get("/admin/portal", headers=w.h["admin"])
        filed = await c.post(
            _admin(w, f"{rid}/fedramp-notice"),
            json={"notified_on": datetime.now(UTC).date().isoformat(), "reference": "FR-123"},
            headers=w.h["admin"],
        )
    assert next(x for x in listed.json() if x["id"] == rid)["fedramp_notice"] == "overdue"
    assert "overdue" in page.text
    assert filed.json()["fedramp_notice"] == "filed_late"


@pytest.mark.asyncio
async def test_the_notice_record_is_dated_honestly_and_kept(_auth_enabled: None) -> None:
    w = await _world()
    today = svc.us_today()
    async with _client() as c:
        rid, _ = await _request(c, w)
        approved_id, _ = await _request(c, w)
        await c.post(
            _admin(w, f"{approved_id}/approve"), json={"ttl_days": 30}, headers=w.h["admin"]
        )
        await c.post(_admin(w, f"{rid}/deny"), json={"reason": "no"}, headers=w.h["admin"])

        async def notice(rq: int, on: date, ref: str = "FR-1") -> int:
            r = await c.post(
                _admin(w, f"{rq}/fedramp-notice"),
                json={"notified_on": on.isoformat(), "reference": ref},
                headers=w.h["admin"],
            )
            return r.status_code

        async with session_scope() as s:
            req = await s.get(R, rid)
            assert req is not None and req.decided_at is not None
            denied_on = svc.decision_date(req.decided_at)
        assert await notice(rid, denied_on - timedelta(days=1)) == 422  # before the denial
        assert await notice(rid, today + timedelta(days=1)) == 422  # in the future
        assert await notice(rid, today, " ") == 422
        assert await notice(approved_id, today) == 409  # only denials are reported
        assert await notice(rid, denied_on) == 200
        assert await notice(rid, today, "FR-2") == 409  # the first record stands
    async with session_scope() as s:
        req = await s.get(R, rid)
    assert req is not None and req.fedramp_reference == "FR-1"


@pytest.mark.asyncio
async def test_the_database_holds_each_states_fields() -> None:
    w = await _world()
    base = {
        "organization_id": w.ids["org"],
        "agency_name": "A",
        "requester_name": "B",
        "email": "b@a.gov",
        "system_ids": [w.ids["a"]],
    }
    bad = [
        {
            "status": "denied",
            "decided_at": datetime.now(UTC),
            "decision_reason": " ",
            "fedramp_notify_due": date.today(),
        },
        {"status": "denied", "decided_at": datetime.now(UTC), "decision_reason": "x"},
        {"status": "approved", "decided_at": datetime.now(UTC)},
        {"status": "approved", "decided_at": datetime.now(UTC), "approved_system_ids": [1]},
        {
            "status": "denied",
            "decided_at": datetime.now(UTC),
            "decision_reason": "x",
            "fedramp_notify_due": date.today(),
            "fedramp_notified_on": date.today(),
            "fedramp_reference": "FR-1",
        },
        {"status": "pending", "decided_at": datetime.now(UTC)},
        {"status": "pending", "claimed_at": datetime.now(UTC)},
    ]
    for extra in bad:
        with pytest.raises(IntegrityError):
            async with session_scope() as s:
                s.add(R(receipt_hash=uuid.uuid4().hex, **base, **extra))
                await s.flush()


# ── the pages ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_agency_pages_carry_a_request_to_collected_access(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        link = await _link(c, w)
        form = await c.get("/portal/request", params={"link": link})
        sent = await c.post(
            "/portal/request",
            data={
                "link": link,
                "agency_name": "Dept of Pages",
                "requester_name": "Lee",
                "email": "lee@agency.gov",
                "system_ids": str(w.ids["a"]),
            },
        )
        receipt = sent.text.split('class="portal__secret">', 1)[1].split("<", 1)[0].strip()
        async with session_scope() as s:
            rid = (
                await s.execute(select(R.id).where(R.organization_id == w.ids["org"]))
            ).scalar_one()
        await c.post(_admin(w, f"{rid}/approve"), json={"ttl_days": 30}, headers=w.h["admin"])
        status = await c.post("/portal/request/status", data={"receipt": receipt})
        claimed = await c.post("/portal/request/claim", data={"receipt": receipt})
    assert form.status_code == 200 and "Request access" in form.text
    assert sent.status_code == 200 and "Request sent" in sent.text
    assert "Collect access" in status.text
    assert claimed.status_code == 200 and "/portal?token=" in claimed.text


@pytest.mark.asyncio
async def test_the_admin_page_forms_need_the_admin_role(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        rid, _ = await _request(c, w)
        owner = await c.post(
            f"/admin/portal/access-requests/{rid}/approve",
            data={"organization_id": str(w.ids["org"]), "ttl_days": "30"},
            headers=w.h["control_owner"],
        )
        admin = await c.post(
            f"/admin/portal/access-requests/{rid}/approve",
            data={"organization_id": str(w.ids["org"]), "ttl_days": "30"},
            headers=w.h["admin"],
            follow_redirects=False,
        )
        made = await c.post(
            "/admin/portal/request-links",
            data={"organization_id": str(w.ids["org"]), "system_ids": str(w.ids["a"])},
            headers=w.h["admin"],
        )
    assert owner.status_code == 403
    assert admin.status_code == 303
    assert "Request link created" in made.text and "/portal/request?link=" in made.text


@pytest.mark.asyncio
async def test_approval_refuses_a_system_deleted_since_the_request(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        rid, _ = await _request(c, w)
        async with session_scope() as s:
            sysm = await s.get(System, w.ids["a"])
            assert sysm is not None
            sysm.deleted_at = datetime.now(UTC)
        r = await c.post(_admin(w, f"{rid}/approve"), json={"ttl_days": 30}, headers=w.h["admin"])
    assert r.status_code == 422
    assert "no longer exist" in r.json()["detail"]


def test_claim_locks_the_request_before_deciding() -> None:
    """Two claims racing on one receipt must not both issue a credential: the
    read that decides is ``SELECT ... FOR UPDATE``. Pinned on the source, since a
    race on one connection pool is not deterministic."""
    import inspect  # noqa: PLC0415

    assert "by_receipt(session, receipt, lock=True)" in inspect.getsource(svc.claim)
    assert "with_for_update()" in inspect.getsource(svc.by_receipt)
    # Submissions lock the link, so concurrent ones cannot all pass the caps.
    assert "resolve_link(session, link_token, lock=True)" in inspect.getsource(svc.submit)
    assert "with_for_update()" in inspect.getsource(svc.resolve_link)


# ── the second review's findings ──────────────────────────────────────────


def test_a_monday_evening_eastern_denial_counts_from_monday() -> None:
    """21:00 Eastern on Monday is already Tuesday in UTC; counted from Tuesday
    the deadline would land a day after FedRAMP's."""
    monday_evening_et = datetime(2026, 11, 10, 2, 0, tzinfo=UTC)  # Mon 9 Nov, 21:00 EST
    assert svc.decision_date(monday_evening_et) == date(2026, 11, 9)
    assert svc.notice_due(monday_evening_et) == date(2026, 11, 16)


def test_today_for_overdue_is_the_latest_us_date() -> None:
    late_sunday_utc = datetime(2026, 11, 8, 20, 0, tzinfo=UTC)  # already Monday in Guam
    assert svc.us_today(late_sunday_utc) == date(2026, 11, 9)


@pytest.mark.asyncio
async def test_an_approval_not_collected_in_time_lapses(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        rid, receipt = await _request(c, w)
        await c.post(_admin(w, f"{rid}/approve"), json={"ttl_days": 30}, headers=w.h["admin"])
        async with session_scope() as s:
            await s.execute(
                update(R)
                .where(R.id == rid)
                .values(decided_at=datetime.now(UTC) - svc.CLAIM_WITHIN - timedelta(hours=1))
            )
        status = await c.post("/api/portal/access-requests/status", json={"receipt": receipt})
        claim = await c.post("/api/portal/access-requests/claim", json={"receipt": receipt})
        page = await c.get("/admin/portal", headers=w.h["admin"])
    assert status.json()["claimable"] is False
    assert claim.status_code == 409 and "lapsed" in claim.json()["detail"]
    assert "lapsed" in page.text


@pytest.mark.asyncio
async def test_one_address_holds_a_bounded_number_of_pending_requests(
    _auth_enabled: None,
) -> None:
    w = await _world()
    async with _client() as c:
        link = await _link(c, w)
        codes = [
            (
                await _submit(c, link, email="Same@Agency.gov" if i % 2 else "same@agency.gov")
            ).status_code
            for i in range(svc.MAX_PENDING_PER_EMAIL + 1)
        ]
        other = await _submit(c, link, email="someone.else@agency.gov")
    assert codes == [201] * svc.MAX_PENDING_PER_EMAIL + [429]
    assert other.status_code == 201


@pytest.mark.asyncio
async def test_an_unknown_receipt_is_refused(_auth_enabled: None) -> None:
    async with _client() as c:
        claim = await c.post("/api/portal/access-requests/claim", json={"receipt": "nope"})
        status = await c.post("/api/portal/access-requests/status", json={"receipt": "nope"})
    assert (claim.status_code, status.status_code) == (404, 404)


@pytest.mark.asyncio
async def test_a_narrowed_approval_shares_only_what_was_approved(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        rid, receipt = await _request(c, w)
        r = await c.post(
            _admin(w, f"{rid}/approve"),
            json={"ttl_days": 30, "system_ids": [w.ids["a"]]},
            headers=w.h["admin"],
        )
        assert r.status_code == 200, r.text
        token = (
            await c.post("/api/portal/access-requests/claim", json={"receipt": receipt})
        ).json()["token"]
        docs = await c.get(
            "/api/portal/certification-data", headers={"Authorization": f"Bearer {token}"}
        )
    assert docs.json()["systems"] == [w.ids["a"]]


@pytest.mark.asyncio
async def test_secrets_are_never_cached(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        link = await _link(c, w)
        sent = await _submit(c, link)
        page = await c.get("/portal/request", params={"link": link})
        made = await c.post(
            "/admin/portal/request-links",
            data={"organization_id": str(w.ids["org"]), "system_ids": str(w.ids["a"])},
            headers=w.h["admin"],
        )
        receipt = sent.json()["receipt"]
        async with session_scope() as s:
            rid = (
                (
                    await s.execute(
                        select(R.id).where(R.organization_id == w.ids["org"]).order_by(R.id.desc())
                    )
                )
                .scalars()
                .first()
            )
        await c.post(_admin(w, f"{rid}/approve"), json={"ttl_days": 30}, headers=w.h["admin"])
        claim = await c.post("/api/portal/access-requests/claim", json={"receipt": receipt})
    for resp in (sent, page, made, claim):
        assert resp.headers.get("cache-control") == "no-store", resp.request.url


@pytest.mark.asyncio
async def test_the_notice_shows_when_it_was_recorded(_auth_enabled: None) -> None:
    w = await _world()
    async with _client() as c:
        rid, _ = await _request(c, w)
        await c.post(_admin(w, f"{rid}/deny"), json={"reason": "no"}, headers=w.h["admin"])
        async with session_scope() as s:
            req = await s.get(R, rid)
            assert req is not None and req.decided_at is not None
            on = svc.decision_date(req.decided_at)
        r = await c.post(
            _admin(w, f"{rid}/fedramp-notice"),
            json={"notified_on": on.isoformat(), "reference": "FR-9"},
            headers=w.h["admin"],
        )
    assert r.status_code == 200, r.text
    assert r.json()["fedramp_notice_recorded_at"] is not None
    assert r.json()["fedramp_notified_by"] == w.email["admin"]
