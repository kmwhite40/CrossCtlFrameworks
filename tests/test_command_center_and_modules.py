"""The command center and the pages built over records that had no screen.

Three properties, each the shape of a defect this platform has shipped before:

* **Tenant isolation is in the query.** Two organizations, each with one
  distinctively named record of every kind; every page and the record search
  must show the caller's and never the other's. The service is also driven on
  an unscoped session (``session_scope``), so a missing org predicate cannot
  hide behind RLS -- 19 of 38 cross-tenant tests once could not fail for that
  reason.
* **Deleted systems are gone.** Each organization also has a soft-deleted
  system carrying records; none of them may surface.
* **A ratio over nothing is None.** An organization with no POA&Ms, evidence or
  audit requests gets an em dash, not 0% or 100%.
"""

from __future__ import annotations

import itertools
import os
from datetime import UTC, date, datetime, timedelta

import pytest
from alembic import command
from alembic.config import Config
from fastapi.routing import _IncludedRouter
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.analytics.command_center import command_center, ratio
from ccf.api import navigation
from ccf.api.deps import get_session
from ccf.api.main import create_app
from ccf.auth import Principal, hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import get_session_factory, session_scope, set_session_tenant
from ccf.models import (
    POAM,
    Approval,
    Event,
    Notification,
    Organization,
    Policy,
    Risk,
    System,
    Task,
    User,
    Vendor,
)
from ccf.models_evidence import EvidenceObject, EvidenceVersion
from ccf.models_grc import AuditEngagement, AuditRequest

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


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
    """A session with the RLS tenant cleared (bypass), so the only thing that
    can keep Bravo's rows off Alpha's page is the page's own org predicate.
    Through the normal ``get_session`` RLS hides a missing predicate, and a
    page-level isolation test cannot fail -- measured: four deleted predicates
    survived these tests until this override."""
    factory = get_session_factory()
    async with factory() as session:
        await set_session_tenant(session, None)
        yield session


def _client() -> AsyncClient:
    app = create_app()
    app.dependency_overrides[get_session] = _unscoped_session
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://t")


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _org(label: str, tag: str) -> dict[str, object]:
    """One organization with a record of every kind, each named ``<label>-<kind>-<tag>``.

    Also a soft-deleted system carrying a POA&M and a risk, named
    ``<label>-DELETED-...``, which must never appear anywhere."""
    today = date.today()
    m = lambda kind: f"{label}-{kind}-{tag}"  # noqa: E731
    async with session_scope() as s:
        org = Organization(name=m("org"))
        s.add(org)
        await s.flush()
        user = User(
            email=f"{label.lower()}-{tag}@cc.test",
            organization_id=org.id,
            role="admin",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        live = System(organization_id=org.id, name=m("system"), baseline="moderate")
        gone = System(
            organization_id=org.id,
            name=f"{label}-DELETED-system-{tag}",
            baseline="moderate",
            deleted_at=datetime.now(UTC),
        )
        s.add_all([user, live, gone])
        await s.flush()
        s.add_all(
            [
                POAM(
                    system_id=live.id,
                    title=m("poam"),
                    severity="high",
                    status="open",
                    identified_on=today - timedelta(days=3),
                    due_on=today + timedelta(days=10),
                ),
                POAM(
                    system_id=gone.id,
                    title=f"{label}-DELETED-poam-{tag}",
                    severity="critical",
                    status="open",
                    identified_on=today,
                ),
                Risk(
                    system_id=live.id,
                    title=m("risk"),
                    likelihood="high",
                    impact="moderate",
                    status="open",
                    inherent_score=15,
                    residual_score=6,
                    treatment="mitigate",
                ),
                Risk(
                    system_id=live.id,
                    title=m("accepted-risk"),
                    likelihood="low",
                    impact="low",
                    status="accepted",
                    inherent_score=1,
                    residual_score=1,
                    treatment="accept",
                ),
                Risk(
                    system_id=gone.id,
                    title=f"{label}-DELETED-risk-{tag}",
                    likelihood="high",
                    impact="high",
                    status="open",
                    inherent_score=25,
                    residual_score=25,
                ),
                Task(
                    organization_id=org.id,
                    title=m("task"),
                    status="open",
                    priority="high",
                    assignee_user_id=user.id,
                    due_on=today - timedelta(days=1),
                ),
                Event(
                    organization_id=org.id,
                    actor="tester",
                    verb="created",
                    entity_type="poam",
                    summary=m("event"),
                ),
                Notification(
                    organization_id=org.id,
                    category="test",
                    severity="warning",
                    title=m("notification"),
                ),
                Policy(organization_id=org.id, name=m("policy"), status="active"),
                Vendor(organization_id=org.id, name=m("vendor")),
                Approval(
                    organization_id=org.id,
                    entity_type="risk",
                    entity_id=m("approval"),
                    state="submitted",
                ),
            ]
        )
        ev = EvidenceObject(
            organization_id=org.id,
            title=m("evidence"),
            source_type="upload",
            status="approved",
            expires_on=today + timedelta(days=200),
        )
        eng = AuditEngagement(
            organization_id=org.id,
            name=m("audit"),
            status="fieldwork",
            target_on=today + timedelta(days=30),
        )
        s.add_all([ev, eng])
        await s.flush()
        s.add_all(
            [
                EvidenceVersion(
                    evidence_object_id=ev.id,
                    version=1,
                    sha256="0" * 64,
                    size_bytes=1,
                    filename=m("upload"),
                    storage_backend="db",
                    storage_ref="x",
                    uploaded_by="tester",
                ),
                AuditRequest(
                    engagement_id=eng.id,
                    title=m("pbc"),
                    status="open",
                    owner_user_id=user.id,
                    due_on=today + timedelta(days=5),
                ),
                AuditRequest(engagement_id=eng.id, title=m("pbc-done"), status="accepted"),
            ]
        )
        await s.flush()
        return {"org_id": org.id, "token": user.api_token, "label": label, "tag": tag}


@pytest.fixture
async def two_orgs() -> tuple[dict[str, object], dict[str, object]]:
    tag = f"{next(_SEQ)}x{os.getpid()}"
    return await _org("Alpha", tag), await _org("Bravo", tag)


# ── the pure rule ────────────────────────────────────────────────────────────


def test_a_ratio_over_nothing_is_none_not_zero_or_full() -> None:
    assert ratio(0, 0) is None
    assert ratio(5, 0) is None
    assert ratio(0, 4) == 0
    assert ratio(1, 3) == 33
    assert ratio(3, 3) == 100


# ── the service, on an unscoped session ──────────────────────────────────────


async def test_no_organization_means_no_aggregate() -> None:
    async with session_scope() as s:
        cc = await command_center(s, None)
    assert cc["scoped"] is False
    assert "kpis" not in cc


async def test_the_command_center_counts_one_organization_and_only_live_systems(two_orgs) -> None:
    a, _ = two_orgs
    async with session_scope() as s:
        cc = await command_center(s, int(a["org_id"]))
    k = cc["kpis"]
    # One live POA&M (the deleted system's critical one and Bravo's are out).
    assert k["findings"]["open"] == 1
    assert k["findings"]["by_severity"]["critical"] == 0
    # One open risk; the accepted one is not active, the deleted one is gone.
    assert k["risks"]["open"] == 1
    assert cc["risk"]["cells"]["high"]["moderate"] == 1
    assert cc["risk"]["cells"]["high"]["high"] == 0
    assert k["overdue"]["tasks"] == 1
    assert k["audit"]["requests"] == 2 and k["audit"]["accepted"] == 1 and k["audit"]["pct"] == 50
    uploads = [u["filename"] for u in cc["uploads"]]
    assert uploads == [f"Alpha-upload-{a['tag']}"]
    summaries = [e["summary"] for e in cc["activity"]]
    assert f"Alpha-event-{a['tag']}" in summaries
    assert not any("Bravo" in x for x in summaries)
    cards = [c["title"] for col in cc["kanban"] for c in col["cards"]]
    assert cards == [f"Alpha-poam-{a['tag']}"]
    titles = " ".join(str(mm["title"]) for mm in cc["milestones"])
    assert "Bravo" not in titles and "DELETED" not in titles


async def test_an_empty_denominator_renders_as_unanswerable(two_orgs) -> None:
    """No resolved-or-open POA&M, no dated evidence, no audit request: None."""
    async with session_scope() as s:
        org = Organization(name=f"Empty-{next(_SEQ)}x{os.getpid()}")
        s.add(org)
        await s.flush()
        cc = await command_center(s, org.id)
    k = cc["kpis"]
    assert k["remediation"]["pct"] is None
    assert k["evidence"]["pct"] is None
    assert k["audit"]["pct"] is None
    assert k["control_health"]["pct"] is None
    assert k["monitoring"]["pct"] is None


# ── the pages, through the real auth gate ────────────────────────────────────

PAGES = (
    "/dashboard",
    "/gaps",
    "/my-tasks",
    "/notifications",
    "/risks/heatmap",
    "/exceptions",
    "/policies",
    "/control-owners",
    "/vendors",
    "/approvals",
    "/ui/notifications/panel",
)


@pytest.mark.parametrize("path", PAGES)
async def test_no_page_shows_another_organizations_records(two_orgs, path: str) -> None:
    a, _ = two_orgs
    async with _client() as c:
        resp = await c.get(path, headers=_auth(str(a["token"])))
    assert resp.status_code == 200, resp.text[:400]
    body = resp.text
    assert "Bravo" not in body, f"{path} shows Bravo's records to Alpha"
    assert "DELETED" not in body, f"{path} shows a soft-deleted system's records"


@pytest.mark.parametrize(
    ("path", "kind"),
    [
        ("/my-tasks", "task"),
        ("/notifications", "notification"),
        ("/risks/heatmap", "risk"),
        ("/exceptions", "accepted-risk"),
        ("/policies", "policy"),
        ("/vendors", "vendor"),
        ("/approvals", "approval"),
        ("/dashboard", "poam"),
        ("/dashboard", "upload"),
    ],
)
async def test_each_page_shows_its_own_organizations_record(two_orgs, path: str, kind: str) -> None:
    """The isolation test above would pass on an empty page; this one would not."""
    a, _ = two_orgs
    async with _client() as c:
        body = (await c.get(path, headers=_auth(str(a["token"])))).text
    assert f"Alpha-{kind}-{a['tag']}" in body, f"{path} does not show the caller's own {kind}"


async def test_the_heat_map_cell_drills_down_to_its_risks(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        hit = (
            await c.get(
                "/risks/heatmap?likelihood=high&impact=moderate", headers=_auth(str(a["token"]))
            )
        ).text
        miss = (
            await c.get("/risks/heatmap?likelihood=low&impact=high", headers=_auth(str(a["token"])))
        ).text
    assert f"Alpha-risk-{a['tag']}" in hit
    assert f"Alpha-risk-{a['tag']}" not in miss
    assert "No open risks sit in this cell." in miss


async def test_record_search_is_scoped_to_the_callers_organization(two_orgs) -> None:
    a, b = two_orgs
    async with _client() as c:
        resp = await c.get(f"/ui/search?q={b['tag']}", headers=_auth(str(a["token"])))
    assert resp.status_code == 200
    labels = [r["label"] for r in resp.json()["results"]]
    assert labels, "search found nothing at all, so it cannot show scoping"
    assert all(lbl.startswith("Alpha-") for lbl in labels), labels
    kinds = {r["kind"].split(" · ")[0] for r in resp.json()["results"]}
    assert {"System", "Risk", "POA&M", "Evidence", "Policy", "Vendor", "Audit", "Task"} <= kinds
    assert all(
        r["href"].startswith("/") and not r["href"].startswith("//") for r in resp.json()["results"]
    )


async def test_the_notification_badge_counts_the_callers_unread(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        before = (await c.get("/ui/notifications/badge", headers=_auth(str(a["token"])))).text
        await c.post("/api/notifications/read-all", headers=_auth(str(a["token"])))
        after = (await c.get("/ui/notifications/badge", headers=_auth(str(a["token"])))).text
    assert 'aria-label="1 unread">1<' in before
    assert 'aria-label="0 unread"><' in after
    # The fragment re-arms itself: it must keep its own refresh trigger.
    assert 'hx-trigger="notif-changed from:body"' in after


# ── navigation: every entry resolves, every gap is labelled ─────────────────


def _get_paths() -> set[str]:
    """Every GET path the app serves. Included routers are wrapped
    (``_IncludedRouter``), so a walk of ``app.routes`` alone finds nothing --
    hence the floor asserted by the caller."""
    paths: set[str] = set()

    def walk(routes, prefix: str = "") -> None:
        for route in routes:
            if isinstance(route, _IncludedRouter):
                walk(route.original_router.routes, prefix)
                continue
            sub = getattr(route, "routes", None)
            if sub is not None and not getattr(route, "methods", None):
                walk(sub, prefix + (getattr(route, "path", "") or ""))
                continue
            if "GET" in (getattr(route, "methods", set()) or set()):
                paths.add(prefix + (getattr(route, "path", "") or ""))

    walk(create_app().routes)
    return paths


def test_every_navigation_entry_resolves_to_a_route() -> None:
    routes = _get_paths()
    assert len(routes) > 100, f"route walk found only {len(routes)} paths"
    for group, item in navigation.all_items():
        path = item.href.split("#")[0].split("?")[0]
        if item.status is navigation.Status.PLANNED:
            assert item.href == f"/planned/{item.key}", item
            assert "/planned/{slug}" in routes
        else:
            assert path in routes, (
                f"{group.label} > {item.label} links {item.href}, which no route serves"
            )
        for href in item.nearby:
            assert href.split("?")[0] in routes, (
                f"{item.label} suggests {href}, which no route serves"
            )


def test_every_gap_says_what_is_missing() -> None:
    for _, item in navigation.all_items():
        if item.status is not navigation.Status.LIVE:
            assert len(item.note) > 30, f"{item.label} is {item.status} without saying why"


async def test_a_planned_page_says_so_and_an_unknown_one_is_404(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        page = await c.get("/planned/kri", headers=_auth(str(a["token"])))
        missing = await c.get("/planned/not-a-thing", headers=_auth(str(a["token"])))
    assert page.status_code == 200
    assert "Concord does not do this yet" in page.text
    assert "No appetite statement" in page.text
    assert missing.status_code == 404


async def test_an_assignment_across_organizations_shows_no_title(two_orgs) -> None:
    """A task in Bravo assigned to Alpha's user (a bad import, a moved user) is
    still Bravo's record. ``/my-tasks`` filters by organization as well as by
    assignee, so it shows nothing rather than leaking the title."""
    a, b = two_orgs
    async with session_scope() as s:
        alpha_user = (
            await s.execute(select(User.id).where(User.organization_id == int(a["org_id"])))
        ).scalar_one()
        s.add(
            Task(
                organization_id=int(b["org_id"]),
                title=f"Bravo-crossassign-{b['tag']}",
                status="open",
                assignee_user_id=alpha_user,
            )
        )
        await s.flush()
    async with _client() as c:
        body = (await c.get("/my-tasks", headers=_auth(str(a["token"])))).text
    assert f"Alpha-task-{a['tag']}" in body
    assert "crossassign" not in body


async def test_the_rail_offers_exactly_the_pages_the_role_may_open(two_orgs) -> None:
    """The rail hides what the route would refuse, and hides nothing else.

    Driven per role through the real gate: for every rail page without a
    query string, a 403 must coincide with the item being hidden. A rail that
    showed a 403 page, or hid a page the role may open, fails here."""
    a, _ = two_orgs
    tokens: dict[str, str] = {}
    async with session_scope() as s:
        for role in ("viewer", "assessor", "control_owner"):
            u = User(
                email=f"{role}-{a['tag']}@cc.test",
                organization_id=int(a["org_id"]),
                role=role,
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
            s.add(u)
            tokens[role] = u.api_token
        await s.flush()
    mismatches = []
    async with _client() as c:
        for role, token in tokens.items():
            who = Principal(user_id=1, email="x", org_id=int(a["org_id"]), role=role)
            for _, item in navigation.all_items():
                if "?" in item.href or item.href.startswith("/docs"):
                    continue
                path = item.href.split("#")[0]
                status = (await c.get(path, headers=_auth(token))).status_code
                if (status == 403) == navigation.visible_to(item, who):
                    mismatches.append(f"{role}: {item.label} {path} -> {status}")
    assert not mismatches, "\n".join(mismatches)


async def test_people_get_an_error_page_and_clients_keep_their_json(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        browser = await c.get(
            "/admin/self-assurance", headers={**_auth(str(a["token"])), "Accept": "text/html"}
        )
        client = await c.get("/admin/self-assurance", headers=_auth(str(a["token"])))
        api = await c.get(
            "/api/admin/self-assurance/package",
            headers={**_auth(str(a["token"])), "Accept": "text/html"},
        )
    assert browser.status_code == 403
    assert "text/html" in browser.headers["content-type"]
    assert (
        "You don&#39;t have access to this page" in browser.text
        or "You don't have access" in browser.text
    )
    assert '<aside class="sidebar"' in browser.text
    assert client.status_code == 403 and "detail" in client.json()
    # An /api path never gets HTML, whatever it asks for.
    assert api.status_code == 403 and "detail" in api.json()
