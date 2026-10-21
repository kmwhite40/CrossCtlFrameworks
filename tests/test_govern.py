"""Governance structure: business units, teams, committees, objectives and the
organization's own settings (workstream C of the GRC build-out).

What is pinned, each the shape of a defect this platform has shipped before:

* **Tenant isolation is in the query.** The app runs on an RLS-bypass session
  (``_unscoped_session``), so only the page's or the route's own org predicate
  can keep Bravo's records off Alpha's screens. Foreign keys cannot cross
  tenants (migration 0101 refuses it), but ids held in JSON can: an Alpha
  meeting names a Bravo attendee and decision owner, and a Bravo event names
  an Alpha objective, so the predicates guarding those can fail.
* **Every write refuses another organization's ids** -- the record changed and
  every record attached (user, system, risk, policy, KRI, unit) -- with 404.
* **Role gates**: viewers, and roles outside each gate, get 403; the permitted
  role succeeds. Meetings: the chair or an admin, nobody else.
* **No cycles** in the business-unit tree.
"""

from __future__ import annotations

import itertools
import os
import re
from collections.abc import Callable
from datetime import UTC, date, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.deps import get_session
from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import get_session_factory, session_scope, set_session_tenant
from ccf.governance import org_structure as svc
from ccf.models import AuditLog, Control, Event, Organization, Policy, Risk, System, User
from ccf.models_program import (
    BusinessUnit,
    Committee,
    CommitteeMeeting,
    CommitteeMember,
    KeyRiskIndicator,
    ObjectiveLink,
    StrategicObjective,
    Team,
    TeamMember,
)
from ccf.self_assurance.service import SELF_ORG

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()
TODAY = date.today()


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
    """RLS tenant cleared: only the code's own org predicates keep tenants apart."""
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


ROLES = ("admin", "control_owner", "assessor", "viewer", "chair")


async def _org(label: str, tag: str) -> SimpleNamespace:
    """One organization with a record of every kind, named ``<label>-<kind>-<tag>``."""
    m = lambda kind: f"{label}-{kind}-{tag}"  # noqa: E731
    o = SimpleNamespace(label=label, tag=tag, tokens={}, users={})
    async with session_scope() as s:
        org = Organization(name=m("org"))
        s.add(org)
        await s.flush()
        o.org = org.id
        for role in ROLES:
            u = User(
                email=f"{label.lower()}-{role}-{tag}@gv.test",
                organization_id=org.id,
                role="control_owner" if role == "chair" else role,
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
            s.add(u)
            await s.flush()
            o.users[role] = u.id
            o.tokens[role] = u.api_token
        gone_user = User(
            email=f"{label.lower()}-inactive-{tag}@gv.test",
            organization_id=org.id,
            role="assessor",
            active=False,
        )
        live = System(organization_id=org.id, name=m("system"), baseline="moderate")
        live2 = System(organization_id=org.id, name=m("system2"), baseline="moderate")
        gone = System(
            organization_id=org.id,
            name=m("DELETED-system"),
            baseline="moderate",
            deleted_at=datetime.now(UTC),
        )
        s.add_all([gone_user, live, live2, gone])
        await s.flush()
        o.inactive_user, o.system, o.system2, o.deleted_system = (
            gone_user.id,
            live.id,
            live2.id,
            gone.id,
        )
        risk = Risk(system_id=live.id, title=m("risk"), status="open")
        dead_risk = Risk(system_id=gone.id, title=m("DELETED-risk"), status="open")
        # An enterprise risk (0100): no system, owned by the organization directly.
        ent_risk = Risk(
            organization_id=org.id, register="enterprise", title=m("ent-risk"), status="open"
        )
        policy = Policy(organization_id=org.id, name=m("policy"), status="active")
        kri = KeyRiskIndicator(organization_id=org.id, name=m("kri"))
        root = BusinessUnit(organization_id=org.id, name=m("bu-root"))
        s.add_all([risk, dead_risk, ent_risk, policy, kri, root])
        await s.flush()
        child = BusinessUnit(organization_id=org.id, name=m("bu-child"), parent_id=root.id)
        s.add(child)
        await s.flush()
        grand = BusinessUnit(organization_id=org.id, name=m("bu-grand"), parent_id=child.id)
        s.add(grand)
        await s.flush()
        live.business_unit_id = grand.id
        o.risk, o.dead_risk, o.policy, o.kri = risk.id, dead_risk.id, policy.id, kri.id
        o.ent_risk = ent_risk.id
        o.root, o.child, o.grand = root.id, child.id, grand.id

        team = Team(organization_id=org.id, name=m("team"), business_unit_id=child.id)
        team2 = Team(organization_id=org.id, name=m("team2"))
        committee = Committee(
            organization_id=org.id,
            name=m("committee"),
            charter=m("charter"),
            cadence="quarterly",
            chair_user_id=o.users["chair"],
        )
        committee2 = Committee(organization_id=org.id, name=m("committee2"))
        objective = StrategicObjective(organization_id=org.id, title=m("objective"))
        objective2 = StrategicObjective(organization_id=org.id, title=m("objective2"))
        s.add_all([team, team2, committee, committee2, objective, objective2])
        await s.flush()
        o.team, o.team2 = team.id, team2.id
        o.committee, o.committee2 = committee.id, committee2.id
        o.objective, o.objective2 = objective.id, objective2.id
        member = TeamMember(
            organization_id=org.id, team_id=team.id, user_id=o.users["admin"], role="member"
        )
        cmember = CommitteeMember(
            organization_id=org.id, committee_id=committee.id, user_id=o.users["assessor"]
        )
        meeting = CommitteeMeeting(
            organization_id=org.id,
            committee_id=committee.id,
            held_on=TODAY - timedelta(days=7),
            attendee_user_ids=[o.users["chair"]],
            minutes=m("minutes"),
            decisions=[
                {
                    "text": m("action-open"),
                    "owner_user_id": o.users["control_owner"],
                    "due_on": (TODAY - timedelta(days=1)).isoformat(),
                    "closed_on": None,
                },
                {"text": m("decision-no-due"), "owner_user_id": None, "due_on": None},
            ],
        )
        link = ObjectiveLink(
            organization_id=org.id,
            objective_id=objective.id,
            entity_type="risk",
            entity_id=str(risk.id),
        )
        s.add_all([member, cmember, meeting, link])
        await s.flush()
        o.member, o.cmember, o.meeting, o.link = member.id, cmember.id, meeting.id, link.id
    return o


async def _poison(a: SimpleNamespace, b: SimpleNamespace) -> None:
    """The cross-tenant references the database cannot refuse.

    Migration 0101 refuses any foreign key whose parent is another org's (a
    Bravo member on Alpha's team, an Alpha unit owned by a Bravo user), so the
    fixtures keep every foreign key inside its own organization. What 0101
    cannot see is an id held in JSON or in a free-text column: a meeting's
    attendees and decision owners, and an event's ``entity_id``. Those are
    planted here, so the page predicates that guard them can fail."""
    async with session_scope() as s:
        s.add(
            Event(
                organization_id=b.org,
                actor="x",
                verb="status_changed",
                entity_type="objective",
                entity_id=str(a.objective),
                summary=f"Bravo-stray-event-{b.tag}",
            )
        )
        meeting = await s.get(CommitteeMeeting, a.meeting)
        assert meeting is not None
        meeting.attendee_user_ids = [*meeting.attendee_user_ids, b.users["admin"]]
        meeting.decisions = [
            *meeting.decisions,
            {
                "text": f"Alpha-decision-for-bravo-{a.tag}",
                "owner_user_id": b.users["admin"],
                "due_on": None,
            },
        ]


@pytest.fixture
async def two() -> tuple[SimpleNamespace, SimpleNamespace]:
    tag = f"{next(_SEQ)}g{os.getpid()}"
    a, b = await _org("Alpha", tag), await _org("Bravo", tag)
    await _poison(a, b)
    return a, b


def _leaks(body: str, b: SimpleNamespace) -> list[str]:
    """Every Bravo record name or user email (this run's tag) in ``body``."""
    return sorted(set(re.findall(rf"bravo-[\w-]*?-{re.escape(b.tag)}", body, flags=re.I)))


def _attr(body: str, element_id: str, name: str) -> str:
    found = re.search(rf'id="{re.escape(element_id)}"[^>]*\b{name}="([^"]*)"', body)
    assert found, f"{element_id} {name} not on the page"
    return found.group(1)


async def _get(c: AsyncClient, token: str, path: str) -> str:
    resp = await c.get(path, headers=_auth(token))
    assert resp.status_code == 200, (path, resp.status_code, resp.text[:300])
    return resp.text


async def _post(c: AsyncClient, token: str, path: str, data: Any = None) -> Any:
    return await c.post(path, data=data or {}, headers=_auth(token), follow_redirects=False)


# ── pure rules ───────────────────────────────────────────────────────────────


def test_a_cycle_is_detected_at_any_depth() -> None:
    parents = {1: None, 2: 1, 3: 2, 4: None}
    assert svc.creates_cycle(parents, 1, 3)  # root under its grandchild
    assert svc.creates_cycle(parents, 2, 2)
    assert not svc.creates_cycle(parents, 3, 1)
    assert not svc.creates_cycle(parents, 1, 4)
    assert not svc.creates_cycle(parents, 1, None)
    # a loop already in the data does not hang the walk
    assert not svc.creates_cycle({5: 6, 6: 5, 7: None}, 7, 5)


def test_the_tree_puts_children_under_parents_and_drops_nothing() -> None:
    u = lambda i, name, parent: SimpleNamespace(id=i, name=name, parent_id=parent)  # noqa: E731
    units = [u(1, "b", None), u(2, "a", None), u(3, "z", 1), u(4, "y", 1), u(5, "x", 4)]
    order = [(x.id, d) for x, d in svc.unit_tree(units)]  # type: ignore[arg-type]
    assert order == [(2, 0), (1, 0), (4, 1), (5, 2), (3, 1)]
    looped = [u(1, "a", 2), u(2, "b", 1)]
    assert sorted(x.id for x, _ in svc.unit_tree(looped)) == [1, 2]  # type: ignore[arg-type]


def test_a_units_total_includes_every_unit_below_it() -> None:
    parents = {1: None, 2: 1, 3: 2, 4: None}
    totals = svc.rollup(parents, {1: 1, 2: 2, 3: 4, 4: 8})
    assert totals == {1: 7, 2: 6, 3: 4, 4: 8}
    assert svc.descendants(parents, 1) == {2, 3}


def test_an_open_action_has_a_due_date_and_no_closure() -> None:
    due = (TODAY - timedelta(days=1)).isoformat()
    later = (TODAY + timedelta(days=3)).isoformat()
    meeting = SimpleNamespace(
        decisions=[
            {"text": "late", "due_on": due},
            {"text": "no date", "due_on": None},
            {"text": "done", "due_on": due, "closed_on": TODAY.isoformat()},
            {"text": "soon", "due_on": later},
        ]
    )
    actions = svc.open_actions([meeting], TODAY)
    assert [(a["text"], a["overdue"]) for a in actions] == [("late", True), ("soon", False)]


# ── isolation: pages ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("path", "own"),
    [
        ("/org-units", lambda a: [f"Alpha-bu-grand-{a.tag}", f"Alpha-system-{a.tag}"]),
        ("/teams", lambda a: [f"Alpha-team-{a.tag}", f"alpha-admin-{a.tag}@gv.test"]),
        ("/committees", lambda a: [f"Alpha-committee-{a.tag}", f"Alpha-action-open-{a.tag}"]),
        ("/committees/{committee}", lambda a: [f"Alpha-charter-{a.tag}", f"Alpha-minutes-{a.tag}"]),
        ("/objectives", lambda a: [f"Alpha-objective-{a.tag}"]),
        (
            "/objectives/{objective}",
            lambda a: [f"Alpha-risk-{a.tag}", f"Alpha-ent-risk-{a.tag}", f"Alpha-policy-{a.tag}"],
        ),
        ("/settings/organization", lambda a: [f"Alpha-org-{a.tag}"]),
    ],
)
async def test_each_page_shows_its_own_records_and_never_another_organizations(
    two, path: str, own: Callable[[SimpleNamespace], list[str]]
) -> None:
    a, b = two
    async with _client() as c:
        # An admin: the write forms and their pickers render too, and a
        # picker listing another tenant's users or records is a leak.
        body = await _get(c, a.tokens["admin"], path.format(**vars(a)))
    for text in own(a):
        assert text in body, f"{path} does not show {text}"
    assert not _leaks(body, b), f"{path} shows Bravo's {_leaks(body, b)}"


async def test_child_rows_of_another_organization_are_not_counted(two) -> None:
    """Counts on Alpha's pages are Alpha's rows, exactly.

    Since 0101 a child row cannot hang on another org's parent, so these pin
    the counts rather than prove each child predicate (see the report)."""
    a, _ = two
    async with _client() as c:
        units = await _get(c, a.tokens["viewer"], "/org-units")
        teams = await _get(c, a.tokens["viewer"], "/teams")
        committees = await _get(c, a.tokens["viewer"], "/committees")
        committee = await _get(c, a.tokens["viewer"], f"/committees/{a.committee}")
        objectives = await _get(c, a.tokens["viewer"], "/objectives")
        objective = await _get(c, a.tokens["viewer"], f"/objectives/{a.objective}")
        settings = await _get(c, a.tokens["viewer"], "/settings/organization")
    assert _attr(units, f"unit-{a.root}", "data-teams") == "0"
    assert _attr(units, f"unit-{a.child}", "data-teams") == "1"
    assert _attr(teams, f"team-{a.team}", "data-members") == "1"
    assert _attr(committees, f"committee-{a.committee}", "data-members") == "1"
    assert _attr(committees, f"committee-{a.committee}", "data-open") == "1"
    assert 'data-members="1"' in committee
    assert _attr(objectives, f"objective-{a.objective}", "data-links") == "1"
    assert 'data-links="1"' in objective
    counts = dict(re.findall(r'data-count="([^"]+)">(\d+)<', settings))
    assert counts == {
        "Active users": "5",
        "Live systems": "2",
        "Business units": "3",
        "Teams": "2",
        "Committees": "2",
        "Strategic objectives": "2",
    }


async def test_another_organizations_records_are_not_found(two) -> None:
    a, b = two
    async with _client() as c:
        for path in (f"/committees/{b.committee}", f"/objectives/{b.objective}"):
            resp = await c.get(path, headers=_auth(a.tokens["admin"]))
            assert resp.status_code == 404, path


async def test_systems_by_unit_sum_to_the_live_systems(two) -> None:
    """Assigned + not assigned = live systems; deleted ones are in neither,
    and a unit's total includes the units below it."""
    a, _ = two
    async with _client() as c:
        body = await _get(c, a.tokens["viewer"], "/org-units")
    live, assigned, unassigned = (
        int(re.search(rf'data-{k}="(\d+)"', body).group(1))  # type: ignore[union-attr]
        for k in ("live", "assigned", "unassigned")
    )
    assert (live, assigned, unassigned) == (2, 1, 1)
    assert assigned + unassigned == live
    assert f"Alpha-DELETED-system-{a.tag}" not in body
    assert _attr(body, f"unit-{a.grand}", "data-direct") == "1"
    assert _attr(body, f"unit-{a.root}", "data-direct") == "0"
    assert _attr(body, f"unit-{a.root}", "data-total") == "1"


# ── isolation: every write refuses another organization's ids ───────────────

#: (path, form) -- each names exactly one record that is not Alpha's (or not
#: live, or not active). ``{x}`` is Alpha's, ``{b_x}`` is Bravo's.
FOREIGN_WRITES: list[tuple[str, dict[str, str]]] = [
    ("/org-units", {"name": "n", "parent_id": "{b_root}"}),
    ("/org-units", {"name": "n", "owner_user_id": "{b_admin}"}),
    ("/org-units", {"name": "n", "owner_user_id": "{inactive_user}"}),
    ("/org-units/{b_root}", {"name": "n"}),
    ("/org-units/{root}", {"name": "n", "parent_id": "{b_root}"}),
    ("/org-units/{root}", {"name": "n", "owner_user_id": "{b_admin}"}),
    ("/org-units/{b_root}/delete", {}),
    ("/org-units/assign", {"system_id": "{b_system}", "business_unit_id": "{root}"}),
    ("/org-units/assign", {"system_id": "{system2}", "business_unit_id": "{b_root}"}),
    ("/org-units/assign", {"system_id": "{deleted_system}", "business_unit_id": "{root}"}),
    ("/teams", {"name": "n", "business_unit_id": "{b_root}"}),
    ("/teams/{b_team}", {"name": "n"}),
    ("/teams/{team}", {"name": "n", "business_unit_id": "{b_root}"}),
    ("/teams/{b_team}/delete", {}),
    ("/teams/{team}/members", {"user_id": "{b_admin}"}),
    ("/teams/{team}/members", {"user_id": "{inactive_user}"}),
    ("/teams/{b_team}/members", {"user_id": "{admin}"}),
    ("/teams/{team}/members/{b_member}/remove", {}),
    ("/teams/{team2}/members/{member}/remove", {}),
    ("/committees", {"name": "n", "chair_user_id": "{b_admin}"}),
    ("/committees/{b_committee}", {"name": "n"}),
    ("/committees/{committee}", {"name": "n", "chair_user_id": "{b_admin}"}),
    ("/committees/{committee}/members", {"user_id": "{b_admin}"}),
    ("/committees/{b_committee}/members", {"user_id": "{admin}"}),
    ("/committees/{committee}/members/{b_cmember}/remove", {}),
    ("/committees/{committee2}/members/{cmember}/remove", {}),
    ("/committees/{b_committee}/meetings", {"held_on": "2026-10-01"}),
    (
        "/committees/{committee}/meetings",
        {"held_on": "2026-10-01", "attendee_user_ids": "{b_admin}"},
    ),
    (
        "/committees/{committee}/meetings",
        {"held_on": "2026-10-01", "decision_text": "t", "decision_owner": "{b_admin}"},
    ),
    ("/committees/{committee}/meetings/{b_meeting}/decisions/0/close", {}),
    ("/committees/{committee2}/meetings/{meeting}/decisions/0/close", {}),
    ("/committees/{b_committee}/meetings/{b_meeting}/decisions/0/close", {}),
    ("/objectives", {"title": "t", "owner_user_id": "{b_admin}"}),
    ("/objectives/{b_objective}", {"title": "t"}),
    ("/objectives/{objective}", {"title": "t", "owner_user_id": "{b_admin}"}),
    ("/objectives/{b_objective}/status", {"status": "at_risk"}),
    ("/objectives/{b_objective}/links", {"entity_type": "risk", "entity_id": "{risk}"}),
    ("/objectives/{objective}/links", {"entity_type": "risk", "entity_id": "{b_risk}"}),
    ("/objectives/{objective}/links", {"entity_type": "risk", "entity_id": "{dead_risk}"}),
    ("/objectives/{objective}/links", {"entity_type": "risk", "entity_id": "{b_ent_risk}"}),
    ("/objectives/{objective}/links", {"entity_type": "system", "entity_id": "{b_system}"}),
    ("/objectives/{objective}/links", {"entity_type": "system", "entity_id": "{deleted_system}"}),
    ("/objectives/{objective}/links", {"entity_type": "policy", "entity_id": "{b_policy}"}),
    ("/objectives/{objective}/links", {"entity_type": "kri", "entity_id": "{b_kri}"}),
    ("/objectives/{objective}/links", {"entity_type": "control", "entity_id": "NO-SUCH-CTRL"}),
    ("/objectives/{objective}/links/{b_link}/remove", {}),
    ("/objectives/{objective2}/links/{link}/remove", {}),
]


def _fill(text: str, a: SimpleNamespace, b: SimpleNamespace) -> str:
    keys: dict[str, Any] = {**vars(a), **a.users}
    keys |= {f"b_{k}": v for k, v in {**vars(b), **b.users}.items()}
    return text.format(**keys)


async def _snapshot(a: SimpleNamespace, b: SimpleNamespace) -> dict[str, Any]:
    """Everything a refused write must leave as it was."""
    async with session_scope() as s:

        async def rows(model: Any, *cols: Any) -> list[Any]:
            stmt = select(*cols).where(model.organization_id.in_([a.org, b.org]))
            return sorted(tuple(r) for r in (await s.execute(stmt)).all())

        return {
            "units": await rows(
                BusinessUnit, BusinessUnit.id, BusinessUnit.name, BusinessUnit.parent_id,
                BusinessUnit.owner_user_id,
            ),
            "systems": await rows(System, System.id, System.business_unit_id),
            "teams": await rows(Team, Team.id, Team.name, Team.business_unit_id),
            "team_members": await rows(TeamMember, TeamMember.id, TeamMember.user_id),
            "committees": await rows(
                Committee, Committee.id, Committee.name, Committee.chair_user_id
            ),
            "committee_members": await rows(CommitteeMember, CommitteeMember.id),
            "meetings": await rows(CommitteeMeeting, CommitteeMeeting.id),
            "objectives": await rows(
                StrategicObjective,
                StrategicObjective.id,
                StrategicObjective.title,
                StrategicObjective.status,
                StrategicObjective.owner_user_id,
            ),
            "links": await rows(ObjectiveLink, ObjectiveLink.id),
        }  # fmt: skip


@pytest.mark.parametrize(("path", "form"), FOREIGN_WRITES, ids=lambda v: str(v)[:60])
async def test_a_write_naming_another_organizations_record_is_not_found(
    two, path: str, form: dict[str, str]
) -> None:
    a, b = two
    before = await _snapshot(a, b)
    data = {k: _fill(v, a, b) for k, v in form.items()}
    async with _client() as c:
        resp = await _post(c, a.tokens["admin"], _fill(path, a, b), data)
    assert resp.status_code == 404, (path, data, resp.status_code, resp.text[:200])
    assert await _snapshot(a, b) == before


async def _names(*ids: int) -> dict[int, str]:
    async with session_scope() as s:
        rows = (await s.execute(select(Organization).where(Organization.id.in_(ids)))).scalars()
        return {o.id: o.name for o in rows}


def _auth_off() -> None:
    """The system principal: global, i.e. a platform administrator."""
    os.environ.pop("CCF_AUTH_ENABLED", None)
    get_settings.cache_clear()


async def test_a_tenant_admin_cannot_rename_an_organization(two) -> None:
    """Concord finds some organizations by name (SELF_ORG, ``user-create
    --org``), so a tenant must not choose its own: renames are a platform
    administrator's."""
    a, b = two
    async with _client() as c:
        own = await _post(
            c,
            a.tokens["admin"],
            "/settings/organization",
            {"name": f"Alpha-renamed-{a.tag}", "organization_id": str(a.org)},
        )
        page = await _get(c, a.tokens["admin"], "/settings/organization")
    assert own.status_code == 403
    assert "platform" in own.text
    assert 'method="post"' not in page
    assert "Renames are done by a platform administrator" in page
    assert await _names(a.org, b.org) == {a.org: f"Alpha-org-{a.tag}", b.org: f"Bravo-org-{b.tag}"}


async def test_a_platform_administrator_renames_an_organization(two) -> None:
    a, b = two
    _auth_off()
    async with _client() as c:
        page = (await c.get("/settings/organization")).text
        taken = await c.post(
            "/settings/organization",
            data={"name": f"Bravo-org-{b.tag}", "organization_id": str(a.org)},
        )
        ok = await c.post(
            "/settings/organization",
            data={"name": f"  Alpha   renamed-{a.tag} ", "organization_id": str(a.org)},
        )
        missing = await c.post(
            "/settings/organization", data={"name": "x", "organization_id": "999999999"}
        )
    assert f"Alpha-org-{a.tag}" in page and 'name="organization_id"' in page
    assert taken.status_code == 400 and "already in use" in taken.text
    assert ok.status_code == 303
    assert missing.status_code == 404
    assert await _names(a.org, b.org) == {
        a.org: f"Alpha renamed-{a.tag}",
        b.org: f"Bravo-org-{b.tag}",
    }
    async with session_scope() as s:
        audit = (
            await s.execute(
                select(AuditLog).where(
                    AuditLog.action == "organization_rename", AuditLog.entity_id == str(a.org)
                )
            )
        ).scalar_one()
    assert audit.organization_id == a.org


@pytest.mark.parametrize(
    "spelling",
    [
        SELF_ORG,
        SELF_ORG.upper(),
        SELF_ORG.lower(),
        f"  {SELF_ORG}  ",
        SELF_ORG.replace(" ", " \t  "),
    ],
)
async def test_the_platform_organizations_name_is_reserved(two, spelling: str) -> None:
    a, _ = two
    _auth_off()
    async with _client() as c:
        resp = await c.post(
            "/settings/organization", data={"name": spelling, "organization_id": str(a.org)}
        )
    assert resp.status_code == 400, resp.text[:200]
    assert "reserved" in resp.text
    assert await _names(a.org) == {a.org: f"Alpha-org-{a.tag}"}


async def test_the_platform_organization_cannot_be_renamed_away() -> None:
    async with session_scope() as s:
        platform = (
            await s.execute(select(Organization).where(Organization.name == SELF_ORG))
        ).scalar_one_or_none()
        if platform is None:
            platform = Organization(name=SELF_ORG)
            s.add(platform)
            await s.flush()
        pid = platform.id
    _auth_off()
    async with _client() as c:
        resp = await c.post(
            "/settings/organization",
            data={"name": f"Squatted-{next(_SEQ)}", "organization_id": str(pid)},
        )
    assert resp.status_code == 400
    assert await _names(pid) == {pid: SELF_ORG}


async def test_a_principal_without_an_organization_cannot_write() -> None:
    """Auth off: the system principal is global; a row for no org is refused."""
    os.environ.pop("CCF_AUTH_ENABLED", None)
    get_settings.cache_clear()
    async with _client() as c:
        resp = await c.post("/org-units", data={"name": f"nobody-{next(_SEQ)}"})
    assert resp.status_code == 400
    assert "organization" in resp.text


# ── role gates ───────────────────────────────────────────────────────────────

#: (path, form, roles that may) for every write route; paths use Alpha's ids.
GATED: list[tuple[str, dict[str, str], set[str]]] = [
    ("/org-units", {"name": "gate-{tag}-{role}"}, {"admin"}),
    ("/org-units/{root}", {"name": "Alpha-bu-root-{tag}"}, {"admin"}),
    ("/org-units/{child}/delete", {}, {"admin"}),
    ("/org-units/assign", {"system_id": "{system2}", "business_unit_id": "{root}"}, {"admin"}),
    ("/teams", {"name": "gate-{tag}-{role}"}, {"admin"}),
    ("/teams/{team}", {"name": "Alpha-team-{tag}"}, {"admin"}),
    ("/teams/{team}/members", {"user_id": "{viewer}"}, {"admin"}),
    ("/teams/{team}/members/{member}/remove", {}, {"admin"}),
    ("/teams/{team2}/delete", {}, {"admin"}),
    ("/committees", {"name": "gate-{tag}-{role}"}, {"admin"}),
    (
        "/committees/{committee}",
        {"name": "Alpha-committee-{tag}", "chair_user_id": "{chair}"},
        {"admin"},
    ),
    ("/committees/{committee}/members", {"user_id": "{viewer}"}, {"admin"}),
    ("/committees/{committee}/members/{cmember}/remove", {}, {"admin"}),
    ("/committees/{committee}/meetings", {"held_on": "2026-10-01"}, {"admin", "chair"}),
    ("/committees/{committee}/meetings/{meeting}/decisions/0/close", {}, {"admin", "chair"}),
    ("/objectives", {"title": "gate"}, {"admin", "control_owner", "chair"}),
    ("/objectives/{objective}", {"title": "t"}, {"admin", "control_owner", "chair"}),
    ("/objectives/{objective}/status", {"status": "at_risk"}, {"admin", "control_owner", "chair"}),
    (
        "/objectives/{objective}/links",
        {"entity_type": "policy", "entity_id": "{policy}"},
        {"admin", "control_owner", "chair"},
    ),
    ("/objectives/{objective}/links/{link}/remove", {}, {"admin", "control_owner", "chair"}),
    # Platform administrators only: no tenant role may rename (see below).
    (
        "/settings/organization",
        {"name": "Alpha-org-{tag}-{role}", "organization_id": "{org}"},
        set(),
    ),
]  # fmt: skip


@pytest.mark.parametrize(("path", "form", "allowed"), GATED, ids=lambda v: str(v)[:50])
@pytest.mark.parametrize("role", ROLES)
async def test_each_write_admits_exactly_its_roles(
    two, path: str, form: dict[str, str], allowed: set[str], role: str
) -> None:
    a, b = two
    fill = lambda t: _fill(t.replace("{role}", role), a, b)  # noqa: E731
    async with _client() as c:
        resp = await _post(c, a.tokens[role], fill(path), {k: fill(v) for k, v in form.items()})
    if role in allowed:
        assert resp.status_code == 303, (role, path, resp.status_code, resp.text[:300])
    else:
        assert resp.status_code == 403, (role, path, resp.status_code, resp.text[:300])


async def test_only_the_chair_or_an_admin_records_a_meeting_and_says_so(two) -> None:
    a, _ = two
    async with _client() as c:
        owner = await _post(
            c,
            a.tokens["control_owner"],
            f"/committees/{a.committee}/meetings",
            {"held_on": TODAY.isoformat()},
        )
    assert owner.status_code == 403
    assert "chair" in owner.text


# ── behaviour ────────────────────────────────────────────────────────────────


async def test_a_unit_cannot_be_moved_under_itself_or_below_itself(two) -> None:
    a, _ = two
    async with _client() as c:
        tok = a.tokens["admin"]
        root_name = f"Alpha-bu-root-{a.tag}"
        own = await _post(c, tok, f"/org-units/{a.root}", {"name": root_name, "parent_id": a.root})
        under_grand = await _post(
            c, tok, f"/org-units/{a.root}", {"name": root_name, "parent_id": a.grand}
        )
        under_child = await _post(
            c, tok, f"/org-units/{a.root}", {"name": root_name, "parent_id": a.child}
        )
        fine = await _post(
            c,
            tok,
            f"/org-units/{a.grand}",
            {"name": f"Alpha-bu-grand-{a.tag}", "parent_id": a.root},
        )
    assert own.status_code == 400 and "own parent" in own.text
    assert under_grand.status_code == 400 and "cycle" in under_grand.text
    assert under_child.status_code == 400 and "cycle" in under_child.text
    assert fine.status_code == 303
    async with session_scope() as s:
        root = await s.get(BusinessUnit, a.root)
        grand = await s.get(BusinessUnit, a.grand)
        assert root is not None and grand is not None
        assert root.parent_id is None
        assert grand.parent_id == a.root


async def test_deleting_a_unit_moves_its_children_up_and_releases_its_systems(two) -> None:
    a, b = two
    async with session_scope() as s:
        system2 = await s.get(System, a.system2)
        assert system2 is not None
        system2.business_unit_id = a.child
    async with _client() as c:
        resp = await _post(c, a.tokens["admin"], f"/org-units/{a.child}/delete")
    assert resp.status_code == 303
    async with session_scope() as s:
        grand = await s.get(BusinessUnit, a.grand)
        assert grand is not None and grand.parent_id == a.root
        audit = (
            await s.execute(
                select(AuditLog).where(
                    AuditLog.action == "business_unit_delete", AuditLog.entity_id == str(a.child)
                )
            )
        ).scalar_one()
    assert audit.organization_id == a.org
    assert audit.diff["sub_units"] == [a.grand]
    assert audit.diff["systems_unassigned"] == [a.system2]

    async with _client() as c:
        await _post(c, a.tokens["admin"], f"/org-units/{a.root}/delete")
    async with session_scope() as s:
        audit = (
            await s.execute(
                select(AuditLog).where(
                    AuditLog.action == "business_unit_delete", AuditLog.entity_id == str(a.root)
                )
            )
        ).scalar_one()
    # The grandchild moved up to the root and its system with it; deleting the
    # root moves the grandchild to the top level. Its system stays assigned.
    assert audit.diff["sub_units"] == [a.grand]
    assert audit.diff["systems_unassigned"] == []
    async with session_scope() as s:
        grand = await s.get(BusinessUnit, a.grand)
        system = await s.get(System, a.system)
        bravo_root = await s.get(BusinessUnit, b.root)
    assert grand is not None and grand.parent_id is None
    assert system is not None and system.business_unit_id == a.grand
    assert bravo_root is not None


async def test_assigning_a_system_sets_its_unit_and_is_audited(two) -> None:
    a, _ = two
    async with _client() as c:
        resp = await _post(
            c,
            a.tokens["admin"],
            "/org-units/assign",
            {"system_id": a.system2, "business_unit_id": a.child},
        )
        cleared = await _post(
            c,
            a.tokens["admin"],
            "/org-units/assign",
            {"system_id": a.system, "business_unit_id": ""},
        )
        body = await _get(c, a.tokens["viewer"], "/org-units")
    assert resp.status_code == cleared.status_code == 303
    assert _attr(body, f"unit-{a.child}", "data-direct") == "1"
    assert _attr(body, f"unit-{a.root}", "data-total") == "1"
    async with session_scope() as s:
        system2 = await s.get(System, a.system2)
        system = await s.get(System, a.system)
        assert system2 is not None and system2.business_unit_id == a.child
        assert system is not None and system.business_unit_id is None
        actions = (
            (
                await s.execute(
                    select(AuditLog.diff).where(
                        AuditLog.action == "system_business_unit_set",
                        AuditLog.organization_id == a.org,
                    )
                )
            )
            .scalars()
            .all()
        )
    assert {"business_unit_id": {"from": None, "to": a.child}} in actions


async def test_a_team_has_one_lead(two) -> None:
    a, b = two
    async with session_scope() as s:
        # Bravo's own team has a lead; Alpha naming a lead must not touch it.
        s.add(
            TeamMember(
                organization_id=b.org, team_id=b.team, user_id=b.users["viewer"], role="lead"
            )
        )
    async with _client() as c:
        tok = a.tokens["admin"]
        first = await _post(
            c, tok, f"/teams/{a.team}/members", {"user_id": a.users["viewer"], "role": "lead"}
        )
        second = await _post(
            c, tok, f"/teams/{a.team}/members", {"user_id": a.users["chair"], "role": "lead"}
        )
        bad = await _post(
            c, tok, f"/teams/{a.team}/members", {"user_id": a.users["chair"], "role": "boss"}
        )
    assert first.status_code == second.status_code == 303
    assert bad.status_code == 400
    async with session_scope() as s:
        rows = (
            (await s.execute(select(TeamMember).where(TeamMember.team_id == a.team)))
            .scalars()
            .all()
        )
        bravo_lead = (
            await s.execute(
                select(TeamMember.role).where(
                    TeamMember.team_id == b.team, TeamMember.user_id == b.users["viewer"]
                )
            )
        ).scalar_one()
    roles = {r.user_id: r.role for r in rows}
    assert roles[a.users["chair"]] == "lead"
    assert roles[a.users["viewer"]] == "member"
    assert bravo_lead == "lead"


async def test_a_meeting_records_attendees_minutes_and_actions_until_closed(two) -> None:
    a, _ = two
    due = (TODAY + timedelta(days=14)).isoformat()
    async with _client() as c:
        tok = a.tokens["chair"]
        missing_text = await _post(
            c,
            tok,
            f"/committees/{a.committee}/meetings",
            {"held_on": TODAY.isoformat(), "decision_text": "", "decision_due": due},
        )
        resp = await c.post(
            f"/committees/{a.committee}/meetings",
            data={
                "held_on": TODAY.isoformat(),
                "minutes": "Quarterly review",
                "attendee_user_ids": [str(a.users["chair"]), str(a.users["admin"])],
                "decision_text": ["Adopt the new charter", "", "Note the report"],
                "decision_owner": [str(a.users["control_owner"]), "", ""],
                "decision_due": [due, "", ""],
            },
            headers=_auth(tok),
        )
        page = await _get(c, a.tokens["viewer"], "/committees")
    assert missing_text.status_code == 400
    assert resp.status_code == 303
    assert "Adopt the new charter" in page
    assert _attr(page, f"committee-{a.committee}", "data-open") == "2"
    async with session_scope() as s:
        meeting = (
            await s.execute(
                select(CommitteeMeeting).where(
                    CommitteeMeeting.committee_id == a.committee,
                    CommitteeMeeting.organization_id == a.org,
                    CommitteeMeeting.minutes == "Quarterly review",
                )
            )
        ).scalar_one()
    assert meeting.attendee_user_ids == [a.users["chair"], a.users["admin"]]
    assert [d["text"] for d in meeting.decisions] == ["Adopt the new charter", "Note the report"]
    assert meeting.recorded_by == f"alpha-chair-{a.tag}@gv.test"

    async with _client() as c:
        closed = await _post(
            c,
            a.tokens["chair"],
            f"/committees/{a.committee}/meetings/{meeting.id}/decisions/0/close",
        )
        again = await _post(
            c,
            a.tokens["chair"],
            f"/committees/{a.committee}/meetings/{meeting.id}/decisions/0/close",
        )
        page = await _get(c, a.tokens["viewer"], "/committees")
    assert closed.status_code == 303 and again.status_code == 400
    assert _attr(page, f"committee-{a.committee}", "data-open") == "1"


async def test_an_objective_status_change_is_an_event_and_links_are_validated(two) -> None:
    a, _ = two
    async with session_scope() as s:
        ident = f"GV-{a.tag}"
        s.add(Control(identifier=ident, control_name="Governance test control"))
    async with _client() as c:
        tok = a.tokens["control_owner"]
        same = await _post(c, tok, f"/objectives/{a.objective}/status", {"status": "planned"})
        bogus = await _post(c, tok, f"/objectives/{a.objective}/status", {"status": "great"})
        moved = await _post(
            c, tok, f"/objectives/{a.objective}/status", {"status": "at_risk", "note": "slipping"}
        )
        for etype, eid in (
            ("control", ident),
            ("system", a.system),
            ("policy", a.policy),
            ("kri", a.kri),
            ("risk", a.ent_risk),  # an enterprise risk: no system, owned by the org
            ("risk", a.risk),  # already linked: no duplicate
        ):
            r = await _post(
                c, tok, f"/objectives/{a.objective}/links", {"entity_type": etype, "entity_id": eid}
            )
            assert r.status_code == 303, (etype, r.text[:200])
        wrong_type = await _post(
            c, tok, f"/objectives/{a.objective}/links", {"entity_type": "vendor", "entity_id": "1"}
        )
        body = await _get(c, a.tokens["viewer"], f"/objectives/{a.objective}")
    assert same.status_code == 400 and bogus.status_code == 400 and wrong_type.status_code == 400
    assert moved.status_code == 303
    assert "planned → at risk — slipping" in body
    assert 'data-links="6"' in body
    for label in (
        "Governance test control",
        f"Alpha-system-{a.tag}",
        f"Alpha-kri-{a.tag}",
        f"Alpha-ent-risk-{a.tag}",
    ):
        assert label in body
    async with session_scope() as s:
        ev = (
            await s.execute(
                select(Event).where(
                    Event.organization_id == a.org,
                    Event.entity_type == "objective",
                    Event.entity_id == str(a.objective),
                )
            )
        ).scalar_one()
        obj = await s.get(StrategicObjective, a.objective)
    assert ev.payload == {"from": "planned", "to": "at_risk", "note": "slipping"}
    assert obj is not None and obj.status == "at_risk"


async def test_creating_records_puts_them_in_the_callers_organization(two) -> None:
    a, _ = two
    async with _client() as c:
        tok = a.tokens["admin"]
        dup = await _post(c, tok, "/org-units", {"name": f"Alpha-bu-root-{a.tag}"})
        unit = await _post(
            c,
            tok,
            "/org-units",
            {
                "name": f"Alpha-new-bu-{a.tag}",
                "parent_id": a.root,
                "owner_user_id": a.users["admin"],
            },
        )
        team = await _post(
            c, tok, "/teams", {"name": f"Alpha-new-team-{a.tag}", "business_unit_id": a.root}
        )
        com = await _post(
            c,
            tok,
            "/committees",
            {
                "name": f"Alpha-new-com-{a.tag}",
                "cadence": "monthly",
                "chair_user_id": a.users["chair"],
            },
        )
        bad_cadence = await _post(c, tok, "/committees", {"name": "x", "cadence": "hourly"})
        obj = await _post(
            c,
            tok,
            "/objectives",
            {
                "title": f"Alpha-new-obj-{a.tag}",
                "target_on": "2027-03-31",
                "owner_user_id": a.users["control_owner"],
            },
        )
        bad_date = await _post(c, tok, "/objectives", {"title": "x", "target_on": "soon"})
    assert dup.status_code == 400 and "already exists" in dup.text
    assert bad_cadence.status_code == 400 and bad_date.status_code == 400
    assert all(r.status_code == 303 for r in (unit, team, com, obj))
    async with session_scope() as s:
        for model, col, name in (
            (BusinessUnit, BusinessUnit.name, f"Alpha-new-bu-{a.tag}"),
            (Team, Team.name, f"Alpha-new-team-{a.tag}"),
            (Committee, Committee.name, f"Alpha-new-com-{a.tag}"),
            (StrategicObjective, StrategicObjective.title, f"Alpha-new-obj-{a.tag}"),
        ):
            row = (await s.execute(select(model).where(col == name))).scalar_one()
            assert row.organization_id == a.org, name
        logged = set(
            (
                await s.execute(select(AuditLog.action).where(AuditLog.organization_id == a.org))
            ).scalars()
        )
    assert {"business_unit_create", "team_create", "committee_create", "objective_create"} <= logged


async def test_empty_pages_say_what_is_missing() -> None:
    tag = f"{next(_SEQ)}e{os.getpid()}"
    async with session_scope() as s:
        org = Organization(name=f"Empty-org-{tag}")
        s.add(org)
        await s.flush()
        u = User(
            email=f"empty-{tag}@gv.test",
            organization_id=org.id,
            role="viewer",
            active=True,
            api_token=new_api_token(),
        )
        s.add(u)
        await s.flush()
        token = u.api_token
    async with _client() as c:
        for path, text in (
            ("/org-units", "No business units yet"),
            ("/teams", "No teams yet"),
            ("/committees", "No committees yet"),
            ("/objectives", "No strategic objectives yet"),
        ):
            body = await _get(c, token, path)
            assert text in body, path
            assert '<form method="post"' not in body, f"{path} offers a viewer a write form"


async def test_a_name_another_organization_uses_is_free_here(two) -> None:
    """Names are unique per organization, not across tenants -- and the
    refusal must not reveal that another tenant holds the name."""
    a, b = two
    async with _client() as c:
        for path, field, name in (
            ("/org-units", "name", f"Bravo-bu-root-{b.tag}"),
            ("/teams", "name", f"Bravo-team-{b.tag}"),
            ("/committees", "name", f"Bravo-committee-{b.tag}"),
        ):
            resp = await _post(c, a.tokens["admin"], path, {field: name})
            assert resp.status_code == 303, (path, resp.status_code, resp.text[:200])
