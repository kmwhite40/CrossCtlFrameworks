"""Governance pages: business units, teams, committees, strategic objectives and
the organization's own settings.

Spec: docs/superpowers/specs/2026-10-20-grc-buildout-design.md (workstream C).

Tenant scope is explicit in every query: reads filter on the caller's
organization (``_principal_org``; ``None`` only when auth is off or the
principal is global, which is unscoped by design), and every write resolves
each id it is given -- the record it changes and every record it attaches --
through ``ccf.governance.org_structure``, which refuses anything outside the
caller's organization as not found. Writes need an organization: a global
principal is refused with 400 rather than writing a row that belongs to no one.

Role gates:

* business units, teams, committee charter and membership, the organization's
  name: ``admin`` (configuration);
* committee meetings and closing their actions: ``admin`` or the committee's
  chair -- the route admits the three working roles and the handler then
  checks the chair, saying why when it refuses;
* strategic objectives and their links and status: ``admin`` or
  ``control_owner`` (records people maintain).

Every write records an audit event (``record_event``); an objective's status
change is also an activity event, so its history can be shown.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ...analytics import posture
from ...auth import Principal
from ...governance import bus
from ...governance import org_structure as svc
from ...models import Event, Organization, Policy, Risk, System, User
from ...models_program import (
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
from .. import navigation
from ..audit import record_event
from ..auth_deps import require_role, resolve_caller_org
from ..deps import get_session
from .ui import _principal_org, templates

router = APIRouter(include_in_schema=False)

ADMIN = ("admin",)
OBJECTIVE_WRITERS = ("admin", "control_owner")
#: Who may reach the meeting routes at all; the chair check narrows it.
MEETING_ROLES = ("admin", "control_owner", "assessor")


# ── helpers ──────────────────────────────────────────────────────────────────


def _active(key: str, fallback: str) -> str:
    """The spec's navigation key once the rail has it, else its nearest home.

    ``teams`` and ``org_settings`` are added to ``navigation.py`` by the
    integrator; until then the page highlights the entry it sits under
    (Users, Teams & Roles; Organization Settings) instead of none."""
    keys = {item.key for _, item in navigation.all_items()}
    return key if key in keys else fallback


def _render(request: Request, template: str, active: str, **ctx: Any) -> HTMLResponse:
    return templates.TemplateResponse(request, template, {"active": active, **ctx})


def _principal(request: Request) -> Principal | None:
    p = getattr(request.state, "principal", None)
    return p if isinstance(p, Principal) else None


def _has_role(request: Request, roles: tuple[str, ...]) -> bool:
    """Whether to offer a form. Display only; the routes' gates decide."""
    p = _principal(request)
    return p is None or p.is_global or p.role in roles


def _is_admin(request: Request) -> bool:
    return _has_role(request, ADMIN)


def _write_org(principal: Principal) -> int:
    if principal.org_id is None:
        raise HTTPException(
            400,
            "this page changes one organization's records; sign in as a member of "
            "that organization",
        )
    return principal.org_id


@contextmanager
def _refusals() -> Iterator[None]:
    """Service refusals as HTTP answers: not in the org is 404, invalid is 400."""
    try:
        yield
    except svc.NotInOrganizationError as exc:
        raise HTTPException(404, str(exc)) from exc
    except svc.RefusedError as exc:
        raise HTTPException(400, str(exc)) from exc


def _scope(column: Any, org: int | None) -> list[Any]:
    return [column == org] if org is not None else []


async def _labels(session: AsyncSession, org: int | None, ids: set[Any]) -> dict[int, str]:
    """Display names for user ids, only for users of ``org``."""
    clean = {i for i in ids if isinstance(i, int)}
    if not clean:
        return {}
    rows = (
        await session.execute(
            select(User.id, User.full_name, User.email).where(
                User.id.in_(clean), *_scope(User.organization_id, org)
            )
        )
    ).all()
    return {r.id: (r.full_name or r.email) for r in rows}


async def _audit(  # noqa: PLR0917 -- one call shape at ~25 sites
    session: AsyncSession,
    principal: Principal,
    org: int,
    action: str,
    entity_type: str,
    entity_id: Any,
    diff: dict[str, Any],
) -> None:
    await record_event(
        session,
        actor=principal.email,
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id) if entity_id is not None else None,
        diff=diff,
        organization_id=org,
    )


async def _name_free(
    session: AsyncSession, model: Any, org: int, name: str, what: str, *, exclude: int | None = None
) -> str:
    name = name.strip()
    if not name:
        raise HTTPException(400, f"a {what} needs a name")
    stmt = select(model.id).where(model.organization_id == org, model.name == name)
    if exclude is not None:
        stmt = stmt.where(model.id != exclude)
    if (await session.execute(stmt)).first() is not None:
        raise HTTPException(400, f"a {what} named {name!r} already exists in this organization")
    return name


def _see_other(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


# ── Business units ───────────────────────────────────────────────────────────


@router.get("/org-units", response_class=HTMLResponse)
async def org_units_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    units = list(
        (
            await session.execute(
                select(BusinessUnit).where(*_scope(BusinessUnit.organization_id, org))
            )
        ).scalars()
    )
    unit_ids = {u.id for u in units}
    parents = {u.id: u.parent_id for u in units}
    systems = list(
        (
            await session.execute(
                select(System)
                .where(System.id.in_(posture.org_system_subq(org)))
                .order_by(System.name)
            )
        ).scalars()
    )
    direct = Counter(s.business_unit_id for s in systems if s.business_unit_id in unit_ids)
    total = svc.rollup(parents, dict(direct))
    teams = Counter(
        r.business_unit_id
        for r in (
            await session.execute(
                select(Team.business_unit_id).where(*_scope(Team.organization_id, org))
            )
        ).all()
    )
    owners = await _labels(session, org, {u.owner_user_id for u in units})
    names = {u.id: u.name for u in units}
    rows = []
    for unit, depth in svc.unit_tree(units):
        blocked = svc.descendants(parents, unit.id) | {unit.id}
        rows.append(
            {
                "unit": unit,
                "depth": depth,
                "parent": names.get(unit.parent_id) if unit.parent_id else None,
                "owner": owners.get(unit.owner_user_id) if unit.owner_user_id else None,
                "direct": direct.get(unit.id, 0),
                "total": total.get(unit.id, 0),
                "teams": teams.get(unit.id, 0),
                "parent_options": sorted(
                    (u for u in units if u.id not in blocked), key=lambda u: u.name.lower()
                ),
            }
        )
    assigned = sum(direct.values())
    return _render(
        request,
        "org_units.html",
        "org_units",
        rows=rows,
        units=sorted(units, key=lambda u: u.name.lower()),
        unit_names=names,
        systems=systems,
        users=await svc.org_users(session, org),
        live_systems=len(systems),
        assigned=assigned,
        unassigned=len(systems) - assigned,
        can_admin=_is_admin(request),
    )


@router.post("/org-units")
async def org_unit_create(
    *,
    name: str = Form(...),
    description: str = Form(""),
    parent_id: str = Form(""),
    owner_user_id: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*ADMIN)),
) -> RedirectResponse:
    org = _write_org(principal)
    with _refusals():
        pid = svc.parse_id(parent_id, "parent unit")
        oid = svc.parse_id(owner_user_id, "owner")
        await svc.check_parent(session, org, None, pid)
        if oid is not None:
            await svc.user_in_org(session, org, oid)
    clean = await _name_free(session, BusinessUnit, org, name, "business unit")
    unit = BusinessUnit(
        organization_id=org,
        name=clean,
        description=description.strip() or None,
        parent_id=pid,
        owner_user_id=oid,
    )
    session.add(unit)
    await session.flush()
    await _audit(
        session,
        principal,
        org,
        "business_unit_create",
        "business_unit",
        unit.id,
        {"name": clean, "parent_id": pid, "owner_user_id": oid},
    )
    await session.commit()
    return _see_other("/org-units")


@router.post("/org-units/assign")
async def org_unit_assign_system(
    system_id: int = Form(...),
    business_unit_id: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*ADMIN)),
) -> RedirectResponse:
    """Put a live system of the caller's org in one of its units (or none)."""
    org = _write_org(principal)
    with _refusals():
        sys = await svc.live_system(session, org, system_id)
        uid = svc.parse_id(business_unit_id, "business unit")
        if uid is not None:
            await svc.owned(session, BusinessUnit, org, uid, "business unit")
    previous = sys.business_unit_id
    sys.business_unit_id = uid
    await _audit(
        session,
        principal,
        org,
        "system_business_unit_set",
        "system",
        sys.id,
        {"business_unit_id": {"from": previous, "to": uid}},
    )
    await session.commit()
    return _see_other("/org-units")


@router.post("/org-units/{unit_id}")
async def org_unit_update(
    *,
    unit_id: int,
    name: str = Form(...),
    description: str = Form(""),
    parent_id: str = Form(""),
    owner_user_id: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*ADMIN)),
) -> RedirectResponse:
    org = _write_org(principal)
    with _refusals():
        unit = await svc.owned(session, BusinessUnit, org, unit_id, "business unit")
        pid = svc.parse_id(parent_id, "parent unit")
        oid = svc.parse_id(owner_user_id, "owner")
        await svc.check_parent(session, org, unit.id, pid)
        if oid is not None:
            await svc.user_in_org(session, org, oid)
    clean = await _name_free(session, BusinessUnit, org, name, "business unit", exclude=unit.id)
    before = {"name": unit.name, "parent_id": unit.parent_id, "owner_user_id": unit.owner_user_id}
    unit.name = clean
    unit.description = description.strip() or None
    unit.parent_id = pid
    unit.owner_user_id = oid
    await _audit(
        session,
        principal,
        org,
        "business_unit_update",
        "business_unit",
        unit.id,
        {"from": before, "to": {"name": clean, "parent_id": pid, "owner_user_id": oid}},
    )
    await session.commit()
    return _see_other("/org-units")


@router.post("/org-units/{unit_id}/delete")
async def org_unit_delete(
    unit_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*ADMIN)),
) -> RedirectResponse:
    """Delete a unit. Its sub-units move up to its parent rather than becoming
    roots; its systems and teams become unassigned (the foreign keys say so)."""
    org = _write_org(principal)
    with _refusals():
        unit = await svc.owned(session, BusinessUnit, org, unit_id, "business unit")
    moved = (
        await session.execute(
            update(BusinessUnit)
            .where(BusinessUnit.organization_id == org, BusinessUnit.parent_id == unit.id)
            .values(parent_id=unit.parent_id)
            .returning(BusinessUnit.id)
        )
    ).all()
    released = (
        await session.execute(
            update(System)
            .where(System.organization_id == org, System.business_unit_id == unit.id)
            .values(business_unit_id=None)
            .returning(System.id)
        )
    ).all()
    await session.delete(unit)
    await _audit(
        session,
        principal,
        org,
        "business_unit_delete",
        "business_unit",
        unit_id,
        {
            "name": unit.name,
            "sub_units_moved_to": unit.parent_id,
            "sub_units": [r.id for r in moved],
            "systems_unassigned": [r.id for r in released],
        },
    )
    await session.commit()
    return _see_other("/org-units")


# ── Teams ────────────────────────────────────────────────────────────────────


@router.get("/teams", response_class=HTMLResponse)
async def teams_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    teams = list(
        (
            await session.execute(
                select(Team).where(*_scope(Team.organization_id, org)).order_by(Team.name)
            )
        ).scalars()
    )
    members = list(
        (
            await session.execute(
                select(TeamMember).where(
                    *_scope(TeamMember.organization_id, org),
                    TeamMember.team_id.in_([t.id for t in teams]),
                )
            )
        ).scalars()
    )
    names = await _labels(session, org, {m.user_id for m in members})
    by_team: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for m in members:
        by_team[m.team_id].append(
            {"id": m.id, "user": names.get(m.user_id, f"user {m.user_id}"), "role": m.role}
        )
    for rows in by_team.values():
        rows.sort(key=lambda r: (r["role"] != "lead", r["user"].lower()))
    units = list(
        (
            await session.execute(
                select(BusinessUnit)
                .where(*_scope(BusinessUnit.organization_id, org))
                .order_by(BusinessUnit.name)
            )
        ).scalars()
    )
    unit_names = {u.id: u.name for u in units}
    return _render(
        request,
        "teams.html",
        _active("teams", "users"),
        teams=[
            {
                "team": t,
                "unit": unit_names.get(t.business_unit_id) if t.business_unit_id else None,
                "members": by_team.get(t.id, []),
                "leads": [m["user"] for m in by_team.get(t.id, []) if m["role"] == "lead"],
            }
            for t in teams
        ],
        units=units,
        users=await svc.org_users(session, org),
        roles=svc.TEAM_ROLES,
        can_admin=_is_admin(request),
    )


@router.post("/teams")
async def team_create(
    name: str = Form(...),
    description: str = Form(""),
    business_unit_id: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*ADMIN)),
) -> RedirectResponse:
    org = _write_org(principal)
    with _refusals():
        uid = svc.parse_id(business_unit_id, "business unit")
        if uid is not None:
            await svc.owned(session, BusinessUnit, org, uid, "business unit")
    clean = await _name_free(session, Team, org, name, "team")
    team = Team(
        organization_id=org,
        name=clean,
        description=description.strip() or None,
        business_unit_id=uid,
    )
    session.add(team)
    await session.flush()
    await _audit(
        session,
        principal,
        org,
        "team_create",
        "team",
        team.id,
        {"name": clean, "business_unit_id": uid},
    )
    await session.commit()
    return _see_other("/teams")


@router.post("/teams/{team_id}")
async def team_update(
    *,
    team_id: int,
    name: str = Form(...),
    description: str = Form(""),
    business_unit_id: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*ADMIN)),
) -> RedirectResponse:
    org = _write_org(principal)
    with _refusals():
        team = await svc.owned(session, Team, org, team_id, "team")
        uid = svc.parse_id(business_unit_id, "business unit")
        if uid is not None:
            await svc.owned(session, BusinessUnit, org, uid, "business unit")
    clean = await _name_free(session, Team, org, name, "team", exclude=team.id)
    before = {"name": team.name, "business_unit_id": team.business_unit_id}
    team.name = clean
    team.description = description.strip() or None
    team.business_unit_id = uid
    await _audit(
        session,
        principal,
        org,
        "team_update",
        "team",
        team.id,
        {"from": before, "to": {"name": clean, "business_unit_id": uid}},
    )
    await session.commit()
    return _see_other("/teams")


@router.post("/teams/{team_id}/delete")
async def team_delete(
    team_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*ADMIN)),
) -> RedirectResponse:
    org = _write_org(principal)
    with _refusals():
        team = await svc.owned(session, Team, org, team_id, "team")
    await session.delete(team)
    await _audit(session, principal, org, "team_delete", "team", team_id, {"name": team.name})
    await session.commit()
    return _see_other("/teams")


@router.post("/teams/{team_id}/members")
async def team_member_add(
    team_id: int,
    user_id: int = Form(...),
    role: str = Form("member"),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*ADMIN)),
) -> RedirectResponse:
    """Add a user of the same organization, or change their role. A team has
    one lead: naming a new one makes the previous lead a member."""
    org = _write_org(principal)
    if role not in svc.TEAM_ROLES:
        raise HTTPException(400, f"team role must be one of {', '.join(svc.TEAM_ROLES)}")
    with _refusals():
        team = await svc.owned(session, Team, org, team_id, "team")
        await svc.user_in_org(session, org, user_id)
    demoted: list[int] = []
    if role == "lead":
        demoted = [
            r.user_id
            for r in (
                await session.execute(
                    update(TeamMember)
                    .where(
                        TeamMember.organization_id == org,
                        TeamMember.team_id == team.id,
                        TeamMember.role == "lead",
                        TeamMember.user_id != user_id,
                    )
                    .values(role="member")
                    .returning(TeamMember.user_id)
                )
            ).all()
        ]
    existing = (
        await session.execute(
            select(TeamMember).where(
                TeamMember.organization_id == org,
                TeamMember.team_id == team.id,
                TeamMember.user_id == user_id,
            )
        )
    ).scalar_one_or_none()
    if existing is None:
        session.add(TeamMember(organization_id=org, team_id=team.id, user_id=user_id, role=role))
    else:
        existing.role = role
    await _audit(
        session,
        principal,
        org,
        "team_member_set",
        "team",
        team.id,
        {"user_id": user_id, "role": role, "previous_lead_now_member": demoted},
    )
    await session.commit()
    return _see_other("/teams")


@router.post("/teams/{team_id}/members/{member_id}/remove")
async def team_member_remove(
    team_id: int,
    member_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*ADMIN)),
) -> RedirectResponse:
    org = _write_org(principal)
    with _refusals():
        team = await svc.owned(session, Team, org, team_id, "team")
        member = await svc.owned(session, TeamMember, org, member_id, "team member")
    if member.team_id != team.id:
        raise HTTPException(404, f"no team member {member_id} on team {team_id}")
    await session.delete(member)
    await _audit(
        session,
        principal,
        org,
        "team_member_remove",
        "team",
        team.id,
        {"user_id": member.user_id, "role": member.role},
    )
    await session.commit()
    return _see_other("/teams")


# ── Committees ───────────────────────────────────────────────────────────────


async def _committee_meetings(
    session: AsyncSession, org: int | None, committee_ids: list[int]
) -> list[CommitteeMeeting]:
    if not committee_ids:
        return []
    return list(
        (
            await session.execute(
                select(CommitteeMeeting)
                .where(
                    *_scope(CommitteeMeeting.organization_id, org),
                    CommitteeMeeting.committee_id.in_(committee_ids),
                )
                .order_by(CommitteeMeeting.held_on.desc(), CommitteeMeeting.id.desc())
            )
        ).scalars()
    )


@router.get("/committees", response_class=HTMLResponse)
async def committees_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    committees = list(
        (
            await session.execute(
                select(Committee)
                .where(*_scope(Committee.organization_id, org))
                .order_by(Committee.active.desc(), Committee.name)
            )
        ).scalars()
    )
    ids = [c.id for c in committees]
    member_counts = Counter(
        r.committee_id
        for r in (
            await session.execute(
                select(CommitteeMember.committee_id).where(
                    *_scope(CommitteeMember.organization_id, org),
                    CommitteeMember.committee_id.in_(ids),
                )
            )
        ).all()
    )
    meetings = await _committee_meetings(session, org, ids)
    by_committee: dict[int, list[CommitteeMeeting]] = defaultdict(list)
    for m in meetings:
        by_committee[m.committee_id].append(m)
    today = date.today()
    actions = svc.open_actions(meetings, today)
    names = await _labels(
        session,
        org,
        {c.chair_user_id for c in committees} | {a["owner_user_id"] for a in actions},
    )
    committee_names = {c.id: c.name for c in committees}
    rows = []
    for c in committees:
        held = by_committee.get(c.id, [])
        rows.append(
            {
                "committee": c,
                "chair": names.get(c.chair_user_id) if c.chair_user_id else None,
                "members": member_counts.get(c.id, 0),
                "meetings": len(held),
                "last_held": held[0].held_on if held else None,
                "open_actions": sum(1 for a in actions if a["meeting"].committee_id == c.id),
            }
        )
    return _render(
        request,
        "committees.html",
        "committees",
        rows=rows,
        actions=[
            {
                **a,
                "committee_id": a["meeting"].committee_id,
                "committee": committee_names.get(a["meeting"].committee_id, ""),
                "owner": names.get(a["owner_user_id"]) if a["owner_user_id"] else None,
            }
            for a in actions
        ],
        overdue=sum(1 for a in actions if a["overdue"]),
        users=await svc.org_users(session, org),
        cadences=svc.CADENCES,
        can_admin=_is_admin(request),
    )


@router.post("/committees")
async def committee_create(
    *,
    name: str = Form(...),
    charter: str = Form(""),
    cadence: str = Form(""),
    chair_user_id: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*ADMIN)),
) -> RedirectResponse:
    org = _write_org(principal)
    if cadence and cadence not in svc.CADENCES:
        raise HTTPException(400, f"cadence must be one of {', '.join(svc.CADENCES)}")
    with _refusals():
        chair = svc.parse_id(chair_user_id, "chair")
        if chair is not None:
            await svc.user_in_org(session, org, chair)
    clean = await _name_free(session, Committee, org, name, "committee")
    committee = Committee(
        organization_id=org,
        name=clean,
        charter=charter.strip() or None,
        cadence=cadence or None,
        chair_user_id=chair,
    )
    session.add(committee)
    await session.flush()
    await _audit(
        session,
        principal,
        org,
        "committee_create",
        "committee",
        committee.id,
        {"name": clean, "cadence": cadence or None, "chair_user_id": chair},
    )
    await session.commit()
    return _see_other(f"/committees/{committee.id}")


@router.get("/committees/{committee_id}", response_class=HTMLResponse)
async def committee_detail(
    committee_id: int, request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    committee = (
        await session.execute(
            select(Committee).where(
                Committee.id == committee_id, *_scope(Committee.organization_id, org)
            )
        )
    ).scalar_one_or_none()
    if committee is None:
        raise HTTPException(404, "no such committee")
    members = list(
        (
            await session.execute(
                select(CommitteeMember).where(
                    *_scope(CommitteeMember.organization_id, org),
                    CommitteeMember.committee_id == committee.id,
                )
            )
        ).scalars()
    )
    meetings = await _committee_meetings(session, org, [committee.id])
    today = date.today()
    actions = svc.open_actions(meetings, today)
    ids: set[Any] = {committee.chair_user_id} | {m.user_id for m in members}
    for m in meetings:
        ids |= set(m.attendee_user_ids or [])
        ids |= {d.get("owner_user_id") for d in (m.decisions or []) if isinstance(d, dict)}
    names = await _labels(session, org, ids)
    principal = _principal(request)
    is_chair = (
        principal is not None
        and principal.user_id is not None
        and principal.user_id == committee.chair_user_id
    )
    return _render(
        request,
        "committee_detail.html",
        "committees",
        committee=committee,
        chair=names.get(committee.chair_user_id) if committee.chair_user_id else None,
        members=sorted(
            [
                {"id": m.id, "user": names.get(m.user_id, f"user {m.user_id}"), "role": m.role}
                for m in members
            ],
            key=lambda r: (r["role"] != "secretary", r["user"].lower()),
        ),
        meetings=[
            {
                "meeting": m,
                "attendees": [names.get(u, f"user {u}") for u in (m.attendee_user_ids or [])],
                "decisions": [
                    {
                        **d,
                        "index": i,
                        "owner": names.get(d.get("owner_user_id")),
                        "overdue": bool(
                            d.get("due_on")
                            and not d.get("closed_on")
                            and date.fromisoformat(d["due_on"]) < today
                        ),
                    }
                    for i, d in enumerate(m.decisions or [])
                    if isinstance(d, dict)
                ],
            }
            for m in meetings
        ],
        actions=[
            {**a, "owner": names.get(a["owner_user_id"]) if a["owner_user_id"] else None}
            for a in actions
        ],
        users=await svc.org_users(session, org),
        roles=svc.COMMITTEE_ROLES,
        cadences=svc.CADENCES,
        can_admin=_is_admin(request),
        can_record=_is_admin(request) or is_chair,
        today=today,
        blank_decisions=range(3),
    )


@router.post("/committees/{committee_id}")
async def committee_update(
    *,
    committee_id: int,
    name: str = Form(...),
    charter: str = Form(""),
    cadence: str = Form(""),
    chair_user_id: str = Form(""),
    active: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*ADMIN)),
) -> RedirectResponse:
    org = _write_org(principal)
    if cadence and cadence not in svc.CADENCES:
        raise HTTPException(400, f"cadence must be one of {', '.join(svc.CADENCES)}")
    with _refusals():
        committee = await svc.owned(session, Committee, org, committee_id, "committee")
        chair = svc.parse_id(chair_user_id, "chair")
        if chair is not None:
            await svc.user_in_org(session, org, chair)
    clean = await _name_free(session, Committee, org, name, "committee", exclude=committee.id)
    new_charter = charter.strip() or None
    before = {
        "name": committee.name,
        "cadence": committee.cadence,
        "chair_user_id": committee.chair_user_id,
        "active": committee.active,
    }
    after = {
        "name": clean,
        "cadence": cadence or None,
        "chair_user_id": chair,
        "active": bool(active),
    }
    charter_changed = new_charter != committee.charter
    committee.name = clean
    committee.charter = new_charter
    committee.cadence = cadence or None
    committee.chair_user_id = chair
    committee.active = bool(active)
    await _audit(
        session,
        principal,
        org,
        "committee_update",
        "committee",
        committee.id,
        {"from": before, "to": after, "charter_changed": charter_changed},
    )
    await session.commit()
    return _see_other(f"/committees/{committee.id}")


@router.post("/committees/{committee_id}/members")
async def committee_member_add(
    committee_id: int,
    user_id: int = Form(...),
    role: str = Form("member"),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*ADMIN)),
) -> RedirectResponse:
    org = _write_org(principal)
    if role not in svc.COMMITTEE_ROLES:
        raise HTTPException(
            400,
            f"committee role must be one of {', '.join(svc.COMMITTEE_ROLES)}; the chair "
            "is set on the committee itself",
        )
    with _refusals():
        committee = await svc.owned(session, Committee, org, committee_id, "committee")
        await svc.user_in_org(session, org, user_id)
    existing = (
        await session.execute(
            select(CommitteeMember).where(
                CommitteeMember.organization_id == org,
                CommitteeMember.committee_id == committee.id,
                CommitteeMember.user_id == user_id,
            )
        )
    ).scalar_one_or_none()
    if existing is None:
        session.add(
            CommitteeMember(
                organization_id=org, committee_id=committee.id, user_id=user_id, role=role
            )
        )
    else:
        existing.role = role
    await _audit(
        session,
        principal,
        org,
        "committee_member_set",
        "committee",
        committee.id,
        {"user_id": user_id, "role": role},
    )
    await session.commit()
    return _see_other(f"/committees/{committee.id}")


@router.post("/committees/{committee_id}/members/{member_id}/remove")
async def committee_member_remove(
    committee_id: int,
    member_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*ADMIN)),
) -> RedirectResponse:
    org = _write_org(principal)
    with _refusals():
        committee = await svc.owned(session, Committee, org, committee_id, "committee")
        member = await svc.owned(session, CommitteeMember, org, member_id, "committee member")
    if member.committee_id != committee.id:
        raise HTTPException(404, f"no member {member_id} on committee {committee_id}")
    await session.delete(member)
    await _audit(
        session,
        principal,
        org,
        "committee_member_remove",
        "committee",
        committee.id,
        {"user_id": member.user_id, "role": member.role},
    )
    await session.commit()
    return _see_other(f"/committees/{committee.id}")


def _require_chair_or_admin(principal: Principal, committee: Committee) -> None:
    if principal.is_global or principal.role == "admin":
        return
    if principal.user_id is not None and principal.user_id == committee.chair_user_id:
        return
    raise HTTPException(
        403,
        "only the committee's chair or an administrator records its meetings and "
        "closes its actions",
    )


@router.post("/committees/{committee_id}/meetings")
async def committee_meeting_record(
    *,
    committee_id: int,
    held_on: str = Form(...),
    minutes: str = Form(""),
    attendee_user_ids: list[str] = Form([]),
    decision_text: list[str] = Form([]),
    decision_owner: list[str] = Form([]),
    decision_due: list[str] = Form([]),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*MEETING_ROLES)),
) -> RedirectResponse:
    org = _write_org(principal)
    with _refusals():
        committee = await svc.owned(session, Committee, org, committee_id, "committee")
    _require_chair_or_admin(principal, committee)
    with _refusals():
        when = svc.parse_date(held_on, "meeting date")
        if when is None:
            raise svc.RefusedError("a meeting needs the date it was held")
        attendees: list[int] = []
        for raw in attendee_user_ids:
            uid = svc.parse_id(raw, "attendee")
            if uid is not None and uid not in attendees:
                await svc.user_in_org(session, org, uid)
                attendees.append(uid)
        decisions = await svc.build_decisions(
            session, org, decision_text, decision_owner, decision_due
        )
    meeting = CommitteeMeeting(
        organization_id=org,
        committee_id=committee.id,
        held_on=when,
        attendee_user_ids=attendees,
        minutes=minutes.strip() or None,
        decisions=decisions,
        recorded_by=principal.email,
    )
    session.add(meeting)
    await session.flush()
    await _audit(
        session,
        principal,
        org,
        "committee_meeting_record",
        "committee",
        committee.id,
        {
            "meeting_id": meeting.id,
            "held_on": when.isoformat(),
            "attendees": attendees,
            "decisions": len(decisions),
        },
    )
    await session.commit()
    return _see_other(f"/committees/{committee.id}#meeting-{meeting.id}")


@router.post("/committees/{committee_id}/meetings/{meeting_id}/decisions/{index}/close")
async def committee_decision_close(
    committee_id: int,
    meeting_id: int,
    index: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*MEETING_ROLES)),
) -> RedirectResponse:
    org = _write_org(principal)
    with _refusals():
        committee = await svc.owned(session, Committee, org, committee_id, "committee")
        meeting = await svc.owned(session, CommitteeMeeting, org, meeting_id, "meeting")
    if meeting.committee_id != committee.id:
        raise HTTPException(404, f"no meeting {meeting_id} for committee {committee_id}")
    _require_chair_or_admin(principal, committee)
    decisions = [dict(d) if isinstance(d, dict) else d for d in (meeting.decisions or [])]
    if not 0 <= index < len(decisions) or not isinstance(decisions[index], dict):
        raise HTTPException(404, f"no decision {index} in that meeting")
    if decisions[index].get("closed_on"):
        raise HTTPException(400, "that action is already closed")
    decisions[index]["closed_on"] = date.today().isoformat()
    decisions[index]["closed_by"] = principal.email
    meeting.decisions = decisions  # reassigned: JSONB is not mutation-tracked
    await _audit(
        session,
        principal,
        org,
        "committee_action_close",
        "committee",
        committee.id,
        {"meeting_id": meeting.id, "decision": index, "text": decisions[index].get("text")},
    )
    await session.commit()
    return _see_other(f"/committees/{committee.id}#meeting-{meeting.id}")


# ── Strategic objectives ─────────────────────────────────────────────────────


@router.get("/objectives", response_class=HTMLResponse)
async def objectives_page(
    request: Request,
    status: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    org = _principal_org(request)
    objectives = list(
        (
            await session.execute(
                select(StrategicObjective)
                .where(*_scope(StrategicObjective.organization_id, org))
                .order_by(StrategicObjective.target_on.asc().nulls_last(), StrategicObjective.id)
            )
        ).scalars()
    )
    counts = Counter(o.status for o in objectives)
    shown = [o for o in objectives if not status or o.status == status]
    link_counts: dict[int, Counter[str]] = defaultdict(Counter)
    for r in (
        await session.execute(
            select(ObjectiveLink.objective_id, ObjectiveLink.entity_type).where(
                *_scope(ObjectiveLink.organization_id, org),
                ObjectiveLink.objective_id.in_([o.id for o in shown]),
            )
        )
    ).all():
        link_counts[r.objective_id][r.entity_type] += 1
    owners = await _labels(session, org, {o.owner_user_id for o in shown})
    today = date.today()
    return _render(
        request,
        "objectives.html",
        "objectives",
        rows=[
            {
                "objective": o,
                "owner": owners.get(o.owner_user_id) if o.owner_user_id else None,
                "links": dict(link_counts.get(o.id, {})),
                "late": bool(
                    o.target_on and o.target_on < today and o.status not in ("achieved", "retired")
                ),
            }
            for o in shown
        ],
        total=len(objectives),
        counts=counts,
        statuses=svc.OBJECTIVE_STATUSES,
        status=status or "",
        users=await svc.org_users(session, org),
        can_write=_has_role(request, OBJECTIVE_WRITERS),
    )


@router.post("/objectives")
async def objective_create(
    *,
    title: str = Form(...),
    description: str = Form(""),
    measure: str = Form(""),
    owner_user_id: str = Form(""),
    target_on: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*OBJECTIVE_WRITERS)),
) -> RedirectResponse:
    org = _write_org(principal)
    if not title.strip():
        raise HTTPException(400, "an objective needs a title")
    with _refusals():
        oid = svc.parse_id(owner_user_id, "owner")
        if oid is not None:
            await svc.user_in_org(session, org, oid)
        target = svc.parse_date(target_on, "target date")
    obj = StrategicObjective(
        organization_id=org,
        title=title.strip(),
        description=description.strip() or None,
        measure=measure.strip() or None,
        owner_user_id=oid,
        target_on=target,
        status="planned",
    )
    session.add(obj)
    await session.flush()
    await _audit(
        session,
        principal,
        org,
        "objective_create",
        "objective",
        obj.id,
        {"title": obj.title, "owner_user_id": oid, "target_on": target_on or None},
    )
    await session.commit()
    return _see_other(f"/objectives/{obj.id}")


@router.get("/objectives/{objective_id}", response_class=HTMLResponse)
async def objective_detail(
    objective_id: int, request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    obj = (
        await session.execute(
            select(StrategicObjective).where(
                StrategicObjective.id == objective_id,
                *_scope(StrategicObjective.organization_id, org),
            )
        )
    ).scalar_one_or_none()
    if obj is None:
        raise HTTPException(404, "no such objective")
    links = list(
        (
            await session.execute(
                select(ObjectiveLink)
                .where(
                    *_scope(ObjectiveLink.organization_id, org),
                    ObjectiveLink.objective_id == obj.id,
                )
                .order_by(ObjectiveLink.entity_type, ObjectiveLink.id)
            )
        ).scalars()
    )
    labels = await svc.link_labels(session, org, links)
    grouped: dict[str, list[dict[str, Any]]] = {t: [] for t in svc.LINK_TYPES}
    for link in links:
        found = labels.get((link.entity_type, link.entity_id))
        grouped.setdefault(link.entity_type, []).append(
            {
                "link": link,
                "label": found[0] if found else None,
                "href": found[1] if found else None,
            }
        )
    history = list(
        (
            await session.execute(
                select(Event)
                .where(
                    *_scope(Event.organization_id, org),
                    Event.entity_type == "objective",
                    Event.entity_id == str(obj.id),
                )
                .order_by(Event.created_at.desc(), Event.id.desc())
                .limit(50)
            )
        ).scalars()
    )
    live = posture.org_system_subq(org)
    risks = (
        await session.execute(
            select(Risk.id, Risk.title).where(svc.risk_in_org(org)).order_by(Risk.title)
        )
    ).all()
    systems = (
        await session.execute(
            select(System.id, System.name).where(System.id.in_(live)).order_by(System.name)
        )
    ).all()
    policies = (
        await session.execute(
            select(Policy.id, Policy.name)
            .where(*_scope(Policy.organization_id, org))
            .order_by(Policy.name)
        )
    ).all()
    kris = (
        await session.execute(
            select(KeyRiskIndicator.id, KeyRiskIndicator.name)
            .where(*_scope(KeyRiskIndicator.organization_id, org))
            .order_by(KeyRiskIndicator.name)
        )
    ).all()
    owner = await _labels(session, org, {obj.owner_user_id})
    return _render(
        request,
        "objective_detail.html",
        "objectives",
        objective=obj,
        owner=owner.get(obj.owner_user_id) if obj.owner_user_id else None,
        grouped=grouped,
        link_count=len(links),
        history=history,
        pickers={
            "risk": [(r.id, r.title) for r in risks],
            "system": [(s.id, s.name) for s in systems],
            "policy": [(p.id, p.name) for p in policies],
            "kri": [(k.id, k.name) for k in kris],
        },
        statuses=svc.OBJECTIVE_STATUSES,
        users=await svc.org_users(session, org),
        can_write=_has_role(request, OBJECTIVE_WRITERS),
    )


@router.post("/objectives/{objective_id}")
async def objective_update(
    *,
    objective_id: int,
    title: str = Form(...),
    description: str = Form(""),
    measure: str = Form(""),
    owner_user_id: str = Form(""),
    target_on: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*OBJECTIVE_WRITERS)),
) -> RedirectResponse:
    org = _write_org(principal)
    if not title.strip():
        raise HTTPException(400, "an objective needs a title")
    with _refusals():
        obj = await svc.owned(session, StrategicObjective, org, objective_id, "objective")
        oid = svc.parse_id(owner_user_id, "owner")
        if oid is not None:
            await svc.user_in_org(session, org, oid)
        target = svc.parse_date(target_on, "target date")
    before = {
        "title": obj.title,
        "owner_user_id": obj.owner_user_id,
        "target_on": obj.target_on.isoformat() if obj.target_on else None,
    }
    obj.title = title.strip()
    obj.description = description.strip() or None
    obj.measure = measure.strip() or None
    obj.owner_user_id = oid
    obj.target_on = target
    await _audit(
        session,
        principal,
        org,
        "objective_update",
        "objective",
        obj.id,
        {
            "from": before,
            "to": {
                "title": obj.title,
                "owner_user_id": oid,
                "target_on": target.isoformat() if target else None,
            },
        },
    )
    await session.commit()
    return _see_other(f"/objectives/{obj.id}")


@router.post("/objectives/{objective_id}/status")
async def objective_status(
    objective_id: int,
    status: str = Form(...),
    note: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*OBJECTIVE_WRITERS)),
) -> RedirectResponse:
    org = _write_org(principal)
    if status not in svc.OBJECTIVE_STATUSES:
        raise HTTPException(400, f"status must be one of {', '.join(svc.OBJECTIVE_STATUSES)}")
    with _refusals():
        obj = await svc.owned(session, StrategicObjective, org, objective_id, "objective")
    previous = obj.status
    if previous == status:
        raise HTTPException(400, f"the objective is already {status.replace('_', ' ')}")
    obj.status = status
    clean_note = note.strip() or None
    summary = f"{obj.title}: {previous.replace('_', ' ')} → {status.replace('_', ' ')}"
    if clean_note:
        summary += f" — {clean_note}"
    await bus.emit(
        session,
        verb="status_changed",
        entity_type="objective",
        entity_id=obj.id,
        summary=summary,
        org_id=org,
        actor=principal.email,
        payload={"from": previous, "to": status, "note": clean_note},
    )
    await _audit(
        session,
        principal,
        org,
        "objective_status",
        "objective",
        obj.id,
        {"status": {"from": previous, "to": status}, "note": clean_note},
    )
    await session.commit()
    return _see_other(f"/objectives/{obj.id}")


@router.post("/objectives/{objective_id}/links")
async def objective_link_add(
    objective_id: int,
    entity_type: str = Form(...),
    entity_id: str = Form(...),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*OBJECTIVE_WRITERS)),
) -> RedirectResponse:
    """Link an objective to a risk, control, system, policy or KRI -- each
    validated to exist in the caller's organization (controls: the catalog)."""
    org = _write_org(principal)
    with _refusals():
        obj = await svc.owned(session, StrategicObjective, org, objective_id, "objective")
        canonical, label = await svc.resolve_link(session, org, entity_type, entity_id)
    exists = (
        await session.execute(
            select(ObjectiveLink.id).where(
                ObjectiveLink.organization_id == org,
                ObjectiveLink.objective_id == obj.id,
                ObjectiveLink.entity_type == entity_type,
                ObjectiveLink.entity_id == canonical,
            )
        )
    ).first()
    if exists is None:
        session.add(
            ObjectiveLink(
                organization_id=org,
                objective_id=obj.id,
                entity_type=entity_type,
                entity_id=canonical,
            )
        )
        await _audit(
            session,
            principal,
            org,
            "objective_link_add",
            "objective",
            obj.id,
            {"entity_type": entity_type, "entity_id": canonical, "label": label},
        )
        await session.commit()
    return _see_other(f"/objectives/{obj.id}")


@router.post("/objectives/{objective_id}/links/{link_id}/remove")
async def objective_link_remove(
    objective_id: int,
    link_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*OBJECTIVE_WRITERS)),
) -> RedirectResponse:
    org = _write_org(principal)
    with _refusals():
        obj = await svc.owned(session, StrategicObjective, org, objective_id, "objective")
        link = await svc.owned(session, ObjectiveLink, org, link_id, "objective link")
    if link.objective_id != obj.id:
        raise HTTPException(404, f"no link {link_id} on objective {objective_id}")
    await session.execute(
        delete(ObjectiveLink).where(
            ObjectiveLink.id == link.id, ObjectiveLink.organization_id == org
        )
    )
    await _audit(
        session,
        principal,
        org,
        "objective_link_remove",
        "objective",
        obj.id,
        {"entity_type": link.entity_type, "entity_id": link.entity_id},
    )
    await session.commit()
    return _see_other(f"/objectives/{obj.id}")


# ── Organization settings ────────────────────────────────────────────────────


@router.get("/settings/organization", response_class=HTMLResponse)
async def org_settings_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    record = None
    counts: dict[str, int] = {}
    if org is not None:
        record = (
            await session.execute(
                select(Organization).where(
                    Organization.id == org, Organization.deleted_at.is_(None)
                )
            )
        ).scalar_one_or_none()

        async def count(model: Any, *where: Any) -> int:
            stmt = select(func.count()).select_from(model).where(*where)
            return int((await session.execute(stmt)).scalar_one())

        counts = {
            "Active users": await count(User, User.organization_id == org, User.active.is_(True)),
            "Live systems": await count(System, System.id.in_(posture.org_system_subq(org))),
            "Business units": await count(BusinessUnit, BusinessUnit.organization_id == org),
            "Teams": await count(Team, Team.organization_id == org),
            "Committees": await count(Committee, Committee.organization_id == org),
            "Strategic objectives": await count(
                StrategicObjective, StrategicObjective.organization_id == org
            ),
        }
    return _render(
        request,
        "org_settings.html",
        _active("org_settings", "settings"),
        org=record,
        counts=counts,
        can_admin=_is_admin(request) and record is not None,
    )


@router.post("/settings/organization")
async def org_settings_rename(
    name: str = Form(...),
    organization_id: int | None = Form(None),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*ADMIN)),
) -> RedirectResponse:
    """Rename the caller's own organization. The org is the principal's; a
    posted ``organization_id`` may only confirm it (another is 403)."""
    org = _write_org(principal)
    resolve_caller_org(principal.org_id, organization_id)
    record = (
        await session.execute(
            select(Organization).where(Organization.id == org, Organization.deleted_at.is_(None))
        )
    ).scalar_one_or_none()
    if record is None:
        raise HTTPException(404, "no such organization")
    clean = name.strip()
    if not clean:
        raise HTTPException(400, "an organization needs a name")
    if len(clean) > 255:
        raise HTTPException(400, "an organization name is at most 255 characters")
    previous = record.name
    if clean == previous:
        return _see_other("/settings/organization")
    try:
        async with session.begin_nested():
            record.name = clean
            await session.flush()
    except IntegrityError as exc:
        # Names are unique across the deployment. The holder is another
        # tenant, so it is not named.
        raise HTTPException(400, "that name is already in use; choose another") from exc
    await _audit(
        session,
        principal,
        org,
        "organization_rename",
        "organization",
        org,
        {"name": {"from": previous, "to": clean}},
    )
    await session.commit()
    return _see_other("/settings/organization")
