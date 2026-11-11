"""Organization structure and governance bodies: business units, teams,
committees and strategic objectives.

Every lookup here takes the caller's organization and refuses a record that is
not in it with :class:`NotInOrganizationError` (the routes answer 404, so another
tenant's id is indistinguishable from one that does not exist). Ids arrive in
form bodies -- a parent unit, an owner, a system, a linked risk -- and none of
them is trusted for ownership: each is looked up and its organization checked,
never assumed from the record it is being attached to.

Nothing here invents a value. A committee's open actions are the decisions its
minutes recorded with a due date and no closure; an objective's status is what
a person set, and every change is an event.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from datetime import date
from itertools import zip_longest
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..analytics import posture
from ..models import Control, Policy, Risk, System, User
from ..models_program import BusinessUnit, KeyRiskIndicator

#: ``StrategicObjective.status`` vocabulary, in the order a reader scans it.
OBJECTIVE_STATUSES: tuple[str, ...] = (
    "planned",
    "on_track",
    "at_risk",
    "off_track",
    "achieved",
    "retired",
)
#: What an objective may be linked to (``ObjectiveLink.entity_type``).
LINK_TYPES: tuple[str, ...] = ("risk", "control", "system", "policy", "kri")
TEAM_ROLES: tuple[str, ...] = ("lead", "member")
#: The chair is ``Committee.chair_user_id``, one person; members are the rest.
COMMITTEE_ROLES: tuple[str, ...] = ("secretary", "member")
CADENCES: tuple[str, ...] = ("weekly", "monthly", "quarterly", "semiannual", "annual", "ad_hoc")


class NotInOrganizationError(LookupError):
    """The id names nothing in the caller's organization (routes answer 404)."""


class RefusedError(ValueError):
    """A well-formed request that would leave a record invalid (routes answer 400)."""


# ── Ownership checks ─────────────────────────────────────────────────────────


async def owned[M](session: AsyncSession, model: type[M], org: int, record_id: int, what: str) -> M:
    """The ``model`` row ``record_id`` iff its ``organization_id`` is ``org``."""
    row = (
        await session.execute(
            select(model).where(
                model.id == record_id,  # type: ignore[attr-defined]
                model.organization_id == org,  # type: ignore[attr-defined]
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise NotInOrganizationError(f"no {what} {record_id} in this organization")
    return row


async def user_in_org(session: AsyncSession, org: int, user_id: int) -> User:
    """An active user of ``org``; anyone else is refused as not found."""
    user = (
        await session.execute(
            select(User).where(
                User.id == user_id, User.organization_id == org, User.active.is_(True)
            )
        )
    ).scalar_one_or_none()
    if user is None:
        raise NotInOrganizationError(f"no user {user_id} in this organization")
    return user


async def live_system(session: AsyncSession, org: int, system_id: int) -> System:
    """A system of ``org`` that has not been deleted."""
    sys = (
        await session.execute(
            select(System).where(
                System.id == system_id,
                System.organization_id == org,
                System.deleted_at.is_(None),
            )
        )
    ).scalar_one_or_none()
    if sys is None:
        raise NotInOrganizationError(f"no system {system_id} in this organization")
    return sys


async def org_users(session: AsyncSession, org: int | None) -> list[User]:
    """Active users to offer in a picker (``None``: unscoped, auth disabled)."""
    stmt = select(User).where(User.active.is_(True)).order_by(User.email)
    if org is not None:
        stmt = stmt.where(User.organization_id == org)
    return list((await session.execute(stmt)).scalars())


def user_label(user: User | None) -> str | None:
    return None if user is None else (user.full_name or user.email)


# ── Business-unit tree ───────────────────────────────────────────────────────


async def unit_parents(session: AsyncSession, org: int) -> dict[int, int | None]:
    rows = (
        await session.execute(
            select(BusinessUnit.id, BusinessUnit.parent_id).where(
                BusinessUnit.organization_id == org
            )
        )
    ).all()
    return {r.id: r.parent_id for r in rows}


def creates_cycle(parents: dict[int, int | None], unit_id: int, parent_id: int | None) -> bool:
    """Whether making ``parent_id`` the parent of ``unit_id`` closes a loop.

    Walks up from the proposed parent; reaching ``unit_id`` means the unit would
    become its own ancestor. The walk stops on a repeat, so a loop already in the
    data cannot hang it."""
    seen: set[int] = set()
    node = parent_id
    while node is not None and node not in seen:
        if node == unit_id:
            return True
        seen.add(node)
        node = parents.get(node)
    return False


def descendants(parents: dict[int, int | None], unit_id: int) -> set[int]:
    """Every unit below ``unit_id`` (not including it)."""
    children: dict[int | None, list[int]] = defaultdict(list)
    for uid, pid in parents.items():
        children[pid].append(uid)
    out: set[int] = set()
    stack = list(children.get(unit_id, []))
    while stack:
        uid = stack.pop()
        if uid in out or uid == unit_id:
            continue
        out.add(uid)
        stack.extend(children.get(uid, []))
    return out


async def check_parent(
    session: AsyncSession, org: int, unit_id: int | None, parent_id: int | None
) -> None:
    """Refuse a parent outside the org, the unit itself, or one of its descendants."""
    if parent_id is None:
        return
    await owned(session, BusinessUnit, org, parent_id, "business unit")
    if unit_id is None:
        return
    if parent_id == unit_id:
        raise RefusedError("a business unit cannot be its own parent")
    if creates_cycle(await unit_parents(session, org), unit_id, parent_id):
        raise RefusedError(
            "that parent is below this unit in the tree; making it the parent would create a cycle"
        )


def unit_tree(units: Sequence[BusinessUnit]) -> list[tuple[BusinessUnit, int]]:
    """Units in depth-first order with their depth, siblings by name.

    A unit whose parent is not in ``units`` is shown as a root, and any unit not
    reached from a root (only possible if a loop got into the data) is appended
    at depth 0 rather than dropped."""
    by_id = {u.id: u for u in units}
    children: dict[int | None, list[BusinessUnit]] = defaultdict(list)
    for u in units:
        parent = u.parent_id if u.parent_id in by_id else None
        children[parent].append(u)
    for kids in children.values():
        kids.sort(key=lambda u: u.name.lower())
    out: list[tuple[BusinessUnit, int]] = []
    seen: set[int] = set()

    def walk(parent: int | None, depth: int) -> None:
        for u in children.get(parent, []):
            if u.id in seen:
                continue
            seen.add(u.id)
            out.append((u, depth))
            walk(u.id, depth + 1)

    walk(None, 0)
    for u in sorted(units, key=lambda u: u.name.lower()):
        if u.id not in seen:
            seen.add(u.id)
            out.append((u, 0))
    return out


def rollup(parents: dict[int, int | None], direct: dict[int, int]) -> dict[int, int]:
    """Each unit's count including every unit below it."""
    return {
        uid: direct.get(uid, 0) + sum(direct.get(d, 0) for d in descendants(parents, uid))
        for uid in parents
    }


# ── Committees ───────────────────────────────────────────────────────────────


def parse_date(value: str | None, what: str) -> date | None:
    value = (value or "").strip()
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise RefusedError(f"{what} must be a date (YYYY-MM-DD), not {value!r}") from exc


def parse_id(value: str | None, what: str) -> int | None:
    value = (value or "").strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError as exc:
        raise RefusedError(f"{what} must be a record id, not {value!r}") from exc


async def build_decisions(
    session: AsyncSession,
    org: int,
    texts: Iterable[str],
    owners: Iterable[str],
    dues: Iterable[str],
) -> list[dict[str, Any]]:
    """Decision rows from the meeting form's parallel lists.

    A row with no text is a blank form row and is skipped; a row with an owner
    or due date but no text is refused, since it would record an action nobody
    can read. Each owner must be a user of the org."""
    out: list[dict[str, Any]] = []
    # Padded, not truncated: a client that omits a column must not silently
    # drop the decisions it did send.
    for raw_text, owner, due in zip_longest(texts, owners, dues, fillvalue=""):
        text = (raw_text or "").strip()
        owner_id = parse_id(owner, "decision owner")
        due_on = parse_date(due, "decision due date")
        if not text:
            if owner_id is not None or due_on is not None:
                raise RefusedError("a decision with an owner or due date needs its text")
            continue
        if owner_id is not None:
            await user_in_org(session, org, owner_id)
        out.append(
            {
                "text": text,
                "owner_user_id": owner_id,
                "due_on": due_on.isoformat() if due_on else None,
                "closed_on": None,
                "closed_by": None,
            }
        )
    return out


def open_actions(meetings: Iterable[Any], today: date) -> list[dict[str, Any]]:
    """Decisions with a due date and no closure, earliest due first.

    A decision without a due date is a decision, not an action, and is not
    listed. ``overdue`` is due before ``today``."""
    out: list[dict[str, Any]] = []
    for m in meetings:
        for idx, d in enumerate(m.decisions or []):
            if not isinstance(d, dict) or not d.get("due_on") or d.get("closed_on"):
                continue
            due = date.fromisoformat(d["due_on"])
            out.append(
                {
                    "meeting": m,
                    "index": idx,
                    "text": d.get("text", ""),
                    "owner_user_id": d.get("owner_user_id"),
                    "due_on": due,
                    "overdue": due < today,
                }
            )
    out.sort(key=lambda a: a["due_on"])
    return out


# ── Objective links ──────────────────────────────────────────────────────────


def risk_in_org(org: int | None) -> Any:
    """A risk the org owns: an enterprise risk (no system) owned directly, or a
    risk on one of the org's **live** systems -- never one on a deleted system.

    Since 0100 a trigger keeps ``Risk.organization_id`` equal to its system's,
    so the system branch alone decides system risks; checking the org column
    there too would admit a risk whose system was soft-deleted.

    The one definition is ``posture.risk_in_scope``; this name is kept for
    the callers here."""
    return posture.risk_in_scope(org)


async def resolve_link(
    session: AsyncSession, org: int, entity_type: str, entity_id: str
) -> tuple[str, str]:
    """The canonical id and a label for a link target the caller may link.

    Risks are the org's enterprise risks or risks on its live systems
    (:func:`risk_in_org`); systems must be live; policies and KRIs must be the
    org's own. Controls are the shared catalog, matched on the exact
    identifier."""
    raw = (entity_id or "").strip()
    if entity_type not in LINK_TYPES:
        raise RefusedError(f"cannot link an objective to {entity_type!r}")
    if not raw:
        raise RefusedError("choose a record to link")
    if entity_type == "control":
        row = (
            await session.execute(
                select(Control.identifier, Control.control_name).where(Control.identifier == raw)
            )
        ).first()
        if row is None:
            raise NotInOrganizationError(f"no control {raw!r} in the catalog")
        return row.identifier, f"{row.identifier} — {row.control_name or ''}".rstrip(" —")
    rid = parse_id(raw, entity_type)
    assert rid is not None
    if entity_type == "risk":
        risk = (
            await session.execute(select(Risk).where(Risk.id == rid, risk_in_org(org)))
        ).scalar_one_or_none()
        if risk is None:
            raise NotInOrganizationError(f"no risk {rid} in this organization")
        return str(risk.id), risk.title
    if entity_type == "system":
        return str(rid), (await live_system(session, org, rid)).name
    if entity_type == "policy":
        return str(rid), (await owned(session, Policy, org, rid, "policy")).name
    kri = await owned(session, KeyRiskIndicator, org, rid, "KRI")
    return str(rid), kri.name


async def link_labels(
    session: AsyncSession, org: int | None, links: Iterable[Any]
) -> dict[tuple[str, str], tuple[str, str] | None]:
    """``(type, id) -> (label, href)`` for each link, ``None`` when the target is
    gone or no longer in the org (a deleted system, a removed policy)."""
    out: dict[tuple[str, str], tuple[str, str] | None] = {}
    for link in links:
        key = (link.entity_type, link.entity_id)
        if org is None:
            out[key] = (f"{link.entity_type} {link.entity_id}", "#")
            continue
        try:
            _, label = await resolve_link(session, org, link.entity_type, link.entity_id)
        except (NotInOrganizationError, RefusedError):
            out[key] = None
            continue
        href = {
            "risk": f"/risks/{link.entity_id}",
            "control": f"/controls/{link.entity_id}",
            "system": f"/systems/{link.entity_id}",
            "policy": f"/policies#policy-{link.entity_id}",
            "kri": "/kri",
        }[link.entity_type]
        out[key] = (label, href)
    return out
