"""Control assurance and evidence operations (spec section H).

Four reads and one write, each scoped to one organization in the query itself:

* :func:`control_effectiveness` -- per control, the latest automated test
  outcomes on live systems, the latest *final* audit-workpaper conclusion, the
  approved compensating controls in force, and a rating from :func:`rate`.
* :func:`evidence_mapping` -- controls x evidence (repository objects and
  legacy implementation evidence), and baseline controls with none.
* :func:`evidence_expiration` -- expired and expiring evidence objects.
* :func:`request_renewal` -- one renewal task per evidence object, never two.
* :func:`integrations_hub` -- connectors, webhooks, sign-in configuration and
  issue-tracker links, as recorded.

``org_id`` of ``None`` (a global principal, or auth disabled) returns the
unscoped shape rather than every tenant's records mixed together: a rating
over two organizations' tests describes neither.

Tenant predicates are written once per query on purpose. A second, redundant
predicate would survive the mutation check (delete it and the other still
holds), so it would be untested code pretending to be a guard.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..analytics.command_center import TASK_OPEN_STATUSES
from ..analytics.posture import org_system_subq
from ..catalog.baseline_delta import baseline_members
from ..catalog.canonical import canonicalize
from ..config import get_settings
from ..governance.waivers import cover, waivers_for_tests
from ..models import (
    Control,
    ControlImplementation,
    Evidence,
    Organization,
    System,
    Task,
    User,
    Webhook,
)
from ..models_evidence import EvidenceObject
from ..models_grc import (
    ConnectorConfig,
    ControlTest,
    ControlTestResourceResult,
    ControlTestResult,
    ExternalIssueLink,
)
from ..models_identity import GroupRoleMapping, IdentityProvider
from ..models_program import AuditWorkpaper, CompensatingControl
from ..posture.evidence import non_passing_attribution, pass_attribution
from ..posture.latest import latest_result_ids
from ..posture.types import ResourceFinding

# ── control effectiveness ───────────────────────────────────────────────────

#: Test methods whose results a machine produced. ``manual`` tests are a
#: person's record and are not "automated test outcomes" (spec H).
AUTOMATED_METHODS: tuple[str, ...] = ("automated", "connector")

EFFECTIVE = "effective"
INEFFECTIVE = "ineffective"
NOT_DETERMINED = "not_determined"
RATINGS: tuple[str, ...] = (EFFECTIVE, INEFFECTIVE, NOT_DETERMINED)

#: The rule, word for word as the page states it. :func:`rate` is the code;
#: ``tests/test_assure.py`` pins each outcome.
RATING_RULE: dict[str, str] = {
    EFFECTIVE: (
        "At least one automated test has a latest result for the control, every such "
        "latest result is pass, and the latest final audit workpaper conclusion (if "
        "any) is not ineffective."
    ),
    INEFFECTIVE: (
        "A latest automated test result is fail and no waiver in force covers every "
        "failing resource -- or the latest final audit workpaper conclusion is "
        "ineffective. An approved compensating control is shown beside the failure but "
        "does not change the rating: the control as specified still failed, and whether "
        "the substitute works is its own assessment."
    ),
    NOT_DETERMINED: (
        "Anything else: no automated test result, a warn or manual-review result, or a "
        "failure that is formally accepted. Absence of data is never rated effective."
    ),
}

#: Verdicts that are evidence the control is not (or could not be shown to be)
#: operating. They reach every control the check declares; a pass credits only
#: the primary control (``ccf.posture.evidence``).
_NON_PASSING = frozenset({"fail", "warn", "manual_review_required"})


@dataclass(frozen=True)
class Outcome:
    """One latest automated test result as it bears on one control."""

    status: str
    accepted: bool = False


def rate(outcomes: list[Outcome], conclusion: str | None) -> str:
    """The effectiveness rating. See :data:`RATING_RULE`."""
    if conclusion == "ineffective" or any(o.status == "fail" and not o.accepted for o in outcomes):
        return INEFFECTIVE
    if outcomes and all(o.status == "pass" for o in outcomes):
        return EFFECTIVE
    return NOT_DETERMINED


def control_key(raw: str | None) -> str | None:
    """One spelling per control: ``AC-02`` and ``AC-2`` are the same control.

    Identifiers that are not 800-53 ids (CMMC practices) are kept as written,
    trimmed and upper-cased, rather than guessed at."""
    if not raw or not raw.strip():
        return None
    canonical = canonicalize(raw)
    return canonical.value if canonical else raw.strip().upper()


_FAMILY = re.compile(r"^([A-Z]+)")


def family_of(key: str) -> str:
    canonical = canonicalize(key)
    if canonical:
        return canonical.family
    m = _FAMILY.match(key)
    return m.group(1) if m else "—"


def _reason(rating: str, outcomes: list[dict[str, Any]], conclusion: str | None) -> str:
    """Why this control got its rating, in a sentence a reader can check."""
    if rating == INEFFECTIVE:
        parts = []
        unaccepted = sum(1 for o in outcomes if o["status"] == "fail" and not o["accepted"])
        if unaccepted:
            parts.append(f"{unaccepted} failing test{'s' if unaccepted != 1 else ''} not accepted")
        compensated = sum(1 for o in outcomes if o.get("compensated") and not o["accepted"])
        if compensated:
            parts.append(f"{compensated} of them under an approved compensating control")
        if conclusion == "ineffective":
            parts.append("final audit conclusion is ineffective")
        return "; ".join(parts)
    if rating == EFFECTIVE:
        n = len(outcomes)
        return f"all {n} latest automated result{'s' if n != 1 else ''} pass"
    if not outcomes:
        return "no automated test result"
    accepted = sum(1 for o in outcomes if o["status"] == "fail" and o["accepted"])
    other = sum(1 for o in outcomes if o["status"] != "pass" and o["status"] != "fail")
    parts = []
    if accepted:
        parts.append(f"{accepted} failure{'s' if accepted != 1 else ''} formally accepted")
    if other:
        parts.append(f"{other} result{'s' if other != 1 else ''} need a human (warn/manual review)")
    return "; ".join(parts) or "not every latest result passes"


async def _live_systems(session: AsyncSession, org_id: int) -> dict[int, str]:
    return dict(
        (
            await session.execute(
                select(System.id, System.name)
                .where(System.id.in_(org_system_subq(org_id)))
                .order_by(System.name)
            )
        ).all()
    )


async def control_effectiveness(
    session: AsyncSession,
    org_id: int | None,
    *,
    today: date | None = None,
    system_id: int | None = None,
    family: str | None = None,
) -> dict[str, Any]:
    today = today or date.today()
    empty: dict[str, Any] = {
        "scoped": org_id is not None,
        "rows": [],
        "counts": dict.fromkeys(RATINGS, 0),
        "total": 0,
        "systems": {},
        "families": [],
        "rule": RATING_RULE,
    }
    if org_id is None:
        return empty
    systems = await _live_systems(session, org_id)
    empty["systems"] = systems

    latest = latest_result_ids()
    stmt = (
        select(ControlTest, ControlTestResult)
        .join(latest, latest.c.control_test_id == ControlTest.id)
        .join(ControlTestResult, ControlTestResult.id == latest.c.result_id)
        .where(
            # The one tenant predicate: live systems of this organization.
            ControlTest.system_id.in_(org_system_subq(org_id)),
            ControlTest.active.is_(True),
            ControlTest.method.in_(AUTOMATED_METHODS),
        )
        .order_by(ControlTest.id)
    )
    if system_id is not None:
        stmt = stmt.where(ControlTest.system_id == system_id)
    tests = (await session.execute(stmt)).all()

    # Acceptances, decided exactly as the compliance-gaps report decides them.
    failing = [(t, r) for t, r in tests if r.status == "fail"]
    findings: dict[int, list[ResourceFinding]] = defaultdict(list)
    if failing:
        for rid, resource_id, resource_type, verdict, observed in (
            await session.execute(
                select(
                    ControlTestResourceResult.result_id,
                    ControlTestResourceResult.resource_id,
                    ControlTestResourceResult.resource_type,
                    ControlTestResourceResult.verdict,
                    ControlTestResourceResult.observed,
                ).where(ControlTestResourceResult.result_id.in_([r.id for _t, r in failing]))
            )
        ).all():
            findings[rid].append(
                ResourceFinding(
                    resource_id=resource_id,
                    resource_type=resource_type,
                    verdict=verdict,
                    observed=str(observed or ""),
                )
            )
    candidates = await waivers_for_tests(session, [t for t, _r in failing])
    waived = {
        t.id
        for t, r in failing
        if cover(findings.get(r.id, ()), candidates.get(t.id, []), today=today).suppress
    }

    # Approved compensating controls in force, on live systems.
    comp_stmt = (
        select(CompensatingControl)
        .join(System, System.id == CompensatingControl.system_id)
        .where(
            CompensatingControl.organization_id == org_id,
            System.deleted_at.is_(None),
            CompensatingControl.status == "approved",
        )
    )
    if system_id is not None:
        comp_stmt = comp_stmt.where(CompensatingControl.system_id == system_id)
    compensating: dict[str, list[dict[str, Any]]] = defaultdict(list)
    comp_pairs: set[tuple[int, str]] = set()
    for cc in (await session.execute(comp_stmt)).scalars().all():
        key = control_key(cc.control_identifier)
        if key is None or (cc.expires_on is not None and cc.expires_on < today):
            continue
        compensating[key].append(
            {
                "id": cc.id,
                "system": systems.get(cc.system_id, "—"),
                "measure": cc.measure,
                "expires_on": cc.expires_on,
            }
        )
        comp_pairs.add((cc.system_id, key))

    outcomes: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for test, result in tests:
        if result.status == "pass":
            reached = pass_attribution(test.control_id)
        elif result.status in _NON_PASSING:
            reached = non_passing_attribution(test.control_id, test.control_ids)
        else:
            continue  # not_applicable / not_tested say nothing about the control
        for raw in reached:
            key = control_key(raw)
            if key is None:
                continue
            # Accepted means what it means on Compliance Gaps and to the scan
            # (``waivers.cover(...).suppress``). A compensating control is
            # recorded beside it, never as an acceptance: otherwise one failure
            # would be failing on the dashboard and accepted here.
            failed = result.status == "fail"
            accepted = failed and test.id in waived
            compensated = failed and (test.system_id, key) in comp_pairs
            outcomes[key].append(
                {
                    "test_id": test.id,
                    "test": test.name,
                    "system": systems.get(test.system_id or 0, "—"),
                    "status": result.status,
                    "run_at": result.run_at,
                    "accepted": accepted,
                    "compensated": compensated,
                }
            )

    # The latest final workpaper conclusion per control. Organization-wide:
    # an engagement's scope is not tied to one system.
    conclusions: dict[str, dict[str, Any]] = {}
    for wp in (
        (
            await session.execute(
                select(AuditWorkpaper)
                .where(
                    AuditWorkpaper.organization_id == org_id,
                    AuditWorkpaper.status == "final",
                    AuditWorkpaper.control_id.is_not(None),
                )
                .order_by(AuditWorkpaper.reviewed_at.desc().nulls_last(), AuditWorkpaper.id.desc())
            )
        )
        .scalars()
        .all()
    ):
        key = control_key(wp.control_id)
        if key is not None and key not in conclusions:
            conclusions[key] = {
                "id": wp.id,
                "engagement_id": wp.engagement_id,
                "title": wp.title,
                "conclusion": wp.conclusion,
                "reviewed_at": wp.reviewed_at,
                "reviewed_by": wp.reviewed_by,
            }

    keys = set(outcomes) | set(conclusions) | set(compensating)
    families = sorted({family_of(k) for k in keys})
    if family:
        keys = {k for k in keys if family_of(k) == family.upper()}
    rows = []
    for key in sorted(keys):
        outs = outcomes.get(key, [])
        wp = conclusions.get(key)
        conclusion = wp["conclusion"] if wp else None
        rating = rate([Outcome(o["status"], o["accepted"]) for o in outs], conclusion)
        rows.append(
            {
                "control": key,
                "family": family_of(key),
                "rating": rating,
                "reason": _reason(rating, outs, conclusion),
                "outcomes": outs,
                "passing": sum(1 for o in outs if o["status"] == "pass"),
                "failing": sum(1 for o in outs if o["status"] == "fail"),
                "workpaper": wp,
                "compensating": compensating.get(key, []),
            }
        )
    order = {INEFFECTIVE: 0, NOT_DETERMINED: 1, EFFECTIVE: 2}
    rows.sort(key=lambda r: (order[r["rating"]], r["control"]))
    counts = Counter(r["rating"] for r in rows)
    return {
        **empty,
        "rows": rows,
        "counts": {k: counts.get(k, 0) for k in RATINGS},
        "total": len(rows),
        "families": families,
    }


# ── evidence-to-control mapping ─────────────────────────────────────────────


async def evidence_mapping(
    session: AsyncSession, org_id: int | None, *, system_id: int | None = None
) -> dict[str, Any]:
    empty: dict[str, Any] = {
        "scoped": org_id is not None,
        "controls": [],
        "untied": [],
        "gaps": [],
        "systems": {},
        "objects": 0,
        "legacy": 0,
    }
    if org_id is None:
        return empty
    systems = await _live_systems(session, org_id)
    by_control: dict[str, list[dict[str, Any]]] = defaultdict(list)
    untied: list[dict[str, Any]] = []
    #: (system_id, control) pairs that have any evidence -- what closes a gap.
    covered: set[tuple[int, str]] = set()

    objects = 0
    for obj, impl_system, identifier in (
        await session.execute(
            select(EvidenceObject, ControlImplementation.system_id, Control.identifier)
            .outerjoin(
                ControlImplementation,
                ControlImplementation.id == EvidenceObject.implementation_id,
            )
            .outerjoin(Control, Control.id == ControlImplementation.control_id)
            .where(EvidenceObject.organization_id == org_id)
            .order_by(EvidenceObject.id)
        )
    ).all():
        sid = obj.system_id or impl_system
        if sid is not None and sid not in systems:
            continue  # a soft-deleted system's evidence is not this org's current record
        if system_id is not None and sid != system_id:
            continue
        objects += 1
        entry = {
            "kind": "Repository object",
            "id": obj.id,
            "title": obj.title,
            "system": systems.get(sid) if sid is not None else None,
            "status": obj.status,
            "expires_on": obj.expires_on,
            "owner": obj.owner,
            "href": "/evidence",
            "linked": "implementation" if identifier else "tag",
        }
        key = control_key(identifier or obj.control_id)
        if key is None:
            untied.append(entry)
            continue
        by_control[key].append(entry)
        if sid is not None:
            covered.add((sid, key))

    legacy = 0
    legacy_stmt = (
        select(Evidence, ControlImplementation.system_id, Control.identifier)
        .join(ControlImplementation, ControlImplementation.id == Evidence.implementation_id)
        .join(Control, Control.id == ControlImplementation.control_id)
        .where(ControlImplementation.system_id.in_(org_system_subq(org_id)))
        .order_by(Evidence.id)
    )
    if system_id is not None:
        legacy_stmt = legacy_stmt.where(ControlImplementation.system_id == system_id)
    for ev, sid, identifier in (await session.execute(legacy_stmt)).all():
        key = control_key(identifier)
        if key is None:
            continue
        legacy += 1
        by_control[key].append(
            {
                "kind": f"Implementation evidence ({ev.kind})",
                "id": ev.id,
                "title": ev.title,
                "system": systems.get(sid),
                "status": None,
                "expires_on": ev.expires_on,
                "owner": None,
                "href": f"/systems/{sid}",
                "linked": "implementation",
            }
        )
        covered.add((sid, key))

    gaps = []
    baselines: dict[str, set[str]] = {}
    for sid, name in systems.items():
        if system_id is not None and sid != system_id:
            continue
        system = await session.get(System, sid)
        raw: object = system.baseline if system is not None else None
        level = str(getattr(raw, "value", raw) or "")
        if not level:
            gaps.append({"system_id": sid, "system": name, "baseline": None, "missing": None})
            continue
        if level not in baselines:
            baselines[level] = await baseline_members(session, level)
        members = baselines[level]
        missing = sorted(c for c in members if (sid, c) not in covered)
        gaps.append(
            {
                "system_id": sid,
                "system": name,
                "baseline": level,
                "size": len(members),
                "missing": missing,
            }
        )

    return {
        **empty,
        "systems": systems,
        "controls": [{"control": k, "evidence": v} for k, v in sorted(by_control.items())],
        "untied": untied,
        "gaps": gaps,
        "objects": objects,
        "legacy": legacy,
    }


# ── evidence expiration and renewal ─────────────────────────────────────────

#: Upper bounds (days from today, inclusive) of the "expiring" buckets.
WINDOWS: tuple[int, ...] = (30, 60, 90)

RENEWAL_KIND = "evidence_renewal"


def renewal_key(obj_id: int) -> str:
    """The dedupe key: one renewal task per evidence object, ever, reopened
    when renewal is requested again after the previous request closed."""
    return f"evidence-renewal:{obj_id}"


def bucket(expires_on: date, today: date) -> str | None:
    if expires_on < today:
        return "expired"
    days = (expires_on - today).days
    for w in WINDOWS:
        if days <= w:
            return f"within_{w}"
    return None


async def owner_user_id(session: AsyncSession, org_id: int, owner: str | None) -> int | None:
    """The active user of ``org_id`` whose email is the evidence owner, if any.

    Only an email resolves: ``owner`` is free text, and a display name is not
    unique enough to hand someone work."""
    if not owner or not owner.strip():
        return None
    return (
        await session.execute(
            select(User.id).where(
                User.organization_id == org_id,
                User.active.is_(True),
                func.lower(User.email) == owner.strip().lower(),
            )
        )
    ).scalar_one_or_none()


async def evidence_expiration(
    session: AsyncSession, org_id: int | None, *, today: date | None = None
) -> dict[str, Any]:
    today = today or date.today()
    empty: dict[str, Any] = {
        "scoped": org_id is not None,
        "rows": [],
        "counts": {"expired": 0, **{f"within_{w}": 0 for w in WINDOWS}},
        "windows": WINDOWS,
        "today": today,
    }
    if org_id is None:
        return empty
    systems = await _live_systems(session, org_id)
    horizon = today + timedelta(days=WINDOWS[-1])
    objs = (
        (
            await session.execute(
                select(EvidenceObject)
                .where(
                    EvidenceObject.organization_id == org_id,
                    EvidenceObject.expires_on.is_not(None),
                    EvidenceObject.expires_on <= horizon,
                )
                .order_by(EvidenceObject.expires_on, EvidenceObject.id)
            )
        )
        .scalars()
        .all()
    )
    objs = [o for o in objs if o.system_id is None or o.system_id in systems]
    tasks: dict[str, Task] = {}
    if objs:
        tasks = {
            t.dedupe_key: t
            for t in (
                await session.execute(
                    select(Task).where(
                        Task.organization_id == org_id,
                        Task.dedupe_key.in_([renewal_key(o.id) for o in objs]),
                    )
                )
            )
            .scalars()
            .all()
            if t.dedupe_key
        }
    owners = {o.owner.strip().lower() for o in objs if o.owner and o.owner.strip()}
    users: dict[str, int] = {}
    if owners:
        users = {
            email.lower(): uid
            for uid, email in (
                await session.execute(
                    select(User.id, User.email).where(
                        User.organization_id == org_id,
                        User.active.is_(True),
                        func.lower(User.email).in_(owners),
                    )
                )
            ).all()
        }
    rows = []
    counts = Counter()
    for o in objs:
        b = bucket(o.expires_on, today)  # type: ignore[arg-type]
        if b is None:
            continue
        counts[b] += 1
        task = tasks.get(renewal_key(o.id))
        rows.append(
            {
                "id": o.id,
                "title": o.title,
                "control": o.control_id,
                "system": systems.get(o.system_id) if o.system_id else None,
                "owner": o.owner,
                "owner_is_user": bool(o.owner and o.owner.strip().lower() in users),
                "status": o.status,
                "expires_on": o.expires_on,
                "days": (o.expires_on - today).days,  # type: ignore[operator]
                "bucket": b,
                "task": task if task is not None and task.status in TASK_OPEN_STATUSES else None,
            }
        )
    return {**empty, "rows": rows, "counts": {k: counts.get(k, 0) for k in empty["counts"]}}


class EvidenceNotFoundError(LookupError):
    """The evidence object does not exist for this caller."""


class UnassignableError(ValueError):
    """The evidence object belongs to no organization, so no task can hold it."""


async def request_renewal(
    session: AsyncSession, *, obj_id: int, principal_org: int | None
) -> tuple[Task, bool]:
    """Open (or keep) the renewal task for one evidence object.

    Returns ``(task, created)``; ``created`` is False when an open renewal task
    already existed, which is the deduplication: a second click changes
    nothing. The task belongs to the evidence object's organization (the
    caller's, when the caller is scoped -- another organization's object is
    :class:`EvidenceNotFoundError`), and is assigned only to an active user of that
    organization whose email is the owner; otherwise it is left unassigned.
    """
    stmt = select(EvidenceObject).where(EvidenceObject.id == obj_id)
    if principal_org is not None:
        stmt = stmt.where(EvidenceObject.organization_id == principal_org)
    obj = (await session.execute(stmt)).scalar_one_or_none()
    if obj is None:
        raise EvidenceNotFoundError(obj_id)
    if obj.organization_id is None:
        raise UnassignableError(obj_id)
    org_id = obj.organization_id
    if obj.system_id is not None:
        live = (
            await session.execute(
                select(System.id).where(
                    System.id == obj.system_id, System.id.in_(org_system_subq(org_id))
                )
            )
        ).scalar_one_or_none()
        if live is None:
            raise EvidenceNotFoundError(obj_id)

    key = renewal_key(obj.id)
    assignee = await owner_user_id(session, org_id, obj.owner)
    expired = obj.expires_on is not None and obj.expires_on < date.today()
    description = f"Evidence object {obj.id} ({obj.control_id or 'no control tag'}) " + (
        f"expired on {obj.expires_on}." if expired else f"expires on {obj.expires_on}."
    )
    if assignee is None:
        description += (
            f" Owner {obj.owner!r} is not an active user of this organization;"
            if obj.owner
            else " The object has no owner;"
        ) + " the task is unassigned."
    fields = {
        "title": f"Renew evidence: {obj.title}"[:512],
        "description": description,
        "priority": "high" if expired else "medium",
        "assignee_user_id": assignee,
        "due_on": obj.expires_on,
    }
    existing = (
        await session.execute(select(Task).where(Task.dedupe_key == key))
    ).scalar_one_or_none()
    if existing is not None:
        if existing.organization_id != org_id:
            raise EvidenceNotFoundError(obj_id)
        if existing.status in TASK_OPEN_STATUSES:
            return existing, False
        for k, v in fields.items():
            setattr(existing, k, v)
        existing.status = "open"
        existing.closed_at = None
        await session.flush()
        return existing, True
    task = Task(
        organization_id=org_id,
        kind=RENEWAL_KIND,
        status="open",
        system_id=obj.system_id,
        entity_type="evidence_object",
        entity_id=str(obj.id),
        source="manual",
        dedupe_key=key,
        **fields,
    )
    try:
        async with session.begin_nested():
            session.add(task)
            await session.flush()
    except IntegrityError:
        # A concurrent click won the unique dedupe key; theirs is the task.
        winner = (await session.execute(select(Task).where(Task.dedupe_key == key))).scalar_one()
        return winner, False
    return task, True


# ── integrations hub ────────────────────────────────────────────────────────


async def integrations_hub(session: AsyncSession, org_id: int | None) -> dict[str, Any]:
    s = get_settings()
    out: dict[str, Any] = {
        "scoped": org_id is not None,
        "connectors": [],
        "webhooks": [],
        "issue_links": [],
        "sso": {
            "oidc_enabled": s.oidc_enabled,
            "issuer": s.oidc_issuer if s.oidc_enabled else None,
            "scim_enabled": s.scim_enabled,
            "piv_enabled": s.piv_enabled,
            "jit": s.auth_jit_provisioning,
            "idp_records": 0,
            "idp_enabled": 0,
            "group_mappings": 0,
            "mfa_policy": None,
        },
    }
    if org_id is None:
        return out
    out["connectors"] = [
        {
            "id": c.id,
            "name": c.name,
            "type": c.connector_type,
            "status": c.status,
            "last_sync": c.last_sync,
            "readiness": c.readiness_status,
            "has_credential": c.key_last4 is not None,
        }
        for c in (
            await session.execute(
                select(ConnectorConfig)
                .where(ConnectorConfig.organization_id == org_id)
                .order_by(ConnectorConfig.name)
            )
        )
        .scalars()
        .all()
    ]
    # The secret is reduced to a yes/no here and never leaves this function.
    out["webhooks"] = [
        {
            "id": w.id,
            "url": w.url,
            "events": list(w.events or []),
            "active": w.active,
            "signed": bool(w.secret),
            "created_at": w.created_at,
        }
        for w in (
            await session.execute(
                select(Webhook).where(Webhook.organization_id == org_id).order_by(Webhook.id)
            )
        )
        .scalars()
        .all()
    ]
    links: dict[str, Counter[str]] = defaultdict(Counter)
    for provider, status, n in (
        await session.execute(
            select(ExternalIssueLink.provider, ExternalIssueLink.last_status, func.count())
            .where(ExternalIssueLink.organization_id == org_id)
            .group_by(ExternalIssueLink.provider, ExternalIssueLink.last_status)
        )
    ).all():
        links[provider][status] += int(n)
    out["issue_links"] = [
        {
            "provider": p,
            "total": sum(c.values()),
            "ok": c.get("ok", 0),
            "failed": c.get("failed", 0),
        }
        for p, c in sorted(links.items())
    ]
    idps = (
        (
            await session.execute(
                select(IdentityProvider.enabled).where(IdentityProvider.organization_id == org_id)
            )
        )
        .scalars()
        .all()
    )
    out["sso"]["idp_records"] = len(idps)
    out["sso"]["idp_enabled"] = sum(1 for e in idps if e)
    out["sso"]["group_mappings"] = int(
        (
            await session.execute(
                select(func.count())
                .select_from(GroupRoleMapping)
                .where(GroupRoleMapping.organization_id == org_id)
            )
        ).scalar_one()
    )
    org = await session.get(Organization, org_id)
    if org is not None:
        raw: object = org.mfa_policy
        out["sso"]["mfa_policy"] = str(getattr(raw, "value", raw))
    return out


__all__ = [
    "AUTOMATED_METHODS",
    "EFFECTIVE",
    "INEFFECTIVE",
    "NOT_DETERMINED",
    "RATINGS",
    "RATING_RULE",
    "EvidenceNotFoundError",
    "Outcome",
    "UnassignableError",
    "bucket",
    "control_effectiveness",
    "control_key",
    "evidence_expiration",
    "evidence_mapping",
    "integrations_hub",
    "owner_user_id",
    "rate",
    "renewal_key",
    "request_renewal",
]
