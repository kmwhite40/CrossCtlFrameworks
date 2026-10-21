"""Risk appetite and key risk indicators (workstream B of the GRC build-out).

Spec: docs/superpowers/specs/2026-10-20-grc-buildout-design.md, "B — risk".

* ``/risk-appetite``: appetite statements per risk category, with a default
  (NULL category) for every category without one; admin-only writes. Lists
  the **breaches** -- open and mitigated risks on live systems whose residual
  score is above the appetite that applies to them.
* ``/kri``: key risk indicators with their latest reading and status against
  warn/critical thresholds read in the KRI's ``direction``, a sparkline of the
  readings, the history, manual readings, and "compute now" for computed KRIs
  (``governance.kri.METRICS``).

Both pages carry the navigation key ``kri`` (the rail's "Risk Appetite &
KRIs" entry owns both).

Risk program (0100):

* ``/risks/{id}``: one risk with its assessment history and treatment plans;
  record an assessment (qualitative 1-5 and/or quantitative SLE and ARO; ALE
  is computed); the latest qualitative assessment sets the risk's scores.
* ``/risks/assessments`` (key ``risk_assess``): the quantitative register --
  ALE per risk and the total -- and recent assessments.
* ``/risks/treatment`` (key ``risk_treat``): treatment plans with actions and
  progress (done actions over actions); an action may link a POA&M on a live
  system of the caller's organization.

Tenant scope is explicit in every query: every table here has its own
``organization_id`` and is filtered on it; risks are scoped by
``governance.risk.risk_in_scope`` (a live system of the organization, or a
system-less risk it owns) and POA&Ms through a live system
(``posture.org_system_subq``). Every id a form names -- a statement, a
KRI, an owner, a linked risk -- is looked up in the caller's organization and
is a 404 otherwise. Every write is role-gated on the route and audited with
``record_event``.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from datetime import date
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...analytics.posture import org_system_subq
from ...auth import Principal
from ...governance import kri as kri_engine
from ...governance.risk import (
    ACTION_STATUSES,
    IMPACT_LABELS,
    LIKELIHOOD_LABELS,
    PLAN_STATUSES,
    SCALE,
    STRATEGIES,
    ale,
    appetite_placements,
    assessment_method,
    band,
    category_key,
    compute_scores,
    effective_scores,
    plan_progress,
    risk_in_scope,
    score_to_level,
)
from ...models import POAM, Risk, System, User
from ...models_program import (
    KeyRiskIndicator,
    KriReading,
    RiskAppetite,
    RiskAssessment,
    RiskTreatmentAction,
    RiskTreatmentPlan,
)
from ..audit import record_event
from ..auth_deps import require_role
from ..deps import get_session
from .risks import _post_write, _rescore
from .ui import _principal_org, no_org_page, templates

router = APIRouter(include_in_schema=False)

#: Appetite is an organization-level decision.
APPETITE_ROLES = ("admin",)
#: Defining what is measured, and its thresholds.
KRI_EDIT_ROLES = ("admin", "control_owner")
#: Entering a measured value is record maintenance.
KRI_READING_ROLES = ("admin", "control_owner", "assessor")
#: Assessing a risk and maintaining its treatment are records people keep.
ASSESS_ROLES = ("admin", "control_owner", "assessor")
TREAT_ROLES = ("admin", "control_owner", "assessor")

ACTIVE = "kri"


# ── helpers ──────────────────────────────────────────────────────────────────


def _org_of(principal: Principal) -> int:
    """The caller's organization; a write without one has nowhere to land."""
    if principal.org_id is None:
        raise HTTPException(400, "this action needs an organization; sign in as a member of one")
    return principal.org_id


def _back(path: str, error: str | None = None) -> RedirectResponse:
    if error:
        base, _, frag = path.partition("#")
        sep = "&" if "?" in base else "?"
        url = f"{base}{sep}error={quote(error)}" + (f"#{frag}" if frag else "")
        return RedirectResponse(url, status_code=303)
    return RedirectResponse(path, status_code=303)


def _plain(v: Any) -> Any:
    return v.isoformat() if isinstance(v, date) else v


def _opt_int(raw: str, field: str) -> int | None:
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{field} must be a whole number") from exc


def _opt_float(raw: str, field: str) -> float | None:
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{field} must be a number") from exc
    if not math.isfinite(value):
        raise ValueError(f"{field} must be a finite number")
    return value


def _opt_date(raw: str, field: str) -> date | None:
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        return date.fromisoformat(raw)
    except ValueError as exc:
        raise ValueError(f"{field} must be a date (YYYY-MM-DD)") from exc


async def _org_user(session: AsyncSession, org_id: int, user_id: int | None) -> int | None:
    """``user_id`` if it is a user of ``org_id``; 404 otherwise."""
    if user_id is None:
        return None
    found = (
        await session.execute(
            select(User.id).where(User.id == user_id, User.organization_id == org_id)
        )
    ).scalar_one_or_none()
    if found is None:
        raise HTTPException(404, "owner not found")
    return found


async def _org_risk(session: AsyncSession, org_id: int, risk_id: int | None) -> int | None:
    """``risk_id`` if the risk is ``org_id``'s (``risk_in_scope``); 404 otherwise."""
    if risk_id is None:
        return None
    found = (
        await session.execute(select(Risk.id).where(Risk.id == risk_id, risk_in_scope(org_id)))
    ).scalar_one_or_none()
    if found is None:
        raise HTTPException(404, "risk not found")
    return found


async def _org_users(session: AsyncSession, org_id: int | None) -> list[Any]:
    if org_id is None:
        return []
    return list(
        (
            await session.execute(
                select(User.id, User.full_name, User.email)
                .where(User.organization_id == org_id, User.active.is_(True))
                .order_by(User.email)
            )
        ).all()
    )


def _names(users: list[Any]) -> dict[int, str]:
    return {u.id: (u.full_name or u.email) for u in users}


# ── Risk appetite ────────────────────────────────────────────────────────────


async def _load_appetite(session: AsyncSession, org_id: int, appetite_id: int) -> RiskAppetite:
    row = (
        await session.execute(
            select(RiskAppetite).where(
                RiskAppetite.id == appetite_id, RiskAppetite.organization_id == org_id
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "appetite statement not found")
    return row


async def _category_taken(
    session: AsyncSession, org_id: int, category: str | None, *, except_id: int | None = None
) -> bool:
    """Whether another statement already covers ``category`` (NULL = the default).

    Checked here because the database's unique constraint cannot see it: two
    NULL categories are distinct to Postgres, and "Technical" and "technical"
    are different strings that appetite matching reads as one category."""
    rows = (
        await session.execute(
            select(RiskAppetite.id, RiskAppetite.category).where(
                RiskAppetite.organization_id == org_id
            )
        )
    ).all()
    key = category_key(category)
    return any(r.id != except_id and category_key(r.category) == key for r in rows)


def _appetite_fields(
    category: str, statement: str, max_residual_score: str, owner_user_id: str, review_on: str
) -> dict[str, Any]:
    statement = statement.strip()
    if not statement:
        raise ValueError("an appetite statement needs its text")
    score = _opt_int(max_residual_score, "the maximum residual score")
    if score is None or not 1 <= score <= 25:
        raise ValueError("the maximum residual score must be 1-25, the residual score's scale")
    cat = " ".join(category.split()) or None
    if cat is not None and len(cat) > 64:
        raise ValueError("a category is at most 64 characters")
    return {
        "category": cat,
        "statement": statement,
        "max_residual_score": score,
        "owner_user_id": _opt_int(owner_user_id, "owner"),
        "review_on": _opt_date(review_on, "the review date"),
    }


@router.get("/risk-appetite", response_class=HTMLResponse)
async def risk_appetite_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    statements: list[RiskAppetite] = []
    breaches: list[dict[str, Any]] = []
    counts = {"breach": 0, "within": 0, "unscored": 0, "no_appetite": 0}
    users: list[Any] = []
    if org is not None:
        statements = list(
            (
                await session.execute(
                    select(RiskAppetite)
                    .where(RiskAppetite.organization_id == org)
                    .order_by(RiskAppetite.category.is_not(None), RiskAppetite.category)
                )
            )
            .scalars()
            .all()
        )
        placements = await appetite_placements(session, org)
        for p in placements.values():
            counts[p.state] += 1
        breach_ids = [rid for rid, p in placements.items() if p.state == "breach"]
        if breach_ids:
            rows = (
                await session.execute(
                    select(Risk, System.name.label("system"))
                    .outerjoin(System, System.id == Risk.system_id)
                    .where(Risk.id.in_(breach_ids), risk_in_scope(org))
                )
            ).all()
            for row in rows:
                breaches.append(
                    {"risk": row.Risk, "system": row.system, "placement": placements[row.Risk.id]}
                )
            breaches.sort(key=lambda b: (-(b["placement"].over_by or 0), b["risk"].id))
        users = await _org_users(session, org)
    return templates.TemplateResponse(
        request,
        "risk_appetite.html",
        {
            "active": ACTIVE,
            "scoped": org is not None,
            "statements": statements,
            "has_default": any(s.category is None for s in statements),
            "breaches": breaches,
            "counts": counts,
            "active_total": sum(counts.values()),
            "users": users,
            "user_names": _names(users),
            "error": request.query_params.get("error"),
        },
    )


@router.post("/risk-appetite")
async def risk_appetite_create(
    *,
    category: str = Form(""),
    statement: str = Form(""),
    max_residual_score: str = Form(""),
    owner_user_id: str = Form(""),
    review_on: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*APPETITE_ROLES)),
) -> RedirectResponse:
    org = _org_of(principal)
    try:
        fields = _appetite_fields(category, statement, max_residual_score, owner_user_id, review_on)
    except ValueError as exc:
        return _back("/risk-appetite", str(exc))
    fields["owner_user_id"] = await _org_user(session, org, fields["owner_user_id"])
    if await _category_taken(session, org, fields["category"]):
        which = f"category {fields['category']!r}" if fields["category"] else "the default"
        return _back("/risk-appetite", f"{which} already has a statement; edit that one")
    row = RiskAppetite(organization_id=org, **fields)
    session.add(row)
    await session.flush()
    await record_event(
        session,
        actor=principal.email,
        action="risk_appetite_created",
        entity_type="risk_appetite",
        entity_id=str(row.id),
        diff={k: _plain(v) for k, v in fields.items()},
        organization_id=org,
    )
    await session.commit()
    return _back("/risk-appetite")


@router.post("/risk-appetite/{appetite_id}")
async def risk_appetite_update(
    appetite_id: int,
    *,
    category: str = Form(""),
    statement: str = Form(""),
    max_residual_score: str = Form(""),
    owner_user_id: str = Form(""),
    review_on: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*APPETITE_ROLES)),
) -> RedirectResponse:
    org = _org_of(principal)
    row = await _load_appetite(session, org, appetite_id)
    try:
        fields = _appetite_fields(category, statement, max_residual_score, owner_user_id, review_on)
    except ValueError as exc:
        return _back("/risk-appetite", str(exc))
    fields["owner_user_id"] = await _org_user(session, org, fields["owner_user_id"])
    if await _category_taken(session, org, fields["category"], except_id=row.id):
        which = f"category {fields['category']!r}" if fields["category"] else "the default"
        return _back("/risk-appetite", f"{which} already has a statement; edit that one")
    before = {k: getattr(row, k) for k in fields}
    for k, v in fields.items():
        setattr(row, k, v)
    await session.flush()
    await record_event(
        session,
        actor=principal.email,
        action="risk_appetite_updated",
        entity_type="risk_appetite",
        entity_id=str(row.id),
        diff={
            k: {"from": _plain(before[k]), "to": _plain(v)}
            for k, v in fields.items()
            if before[k] != v
        },
        organization_id=org,
    )
    await session.commit()
    return _back("/risk-appetite")


@router.post("/risk-appetite/{appetite_id}/delete")
async def risk_appetite_delete(
    appetite_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*APPETITE_ROLES)),
) -> RedirectResponse:
    org = _org_of(principal)
    row = await _load_appetite(session, org, appetite_id)
    snapshot = {
        "category": row.category,
        "statement": row.statement,
        "max_residual_score": row.max_residual_score,
    }
    await session.delete(row)
    await session.flush()
    await record_event(
        session,
        actor=principal.email,
        action="risk_appetite_deleted",
        entity_type="risk_appetite",
        entity_id=str(appetite_id),
        diff=snapshot,
        organization_id=org,
    )
    await session.commit()
    return _back("/risk-appetite")


# ── Key risk indicators ──────────────────────────────────────────────────────


async def _load_kri(session: AsyncSession, org_id: int, kri_id: int) -> KeyRiskIndicator:
    row = (
        await session.execute(
            select(KeyRiskIndicator).where(
                KeyRiskIndicator.id == kri_id, KeyRiskIndicator.organization_id == org_id
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "key risk indicator not found")
    return row


def _kri_fields(
    *,
    name: str,
    description: str,
    metric_key: str,
    unit: str,
    direction: str,
    warn_threshold: str,
    critical_threshold: str,
    owner_user_id: str,
    risk_id: str,
    active: str,
) -> dict[str, Any]:
    name = name.strip()
    if not name:
        raise ValueError("a KRI needs a name")
    if len(name) > 255:
        raise ValueError("a KRI name is at most 255 characters")
    metric = metric_key.strip() or None
    if metric is not None and metric not in kri_engine.METRICS:
        raise ValueError(f"unknown metric {metric!r}")
    direction = direction.strip() or (
        kri_engine.METRICS[metric].direction if metric else "higher_is_worse"
    )
    warn = _opt_float(warn_threshold, "the warning threshold")
    critical = _opt_float(critical_threshold, "the critical threshold")
    problem = kri_engine.threshold_problem(direction, warn, critical)
    if problem:
        raise ValueError(problem)
    unit_v = unit.strip() or (kri_engine.METRICS[metric].unit if metric else "")
    return {
        "name": name,
        "description": description.strip() or None,
        "metric_key": metric,
        "unit": unit_v[:32] or None,
        "direction": direction,
        "warn_threshold": warn,
        "critical_threshold": critical,
        "owner_user_id": _opt_int(owner_user_id, "owner"),
        "risk_id": _opt_int(risk_id, "linked risk"),
        "active": active.strip().lower() not in ("", "0", "false", "off"),
    }


@router.get("/kri", response_class=HTMLResponse)
async def kri_page(request: Request, session: AsyncSession = Depends(get_session)) -> HTMLResponse:
    org = _principal_org(request)
    items: list[dict[str, Any]] = []
    users: list[Any] = []
    risks: list[Any] = []
    tally = dict.fromkeys(kri_engine.STATUSES, 0)
    if org is not None:
        kris = (
            (
                await session.execute(
                    select(KeyRiskIndicator)
                    .where(KeyRiskIndicator.organization_id == org)
                    .order_by(KeyRiskIndicator.active.desc(), KeyRiskIndicator.name)
                )
            )
            .scalars()
            .all()
        )
        history = await kri_engine.readings_by_kri(session, org, [k.id for k in kris])
        risks = list(
            (
                await session.execute(
                    select(Risk.id, Risk.title).where(risk_in_scope(org)).order_by(Risk.title)
                )
            ).all()
        )
        risk_titles = {r.id: r.title for r in risks}
        for k in kris:
            readings = history.get(k.id, [])
            latest = readings[0] if readings else None
            st = kri_engine.status(
                latest.value if latest else None,
                k.direction,
                k.warn_threshold,
                k.critical_threshold,
            )
            if k.active:
                tally[st] += 1
            items.append(
                {
                    "kri": k,
                    "latest": latest,
                    "status": st,
                    "readings": readings,
                    "spark": kri_engine.sparkline_points([r.value for r in reversed(readings)]),
                    "metric": kri_engine.METRICS.get(k.metric_key or ""),
                    "risk_title": risk_titles.get(k.risk_id) if k.risk_id else None,
                }
            )
        users = await _org_users(session, org)
    return templates.TemplateResponse(
        request,
        "kri.html",
        {
            "active": ACTIVE,
            "scoped": org is not None,
            "items": items,
            "tally": tally,
            "active_count": sum(1 for i in items if i["kri"].active),
            "metrics": kri_engine.METRICS,
            "users": users,
            "user_names": _names(users),
            "risks": risks,
            "error": request.query_params.get("error"),
            "notice": request.query_params.get("notice"),
        },
    )


@router.post("/kri")
async def kri_create(
    *,
    name: str = Form(""),
    description: str = Form(""),
    metric_key: str = Form(""),
    unit: str = Form(""),
    direction: str = Form(""),
    warn_threshold: str = Form(""),
    critical_threshold: str = Form(""),
    owner_user_id: str = Form(""),
    risk_id: str = Form(""),
    active: str = Form("1"),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*KRI_EDIT_ROLES)),
) -> RedirectResponse:
    org = _org_of(principal)
    try:
        fields = _kri_fields(
            name=name,
            description=description,
            metric_key=metric_key,
            unit=unit,
            direction=direction,
            warn_threshold=warn_threshold,
            critical_threshold=critical_threshold,
            owner_user_id=owner_user_id,
            risk_id=risk_id,
            active=active,
        )
    except ValueError as exc:
        return _back("/kri", str(exc))
    fields["owner_user_id"] = await _org_user(session, org, fields["owner_user_id"])
    fields["risk_id"] = await _org_risk(session, org, fields["risk_id"])
    row = KeyRiskIndicator(organization_id=org, **fields)
    session.add(row)
    await session.flush()
    await record_event(
        session,
        actor=principal.email,
        action="kri_created",
        entity_type="kri",
        entity_id=str(row.id),
        diff=fields,
        organization_id=org,
    )
    await session.commit()
    return _back(f"/kri#kri-{row.id}")


def _compute_redirect(result: dict[str, Any]) -> RedirectResponse:
    n = len(result["recorded"])
    parts = [f"{n} reading{'s' if n != 1 else ''} recorded"]
    parts += [s["reason"] for s in result["skipped"]]
    return RedirectResponse(f"/kri?notice={quote('; '.join(parts))}", status_code=303)


@router.post("/kri/compute")
async def kri_compute_all(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*KRI_EDIT_ROLES)),
) -> RedirectResponse:
    """Record a computed reading now for every active computed KRI."""
    org = _org_of(principal)
    result = await kri_engine.record_computed_readings(session, org, actor=principal.email)
    await record_event(
        session,
        actor=principal.email,
        action="kri_computed",
        entity_type="kri",
        entity_id=None,
        diff=result,
        organization_id=org,
    )
    await session.commit()
    return _compute_redirect(result)


@router.post("/kri/{kri_id}")
async def kri_update(
    kri_id: int,
    *,
    name: str = Form(""),
    description: str = Form(""),
    metric_key: str = Form(""),
    unit: str = Form(""),
    direction: str = Form(""),
    warn_threshold: str = Form(""),
    critical_threshold: str = Form(""),
    owner_user_id: str = Form(""),
    risk_id: str = Form(""),
    active: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*KRI_EDIT_ROLES)),
) -> RedirectResponse:
    org = _org_of(principal)
    row = await _load_kri(session, org, kri_id)
    try:
        fields = _kri_fields(
            name=name,
            description=description,
            metric_key=metric_key,
            unit=unit,
            direction=direction,
            warn_threshold=warn_threshold,
            critical_threshold=critical_threshold,
            owner_user_id=owner_user_id,
            risk_id=risk_id,
            active=active,
        )
    except ValueError as exc:
        return _back(f"/kri#kri-{kri_id}", str(exc))
    if fields["metric_key"] != row.metric_key:
        has_readings = (
            await session.execute(
                select(KriReading.id)
                .where(KriReading.kri_id == row.id, KriReading.organization_id == org)
                .limit(1)
            )
        ).scalar_one_or_none()
        if has_readings is not None:
            # The history would become a series of two different measures.
            return _back(
                f"/kri#kri-{kri_id}",
                "this KRI already has readings of what it measures now; create a new KRI to "
                "measure something else",
            )
    fields["owner_user_id"] = await _org_user(session, org, fields["owner_user_id"])
    fields["risk_id"] = await _org_risk(session, org, fields["risk_id"])
    before = {k: getattr(row, k) for k in fields}
    for k, v in fields.items():
        setattr(row, k, v)
    await session.flush()
    await record_event(
        session,
        actor=principal.email,
        action="kri_updated",
        entity_type="kri",
        entity_id=str(row.id),
        diff={k: {"from": before[k], "to": v} for k, v in fields.items() if before[k] != v},
        organization_id=org,
    )
    await session.commit()
    return _back(f"/kri#kri-{row.id}")


@router.post("/kri/{kri_id}/readings")
async def kri_record_reading(
    kri_id: int,
    value: str = Form(""),
    note: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*KRI_READING_ROLES)),
) -> RedirectResponse:
    """A hand-entered reading, for a manual KRI only.

    A computed KRI's value comes from its metric; a typed-in one would stand
    in for it, so it is refused."""
    org = _org_of(principal)
    row = await _load_kri(session, org, kri_id)
    if row.metric_key:
        return _back(
            f"/kri#kri-{kri_id}",
            "this KRI is computed from its metric; use Compute now instead of typing a value",
        )
    try:
        v = _opt_float(value, "the reading")
    except ValueError as exc:
        return _back(f"/kri#kri-{kri_id}", str(exc))
    if v is None:
        return _back(f"/kri#kri-{kri_id}", "a reading needs a value")
    reading = KriReading(
        organization_id=org,
        kri_id=row.id,
        value=v,
        source="manual",
        recorded_by=principal.email,
        note=note.strip() or None,
    )
    session.add(reading)
    await session.flush()
    await record_event(
        session,
        actor=principal.email,
        action="kri_reading_recorded",
        entity_type="kri",
        entity_id=str(row.id),
        diff={"value": v, "source": "manual", "reading_id": reading.id},
        organization_id=org,
    )
    await session.commit()
    return _back(f"/kri#kri-{row.id}")


@router.post("/kri/{kri_id}/compute")
async def kri_compute_one(
    kri_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*KRI_EDIT_ROLES)),
) -> RedirectResponse:
    org = _org_of(principal)
    row = await _load_kri(session, org, kri_id)
    if not row.metric_key:
        return _back(
            f"/kri#kri-{kri_id}", "this KRI has no metric to compute; record its readings by hand"
        )
    if not row.active:
        return _back(f"/kri#kri-{kri_id}", "this KRI is inactive; reactivate it to compute it")
    result = await kri_engine.record_computed_readings(
        session, org, kri_ids=[row.id], actor=principal.email
    )
    await record_event(
        session,
        actor=principal.email,
        action="kri_computed",
        entity_type="kri",
        entity_id=str(row.id),
        diff=result,
        organization_id=org,
    )
    await session.commit()
    return _compute_redirect(result)


# ── Risk detail, assessments and treatment (0100) ────────────────────────────


async def _load_risk(session: AsyncSession, org: int | None, risk_id: int) -> tuple[Risk, Any]:
    """The risk and its system's name, if the risk is in ``org``'s scope; 404 otherwise."""
    row = (
        await session.execute(
            select(Risk, System.name.label("system"))
            .outerjoin(System, System.id == Risk.system_id)
            .where(Risk.id == risk_id, risk_in_scope(org))
        )
    ).first()
    if row is None:
        raise HTTPException(404, "risk not found")
    return row.Risk, row.system


def _risk_org(risk: Risk) -> int:
    """The organization a record about ``risk`` belongs to: the risk's own."""
    if risk.organization_id is None:
        raise HTTPException(400, "this risk belongs to no organization; give it a system first")
    return risk.organization_id


def _scope_org(principal: Principal) -> int | None:
    return principal.org_id


async def _load_plan(
    session: AsyncSession, org: int | None, plan_id: int
) -> tuple[RiskTreatmentPlan, Risk]:
    stmt = (
        select(RiskTreatmentPlan, Risk)
        .join(Risk, Risk.id == RiskTreatmentPlan.risk_id)
        .where(RiskTreatmentPlan.id == plan_id, risk_in_scope(org))
    )
    if org is not None:
        stmt = stmt.where(RiskTreatmentPlan.organization_id == org)
    row = (await session.execute(stmt)).first()
    if row is None:
        raise HTTPException(404, "treatment plan not found")
    return row.RiskTreatmentPlan, row.Risk


async def _load_action(
    session: AsyncSession, org: int | None, action_id: int
) -> tuple[RiskTreatmentAction, RiskTreatmentPlan]:
    stmt = (
        select(RiskTreatmentAction, RiskTreatmentPlan)
        .join(RiskTreatmentPlan, RiskTreatmentPlan.id == RiskTreatmentAction.plan_id)
        .join(Risk, Risk.id == RiskTreatmentPlan.risk_id)
        .where(RiskTreatmentAction.id == action_id, risk_in_scope(org))
    )
    if org is not None:
        stmt = stmt.where(RiskTreatmentAction.organization_id == org)
    row = (await session.execute(stmt)).first()
    if row is None:
        raise HTTPException(404, "treatment action not found")
    return row.RiskTreatmentAction, row.RiskTreatmentPlan


async def _org_poam(session: AsyncSession, org_id: int, poam_id: int | None) -> int | None:
    """``poam_id`` if the POA&M is on a live system of ``org_id``; 404 otherwise."""
    if poam_id is None:
        return None
    found = (
        await session.execute(
            select(POAM.id).where(POAM.id == poam_id, POAM.system_id.in_(org_system_subq(org_id)))
        )
    ).scalar_one_or_none()
    if found is None:
        raise HTTPException(404, "POA&M not found")
    return found


async def _plans_with_actions(
    session: AsyncSession, org: int | None, risk_ids: list[int] | None
) -> list[dict[str, Any]]:
    """Plans (optionally for ``risk_ids``) in scope, each with its actions and progress."""
    stmt = (
        select(RiskTreatmentPlan, Risk.title.label("risk_title"), Risk.residual_score)
        .join(Risk, Risk.id == RiskTreatmentPlan.risk_id)
        .where(risk_in_scope(org))
        .order_by(RiskTreatmentPlan.due_on.asc().nulls_last(), RiskTreatmentPlan.id)
    )
    if org is not None:
        stmt = stmt.where(RiskTreatmentPlan.organization_id == org)
    if risk_ids is not None:
        stmt = stmt.where(RiskTreatmentPlan.risk_id.in_(risk_ids))
    plans = (await session.execute(stmt)).all()
    ids = [p.RiskTreatmentPlan.id for p in plans]
    actions: dict[int, list[RiskTreatmentAction]] = {i: [] for i in ids}
    if ids:
        a_stmt = (
            select(RiskTreatmentAction)
            .where(RiskTreatmentAction.plan_id.in_(ids))
            .order_by(RiskTreatmentAction.due_on.asc().nulls_last(), RiskTreatmentAction.id)
        )
        if org is not None:
            a_stmt = a_stmt.where(RiskTreatmentAction.organization_id == org)
        for a in (await session.execute(a_stmt)).scalars().all():
            actions[a.plan_id].append(a)
    today = date.today()
    out = []
    for p in plans:
        plan = p.RiskTreatmentPlan
        acts = actions[plan.id]
        done = sum(1 for a in acts if a.status == "done")
        out.append(
            {
                "plan": plan,
                "risk_title": p.risk_title,
                "risk_residual": p.residual_score,
                "actions": acts,
                "done": done,
                "progress": plan_progress(done, len(acts)),
                "overdue": plan.due_on is not None
                and plan.due_on < today
                and plan.status in ("planned", "in_progress"),
            }
        )
    return out


@router.get("/risks/{risk_id:int}", response_class=HTMLResponse)
async def risk_detail_page(
    risk_id: int, request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    risk, system_name = await _load_risk(session, org, risk_id)
    a_stmt = (
        select(RiskAssessment)
        .where(RiskAssessment.risk_id == risk.id)
        .order_by(RiskAssessment.assessed_on.desc(), RiskAssessment.id.desc())
    )
    if org is not None:
        a_stmt = a_stmt.where(RiskAssessment.organization_id == org)
    assessments = (await session.execute(a_stmt)).scalars().all()
    plans = await _plans_with_actions(session, org, [risk.id])
    owner_org = org if org is not None else risk.organization_id
    users = await _org_users(session, owner_org)
    poams: Sequence[Any] = []
    if owner_org is not None:
        poams = (
            await session.execute(
                select(POAM.id, POAM.title)
                .where(POAM.system_id.in_(org_system_subq(owner_org)))
                .order_by(POAM.id.desc())
                .limit(200)
            )
        ).all()
    placement = (
        (await appetite_placements(session, owner_org, risk_ids=[risk.id])).get(risk.id)
        if owner_org is not None
        else None
    )
    return templates.TemplateResponse(
        request,
        "risk_detail.html",
        {
            "active": "risks" if risk.register == "enterprise" else "risks_cyber",
            "risk": risk,
            "system_name": system_name,
            "effective": effective_scores(
                risk.likelihood_score, risk.likelihood, risk.impact_score, risk.impact
            ),
            "band": band,
            "placement": placement,
            "assessments": assessments,
            "plans": plans,
            "users": users,
            "user_names": _names(users),
            "poams": poams,
            "scale": SCALE,
            "lk_labels": LIKELIHOOD_LABELS,
            "im_labels": IMPACT_LABELS,
            "strategies": STRATEGIES,
            "plan_statuses": PLAN_STATUSES,
            "today": date.today(),
            "error": request.query_params.get("error"),
        },
    )


def _assessment_inputs(
    assessed_on: str, likelihood_score: str, impact_score: str, sle: str, aro: str
) -> tuple[date, int | None, int | None, float | None, float | None, str]:
    """Validated form input for one assessment; ``ValueError`` says what is wrong."""
    on = _opt_date(assessed_on, "the assessment date") or date.today()
    lk = _opt_int(likelihood_score, "likelihood")
    im = _opt_int(impact_score, "impact")
    sle_v = _opt_float(sle, "single-loss expectancy (SLE)")
    aro_v = _opt_float(aro, "annual rate of occurrence (ARO)")
    if on > date.today():
        raise ValueError("an assessment cannot be dated in the future")
    if (lk is None) != (im is None):
        raise ValueError("a qualitative assessment needs both likelihood and impact")
    if lk is not None and (lk not in SCALE or im not in SCALE):
        raise ValueError("likelihood and impact are scored 1-5")
    if (sle_v is None) != (aro_v is None):
        raise ValueError("a quantitative assessment needs both SLE and ARO (ALE is computed)")
    if (sle_v is not None and sle_v < 0) or (aro_v is not None and aro_v < 0):
        raise ValueError("SLE and ARO cannot be negative")
    method = assessment_method(lk is not None, sle_v is not None)
    if method is None:
        raise ValueError("record likelihood and impact, or SLE and ARO, or both")
    return on, lk, im, sle_v, aro_v, method


@router.post("/risks/{risk_id:int}/assessments")
async def risk_assessment_create(
    risk_id: int,
    *,
    assessed_on: str = Form(""),
    likelihood_score: str = Form(""),
    impact_score: str = Form(""),
    sle: str = Form(""),
    aro: str = Form(""),
    notes: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*ASSESS_ROLES)),
) -> RedirectResponse:
    """Record a dated assessment. ALE is SLE x ARO, computed here and never
    taken from the form. When this is the latest qualitative assessment, it
    sets the risk's likelihood and impact (and so its scores)."""
    risk, _ = await _load_risk(session, _scope_org(principal), risk_id)
    org = _risk_org(risk)
    back = f"/risks/{risk.id}#assessments"
    try:
        on, lk, im, sle_v, aro_v, method = _assessment_inputs(
            assessed_on, likelihood_score, impact_score, sle, aro
        )
    except ValueError as exc:
        return _back(back, str(exc))
    inherent, residual = compute_scores(lk, im, risk.treatment)
    row = RiskAssessment(
        organization_id=org,
        risk_id=risk.id,
        assessed_on=on,
        method=method,
        likelihood_score=lk,
        impact_score=im,
        inherent_score=inherent,
        residual_score=residual,
        sle=sle_v,
        aro=aro_v,
        ale=ale(sle_v, aro_v),
        assessor=principal.email,
        notes=notes.strip() or None,
    )
    session.add(row)
    await session.flush()
    applied = False
    if lk is not None:
        newer = (
            await session.execute(
                select(RiskAssessment.id)
                .where(
                    RiskAssessment.risk_id == risk.id,
                    RiskAssessment.organization_id == org,
                    RiskAssessment.likelihood_score.is_not(None),
                    RiskAssessment.assessed_on > on,
                )
                .limit(1)
            )
        ).scalar_one_or_none()
        if newer is None:
            risk.likelihood_score, risk.likelihood = lk, score_to_level(lk)
            risk.impact_score, risk.impact = im, score_to_level(im)
            _rescore(risk)
            await session.flush()
            await _post_write(session, risk, principal, verb="assessed")
            applied = True
    await record_event(
        session,
        actor=principal.email,
        action="risk_assessed",
        entity_type="risk",
        entity_id=str(risk.id),
        diff={
            "assessment_id": row.id,
            "assessed_on": on.isoformat(),
            "method": method,
            "likelihood_score": lk,
            "impact_score": im,
            "sle": sle_v,
            "aro": aro_v,
            "ale": row.ale,
            "applied_to_risk": applied,
        },
        organization_id=org,
    )
    await session.commit()
    return _back(back)


def _plan_fields(
    *, strategy: str, description: str, owner_user_id: str, due_on: str, target: str, status: str
) -> dict[str, Any]:
    strategy = strategy.strip()
    if strategy not in STRATEGIES:
        raise ValueError(f"strategy must be one of {', '.join(STRATEGIES)}")
    status = status.strip() or "planned"
    if status not in PLAN_STATUSES:
        raise ValueError(f"status must be one of {', '.join(PLAN_STATUSES)}")
    tgt = _opt_int(target, "the target residual score")
    if tgt is not None and not 1 <= tgt <= 25:
        raise ValueError("the target residual score must be 1-25")
    return {
        "strategy": strategy,
        "description": description.strip() or None,
        "owner_user_id": _opt_int(owner_user_id, "owner"),
        "due_on": _opt_date(due_on, "the due date"),
        "target_residual_score": tgt,
        "status": status,
    }


@router.post("/risks/{risk_id:int}/plans")
async def risk_plan_create(
    risk_id: int,
    *,
    strategy: str = Form(""),
    description: str = Form(""),
    owner_user_id: str = Form(""),
    due_on: str = Form(""),
    target_residual_score: str = Form(""),
    status: str = Form("planned"),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*TREAT_ROLES)),
) -> RedirectResponse:
    """A treatment plan. Its strategy is a plan, not a decision: choosing
    ``accept`` here does not accept the risk, which still needs the risk's own
    acceptance gate (owner, review date, approved review)."""
    risk, _ = await _load_risk(session, _scope_org(principal), risk_id)
    org = _risk_org(risk)
    back = f"/risks/{risk.id}#treatment"
    try:
        fields = _plan_fields(
            strategy=strategy,
            description=description,
            owner_user_id=owner_user_id,
            due_on=due_on,
            target=target_residual_score,
            status=status,
        )
    except ValueError as exc:
        return _back(back, str(exc))
    fields["owner_user_id"] = await _org_user(session, org, fields["owner_user_id"])
    plan = RiskTreatmentPlan(organization_id=org, risk_id=risk.id, **fields)
    session.add(plan)
    await session.flush()
    await record_event(
        session,
        actor=principal.email,
        action="risk_treatment_plan_created",
        entity_type="risk_treatment_plan",
        entity_id=str(plan.id),
        diff={"risk_id": risk.id, **{k: _plain(v) for k, v in fields.items()}},
        organization_id=org,
    )
    await session.commit()
    return _back(back)


@router.post("/risks/plans/{plan_id:int}")
async def risk_plan_update(
    plan_id: int,
    *,
    strategy: str = Form(""),
    description: str = Form(""),
    owner_user_id: str = Form(""),
    due_on: str = Form(""),
    target_residual_score: str = Form(""),
    status: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*TREAT_ROLES)),
) -> RedirectResponse:
    plan, risk = await _load_plan(session, _scope_org(principal), plan_id)
    org = plan.organization_id
    back = f"/risks/{risk.id}#plan-{plan.id}"
    try:
        fields = _plan_fields(
            strategy=strategy,
            description=description,
            owner_user_id=owner_user_id,
            due_on=due_on,
            target=target_residual_score,
            status=status,
        )
    except ValueError as exc:
        return _back(back, str(exc))
    fields["owner_user_id"] = await _org_user(session, org, fields["owner_user_id"])
    before = {k: getattr(plan, k) for k in fields}
    for k, v in fields.items():
        setattr(plan, k, v)
    await session.flush()
    await record_event(
        session,
        actor=principal.email,
        action="risk_treatment_plan_updated",
        entity_type="risk_treatment_plan",
        entity_id=str(plan.id),
        diff={
            k: {"from": _plain(before[k]), "to": _plain(v)}
            for k, v in fields.items()
            if before[k] != v
        },
        organization_id=org,
    )
    await session.commit()
    return _back(back)


@router.post("/risks/plans/{plan_id:int}/actions")
async def risk_action_create(
    plan_id: int,
    *,
    description: str = Form(""),
    owner_user_id: str = Form(""),
    due_on: str = Form(""),
    poam_id: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*TREAT_ROLES)),
) -> RedirectResponse:
    plan, risk = await _load_plan(session, _scope_org(principal), plan_id)
    org = plan.organization_id
    back = f"/risks/{risk.id}#plan-{plan.id}"
    text = description.strip()
    if not text:
        return _back(back, "an action needs a description")
    try:
        owner = _opt_int(owner_user_id, "owner")
        due = _opt_date(due_on, "the due date")
        poam = _opt_int(poam_id, "POA&M")
    except ValueError as exc:
        return _back(back, str(exc))
    owner = await _org_user(session, org, owner)
    poam = await _org_poam(session, org, poam)
    action = RiskTreatmentAction(
        organization_id=org,
        plan_id=plan.id,
        description=text,
        owner_user_id=owner,
        due_on=due,
        status="open",
        poam_id=poam,
    )
    session.add(action)
    await session.flush()
    await record_event(
        session,
        actor=principal.email,
        action="risk_treatment_action_created",
        entity_type="risk_treatment_action",
        entity_id=str(action.id),
        diff={
            "plan_id": plan.id,
            "description": text,
            "owner_user_id": owner,
            "due_on": _plain(due),
            "poam_id": poam,
        },
        organization_id=org,
    )
    await session.commit()
    return _back(back)


@router.post("/risks/actions/{action_id:int}")
async def risk_action_update(
    action_id: int,
    *,
    status: str = Form(""),
    poam_id: str = Form(""),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*TREAT_ROLES)),
) -> RedirectResponse:
    """Mark an action done or open again, and (re)link its POA&M."""
    action, plan = await _load_action(session, _scope_org(principal), action_id)
    org = action.organization_id
    back = f"/risks/{plan.risk_id}#plan-{plan.id}"
    status = status.strip()
    if status not in ACTION_STATUSES:
        return _back(back, f"status must be one of {', '.join(ACTION_STATUSES)}")
    try:
        poam = _opt_int(poam_id, "POA&M")
    except ValueError as exc:
        return _back(back, str(exc))
    poam = await _org_poam(session, org, poam)
    before = {"status": action.status, "poam_id": action.poam_id}
    action.status, action.poam_id = status, poam
    await session.flush()
    await record_event(
        session,
        actor=principal.email,
        action="risk_treatment_action_updated",
        entity_type="risk_treatment_action",
        entity_id=str(action.id),
        diff={
            "status": {"from": before["status"], "to": status},
            "poam_id": {"from": before["poam_id"], "to": poam},
        },
        organization_id=org,
    )
    await session.commit()
    return _back(back)


@router.get("/risks/assessments", response_class=HTMLResponse)
async def risk_assessments_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    """The quantitative register: each risk's latest ALE, and the total.

    Over risks that are not closed. A risk with no quantitative assessment is
    listed as such and left out of the total; the total over none is ``None``."""
    org = _principal_org(request)
    if org is None:
        return no_org_page(request, "risk_assess")
    risks = (
        await session.execute(
            select(Risk, System.name.label("system"))
            .outerjoin(System, System.id == Risk.system_id)
            .where(risk_in_scope(org), Risk.status != "closed")
            .order_by(Risk.title)
        )
    ).all()
    ids = [r.Risk.id for r in risks]
    latest_q: dict[int, RiskAssessment] = {}
    recent: list[Any] = []
    if ids:
        q_stmt = (
            select(RiskAssessment)
            .where(RiskAssessment.risk_id.in_(ids), RiskAssessment.ale.is_not(None))
            .order_by(
                RiskAssessment.risk_id,
                RiskAssessment.assessed_on.desc(),
                RiskAssessment.id.desc(),
            )
        )
        r_stmt = (
            select(RiskAssessment, Risk.title.label("risk_title"))
            .join(Risk, Risk.id == RiskAssessment.risk_id)
            .where(RiskAssessment.risk_id.in_(ids))
            .order_by(RiskAssessment.assessed_on.desc(), RiskAssessment.id.desc())
            .limit(50)
        )
        if org is not None:
            q_stmt = q_stmt.where(RiskAssessment.organization_id == org)
            r_stmt = r_stmt.where(RiskAssessment.organization_id == org)
        for a in (await session.execute(q_stmt)).scalars().all():
            latest_q.setdefault(a.risk_id, a)
        recent = list((await session.execute(r_stmt)).all())
    rows = [{"risk": r.Risk, "system": r.system, "q": latest_q.get(r.Risk.id)} for r in risks]
    rows.sort(key=lambda x: (x["q"] is None, -(x["q"].ale if x["q"] else 0), x["risk"].title))
    with_ale = [x for x in rows if x["q"] is not None]
    total = round(sum(x["q"].ale for x in with_ale), 2) if with_ale else None
    return templates.TemplateResponse(
        request,
        "risk_assessments.html",
        {
            "active": "risk_assess",
            "rows": rows,
            "with_ale": len(with_ale),
            "total_ale": total,
            "recent": recent,
        },
    )


@router.get("/risks/treatment", response_class=HTMLResponse)
async def risk_treatment_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    if org is None:
        return no_org_page(request, "risk_treat")
    plans = await _plans_with_actions(session, org, None)
    actions = sum(len(p["actions"]) for p in plans)
    done = sum(p["done"] for p in plans)
    return templates.TemplateResponse(
        request,
        "risk_treatment.html",
        {
            "active": "risk_treat",
            "plans": plans,
            "actions_total": actions,
            "actions_done": done,
            "overall": plan_progress(done, actions),
            "open_plans": sum(1 for p in plans if p["plan"].status in ("planned", "in_progress")),
            "overdue": sum(1 for p in plans if p["overdue"]),
            "user_names": _names(await _org_users(session, org)),
        },
    )
