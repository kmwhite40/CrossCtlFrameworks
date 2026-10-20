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

Tenant scope is explicit in every query: every table here has its own
``organization_id`` and is filtered on it; risks are reached through a live
system (``posture.org_system_subq``). Every id a form names -- a statement, a
KRI, an owner, a linked risk -- is looked up in the caller's organization and
is a 404 otherwise. Every write is role-gated on the route and audited with
``record_event``.
"""

from __future__ import annotations

import math
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
from ...governance.risk import appetite_placements, category_key
from ...models import Risk, System, User
from ...models_program import KeyRiskIndicator, KriReading, RiskAppetite
from ..audit import record_event
from ..auth_deps import require_role
from ..deps import get_session
from .ui import _principal_org, templates

router = APIRouter(include_in_schema=False)

#: Appetite is an organization-level decision.
APPETITE_ROLES = ("admin",)
#: Defining what is measured, and its thresholds.
KRI_EDIT_ROLES = ("admin", "control_owner")
#: Entering a measured value is record maintenance.
KRI_READING_ROLES = ("admin", "control_owner", "assessor")

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
    """``risk_id`` if the risk is on one of ``org_id``'s live systems; 404 otherwise."""
    if risk_id is None:
        return None
    found = (
        await session.execute(
            select(Risk.id).where(Risk.id == risk_id, Risk.system_id.in_(org_system_subq(org_id)))
        )
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
                    .join(System, System.id == Risk.system_id)
                    .where(Risk.id.in_(breach_ids), Risk.system_id.in_(org_system_subq(org)))
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
                    select(Risk.id, Risk.title)
                    .where(Risk.system_id.in_(org_system_subq(org)))
                    .order_by(Risk.title)
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
