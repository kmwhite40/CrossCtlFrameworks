"""Systems / control implementation / POA&M endpoints."""

from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, date, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...analytics.framework_posture import baseline_controls, fold_to_control
from ...ato import lifecycle
from ...ato import roles as system_roles
from ...auth import Principal
from ...catalog.baseline_delta import (
    BaselineNotSetError,
    UnknownBaselineError,
    baseline_delta,
)
from ...config import get_settings
from ...constants import POAM_ACTIVE_STATUSES
from ...governance import bus, reactions
from ...models import (
    POAM,
    Assessment,
    Control,
    ControlImplementation,
    Evidence,
    Risk,
    ScoringStatus,
    System,
)
from ...schemas import (
    ComplianceSummary,
    ImplementationOut,
    ImplementationUpdate,
    POAMOut,
    SystemCreate,
    SystemOut,
)
from ..auth_deps import get_principal, require_role, resolve_caller_org
from ..deps import get_session

#: Most-addressed first: how a control with several implementation rows is
#: summarized. ``not_applicable`` is last, so it wins only when nothing else does.
_SUMMARY_PRECEDENCE = (
    "implemented", "inherited", "partial", "planned", "not_implemented", "not_applicable",
)

router = APIRouter(prefix="/api/systems", tags=["systems"])


async def require_system_in_scope(
    session: AsyncSession, system_id: int, principal: Principal
) -> System:
    """Fetch a system, 404-ing if it is outside the principal's organization
    or has been soft-deleted (DATA-04) — a deleted system behaves as gone for
    every normal operation even though its row (and dependents) still exist.
    """
    sys = (
        await session.execute(
            select(System).where(System.id == system_id, System.deleted_at.is_(None))
        )
    ).scalar_one_or_none()
    if sys is None or (principal.org_id is not None and sys.organization_id != principal.org_id):
        raise HTTPException(404, "system not found")
    return sys


@router.get("", response_model=list[SystemOut])
async def list_systems(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[SystemOut]:
    stmt = select(System).where(System.deleted_at.is_(None)).order_by(System.name)
    if principal.org_id is not None:
        stmt = stmt.where(System.organization_id == principal.org_id)
    rows = (await session.execute(stmt)).scalars().all()
    return [SystemOut.model_validate(r) for r in rows]


@router.post("", response_model=SystemOut, status_code=201)
async def create_system(
    body: SystemCreate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> SystemOut:
    data = body.model_dump(exclude_none=True)
    # A scoped principal naming another organization is refused, not quietly
    # redirected into its own: substituting would answer ``201`` with
    # ``{"organization_id": <the caller's org>}`` to a request that named a
    # different one, asserting something the caller never asked for.
    data["organization_id"] = resolve_caller_org(principal.org_id, data["organization_id"])
    obj = System(**data)
    session.add(obj)
    await session.commit()
    await session.refresh(obj)
    return SystemOut.model_validate(obj)


async def _dependent_authorization_record_count(session: AsyncSession, system_id: int) -> int:
    """Count POA&Ms, assessments, risks, evidence, control implementations, and
    scoring statuses attached to ``system_id`` (DATA-04 hard-delete guard) —
    evidence is reached through ``control_implementations`` since it has no
    direct ``system_id`` FK. Control implementations and scoring statuses are
    counted directly (not just their own dependents) because ``System.
    implementations``/scoring statuses cascade-delete with the system
    (``ondelete=CASCADE`` in models.py): a system with SSP control
    implementation statements but no POA&M/assessment/risk/evidence must still
    be refused a hard delete, or those statements are silently wiped."""
    poams = (
        await session.execute(select(func.count(POAM.id)).where(POAM.system_id == system_id))
    ).scalar_one()
    assessments = (
        await session.execute(
            select(func.count(Assessment.id)).where(Assessment.system_id == system_id)
        )
    ).scalar_one()
    risks = (
        await session.execute(select(func.count(Risk.id)).where(Risk.system_id == system_id))
    ).scalar_one()
    evidence = (
        await session.execute(
            select(func.count(Evidence.id))
            .join(
                ControlImplementation,
                ControlImplementation.id == Evidence.implementation_id,
            )
            .where(ControlImplementation.system_id == system_id)
        )
    ).scalar_one()
    implementations = (
        await session.execute(
            select(func.count(ControlImplementation.id)).where(
                ControlImplementation.system_id == system_id
            )
        )
    ).scalar_one()
    scoring_statuses = (
        await session.execute(
            select(func.count(ScoringStatus.id)).where(ScoringStatus.system_id == system_id)
        )
    ).scalar_one()
    return poams + assessments + risks + evidence + implementations + scoring_statuses


@router.delete("/{system_id}", status_code=204)
async def delete_system(
    system_id: int,
    hard: bool = False,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> None:
    """Soft-delete a system (DATA-04): sets ``deleted_at`` so the system
    disappears from inventory/list/get views and tenant scoping, without
    triggering the ``CASCADE`` that would otherwise irreversibly wipe its
    POA&Ms, assessments, evidence, control implementations, and risks.

    Pass ``?hard=true`` to fall back to the old hard ``DELETE`` behavior —
    refused with 409 when the system still has dependent authorization
    records, so a real purge only ever removes an empty system.
    """
    sys = await require_system_in_scope(session, system_id, principal)
    if hard:
        dependent_count = await _dependent_authorization_record_count(session, system_id)
        if dependent_count:
            raise HTTPException(
                409,
                "cannot hard-delete: system has dependent authorization records "
                "(POA&Ms/assessments/evidence) — use the default soft delete instead",
            )
        await session.delete(sys)
    else:
        sys.deleted_at = datetime.now(UTC)
    await session.commit()


class AuthorizeRequest(BaseModel):
    expires_on: date | None = None


@router.post("/{system_id}/authorize", response_model=SystemOut)
async def authorize_system(
    system_id: int,
    body: AuthorizeRequest = AuthorizeRequest(),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> SystemOut:
    """Transition a system's ``ato_status`` to "authorized" in one step.

    The single-operator path only. With authentication enabled an authorization
    is the AO's decision on a reviewed package (``ccf.ato.lifecycle``: ISSO →
    ISSM → AO), and this endpoint would let an admin skip every stage of it, so
    it refuses (409) and points there.

    Refuses (409) on the same blockers the package path enforces: an open
    critical/high POA&M (an unresolved high-risk weakness must not be
    authorized away) or a risk acceptance past its expiry.
    """
    sys = await require_system_in_scope(session, system_id, principal)
    if get_settings().auth_enabled:
        raise HTTPException(
            409,
            "authorize this system through an authorization package: capture one, then "
            "submit it for ISSO, ISSM and Authorizing Official review",
        )

    found = await lifecycle.blockers(session, system_id)
    if found:
        raise HTTPException(409, "cannot authorize: " + "; ".join(b.title for b in found))

    previous_status = sys.ato_status
    sys.ato_status = "authorized"
    sys.ato_expires_on = body.expires_on or (
        date.today() + timedelta(days=lifecycle.DEFAULT_ATO_PERIOD_DAYS)
    )
    await session.flush()
    await bus.emit(
        session,
        verb="authorized",
        entity_type="system",
        entity_id=sys.id,
        summary=(
            f"System {sys.name} authorized ({previous_status or 'none'} → authorized), "
            f"expires {sys.ato_expires_on}"
        ),
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    await session.refresh(sys)
    return SystemOut.model_validate(sys)


class ImpactLevelIn(BaseModel):
    dod_impact_level: str | None = None


@router.put("/{system_id}/dod-impact-level", response_model=SystemOut)
async def set_dod_impact_level(
    system_id: int,
    body: ImpactLevelIn,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role("admin")),
) -> SystemOut:
    """Declare the DoD CC SRG impact level the system is authorized at."""
    sys = await require_system_in_scope(session, system_id, principal)
    try:
        await system_roles.set_dod_impact_level(
            session, system=sys, level=body.dod_impact_level, principal=principal
        )
    except system_roles.RoleError as e:
        raise HTTPException(422, str(e)) from e
    await session.commit()
    await session.refresh(sys)
    return SystemOut.model_validate(sys)


@router.get("/{system_id}/summary", response_model=ComplianceSummary)
async def compliance_summary(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> ComplianceSummary:
    sys = await require_system_in_scope(session, system_id, principal)

    # The baseline's *controls*, folded the way framework_posture folds them.
    # This used to count raw catalog rows (objectives and ODP rows inflate that
    # about 4x), silently assume Moderate when the system declares no baseline,
    # and count implementation rows outside the baseline. A system with no
    # baseline has no denominator, and says so.
    raw: object = sys.baseline
    baseline = str(getattr(raw, "value", raw) or "") or None
    controls = await baseline_controls(session, baseline or "")
    total = len(controls)

    # One status per baseline control: a control with several implementation
    # rows (base and enhancement rows fold together) takes the most-addressed
    # one, and is N/A only when every row says so.
    statuses: dict[str, set[str]] = {}
    for identifier, status in (
        await session.execute(
            select(Control.identifier, ControlImplementation.status)
            .join(Control, Control.id == ControlImplementation.control_id)
            .where(ControlImplementation.system_id == system_id)
        )
    ).all():
        folded = fold_to_control(identifier)
        if folded in controls:
            statuses.setdefault(folded, set()).add(str(status))
    buckets = dict.fromkeys(_SUMMARY_PRECEDENCE, 0)
    for found in statuses.values():
        winner = next(st for st in _SUMMARY_PRECEDENCE if st in found or st == "not_applicable")
        buckets[winner] += 1

    implemented = buckets["implemented"] + buckets["inherited"]
    applicable = total - buckets["not_applicable"]
    coverage = round(implemented / applicable * 100.0, 2) if applicable > 0 else None

    open_poams = (
        await session.execute(
            select(func.count(POAM.id))
            .where(POAM.system_id == system_id)
            .where(POAM.status.in_(POAM_ACTIVE_STATUSES))
        )
    ).scalar_one()
    overdue_poams = (
        await session.execute(
            select(func.count(POAM.id))
            .where(POAM.system_id == system_id)
            .where(POAM.status.in_(POAM_ACTIVE_STATUSES))
            .where(POAM.due_on < func.current_date())
        )
    ).scalar_one()

    return ComplianceSummary(
        system_id=system_id,
        baseline=baseline,
        total_controls=total,
        implemented=buckets["implemented"],
        partial=buckets["partial"],
        planned=buckets["planned"],
        not_implemented=buckets["not_implemented"],
        inherited=buckets["inherited"],
        not_applicable=buckets["not_applicable"],
        coverage_pct=coverage,
        open_poams=open_poams,
        overdue_poams=overdue_poams,
    )


@router.patch("/{system_id}/implementations/{control_id}", response_model=None)
async def upsert_implementation(
    system_id: int,
    control_id: int,
    body: ImplementationUpdate,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    await require_system_in_scope(session, system_id, principal)
    obj = (
        await session.execute(
            select(ControlImplementation)
            .where(ControlImplementation.system_id == system_id)
            .where(ControlImplementation.control_id == control_id)
        )
    ).scalar_one_or_none()
    if obj is None:
        obj = ControlImplementation(system_id=system_id, control_id=control_id)
        session.add(obj)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(obj, k, v)
    await session.flush()
    await bus.emit(
        session,
        verb="updated",
        entity_type="control_implementation",
        entity_id=obj.id,
        summary=f"Control implementation {control_id} → {obj.status}",
        org_id=principal.org_id,
        actor=principal.email,
    )
    # Reaction: suggest the crosswalked controls this status may also apply to.
    propagation = await reactions.propagate_implementation(
        session,
        system_id=system_id,
        control_id=control_id,
        status=obj.status,
        org_id=principal.org_id,
        actor=principal.email,
    )
    await session.commit()
    await session.refresh(obj)
    out = ImplementationOut.model_validate(obj).model_dump()
    out["propagation"] = propagation
    return out


class BulkImplementationRow(BaseModel):
    identifier: str
    status: str
    narrative: str | None = None


@router.post("/{system_id}/implementations/bulk")
async def bulk_import_implementations(
    system_id: int,
    rows: list[BulkImplementationRow],
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> dict[str, int]:
    """Bulk-seed implementation state for a system from a list of rows."""
    await require_system_in_scope(session, system_id, principal)

    ctrls = {c.identifier: c.id for c in (await session.execute(select(Control))).scalars().all()}
    upserted = 0
    skipped = 0
    for r in rows:
        cid = ctrls.get(r.identifier)
        if not cid:
            skipped += 1
            continue
        obj = (
            await session.execute(
                select(ControlImplementation)
                .where(ControlImplementation.system_id == system_id)
                .where(ControlImplementation.control_id == cid)
            )
        ).scalar_one_or_none()
        if obj is None:
            obj = ControlImplementation(system_id=system_id, control_id=cid)
            session.add(obj)
        obj.status = r.status
        if r.narrative is not None:
            obj.narrative = r.narrative
        upserted += 1
    await session.commit()
    return {"upserted": upserted, "skipped": skipped, "total": len(rows)}


class BaselineDeltaOut(BaseModel):
    """Exactly :class:`ccf.catalog.baseline_delta.BaselineDelta`'s seven fields.

    No counts, no percentage, no "gap" key: the platform already carries nine
    distinct notions of "gap" and this endpoint answers a new question, not
    with a new vocabulary. A caller that wants a count takes ``len()``.
    """

    system_id: int
    current: str
    target: str
    added: list[str]
    removed: list[str]
    already_satisfied: list[str]
    outstanding: list[str]
    unmapped: list[str]


@router.get("/{system_id}/baseline-delta", response_model=BaselineDeltaOut)
async def system_baseline_delta(
    system_id: int,
    target: str,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> BaselineDeltaOut:
    """What moving this system to ``target`` would require.

    ``removed`` reports controls in the current baseline that the target does
    not carry (``CM-2(2)`` for Moderate -> High). It is an observation about
    what the catalog says, never a recommendation to stop implementing a
    control -- which is why this endpoint reports and does not advise, open
    POA&Ms, or schedule anything.

    422 rather than a guess when the system has no baseline: a delta from an
    unknown current state is not computable, and 8 of the dev database's 14
    systems are in exactly that state.
    """
    sys = await require_system_in_scope(session, system_id, principal)
    try:
        delta = await baseline_delta(session, system_id=sys.id, target=target)
    except UnknownBaselineError as exc:
        raise HTTPException(400, str(exc)) from exc
    except BaselineNotSetError as exc:
        raise HTTPException(422, str(exc)) from exc
    return BaselineDeltaOut(**asdict(delta))


@router.get("/{system_id}/poams", response_model=list[POAMOut])
async def list_poams(
    system_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> list[POAMOut]:
    await require_system_in_scope(session, system_id, principal)
    rows = (
        (
            await session.execute(
                select(POAM).where(POAM.system_id == system_id).order_by(POAM.due_on)
            )
        )
        .scalars()
        .all()
    )
    return [POAMOut.model_validate(r) for r in rows]
