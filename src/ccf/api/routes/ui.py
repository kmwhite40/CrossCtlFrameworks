"""Server-rendered UI (Jinja2 + HTMX + Tailwind)."""

from __future__ import annotations

import contextlib
from collections.abc import Sequence
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ...analytics import org_summary
from ...config import get_settings
from ...models import (
    POAM,
    AuditLog,
    Control,
    ControlFamily,
    ControlImplementation,
    Evidence,
    Framework,
    FrameworkMapping,
    IngestionRun,
    Organization,
    RejectedRow,
    Risk,
    ScoringControl,
    ScoringStatus,
    SSPControlEntry,
    SSPProject,
    System,
    User,
    WorkbookVersion,
    Worksheet,
    WorksheetRow,
)
from ...scoring.engine import STATES
from ...ssp import constants as ssp_constants
from ...ssp.platforms import PLATFORMS, normalize_platform
from ...ssp.seed import seed_project_entries
from ..deps import get_session
from .diff import diff_workbook
from .scoring import compute_summary

TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Inject settings.readonly into every template's globals (avoids per-route plumbing).
templates.env.globals["settings"] = get_settings()

router = APIRouter(include_in_schema=False)


def _is_htmx(request: Request) -> bool:
    return request.headers.get("hx-request") == "true"


def _ctx(**extra: object) -> dict[str, object]:
    """Inject settings.readonly flag into every UI response."""
    return {"readonly": get_settings().readonly, **extra}


@router.get("/", response_class=HTMLResponse)
async def home(request: Request, session: AsyncSession = Depends(get_session)) -> HTMLResponse:
    controls_ct = (await session.execute(select(func.count(Control.id)))).scalar_one()
    mapping_ct = (await session.execute(select(func.count(FrameworkMapping.id)))).scalar_one()
    frameworks_ct = (await session.execute(select(func.count(Framework.id)))).scalar_one()
    worksheets_ct = (await session.execute(select(func.count(Worksheet.id)))).scalar_one()

    by_family = (
        await session.execute(
            select(ControlFamily.code, ControlFamily.name, func.count(Control.id))
            .join(Control, Control.family_id == ControlFamily.id, isouter=True)
            .group_by(ControlFamily.id)
            .order_by(ControlFamily.code)
        )
    ).all()
    by_baseline = {
        "low": (
            await session.execute(
                select(func.count()).select_from(Control).where(Control.fisma_low.is_(True))
            )
        ).scalar_one(),
        "mod": (
            await session.execute(
                select(func.count()).select_from(Control).where(Control.fisma_mod.is_(True))
            )
        ).scalar_one(),
        "high": (
            await session.execute(
                select(func.count()).select_from(Control).where(Control.fisma_high.is_(True))
            )
        ).scalar_one(),
    }
    last_run = (
        await session.execute(select(IngestionRun).order_by(IngestionRun.id.desc()).limit(1))
    ).scalar_one_or_none()

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "active": "dashboard",
            "controls_ct": controls_ct,
            "mapping_ct": mapping_ct,
            "frameworks_ct": frameworks_ct,
            "worksheets_ct": worksheets_ct,
            "by_family": by_family,
            "by_baseline": by_baseline,
            "last_run": last_run,
        },
    )


@router.get("/controls", response_class=HTMLResponse)
async def controls_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    q: str | None = Query(None),
    family: str | None = Query(None),
    baseline: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> HTMLResponse:
    stmt = select(Control).options(selectinload(Control.family))
    count_stmt = select(func.count(Control.id))
    if family:
        stmt = stmt.join(Control.family).where(ControlFamily.code == family.upper())
        count_stmt = count_stmt.join(Control.family).where(ControlFamily.code == family.upper())
    if baseline:
        col = {"low": Control.fisma_low, "mod": Control.fisma_mod, "high": Control.fisma_high}[
            baseline
        ]
        stmt = stmt.where(col.is_(True))
        count_stmt = count_stmt.where(col.is_(True))
    if q:
        like = f"%{q}%"
        cond = (Control.identifier.ilike(like)) | (Control.control_name.ilike(like))
        stmt = stmt.where(cond)
        count_stmt = count_stmt.where(cond)

    stmt = (
        stmt.order_by(Control.sort_as.nulls_last(), Control.identifier).limit(limit).offset(offset)
    )
    total = (await session.execute(count_stmt)).scalar_one()
    rows = (await session.execute(stmt)).scalars().all()
    families = (
        (await session.execute(select(ControlFamily).order_by(ControlFamily.code))).scalars().all()
    )

    ctx = {
        "active": "controls",
        "rows": rows,
        "total": total,
        "families": families,
        "q": q or "",
        "family": family or "",
        "baseline": baseline or "",
        "limit": limit,
        "offset": offset,
    }
    tpl = "_controls_table.html" if _is_htmx(request) else "controls.html"
    return templates.TemplateResponse(request, tpl, ctx)


@router.get("/controls/{identifier}", response_class=HTMLResponse)
async def control_detail(
    identifier: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    ctl = (
        await session.execute(
            select(Control)
            .where(Control.identifier == identifier)
            .options(
                selectinload(Control.family),
                selectinload(Control.mappings).selectinload(FrameworkMapping.framework),
            )
        )
    ).scalar_one_or_none()
    if ctl is None:
        raise HTTPException(404, "control not found")

    grouped: dict[str, list[FrameworkMapping]] = {}
    for m in sorted(ctl.mappings, key=lambda x: x.column_key):
        fw = m.framework.name if m.framework else "Other"
        grouped.setdefault(fw, []).append(m)

    return templates.TemplateResponse(
        request,
        "control_detail.html",
        {
            "active": "controls",
            "control": ctl,
            "grouped": grouped,
        },
    )


@router.get("/frameworks", response_class=HTMLResponse)
async def frameworks_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    stmt = (
        select(
            Framework.id,
            Framework.code,
            Framework.name,
            Framework.family,
            Framework.description,
            func.count(FrameworkMapping.id).label("mappings"),
        )
        .join(FrameworkMapping, FrameworkMapping.framework_id == Framework.id, isouter=True)
        .group_by(Framework.id)
        .order_by(Framework.family, Framework.name)
    )
    rows = (await session.execute(stmt)).all()
    return templates.TemplateResponse(
        request,
        "frameworks.html",
        {
            "active": "frameworks",
            "rows": rows,
        },
    )


@router.get("/frameworks/{code}", response_class=HTMLResponse)
async def framework_detail(
    code: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    limit: int = Query(100),
    offset: int = Query(0),
) -> HTMLResponse:
    fw = (
        await session.execute(select(Framework).where(Framework.code == code.upper()))
    ).scalar_one_or_none()
    if fw is None:
        raise HTTPException(404, "framework not found")

    total = (
        await session.execute(
            select(func.count(FrameworkMapping.id)).where(FrameworkMapping.framework_id == fw.id)
        )
    ).scalar_one()
    rows = (
        await session.execute(
            select(
                Control.identifier,
                Control.control_name,
                FrameworkMapping.column_key,
                FrameworkMapping.value,
            )
            .join(FrameworkMapping, FrameworkMapping.control_id == Control.id)
            .where(FrameworkMapping.framework_id == fw.id)
            .order_by(Control.sort_as.nulls_last(), Control.identifier)
            .limit(limit)
            .offset(offset)
        )
    ).all()
    return templates.TemplateResponse(
        request,
        "framework_detail.html",
        {
            "active": "frameworks",
            "fw": fw,
            "rows": rows,
            "total": total,
            "limit": limit,
            "offset": offset,
        },
    )


@router.get("/worksheets", response_class=HTMLResponse)
async def worksheets_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    rows = (await session.execute(select(Worksheet).order_by(Worksheet.name))).scalars().all()
    return templates.TemplateResponse(
        request,
        "worksheets.html",
        {
            "active": "worksheets",
            "rows": rows,
        },
    )


@router.get("/worksheets/{slug}", response_class=HTMLResponse)
async def worksheet_detail(
    slug: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    limit: int = Query(100),
    offset: int = Query(0),
) -> HTMLResponse:
    sheet = (
        await session.execute(select(Worksheet).where(Worksheet.slug == slug))
    ).scalar_one_or_none()
    if sheet is None:
        raise HTTPException(404, "worksheet not found")

    total = (
        await session.execute(
            select(func.count(WorksheetRow.id)).where(WorksheetRow.worksheet_id == sheet.id)
        )
    ).scalar_one()
    rows = (
        (
            await session.execute(
                select(WorksheetRow)
                .where(WorksheetRow.worksheet_id == sheet.id)
                .order_by(WorksheetRow.row_index)
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return templates.TemplateResponse(
        request,
        "worksheet_detail.html",
        {
            "active": "worksheets",
            "sheet": sheet,
            "rows": rows,
            "total": total,
            "limit": limit,
            "offset": offset,
        },
    )


@router.get("/systems", response_class=HTMLResponse)
async def systems_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    orgs = (await session.execute(select(Organization).order_by(Organization.name))).scalars().all()
    systems = (await session.execute(select(System).order_by(System.name))).scalars().all()
    by_org: dict[int, list[System]] = {}
    for s in systems:
        by_org.setdefault(s.organization_id, []).append(s)
    return templates.TemplateResponse(
        request,
        "systems.html",
        {
            "active": "systems",
            "organizations": orgs,
            "systems": systems,
            "by_org": by_org,
        },
    )


@router.post("/systems/orgs")
async def create_org(
    name: str = Form(...),
    description: str | None = Form(None),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    if name.strip():
        session.add(Organization(name=name.strip(), description=(description or None)))
        await session.commit()
    return RedirectResponse("/systems", status_code=303)


@router.post("/systems/new")
async def create_system(
    organization_id: int = Form(...),
    name: str = Form(...),
    description: str | None = Form(None),
    baseline: str | None = Form(None),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    if name.strip():
        session.add(
            System(
                organization_id=organization_id,
                name=name.strip(),
                description=(description or None),
                baseline=(baseline or None),
            )
        )
        await session.commit()
    return RedirectResponse("/systems", status_code=303)


@router.get("/poams", response_class=HTMLResponse)
async def poams_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    rows = (await session.execute(select(POAM).order_by(POAM.due_on.nulls_last()))).scalars().all()
    return templates.TemplateResponse(
        request,
        "poams.html",
        {
            "active": "poams",
            "rows": rows,
        },
    )


@router.get("/ingestions", response_class=HTMLResponse)
async def ingestions_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    rows = (
        (await session.execute(select(IngestionRun).order_by(IngestionRun.id.desc()).limit(50)))
        .scalars()
        .all()
    )
    return templates.TemplateResponse(
        request,
        "ingestions.html",
        {
            "active": "ingestions",
            "rows": rows,
        },
    )


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "active": "settings",
        },
    )


@router.get("/systems/{system_id}", response_class=HTMLResponse)
async def system_detail(
    system_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    sys = (await session.execute(select(System).where(System.id == system_id))).scalar_one_or_none()
    if sys is None:
        raise HTTPException(404, "system not found")
    impl_counts = (
        await session.execute(
            select(ControlImplementation.status, func.count())
            .where(ControlImplementation.system_id == system_id)
            .group_by(ControlImplementation.status)
        )
    ).all()
    poams = (
        (
            await session.execute(
                select(POAM).where(POAM.system_id == system_id).order_by(POAM.due_on.nulls_last())
            )
        )
        .scalars()
        .all()
    )
    evidence_count = (
        await session.execute(
            select(func.count(Evidence.id))
            .join(ControlImplementation, ControlImplementation.id == Evidence.implementation_id)
            .where(ControlImplementation.system_id == system_id)
        )
    ).scalar_one()
    return templates.TemplateResponse(
        request,
        "system_detail.html",
        {
            "active": "systems",
            "sys": sys,
            "impl_counts": {s: n for s, n in impl_counts},
            "poams": poams,
            "evidence_count": evidence_count,
        },
    )


@router.get("/risks", response_class=HTMLResponse)
async def risks_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    rows = (await session.execute(select(Risk).order_by(Risk.created_at.desc()))).scalars().all()
    systems = (await session.execute(select(System).order_by(System.name))).scalars().all()
    return templates.TemplateResponse(
        request,
        "risks.html",
        {
            "active": "risks",
            "rows": rows,
            "systems": systems,
        },
    )


@router.get("/users", response_class=HTMLResponse)
async def users_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    rows = (await session.execute(select(User).order_by(User.email))).scalars().all()
    orgs = (await session.execute(select(Organization).order_by(Organization.name))).scalars().all()
    return templates.TemplateResponse(
        request,
        "users.html",
        {
            "active": "users",
            "rows": rows,
            "organizations": orgs,
        },
    )


@router.get("/mappings", response_class=HTMLResponse)
async def mappings_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    q: str | None = Query(None),
    framework: str | None = Query(None),
) -> HTMLResponse:
    frameworks = (
        (await session.execute(select(Framework).order_by(Framework.family, Framework.name)))
        .scalars()
        .all()
    )
    results: Sequence[Any] = ()
    if q and len(q) >= 2:
        stmt = (
            select(
                Control.identifier,
                Control.control_name,
                Framework.code.label("framework_code"),
                Framework.name.label("framework_name"),
                FrameworkMapping.column_key,
                FrameworkMapping.value,
            )
            .select_from(FrameworkMapping)
            .join(Control, Control.id == FrameworkMapping.control_id)
            .join(Framework, Framework.id == FrameworkMapping.framework_id, isouter=True)
            .where(FrameworkMapping.value.ilike(f"%{q}%"))
            .order_by(Control.sort_as.nulls_last(), Control.identifier)
            .limit(100)
        )
        if framework:
            stmt = stmt.where(Framework.code == framework.upper())
        results = (await session.execute(stmt)).all()
    return templates.TemplateResponse(
        request,
        "mappings.html",
        {
            "active": "mappings",
            "q": q or "",
            "framework": framework or "",
            "frameworks": frameworks,
            "results": results,
        },
    )


@router.get("/coverage", response_class=HTMLResponse)
async def coverage_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    cells = (
        await session.execute(
            select(
                Framework.code.label("framework"),
                ControlFamily.code.label("family"),
                func.count(func.distinct(Control.id)).label("controls"),
            )
            .select_from(FrameworkMapping)
            .join(Framework, Framework.id == FrameworkMapping.framework_id)
            .join(Control, Control.id == FrameworkMapping.control_id)
            .join(ControlFamily, ControlFamily.id == Control.family_id, isouter=True)
            .group_by(Framework.code, ControlFamily.code)
        )
    ).all()
    frameworks = sorted({c.framework for c in cells})
    families = sorted({c.family for c in cells if c.family})
    grid = {(c.framework, c.family): c.controls for c in cells}
    max_v = max((c.controls for c in cells), default=1)
    return templates.TemplateResponse(
        request,
        "coverage.html",
        {
            "active": "coverage",
            "frameworks": frameworks,
            "families": families,
            "grid": grid,
            "max_v": max_v,
        },
    )


@router.get("/diff", response_class=HTMLResponse)
async def diff_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    a: str | None = Query(None),
    b: str | None = Query(None),
) -> HTMLResponse:
    versions = (
        (
            await session.execute(
                select(WorkbookVersion).order_by(WorkbookVersion.imported_at.desc())
            )
        )
        .scalars()
        .all()
    )
    result = None
    if a and b:
        try:
            result = await diff_workbook(a=a, b=b, session=session)
        except HTTPException:
            result = {"error": "one or both SHA-256 values not found"}
    return templates.TemplateResponse(
        request,
        "diff.html",
        {
            "active": "diff",
            "versions": versions,
            "a": a or "",
            "b": b or "",
            "result": result,
        },
    )


@router.get("/quarantine", response_class=HTMLResponse)
async def quarantine_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    rows = (
        (
            await session.execute(
                select(RejectedRow).order_by(RejectedRow.rejected_at.desc()).limit(200)
            )
        )
        .scalars()
        .all()
    )
    return templates.TemplateResponse(
        request,
        "quarantine.html",
        {
            "active": "ingestions",
            "rows": rows,
        },
    )


@router.get("/reports", response_class=HTMLResponse)
async def reports_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    framework: str | None = Query(None),
) -> HTMLResponse:
    organizations = (
        (await session.execute(select(Organization).order_by(Organization.name))).scalars().all()
    )
    systems = (await session.execute(select(System).order_by(System.name))).scalars().all()
    families = (
        (await session.execute(select(ControlFamily).order_by(ControlFamily.code))).scalars().all()
    )
    frameworks = (
        (await session.execute(select(Framework).order_by(Framework.family, Framework.name)))
        .scalars()
        .all()
    )
    return templates.TemplateResponse(
        request,
        "reports.html",
        {
            "active": "reports",
            "organizations": organizations,
            "systems": systems,
            "families": families,
            "frameworks": frameworks,
            "selected_framework": (framework or "").upper(),
        },
    )


@router.get("/search", response_class=HTMLResponse)
async def search_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    q: str | None = Query(None),
) -> HTMLResponse:
    results: Sequence[Any] = ()
    if q and len(q) >= 2:
        tsq = func.plainto_tsquery("english", q)
        rows = (
            await session.execute(
                select(
                    Control.identifier,
                    Control.control_name,
                    Control.description,
                    func.ts_rank(Control.search_vector, tsq).label("rank"),
                )
                .where(Control.search_vector.op("@@")(tsq))
                .order_by(func.ts_rank(Control.search_vector, tsq).desc())
                .limit(50)
            )
        ).all()
        results = rows
    return templates.TemplateResponse(
        request,
        "search.html",
        {
            "active": "search",
            "q": q or "",
            "results": results,
        },
    )


# ---------------------------------------------------------------------------
# Live CMMC L2 scoring matrix
# ---------------------------------------------------------------------------

_DOMAIN_BARS = ["AC", "AT", "AU", "CM", "IA", "IR", "MA", "MP", "PE", "PS", "RA", "CA", "SC", "SI"]


async def _scoring_rows(
    session: AsyncSession,
    system_id: int,
    *,
    domain: str | None = None,
    point_value: str | None = None,
    coverage: str | None = None,
) -> list[dict[str, Any]]:
    stmt = select(ScoringControl).order_by(ScoringControl.sort_order)
    if domain:
        stmt = stmt.where(ScoringControl.domain == domain.upper())
    if point_value:
        stmt = stmt.where(ScoringControl.point_value == point_value)
    if coverage:
        stmt = stmt.where(ScoringControl.m365_coverage_status == coverage)
    controls = (await session.execute(stmt)).scalars().all()
    states = {
        cid: (st, notes)
        for cid, st, notes in (
            await session.execute(
                select(ScoringControl.control_id, ScoringStatus.state, ScoringStatus.notes)
                .join(ScoringStatus, ScoringStatus.scoring_control_id == ScoringControl.id)
                .where(ScoringStatus.system_id == system_id)
            )
        ).all()
    }
    rows = []
    for c in controls:
        st, notes = states.get(c.control_id, ("not_assessed", None))
        rows.append({"c": c, "state": st, "notes": notes})
    return rows


@router.get("/scoring", response_class=HTMLResponse)
async def scoring_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    system_id: int | None = Query(None),
    domain: str | None = Query(None),
    point_value: str | None = Query(None),
    coverage: str | None = Query(None),
) -> HTMLResponse:
    systems = (await session.execute(select(System).order_by(System.name))).scalars().all()
    organizations = (
        (await session.execute(select(Organization).order_by(Organization.name))).scalars().all()
    )
    total_controls = (await session.execute(select(func.count(ScoringControl.id)))).scalar_one()
    ctx: dict[str, Any] = {
        "active": "scoring",
        "systems": systems,
        "organizations": organizations,
        "system_id": system_id,
        "total_controls": total_controls,
        "states": STATES,
        "domains": _DOMAIN_BARS,
        "domain": domain or "",
        "point_value": point_value or "",
        "coverage": coverage or "",
    }
    if system_id is not None and total_controls:
        sys = (
            await session.execute(select(System).where(System.id == system_id))
        ).scalar_one_or_none()
        ctx["system"] = sys
        ctx["summary"] = await compute_summary(session, system_id)
        ctx["rows"] = await _scoring_rows(
            session, system_id, domain=domain, point_value=point_value, coverage=coverage
        )
    return templates.TemplateResponse(request, "scoring.html", ctx)


@router.post("/scoring/{system_id}/state", response_class=HTMLResponse)
async def scoring_set_state(
    system_id: int,
    request: Request,
    control_id: str = Form(...),
    state: str = Form(...),
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    if state in STATES:
        ctrl = (
            await session.execute(
                select(ScoringControl).where(ScoringControl.control_id == control_id)
            )
        ).scalar_one_or_none()
        if ctrl is not None:
            status = (
                await session.execute(
                    select(ScoringStatus)
                    .where(ScoringStatus.system_id == system_id)
                    .where(ScoringStatus.scoring_control_id == ctrl.id)
                )
            ).scalar_one_or_none()
            if status is None:
                status = ScoringStatus(system_id=system_id, scoring_control_id=ctrl.id)
                session.add(status)
            status.state = state
            await session.commit()
    summary = await compute_summary(session, system_id)
    return templates.TemplateResponse(
        request,
        "_scoring_score.html",
        {"summary": summary, "system_id": system_id, "domains": _DOMAIN_BARS},
    )


@router.post("/scoring/systems/new")
async def scoring_create_system(
    organization_name: str = Form(...),
    system_name: str = Form(...),
    baseline: str | None = Form(None),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    """Create (or reuse) an org + system and jump straight into scoring it."""
    org_name = organization_name.strip()
    sys_name = system_name.strip()
    if not org_name or not sys_name:
        return RedirectResponse("/scoring", status_code=303)
    org = (
        await session.execute(select(Organization).where(Organization.name == org_name))
    ).scalar_one_or_none()
    if org is None:
        org = Organization(name=org_name)
        session.add(org)
        await session.flush()
    sysm = (
        await session.execute(
            select(System).where(System.organization_id == org.id, System.name == sys_name)
        )
    ).scalar_one_or_none()
    if sysm is None:
        sysm = System(organization_id=org.id, name=sys_name, baseline=(baseline or None))
        session.add(sysm)
        await session.flush()
    sid = sysm.id
    await session.commit()
    return RedirectResponse(f"/scoring?system_id={sid}", status_code=303)


# ---------------------------------------------------------------------------
# SSP builder
# ---------------------------------------------------------------------------


@router.get("/ssp", response_class=HTMLResponse)
async def ssp_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    projects = (
        (await session.execute(select(SSPProject).order_by(SSPProject.created_at.desc())))
        .scalars()
        .all()
    )
    systems = (await session.execute(select(System).order_by(System.name))).scalars().all()
    orgs = (await session.execute(select(Organization).order_by(Organization.name))).scalars().all()
    have_controls = (await session.execute(select(func.count(ScoringControl.id)))).scalar_one()
    return templates.TemplateResponse(
        request,
        "ssp.html",
        {
            "active": "ssp",
            "projects": projects,
            "systems": systems,
            "organizations": orgs,
            "have_controls": have_controls,
            "platforms": PLATFORMS,
        },
    )


@router.post("/ssp/new")
async def ssp_create(
    customer_name: str = Form(...),
    system_id: str | None = Form(None),
    system_name: str | None = Form(None),
    platform: str = Form("m365"),
    prepared_by: str | None = Form(None),
    version: str = Form("0.1"),
    document_date: str | None = Form(None),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    if not customer_name.strip():
        return RedirectResponse("/ssp", status_code=303)
    sid = int(system_id) if system_id and system_id.isdigit() else None
    sname = system_name
    if sid is not None:
        sys = (await session.execute(select(System).where(System.id == sid))).scalar_one_or_none()
        if sys is not None:
            sname = sname or sys.name
    doc_date: date | None = None
    if document_date:
        with contextlib.suppress(ValueError):
            doc_date = date.fromisoformat(document_date)
    proj = SSPProject(
        system_id=sid,
        customer_name=customer_name.strip(),
        system_name=(sname or None),
        platform=normalize_platform(platform),
        prepared_by=(prepared_by or None),
        version=version or "0.1",
        document_date=doc_date,
    )
    session.add(proj)
    await session.flush()
    await seed_project_entries(session, proj)
    return RedirectResponse(f"/ssp/{proj.id}", status_code=303)


@router.post("/ssp/{project_id}/regenerate")
async def ssp_regenerate(
    project_id: int,
    platform: str = Form(...),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    """Switch the target platform and regenerate every control's sample statement."""
    proj = (
        await session.execute(select(SSPProject).where(SSPProject.id == project_id))
    ).scalar_one_or_none()
    if proj is not None:
        proj.platform = normalize_platform(platform)
        await session.flush()
        await seed_project_entries(session, proj, overwrite=True, platform=proj.platform)
    return RedirectResponse(f"/ssp/{project_id}", status_code=303)


@router.get("/ssp/{project_id}", response_class=HTMLResponse)
async def ssp_detail(
    project_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    domain: str | None = Query(None),
) -> HTMLResponse:
    proj = (
        await session.execute(select(SSPProject).where(SSPProject.id == project_id))
    ).scalar_one_or_none()
    if proj is None:
        raise HTTPException(404, "SSP project not found")
    stmt = (
        select(SSPControlEntry)
        .where(SSPControlEntry.project_id == project_id)
        .order_by(SSPControlEntry.sort_order)
    )
    entries = (await session.execute(stmt)).scalars().all()
    by_domain: dict[str, list[SSPControlEntry]] = {}
    for e in entries:
        by_domain.setdefault(e.domain or "?", []).append(e)
    ordered = [d for d in ssp_constants.DOMAIN_ORDER if d in by_domain]
    ordered += [d for d in by_domain if d not in ssp_constants.DOMAIN_ORDER]
    return templates.TemplateResponse(
        request,
        "ssp_detail.html",
        {
            "active": "ssp",
            "project": proj,
            "by_domain": by_domain,
            "ordered_domains": ordered,
            "domain_name": ssp_constants.domain_name,
            "section_number": ssp_constants.section_number,
            "status_options": ssp_constants.IMPLEMENTATION_STATUS_OPTIONS,
            "origination_options": ssp_constants.CONTROL_ORIGINATION_OPTIONS,
            "entry_count": len(entries),
            "platforms": PLATFORMS,
        },
    )


@router.post("/ssp/{project_id}/meta")
async def ssp_save_meta(
    project_id: int,
    customer_name: str = Form(...),
    system_name: str | None = Form(None),
    prepared_by: str | None = Form(None),
    version: str = Form("0.1"),
    document_date: str | None = Form(None),
    status: str = Form("draft"),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    proj = (
        await session.execute(select(SSPProject).where(SSPProject.id == project_id))
    ).scalar_one_or_none()
    if proj is not None:
        proj.customer_name = customer_name.strip() or proj.customer_name
        proj.system_name = system_name or None
        proj.prepared_by = prepared_by or None
        proj.version = version or "0.1"
        proj.status = status or "draft"
        if document_date:
            with contextlib.suppress(ValueError):
                proj.document_date = date.fromisoformat(document_date)
        await session.commit()
    return RedirectResponse(f"/ssp/{project_id}", status_code=303)


@router.post("/ssp/{project_id}/entry/{entry_id}", response_class=HTMLResponse)
async def ssp_save_entry(
    project_id: int,
    entry_id: int,
    request: Request,
    responsible_role: str = Form(""),
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    entry = (
        await session.execute(
            select(SSPControlEntry)
            .where(SSPControlEntry.id == entry_id)
            .where(SSPControlEntry.project_id == project_id)
        )
    ).scalar_one_or_none()
    if entry is None:
        raise HTTPException(404, "entry not found")
    form = await request.form()
    entry.responsible_role = responsible_role or None
    entry.implementation_status = [
        s for s in ssp_constants.IMPLEMENTATION_STATUS_OPTIONS if f"status::{s}" in form
    ]
    entry.control_origination = [
        o for o in ssp_constants.CONTROL_ORIGINATION_OPTIONS if f"orig::{o}" in form
    ]
    narratives: list[dict[str, str]] = []
    for part in entry.part_narratives or []:
        label = part.get("label", "")
        narratives.append(
            {"label": label, "text": str(form.get(f"part::{label}", part.get("text", "")))}
        )
    entry.part_narratives = narratives
    await session.commit()
    return HTMLResponse(
        '<span class="chip chip--ok"><i data-lucide="check"></i> Saved</span>'
        '<script>if(window.lucide)lucide.createIcons();</script>'
    )


# ---------------------------------------------------------------------------
# Enterprise posture command center + audit trail
# ---------------------------------------------------------------------------


@router.get("/posture", response_class=HTMLResponse)
async def posture_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    summary = await org_summary(session, today=datetime.now(UTC).date())
    return templates.TemplateResponse(
        request,
        "posture.html",
        {"active": "posture", "s": summary},
    )


@router.get("/audit", response_class=HTMLResponse)
async def audit_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    entity_type: str | None = Query(None),
    action: str | None = Query(None),
) -> HTMLResponse:
    stmt = select(AuditLog).order_by(AuditLog.id.desc()).limit(200)
    if entity_type:
        stmt = stmt.where(AuditLog.entity_type == entity_type)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    rows = (await session.execute(stmt)).scalars().all()
    entity_types = (
        (await session.execute(select(AuditLog.entity_type).distinct())).scalars().all()
    )
    return templates.TemplateResponse(
        request,
        "audit.html",
        {
            "active": "audit",
            "rows": rows,
            "entity_types": sorted(t for t in entity_types if t),
            "entity_type": entity_type or "",
            "action": action or "",
        },
    )
