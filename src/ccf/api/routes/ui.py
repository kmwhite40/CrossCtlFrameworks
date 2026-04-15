"""Server-rendered UI (Jinja2 + HTMX + Tailwind)."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ...models import (
    Control,
    ControlFamily,
    ControlImplementation,
    Evidence,
    Framework,
    FrameworkMapping,
    IngestionRun,
    Organization,
    POAM,
    RejectedRow,
    Risk,
    System,
    User,
    WorkbookVersion,
    Worksheet,
    WorksheetRow,
)
from ..deps import get_session

TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter(include_in_schema=False)


def _is_htmx(request: Request) -> bool:
    return request.headers.get("hx-request") == "true"


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
        "low": (await session.execute(
            select(func.count()).select_from(Control).where(Control.fisma_low.is_(True))
        )).scalar_one(),
        "mod": (await session.execute(
            select(func.count()).select_from(Control).where(Control.fisma_mod.is_(True))
        )).scalar_one(),
        "high": (await session.execute(
            select(func.count()).select_from(Control).where(Control.fisma_high.is_(True))
        )).scalar_one(),
    }
    last_run = (
        await session.execute(select(IngestionRun).order_by(IngestionRun.id.desc()).limit(1))
    ).scalar_one_or_none()

    return templates.TemplateResponse(request, "dashboard.html", {
        "active": "dashboard",
        "controls_ct": controls_ct,
        "mapping_ct": mapping_ct,
        "frameworks_ct": frameworks_ct,
        "worksheets_ct": worksheets_ct,
        "by_family": by_family,
        "by_baseline": by_baseline,
        "last_run": last_run,
    })


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
        col = {"low": Control.fisma_low, "mod": Control.fisma_mod, "high": Control.fisma_high}[baseline]
        stmt = stmt.where(col.is_(True))
        count_stmt = count_stmt.where(col.is_(True))
    if q:
        like = f"%{q}%"
        cond = (Control.identifier.ilike(like)) | (Control.control_name.ilike(like))
        stmt = stmt.where(cond)
        count_stmt = count_stmt.where(cond)

    stmt = stmt.order_by(Control.sort_as.nulls_last(), Control.identifier).limit(limit).offset(offset)
    total = (await session.execute(count_stmt)).scalar_one()
    rows = (await session.execute(stmt)).scalars().all()
    families = (
        await session.execute(select(ControlFamily).order_by(ControlFamily.code))
    ).scalars().all()

    ctx = {
        "active": "controls",
        "rows": rows, "total": total, "families": families,
        "q": q or "", "family": family or "",
        "baseline": baseline or "", "limit": limit, "offset": offset,
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

    return templates.TemplateResponse(request, "control_detail.html", {
        "active": "controls",
        "control": ctl, "grouped": grouped,
    })


@router.get("/frameworks", response_class=HTMLResponse)
async def frameworks_page(
    request: Request, session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    stmt = (
        select(
            Framework.id, Framework.code, Framework.name, Framework.family,
            Framework.description, func.count(FrameworkMapping.id).label("mappings"),
        )
        .join(FrameworkMapping, FrameworkMapping.framework_id == Framework.id, isouter=True)
        .group_by(Framework.id)
        .order_by(Framework.family, Framework.name)
    )
    rows = (await session.execute(stmt)).all()
    return templates.TemplateResponse(request, "frameworks.html", {
        "active": "frameworks", "rows": rows,
    })


@router.get("/frameworks/{code}", response_class=HTMLResponse)
async def framework_detail(
    code: str, request: Request,
    session: AsyncSession = Depends(get_session),
    limit: int = Query(100), offset: int = Query(0),
) -> HTMLResponse:
    fw = (await session.execute(
        select(Framework).where(Framework.code == code.upper())
    )).scalar_one_or_none()
    if fw is None:
        raise HTTPException(404, "framework not found")

    total = (await session.execute(
        select(func.count(FrameworkMapping.id)).where(FrameworkMapping.framework_id == fw.id)
    )).scalar_one()
    rows = (await session.execute(
        select(Control.identifier, Control.control_name,
               FrameworkMapping.column_key, FrameworkMapping.value)
        .join(FrameworkMapping, FrameworkMapping.control_id == Control.id)
        .where(FrameworkMapping.framework_id == fw.id)
        .order_by(Control.sort_as.nulls_last(), Control.identifier)
        .limit(limit).offset(offset)
    )).all()
    return templates.TemplateResponse(request, "framework_detail.html", {
        "active": "frameworks",
        "fw": fw, "rows": rows, "total": total,
        "limit": limit, "offset": offset,
    })


@router.get("/worksheets", response_class=HTMLResponse)
async def worksheets_page(
    request: Request, session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    rows = (await session.execute(select(Worksheet).order_by(Worksheet.name))).scalars().all()
    return templates.TemplateResponse(request, "worksheets.html", {
        "active": "worksheets", "rows": rows,
    })


@router.get("/worksheets/{slug}", response_class=HTMLResponse)
async def worksheet_detail(
    slug: str, request: Request,
    session: AsyncSession = Depends(get_session),
    limit: int = Query(100), offset: int = Query(0),
) -> HTMLResponse:
    sheet = (await session.execute(
        select(Worksheet).where(Worksheet.slug == slug)
    )).scalar_one_or_none()
    if sheet is None:
        raise HTTPException(404, "worksheet not found")

    total = (await session.execute(
        select(func.count(WorksheetRow.id)).where(WorksheetRow.worksheet_id == sheet.id)
    )).scalar_one()
    rows = (await session.execute(
        select(WorksheetRow)
        .where(WorksheetRow.worksheet_id == sheet.id)
        .order_by(WorksheetRow.row_index)
        .limit(limit).offset(offset)
    )).scalars().all()
    return templates.TemplateResponse(request, "worksheet_detail.html", {
        "active": "worksheets",
        "sheet": sheet, "rows": rows, "total": total,
        "limit": limit, "offset": offset,
    })


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
    return templates.TemplateResponse(request, "systems.html", {
        "active": "systems",
        "organizations": orgs,
        "systems": systems,
        "by_org": by_org,
    })


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
        session.add(System(
            organization_id=organization_id,
            name=name.strip(),
            description=(description or None),
            baseline=(baseline or None),
        ))
        await session.commit()
    return RedirectResponse("/systems", status_code=303)


@router.get("/poams", response_class=HTMLResponse)
async def poams_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    rows = (await session.execute(select(POAM).order_by(POAM.due_on.nulls_last()))).scalars().all()
    return templates.TemplateResponse(request, "poams.html", {
        "active": "poams", "rows": rows,
    })


@router.get("/ingestions", response_class=HTMLResponse)
async def ingestions_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    rows = (await session.execute(
        select(IngestionRun).order_by(IngestionRun.id.desc()).limit(50)
    )).scalars().all()
    return templates.TemplateResponse(request, "ingestions.html", {
        "active": "ingestions", "rows": rows,
    })


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "settings.html", {
        "active": "settings",
    })


@router.get("/systems/{system_id}", response_class=HTMLResponse)
async def system_detail(
    system_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    sys = (await session.execute(select(System).where(System.id == system_id))).scalar_one_or_none()
    if sys is None:
        raise HTTPException(404, "system not found")
    impl_counts = (await session.execute(
        select(ControlImplementation.status, func.count())
        .where(ControlImplementation.system_id == system_id)
        .group_by(ControlImplementation.status)
    )).all()
    poams = (await session.execute(
        select(POAM).where(POAM.system_id == system_id).order_by(POAM.due_on.nulls_last())
    )).scalars().all()
    evidence_count = (await session.execute(
        select(func.count(Evidence.id))
        .join(ControlImplementation, ControlImplementation.id == Evidence.implementation_id)
        .where(ControlImplementation.system_id == system_id)
    )).scalar_one()
    return templates.TemplateResponse(request, "system_detail.html", {
        "active": "systems",
        "sys": sys,
        "impl_counts": {s: n for s, n in impl_counts},
        "poams": poams,
        "evidence_count": evidence_count,
    })


@router.get("/risks", response_class=HTMLResponse)
async def risks_page(
    request: Request, session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    rows = (await session.execute(select(Risk).order_by(Risk.created_at.desc()))).scalars().all()
    systems = (await session.execute(select(System).order_by(System.name))).scalars().all()
    return templates.TemplateResponse(request, "risks.html", {
        "active": "risks", "rows": rows, "systems": systems,
    })


@router.get("/users", response_class=HTMLResponse)
async def users_page(
    request: Request, session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    rows = (await session.execute(select(User).order_by(User.email))).scalars().all()
    orgs = (await session.execute(select(Organization).order_by(Organization.name))).scalars().all()
    return templates.TemplateResponse(request, "users.html", {
        "active": "users", "rows": rows, "organizations": orgs,
    })


@router.get("/mappings", response_class=HTMLResponse)
async def mappings_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    q: str | None = Query(None),
    framework: str | None = Query(None),
) -> HTMLResponse:
    frameworks = (await session.execute(
        select(Framework).order_by(Framework.family, Framework.name)
    )).scalars().all()
    results = []
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
    return templates.TemplateResponse(request, "mappings.html", {
        "active": "mappings",
        "q": q or "",
        "framework": framework or "",
        "frameworks": frameworks,
        "results": results,
    })


@router.get("/coverage", response_class=HTMLResponse)
async def coverage_page(
    request: Request, session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    cells = (await session.execute(
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
    )).all()
    frameworks = sorted({c.framework for c in cells})
    families = sorted({c.family for c in cells if c.family})
    grid = {(c.framework, c.family): c.controls for c in cells}
    max_v = max((c.controls for c in cells), default=1)
    return templates.TemplateResponse(request, "coverage.html", {
        "active": "coverage",
        "frameworks": frameworks, "families": families,
        "grid": grid, "max_v": max_v,
    })


@router.get("/diff", response_class=HTMLResponse)
async def diff_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    a: str | None = Query(None),
    b: str | None = Query(None),
) -> HTMLResponse:
    versions = (await session.execute(
        select(WorkbookVersion).order_by(WorkbookVersion.imported_at.desc())
    )).scalars().all()
    result = None
    if a and b:
        from .diff import diff_workbook
        try:
            result = await diff_workbook(a=a, b=b, session=session)
        except HTTPException:
            result = {"error": "one or both SHA-256 values not found"}
    return templates.TemplateResponse(request, "diff.html", {
        "active": "diff", "versions": versions,
        "a": a or "", "b": b or "", "result": result,
    })


@router.get("/quarantine", response_class=HTMLResponse)
async def quarantine_page(
    request: Request, session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    rows = (await session.execute(
        select(RejectedRow).order_by(RejectedRow.rejected_at.desc()).limit(200)
    )).scalars().all()
    return templates.TemplateResponse(request, "quarantine.html", {
        "active": "ingestions", "rows": rows,
    })


@router.get("/reports", response_class=HTMLResponse)
async def reports_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    framework: str | None = Query(None),
) -> HTMLResponse:
    organizations = (await session.execute(select(Organization).order_by(Organization.name))).scalars().all()
    systems = (await session.execute(select(System).order_by(System.name))).scalars().all()
    families = (await session.execute(select(ControlFamily).order_by(ControlFamily.code))).scalars().all()
    frameworks = (await session.execute(select(Framework).order_by(Framework.family, Framework.name))).scalars().all()
    return templates.TemplateResponse(request, "reports.html", {
        "active": "reports",
        "organizations": organizations,
        "systems": systems,
        "families": families,
        "frameworks": frameworks,
        "selected_framework": (framework or "").upper(),
    })


@router.get("/search", response_class=HTMLResponse)
async def search_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    q: str | None = Query(None),
) -> HTMLResponse:
    results = []
    if q and len(q) >= 2:
        tsq = func.plainto_tsquery("english", q)
        rows = (await session.execute(
            select(
                Control.identifier, Control.control_name,
                Control.description,
                func.ts_rank(Control.search_vector, tsq).label("rank"),
            )
            .where(Control.search_vector.op("@@")(tsq))
            .order_by(func.ts_rank(Control.search_vector, tsq).desc())
            .limit(50)
        )).all()
        results = rows
    return templates.TemplateResponse(request, "search.html", {
        "active": "search", "q": q or "", "results": results,
    })
