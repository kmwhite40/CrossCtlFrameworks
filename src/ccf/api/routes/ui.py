"""Server-rendered UI (Jinja2 + HTMX + Tailwind)."""

from __future__ import annotations

import contextlib
import hashlib
from collections.abc import Sequence
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ...analytics import org_summary
from ...assessment import FINDINGS, seed_assessment_results, summarize_results
from ...auth import sign_session, verify_password
from ...config import get_settings
from ...governance import conmon as conmon_engine
from ...governance import digest as digest_engine
from ...models import (
    POAM,
    Assessment,
    AssessmentControlResult,
    AuditLog,
    Control,
    ControlFamily,
    ControlImplementation,
    Event,
    Evidence,
    Framework,
    FrameworkMapping,
    IngestionRun,
    Notification,
    Organization,
    Policy,
    RejectedRow,
    Risk,
    ScoringControl,
    ScoringStatus,
    SSPControlEntry,
    SSPProject,
    StatementTemplate,
    System,
    Task,
    User,
    Vendor,
    WorkbookVersion,
    Worksheet,
    WorksheetRow,
)
from ...scoring.engine import STATES
from ...ssp import constants as ssp_constants
from ...ssp.odp import render as render_template
from ...ssp.platforms import (
    GOV_ENVIRONMENTS,
    PLATFORMS,
    normalize_platform,
    platform_label,
    services_for,
)
from ...ssp.seed import seed_project_entries
from ..auth_deps import SESSION_COOKIE
from ..deps import get_session
from .diff import diff_workbook
from .scoring import compute_summary

TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "templates"
STATIC_DIR = Path(__file__).resolve().parents[1] / "static"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def _asset_version() -> str:
    """Short hash of the CSS/JS so ``?v=`` busts the browser cache on any change."""
    h = hashlib.sha256()
    for rel in ("css/app.css", "js/app.js"):
        path = STATIC_DIR / rel
        if path.exists():
            h.update(path.read_bytes())
    return h.hexdigest()[:10]


# Inject settings.readonly + an asset-version token into every template's globals.
templates.env.globals["settings"] = get_settings()
templates.env.globals["asset_v"] = _asset_version()

router = APIRouter(include_in_schema=False)


def _is_htmx(request: Request) -> bool:
    return request.headers.get("hx-request") == "true"


def _ctx(**extra: object) -> dict[str, object]:
    """Inject settings.readonly flag into every UI response."""
    return {"readonly": get_settings().readonly, **extra}


def _principal_org(request: Request) -> int | None:
    """Organization id to scope UI queries by.

    ``None`` means unscoped — auth disabled (no principal on the request state)
    or a global principal. Set by ``auth_gate_middleware`` when auth is enabled.
    """
    principal = getattr(request.state, "principal", None)
    return getattr(principal, "org_id", None) if principal is not None else None


async def _scoped_project(
    session: AsyncSession, project_id: int, org: int | None
) -> SSPProject | None:
    """Return the SSP project iff visible to ``org`` (None = unscoped)."""
    proj = (
        await session.execute(select(SSPProject).where(SSPProject.id == project_id))
    ).scalar_one_or_none()
    if proj is None or (org is not None and proj.organization_id != org):
        return None
    return proj


@router.get("/", response_class=HTMLResponse)
async def landing(request: Request) -> HTMLResponse:
    """Public marketing front door — shown before the dashboard."""
    return templates.TemplateResponse(request, "landing.html", {"asset_v": _asset_version()})


@router.get("/dashboard", response_class=HTMLResponse)
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
    org = _principal_org(request)
    orgs_stmt = select(Organization).order_by(Organization.name)
    sys_stmt = select(System).order_by(System.name)
    if org is not None:
        orgs_stmt = orgs_stmt.where(Organization.id == org)
        sys_stmt = sys_stmt.where(System.organization_id == org)
    orgs = (await session.execute(orgs_stmt)).scalars().all()
    systems = (await session.execute(sys_stmt)).scalars().all()
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
    request: Request,
    name: str = Form(...),
    description: str | None = Form(None),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    # Tenant principals may not create new organizations.
    if _principal_org(request) is None and name.strip():
        session.add(Organization(name=name.strip(), description=(description or None)))
        await session.commit()
    return RedirectResponse("/systems", status_code=303)


@router.post("/systems/new")
async def create_system(
    request: Request,
    organization_id: int = Form(...),
    name: str = Form(...),
    description: str | None = Form(None),
    baseline: str | None = Form(None),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    org = _principal_org(request)
    if name.strip():
        session.add(
            System(
                organization_id=(org if org is not None else organization_id),
                name=name.strip(),
                description=(description or None),
                baseline=(baseline or None),
            )
        )
        await session.commit()
    return RedirectResponse("/systems", status_code=303)


@router.post("/systems/{system_id}/delete")
async def delete_system_ui(
    system_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    org = _principal_org(request)
    sys = (await session.execute(select(System).where(System.id == system_id))).scalar_one_or_none()
    if sys is not None and (org is None or sys.organization_id == org):
        await session.delete(sys)
        await session.commit()
    return RedirectResponse("/systems", status_code=303)


@router.get("/poams", response_class=HTMLResponse)
async def poams_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    org = _principal_org(request)
    stmt = select(POAM).order_by(POAM.due_on.nulls_last())
    if org is not None:
        stmt = stmt.where(
            POAM.system_id.in_(select(System.id).where(System.organization_id == org))
        )
    rows = (await session.execute(stmt)).scalars().all()
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
    org = _principal_org(request)
    sys = (await session.execute(select(System).where(System.id == system_id))).scalar_one_or_none()
    if sys is None or (org is not None and sys.organization_id != org):
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
    org = _principal_org(request)
    risk_stmt = select(Risk).order_by(Risk.created_at.desc())
    sys_stmt = select(System).order_by(System.name)
    if org is not None:
        org_systems = select(System.id).where(System.organization_id == org)
        risk_stmt = risk_stmt.where(Risk.system_id.in_(org_systems))
        sys_stmt = sys_stmt.where(System.organization_id == org)
    rows = (await session.execute(risk_stmt)).scalars().all()
    systems = (await session.execute(sys_stmt)).scalars().all()
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
    org = _principal_org(request)
    user_stmt = select(User).order_by(User.email)
    orgs_stmt = select(Organization).order_by(Organization.name)
    if org is not None:
        user_stmt = user_stmt.where(User.organization_id == org)
        orgs_stmt = orgs_stmt.where(Organization.id == org)
    rows = (await session.execute(user_stmt)).scalars().all()
    orgs = (await session.execute(orgs_stmt)).scalars().all()
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
    org = _principal_org(request)
    sys_stmt = select(System).order_by(System.name)
    orgs_stmt = select(Organization).order_by(Organization.name)
    if org is not None:
        sys_stmt = sys_stmt.where(System.organization_id == org)
        orgs_stmt = orgs_stmt.where(Organization.id == org)
    systems = (await session.execute(sys_stmt)).scalars().all()
    organizations = (await session.execute(orgs_stmt)).scalars().all()
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
        if sys is not None and (org is None or sys.organization_id == org):
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
    org = _principal_org(request)
    if org is not None:
        sys = (
            await session.execute(select(System).where(System.id == system_id))
        ).scalar_one_or_none()
        if sys is None or sys.organization_id != org:
            raise HTTPException(404, "system not found")
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
    request: Request,
    organization_name: str = Form(...),
    system_name: str = Form(...),
    baseline: str | None = Form(None),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    """Create (or reuse) an org + system and jump straight into scoring it."""
    principal_org = _principal_org(request)
    org_name = organization_name.strip()
    sys_name = system_name.strip()
    if not sys_name or (principal_org is None and not org_name):
        return RedirectResponse("/scoring", status_code=303)
    if principal_org is not None:
        # Tenant principals are pinned to their own organization.
        org = (
            await session.execute(select(Organization).where(Organization.id == principal_org))
        ).scalar_one_or_none()
        if org is None:
            return RedirectResponse("/scoring", status_code=303)
    else:
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
async def ssp_page(request: Request, session: AsyncSession = Depends(get_session)) -> HTMLResponse:
    org = _principal_org(request)
    proj_stmt = select(SSPProject).order_by(SSPProject.created_at.desc())
    sys_stmt = select(System).order_by(System.name)
    orgs_stmt = select(Organization).order_by(Organization.name)
    if org is not None:
        proj_stmt = proj_stmt.where(SSPProject.organization_id == org)
        sys_stmt = sys_stmt.where(System.organization_id == org)
        orgs_stmt = orgs_stmt.where(Organization.id == org)
    projects = (await session.execute(proj_stmt)).scalars().all()
    systems = (await session.execute(sys_stmt)).scalars().all()
    orgs = (await session.execute(orgs_stmt)).scalars().all()
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
    request: Request,
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
    org = _principal_org(request)
    sid = int(system_id) if system_id and system_id.isdigit() else None
    sname = system_name
    if sid is not None:
        sys = (await session.execute(select(System).where(System.id == sid))).scalar_one_or_none()
        if sys is None or (org is not None and sys.organization_id != org):
            return RedirectResponse("/ssp", status_code=303)
        sname = sname or sys.name
        if org is None:
            org = sys.organization_id
    doc_date: date | None = None
    if document_date:
        with contextlib.suppress(ValueError):
            doc_date = date.fromisoformat(document_date)
    proj = SSPProject(
        organization_id=org,
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
    request: Request,
    platform: str = Form(...),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    """Switch the target platform and regenerate every control's sample statement."""
    proj = await _scoped_project(session, project_id, _principal_org(request))
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
    proj = await _scoped_project(session, project_id, _principal_org(request))
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

    # ODP fill-in slots (reference) and the canned statement library.
    odp_map = dict(
        (
            await session.execute(select(ScoringControl.control_id, ScoringControl.odp_definitions))
        ).all()
    )
    template_rows = (
        (await session.execute(select(StatementTemplate).order_by(StatementTemplate.sort_order)))
        .scalars()
        .all()
    )

    def odp_defs_for(control_id: str) -> list[dict[str, Any]]:
        return list(odp_map.get(control_id) or [])

    def templates_for(control_id: str, dom: str | None) -> list[StatementTemplate]:
        out = []
        for t in template_rows:
            if (
                (t.scope == "control" and t.control_id == control_id)
                or (t.scope == "domain" and t.domain == dom)
                or t.scope == "global"
            ):
                out.append(t)
        return out

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
            "odp_defs_for": odp_defs_for,
            "templates_for": templates_for,
        },
    )


@router.post("/ssp/{project_id}/meta")
async def ssp_save_meta(
    project_id: int,
    request: Request,
    customer_name: str = Form(...),
    system_name: str | None = Form(None),
    prepared_by: str | None = Form(None),
    version: str = Form("0.1"),
    document_date: str | None = Form(None),
    status: str = Form("draft"),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    proj = await _scoped_project(session, project_id, _principal_org(request))
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
    proj = await _scoped_project(session, project_id, _principal_org(request))
    if proj is None:
        raise HTTPException(404, "entry not found")
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
    # Persist organization-defined parameter fill-ins (odp::<key> fields).
    odp_values = {
        k[len("odp::") :]: str(v).strip()
        for k, v in form.multi_items()
        if k.startswith("odp::") and str(v).strip()
    }
    entry.odp_values = odp_values

    # Optionally apply a canned statement template, rendered with the ODP values.
    apply_key = str(form.get("apply_template") or "").strip()
    if apply_key:
        tmpl = (
            await session.execute(
                select(StatementTemplate).where(StatementTemplate.key == apply_key)
            )
        ).scalar_one_or_none()
        if tmpl is not None:
            plat = normalize_platform(proj.platform)
            context = {
                "environment": GOV_ENVIRONMENTS.get(plat, platform_label(plat)),
                "platform": platform_label(plat),
                "services": services_for(plat, entry.domain),
            }
            text, _missing = render_template(tmpl.body, odp_values, context)
            narratives.append({"label": tmpl.title, "text": text})
    entry.part_narratives = narratives
    await session.commit()
    return HTMLResponse(
        '<span class="chip chip--ok"><i data-lucide="check"></i> Saved</span>'
        "<script>if(window.lucide)lucide.createIcons();</script>"
    )


# ---------------------------------------------------------------------------
# Enterprise posture command center + audit trail
# ---------------------------------------------------------------------------


@router.get("/posture", response_class=HTMLResponse)
async def posture_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    summary = await org_summary(
        session, today=datetime.now(UTC).date(), org_id=_principal_org(request)
    )
    return templates.TemplateResponse(
        request,
        "posture.html",
        {"active": "posture", "s": summary},
    )


@router.get("/governance", response_class=HTMLResponse)
async def governance_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    """Governance command center — ConMon health, tasks, alerts, activity, diagrams."""
    org = _principal_org(request)
    today = datetime.now(UTC).date()
    health = await conmon_engine.health_summary(session, today=today, org_id=org)

    def _scoped(stmt: Any, col: Any) -> Any:
        return stmt.where(col == org) if org is not None else stmt

    tasks = (
        (
            await session.execute(
                _scoped(
                    select(Task).where(Task.status.in_(("open", "in_progress", "blocked"))),
                    Task.organization_id,
                )
                .order_by(Task.due_on.nulls_last(), Task.id.desc())
                .limit(25)
            )
        )
        .scalars()
        .all()
    )
    notifs = (
        (
            await session.execute(
                _scoped(select(Notification), Notification.organization_id)
                .order_by(Notification.created_at.desc())
                .limit(25)
            )
        )
        .scalars()
        .all()
    )
    events = (
        (
            await session.execute(
                _scoped(select(Event), Event.organization_id).order_by(Event.id.desc()).limit(25)
            )
        )
        .scalars()
        .all()
    )
    systems = (
        (
            await session.execute(
                _scoped(select(System), System.organization_id).order_by(System.name)
            )
        )
        .scalars()
        .all()
    )
    counts = {
        "policies": (
            await session.execute(_scoped(select(func.count(Policy.id)), Policy.organization_id))
        ).scalar_one(),
        "vendors": (
            await session.execute(_scoped(select(func.count(Vendor.id)), Vendor.organization_id))
        ).scalar_one(),
        "open_tasks": len(tasks),
        "unread_alerts": sum(1 for n in notifs if n.read_at is None),
    }
    return templates.TemplateResponse(
        request,
        "governance.html",
        {
            "active": "governance",
            "health": health,
            "tasks": tasks,
            "notifs": notifs,
            "events": events,
            "systems": systems,
            "counts": counts,
        },
    )


@router.post("/governance/scan")
async def governance_scan(
    request: Request, session: AsyncSession = Depends(get_session)
) -> RedirectResponse:
    """Trigger a ConMon scan + alert digest from the command center."""
    org = _principal_org(request)
    today = datetime.now(UTC).date()
    await conmon_engine.scan(session, today=today, org_id=org)
    await digest_engine.run(session, today=today, org_id=org)
    await session.commit()
    return RedirectResponse("/governance", status_code=303)


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: int | None = Query(None)) -> Response:
    if not get_settings().auth_enabled:
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"error": bool(error)})


@router.post("/login")
async def login_submit(
    email: str = Form(...),
    password: str = Form(...),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    user = (
        await session.execute(select(User).where(User.email == email, User.active.is_(True)))
    ).scalar_one_or_none()
    if user is None or not verify_password(password, user.password_hash):
        return RedirectResponse("/login?error=1", status_code=303)
    settings = get_settings()
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie(
        SESSION_COOKIE,
        sign_session(
            user.id, settings.auth_session_secret, ttl_hours=settings.auth_session_ttl_hours
        ),
        max_age=settings.auth_session_ttl_hours * 3600,
        httponly=True,
        samesite="lax",
        secure=settings.env == "prod",
    )
    return resp


@router.get("/logout")
async def logout_ui() -> RedirectResponse:
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


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
    entity_types = (await session.execute(select(AuditLog.entity_type).distinct())).scalars().all()
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


# ---------------------------------------------------------------------------
# Assessment workflow (CMMC L2)
# ---------------------------------------------------------------------------

_FINDING_META = [
    ("not_assessed", "Not assessed", "chip--ghost"),
    ("satisfied", "Satisfied", "chip--ok"),
    ("other_than_satisfied", "Other than satisfied", "chip--err"),
    ("not_applicable", "N/A", "chip--info"),
]


@router.get("/assessments", response_class=HTMLResponse)
async def assessments_page(
    request: Request, session: AsyncSession = Depends(get_session)
) -> HTMLResponse:
    org = _principal_org(request)
    a_stmt = select(Assessment).order_by(Assessment.id.desc())
    sys_stmt = select(System).order_by(System.name)
    if org is not None:
        a_stmt = a_stmt.join(System, System.id == Assessment.system_id).where(
            System.organization_id == org
        )
        sys_stmt = sys_stmt.where(System.organization_id == org)
    assessments = (await session.execute(a_stmt)).scalars().all()
    systems = (await session.execute(sys_stmt)).scalars().all()
    sys_names = {s.id: s.name for s in systems}
    have_controls = (await session.execute(select(func.count(ScoringControl.id)))).scalar_one()
    # progress per assessment
    progress: dict[int, dict[str, Any]] = {}
    for a in assessments:
        rows = (
            (
                await session.execute(
                    select(AssessmentControlResult).where(
                        AssessmentControlResult.assessment_id == a.id
                    )
                )
            )
            .scalars()
            .all()
        )
        progress[a.id] = summarize_results(rows)
    return templates.TemplateResponse(
        request,
        "assessments.html",
        {
            "active": "assessments",
            "assessments": assessments,
            "systems": systems,
            "sys_names": sys_names,
            "have_controls": have_controls,
            "progress": progress,
        },
    )


@router.post("/assessments/new")
async def assessment_create_ui(
    request: Request,
    system_id: int = Form(...),
    name: str = Form("CMMC L2 Assessment"),
    kind: str = Form("self"),
    assessor: str | None = Form(None),
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    org = _principal_org(request)
    sys = (await session.execute(select(System).where(System.id == system_id))).scalar_one_or_none()
    if sys is None or (org is not None and sys.organization_id != org):
        return RedirectResponse("/assessments", status_code=303)
    a = Assessment(
        system_id=system_id,
        name=name.strip() or "CMMC L2 Assessment",
        kind=kind if kind in ("self", "internal", "3pao", "ig", "audit") else "self",
        assessor=(assessor or None),
        started_on=datetime.now(UTC).date(),
    )
    session.add(a)
    await session.flush()
    await seed_assessment_results(session, a)
    return RedirectResponse(f"/assessments/{a.id}", status_code=303)


async def _scoped_assessment(
    session: AsyncSession, assessment_id: int, org: int | None
) -> Assessment | None:
    a = (
        await session.execute(select(Assessment).where(Assessment.id == assessment_id))
    ).scalar_one_or_none()
    if a is None:
        return None
    sys = (
        await session.execute(select(System).where(System.id == a.system_id))
    ).scalar_one_or_none()
    if sys is None or (org is not None and sys.organization_id != org):
        return None
    return a


@router.get("/assessments/{assessment_id}", response_class=HTMLResponse)
async def assessment_detail(
    assessment_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    a = await _scoped_assessment(session, assessment_id, _principal_org(request))
    if a is None:
        raise HTTPException(404, "assessment not found")
    sys = (await session.execute(select(System).where(System.id == a.system_id))).scalar_one()
    results = (
        (
            await session.execute(
                select(AssessmentControlResult)
                .where(AssessmentControlResult.assessment_id == assessment_id)
                .order_by(AssessmentControlResult.sort_order)
            )
        )
        .scalars()
        .all()
    )
    by_domain: dict[str, list[AssessmentControlResult]] = {}
    for r in results:
        by_domain.setdefault(r.domain or "?", []).append(r)
    ordered = [d for d in ssp_constants.DOMAIN_ORDER if d in by_domain]
    ordered += [d for d in by_domain if d not in ssp_constants.DOMAIN_ORDER]
    return templates.TemplateResponse(
        request,
        "assessment_detail.html",
        {
            "active": "assessments",
            "assessment": a,
            "system": sys,
            "by_domain": by_domain,
            "ordered_domains": ordered,
            "domain_name": ssp_constants.domain_name,
            "section_number": ssp_constants.section_number,
            "summary": summarize_results(results),
            "findings": FINDINGS,
            "finding_meta": _FINDING_META,
        },
    )


@router.post("/assessments/{assessment_id}/result/{result_id}", response_class=HTMLResponse)
async def assessment_save_result(
    assessment_id: int,
    result_id: int,
    request: Request,
    finding: str = Form("not_assessed"),
    examine_note: str = Form(""),
    interview_note: str = Form(""),
    test_note: str = Form(""),
    assessor_note: str = Form(""),
    evidence_ref: str = Form(""),
    session: AsyncSession = Depends(get_session),
) -> HTMLResponse:
    if await _scoped_assessment(session, assessment_id, _principal_org(request)) is None:
        raise HTTPException(404, "assessment not found")
    result = (
        await session.execute(
            select(AssessmentControlResult)
            .where(AssessmentControlResult.id == result_id)
            .where(AssessmentControlResult.assessment_id == assessment_id)
        )
    ).scalar_one_or_none()
    if result is None:
        raise HTTPException(404, "result not found")
    form = await request.form()
    result.finding = finding if finding in FINDINGS else "not_assessed"
    result.examine_note = examine_note or None
    result.interview_note = interview_note or None
    result.test_note = test_note or None
    result.assessor_note = assessor_note or None
    result.evidence_ref = evidence_ref or None
    result.reviewed = "reviewed" in form
    objs: list[dict[str, str]] = []
    for part in result.objective_findings or []:
        label = part.get("label", "")
        of = str(form.get(f"obj::{label}", part.get("finding", "not_assessed")))
        objs.append({"label": label, "text": part.get("text", ""), "finding": of})
    result.objective_findings = objs
    result.observed_on = datetime.now(UTC).date()
    await session.commit()
    return HTMLResponse(
        '<span class="chip chip--ok"><i data-lucide="check"></i> Saved</span>'
        "<script>if(window.lucide)lucide.createIcons();</script>"
    )


@router.post("/assessments/{assessment_id}/poams")
async def assessment_make_poams_ui(
    assessment_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    a = await _scoped_assessment(session, assessment_id, _principal_org(request))
    if a is not None:
        results = (
            (
                await session.execute(
                    select(AssessmentControlResult).where(
                        AssessmentControlResult.assessment_id == assessment_id
                    )
                )
            )
            .scalars()
            .all()
        )
        existing = {
            t
            for (t,) in (
                await session.execute(select(POAM.title).where(POAM.system_id == a.system_id))
            ).all()
        }
        today = datetime.now(UTC).date()
        for r in results:
            if r.finding != "other_than_satisfied":
                continue
            title = f"{r.control_id} — {r.title or 'Other than satisfied'}"
            if title in existing:
                continue
            session.add(
                POAM(
                    system_id=a.system_id,
                    title=title,
                    weakness=(
                        f"Practice {r.control_id} ({r.nist_id}) assessed Other Than Satisfied. "
                        f"{r.assessor_note or ''}"
                    ).strip(),
                    severity="moderate",
                    status="open",
                    identified_on=today,
                )
            )
        await session.commit()
    return RedirectResponse(f"/assessments/{assessment_id}", status_code=303)
