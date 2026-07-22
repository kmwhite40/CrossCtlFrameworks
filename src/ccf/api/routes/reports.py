"""Custom compliance report builder.

Produces per-organization reports scoped to a chosen baseline and
(optionally) a chosen cross-framework crosswalk. Supports HTML, JSON,
and CSV output so audit packages can be exported directly.
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ...analytics.posture import org_summary
from ...auth import Principal
from ...models import (
    Control,
    ControlImplementation,
    Framework,
    FrameworkMapping,
    Organization,
    SSPControlEntry,
    SSPProject,
    System,
)
from ...reporting import report_to_docx, report_to_xlsx
from ...ssp.statements import is_draft_narrative
from ..auth_deps import get_principal
from ..deps import get_session

router = APIRouter(prefix="/api/reports", tags=["reports"])

Baseline = Literal["low", "mod", "high"]
Fmt = Literal["json", "csv", "xlsx", "docx"]
_BASELINES = ("low", "mod", "high")

_XLSX_MEDIA = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
_DOCX_MEDIA = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def _opt_int(name: str, raw: str | None) -> int | None:
    """Parse an optional int query param, treating "" (empty form field) as None."""
    if raw is None or raw.strip() == "":
        return None
    try:
        return int(raw)
    except ValueError as exc:
        raise HTTPException(422, f"{name} must be an integer") from exc


def _opt_str(raw: str | None) -> str | None:
    """Normalize an optional string query param, treating "" as None."""
    if raw is None:
        return None
    val = raw.strip()
    return val or None


async def _scope_controls(session: AsyncSession, baseline: Baseline | None) -> list[Control]:
    stmt = (
        select(Control)
        .options(selectinload(Control.family))
        .order_by(Control.sort_as.nulls_last(), Control.identifier)
    )
    if baseline:
        col = {"low": Control.fisma_low, "mod": Control.fisma_mod, "high": Control.fisma_high}[
            baseline
        ]
        stmt = stmt.where(col.is_(True))
    return list((await session.execute(stmt)).scalars().all())


@router.get("/build", response_model=None)
async def build_report(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
    organization_id: str | None = Query(None, description="Scope to an organization's systems"),
    system_id: str | None = Query(None),
    baseline: str | None = Query(None, description="low | mod | high"),
    framework: str | None = Query(None, description="Framework code to crosswalk, e.g. ISO_27001"),
    family: str | None = Query(None, description="Control family code, e.g. AC"),
    fmt: Fmt = Query("json"),
    filename: str | None = Query(None),
) -> StreamingResponse | dict[str, Any]:
    """Return a custom report as JSON, CSV, XLSX, or DOCX.

    Query params are accepted as strings and coerced here so that empty form
    fields (``organization_id=``, ``baseline=``) are treated as "unset" rather
    than rejected — otherwise the HTML builder's exports would 422.
    """
    organization_id_i = _opt_int("organization_id", organization_id)
    system_id_i = _opt_int("system_id", system_id)
    # Org-scope the request: a tenant-scoped caller may only report on their own
    # organization's data (global/auth-off principals are unscoped).
    if principal.org_id is not None:
        organization_id_i = principal.org_id
    framework = _opt_str(framework)
    family = _opt_str(family)
    filename = _opt_str(filename)
    baseline_s = _opt_str(baseline)
    if baseline_s is not None and baseline_s not in _BASELINES:
        raise HTTPException(422, "baseline must be one of low, mod, high")
    baseline_typed: Baseline | None = baseline_s  # type: ignore[assignment]

    org: Organization | None = None
    sys: System | None = None
    if organization_id_i:
        org = (
            await session.execute(select(Organization).where(Organization.id == organization_id_i))
        ).scalar_one_or_none()
        if not org:
            raise HTTPException(404, "organization not found")
    if system_id_i:
        sys = (
            await session.execute(select(System).where(System.id == system_id_i))
        ).scalar_one_or_none()
        if not sys or (principal.org_id is not None and sys.organization_id != principal.org_id):
            raise HTTPException(404, "system not found")

    fw: Framework | None = None
    if framework:
        fw = (
            await session.execute(select(Framework).where(Framework.code == framework.upper()))
        ).scalar_one_or_none()
        if not fw:
            raise HTTPException(404, "framework not found")

    controls = await _scope_controls(session, baseline_typed)
    if family:
        controls = [c for c in controls if c.family and c.family.code == family.upper()]

    # Implementation status per control (for the chosen system, if any)
    impl_map: dict[int, ControlImplementation] = {}
    if sys:
        impls = (
            (
                await session.execute(
                    select(ControlImplementation).where(ControlImplementation.system_id == sys.id)
                )
            )
            .scalars()
            .all()
        )
        impl_map = {i.control_id: i for i in impls}

    # Framework mapping per control (if requested)
    mapping_map: dict[int, list[FrameworkMapping]] = {}
    if fw:
        rows = (
            (
                await session.execute(
                    select(FrameworkMapping).where(FrameworkMapping.framework_id == fw.id)
                )
            )
            .scalars()
            .all()
        )
        for m in rows:
            mapping_map.setdefault(m.control_id, []).append(m)

    # AI/last-editor provenance (CISO-10, reusing the CISO-02 signal): a
    # control's implementation status can be backed by an SSP entry narrative
    # that's still machine-drafted and not yet human-reviewed. Reuse
    # ``is_draft_narrative`` — the same DRAFT_PREFIX-based signal that drives
    # the AI badge elsewhere (ccf.ssp.statements) — rather than inventing a
    # second, possibly-diverging provenance rule. Scoped to the chosen
    # system's most recently updated SSP project; keyed on the entry's own
    # ``control_id`` string (matches this catalog's ``identifier`` when the
    # SSP was authored against it).
    ai_sourced_map: dict[str, bool] = {}
    if sys:
        project = (
            await session.execute(
                select(SSPProject)
                .where(SSPProject.system_id == sys.id)
                .order_by(SSPProject.updated_at.desc())
            )
        ).scalars().first()
        if project:
            entries = (
                (
                    await session.execute(
                        select(SSPControlEntry).where(SSPControlEntry.project_id == project.id)
                    )
                )
                .scalars()
                .all()
            )
            ai_sourced_map = {e.control_id: is_draft_narrative(e.part_narratives) for e in entries}

    lines: list[dict[str, Any]] = []
    for c in controls:
        impl = impl_map.get(c.id)
        mappings = mapping_map.get(c.id, [])
        lines.append(
            {
                "identifier": c.identifier,
                "family": c.family.code if c.family else None,
                "control_name": c.control_name,
                "baseline_low": bool(c.fisma_low),
                "baseline_mod": bool(c.fisma_mod),
                "baseline_high": bool(c.fisma_high),
                "implementation_status": impl.status if impl else None,
                "responsibility": impl.responsibility if impl else None,
                "owner": impl.owner_user_id if impl else None,
                "last_assessed_on": impl.last_assessed_on.isoformat()
                if impl and impl.last_assessed_on
                else None,
                "crosswalk_framework": fw.code if fw else None,
                "crosswalk_values": "; ".join(f"{m.column_key}={m.value}" for m in mappings)
                or None,
                # True only when there IS an implementation status to attribute
                # and its backing SSP narrative is still AI-drafted/unreviewed.
                "ai_sourced": bool(impl) and ai_sourced_map.get(c.identifier, False),
            }
        )

    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "organization": org.name if org else None,
        "system": sys.name if sys else None,
        "baseline": baseline_typed,
        "framework": fw.code if fw else None,
        "family_filter": family.upper() if family else None,
        "total_rows": len(lines),
    }

    # CISO-10: POA&M/risk posture summary, reconciled to the dashboard — the
    # *same* ``org_summary`` numbers for the same org scope, not a
    # re-derivation, so the export can never silently drift from what
    # leadership sees on screen.
    today = datetime.now(UTC).date()
    posture = await org_summary(session, today=today, org_id=organization_id_i)
    risk_summary = {
        "systems_total": posture["systems_total"],
        "systems_scored": posture["systems_scored"],
        "avg_sprs_score": posture["avg_sprs_score"],
        "min_sprs_score": posture["min_sprs_score"],
        "worst_system": posture["worst_system"],
        "open_poams": posture["open_poams"],
        "overdue_poams": posture["overdue_poams"],
        "accepted_poams": posture["accepted_poams"],
        "risks_by_status": posture["risks_by_status"],
    }

    if fmt == "json":
        return {"summary": summary, "risk_summary": risk_summary, "rows": lines}

    stem = (filename or f"concord-report-{(org.name if org else 'catalog')}").rsplit(".", 1)[0]
    stem = stem.replace(" ", "_")

    if fmt == "xlsx":
        return _download(
            report_to_xlsx(summary, lines, risk_summary), f"{stem}.xlsx", _XLSX_MEDIA
        )

    if fmt == "docx":
        return _download(
            report_to_docx(summary, lines, risk_summary), f"{stem}.docx", _DOCX_MEDIA
        )

    # CSV (default streaming export) — a POA&M/risk posture preamble (mirrors
    # the xlsx Summary sheet / docx heading) ahead of the blank-line-separated
    # controls table, so the risk numbers travel with the file even though CSV
    # has no separate-sheet concept.
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Concord compliance report"])
    for label, value in (
        ("Generated", summary["generated_at"]),
        ("Organization", summary["organization"] or "(catalog)"),
        ("System", summary["system"] or "(any)"),
        ("Baseline", summary["baseline"] or "(all)"),
        ("Total rows", summary["total_rows"]),
    ):
        writer.writerow([label, value])
    writer.writerow([])
    writer.writerow(["POA&M / Risk Posture (reconciled to dashboard)"])
    worst = risk_summary["worst_system"] or {}
    for label, value in (
        ("Systems scored", risk_summary["systems_scored"]),
        ("Avg SPRS score", risk_summary["avg_sprs_score"]),
        ("Min (worst) SPRS score", risk_summary["min_sprs_score"]),
        ("Worst-scoring system", worst.get("name", "")),
        ("Open POA&Ms", risk_summary["open_poams"]),
        ("Overdue POA&Ms", risk_summary["overdue_poams"]),
        ("Risk-accepted POA&Ms", risk_summary["accepted_poams"]),
    ):
        writer.writerow([label, value])
    writer.writerow([])
    writer.writerow(["Controls"])
    dict_writer = csv.DictWriter(
        buf, fieldnames=list(lines[0].keys()) if lines else ["identifier", "family", "control_name"]
    )
    dict_writer.writeheader()
    for row in lines:
        dict_writer.writerow(row)
    return _download(buf.getvalue().encode("utf-8"), f"{stem}.csv", "text/csv")


def _download(payload: bytes, filename: str, media_type: str) -> StreamingResponse:
    return StreamingResponse(
        iter([payload]),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
