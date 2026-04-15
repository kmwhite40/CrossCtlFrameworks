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

from ...models import (
    Control,
    ControlImplementation,
    Framework,
    FrameworkMapping,
    Organization,
    System,
)
from ..deps import get_session

router = APIRouter(prefix="/api/reports", tags=["reports"])

Baseline = Literal["low", "mod", "high"]
Fmt = Literal["json", "csv"]


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
    organization_id: int | None = Query(None, description="Scope to an organization's systems"),
    system_id: int | None = Query(None),
    baseline: Baseline | None = Query(None),
    framework: str | None = Query(None, description="Framework code to crosswalk, e.g. ISO_27001"),
    family: str | None = Query(None, description="Control family code, e.g. AC"),
    fmt: Fmt = Query("json"),
    filename: str | None = Query(None),
) -> StreamingResponse | dict[str, Any]:
    """Return a custom report as JSON or CSV."""
    org: Organization | None = None
    sys: System | None = None
    if organization_id:
        org = (
            await session.execute(select(Organization).where(Organization.id == organization_id))
        ).scalar_one_or_none()
        if not org:
            raise HTTPException(404, "organization not found")
    if system_id:
        sys = (
            await session.execute(select(System).where(System.id == system_id))
        ).scalar_one_or_none()
        if not sys:
            raise HTTPException(404, "system not found")

    fw: Framework | None = None
    if framework:
        fw = (
            await session.execute(select(Framework).where(Framework.code == framework.upper()))
        ).scalar_one_or_none()
        if not fw:
            raise HTTPException(404, "framework not found")

    controls = await _scope_controls(session, baseline)
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
            }
        )

    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "organization": org.name if org else None,
        "system": sys.name if sys else None,
        "baseline": baseline,
        "framework": fw.code if fw else None,
        "family_filter": family.upper() if family else None,
        "total_rows": len(lines),
    }

    if fmt == "json":
        return {"summary": summary, "rows": lines}

    # CSV
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf, fieldnames=list(lines[0].keys()) if lines else ["identifier", "family", "control_name"]
    )
    writer.writeheader()
    for row in lines:
        writer.writerow(row)
    buf.seek(0)
    fname = filename or f"concord-report-{(org.name if org else 'catalog').replace(' ', '_')}.csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )
