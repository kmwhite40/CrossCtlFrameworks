"""Persistence for advisory catalog reconciliation runs.

Reads ``controls``/``framework_mappings``, runs ``reconcile`` (Task 4) against
the pinned OSCAL catalog, and stores the outcome as a ``CatalogIntegrityReport``
row. Read-only against the reference tables: the only write is the report row.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import CatalogIntegrityReport, Control, FrameworkMapping
from .oscal import load_oscal_catalog
from .reconcile import ControlRow, MappingRow, reconcile


async def run_and_store(
    session: AsyncSession, *, oscal_dir: Path | None = None
) -> CatalogIntegrityReport:
    catalog = load_oscal_catalog(oscal_dir)
    ctrls = (await session.execute(select(Control))).scalars().all()
    rows = [
        ControlRow(
            control_number=c.control_number,
            control_name=c.control_name,
            description=c.description,
            discussion=c.discussion,
            fisma_low=c.fisma_low,
            fisma_mod=c.fisma_mod,
            fisma_high=c.fisma_high,
            source_row=c.source_row,
        )
        for c in ctrls
    ]
    by_id = {c.id: c for c in ctrls}
    maps_q = (await session.execute(select(FrameworkMapping))).scalars().all()
    mrows = [
        MappingRow(
            control_number=(by_id[m.control_id].control_number if m.control_id in by_id else None),
            column_key=m.column_key or "",
            framework_code=None,
            value=m.value,
        )
        for m in maps_q
    ]
    result = reconcile(catalog, rows, mrows)
    report = CatalogIntegrityReport(
        oscal_version=catalog.version,
        oscal_sha256=catalog.catalog_sha256,
        controls_checked=result.controls_checked,
        not_evaluated=result.not_evaluated,
        findings_total=len(result.findings),
        findings_by_severity=result.summary["by_severity"],
        findings=[f.as_dict() for f in result.findings],
        crosswalk=result.crosswalk,
        summary=result.summary,
    )
    session.add(report)
    await session.flush()
    return report


async def latest_report(session: AsyncSession) -> CatalogIntegrityReport | None:
    q = select(CatalogIntegrityReport).order_by(CatalogIntegrityReport.run_at.desc()).limit(1)
    return (await session.execute(q)).scalars().first()


def render_text(report: CatalogIntegrityReport) -> str:
    lines = [
        f"OSCAL 800-53r5 catalog integrity — version {report.oscal_version}",
        f"controls checked: {report.controls_checked} "
        f"(not evaluated: {report.not_evaluated}); findings: {report.findings_total}",
        f"by severity: {report.findings_by_severity}",
    ]
    for f in report.findings[:200]:
        lines.append(f"  [{f['severity']:6}] [{f['check']:15}] {f['canonical_id']}: {f['detail']}")
    return "\n".join(lines)
