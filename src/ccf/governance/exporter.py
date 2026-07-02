"""Generic import/export — registers to CSV / JSON / Markdown (item 13).

Extensible: register a dataset by adding a loader that returns a list of flat
dict rows. Rendering to csv/json/md is shared. Heavy DOCX/PDF stays in the SSP
and reports modules; this is the lightweight, scriptable path.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import POAM, Policy, Risk, System, Vendor
from .risk import band

FORMATS = ("csv", "json", "md")


def _org_systems(org_id: int | None) -> Any:
    q = select(System.id)
    return q if org_id is None else q.where(System.organization_id == org_id)


async def _poams(session: AsyncSession, org_id: int | None) -> list[dict[str, Any]]:
    stmt = select(POAM).order_by(POAM.id)
    if org_id is not None:
        stmt = stmt.where(POAM.system_id.in_(_org_systems(org_id)))
    return [
        {
            "id": p.id,
            "title": p.title,
            "severity": p.severity,
            "status": p.status,
            "source": p.source,
            "identified_on": p.identified_on,
            "due_on": p.due_on,
            "scheduled_completion": p.scheduled_completion,
            "point_of_contact": p.point_of_contact,
        }
        for p in (await session.execute(stmt)).scalars().all()
    ]


async def _risks(session: AsyncSession, org_id: int | None) -> list[dict[str, Any]]:
    stmt = select(Risk).order_by(Risk.id)
    if org_id is not None:
        stmt = stmt.where(Risk.system_id.in_(_org_systems(org_id)))
    return [
        {
            "id": r.id,
            "title": r.title,
            "category": r.category,
            "likelihood": r.likelihood,
            "impact": r.impact,
            "treatment": r.treatment,
            "status": r.status,
            "inherent_score": r.inherent_score,
            "residual_score": r.residual_score,
            "residual_band": band(r.residual_score),
        }
        for r in (await session.execute(stmt)).scalars().all()
    ]


async def _vendors(session: AsyncSession, org_id: int | None) -> list[dict[str, Any]]:
    stmt = select(Vendor).order_by(Vendor.name)
    if org_id is not None:
        stmt = stmt.where(Vendor.organization_id == org_id)
    return [
        {
            "id": v.id,
            "name": v.name,
            "criticality": v.criticality,
            "status": v.status,
            "risk_rating": v.risk_rating,
            "authorization": v.authorization,
            "last_reviewed_on": v.last_reviewed_on,
            "next_review_on": v.next_review_on,
        }
        for v in (await session.execute(stmt)).scalars().all()
    ]


async def _policies(session: AsyncSession, org_id: int | None) -> list[dict[str, Any]]:
    stmt = select(Policy).order_by(Policy.name)
    if org_id is not None:
        stmt = stmt.where(Policy.organization_id == org_id)
    return [
        {
            "id": p.id,
            "name": p.name,
            "category": p.category,
            "status": p.status,
            "review_frequency": p.review_frequency,
            "next_review_on": p.next_review_on,
        }
        for p in (await session.execute(stmt)).scalars().all()
    ]


DATASETS = {
    "poams": _poams,
    "risks": _risks,
    "vendors": _vendors,
    "policies": _policies,
}


def _render(rows: list[dict[str, Any]], fmt: str, dataset: str) -> tuple[bytes, str]:
    if fmt == "json":
        return json.dumps(rows, indent=2, default=str).encode(), "application/json"
    cols = list(rows[0].keys()) if rows else ["id"]
    if fmt == "md":
        out = [
            f"# {dataset} register\n",
            "| " + " | ".join(cols) + " |",
            "| " + " | ".join(["---"] * len(cols)) + " |",
        ]
        for r in rows:
            out.append("| " + " | ".join(str(r.get(c, "")) for c in cols) + " |")
        return ("\n".join(out) + "\n").encode(), "text/markdown"
    # csv
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow(r)
    return buf.getvalue().encode(), "text/csv"


async def export(
    session: AsyncSession, *, dataset: str, fmt: str, org_id: int | None = None
) -> tuple[bytes, str, str]:
    """Return (bytes, media_type, filename) for a dataset in the requested format."""
    if dataset not in DATASETS:
        raise ValueError(f"unknown dataset: {dataset}")
    if fmt not in FORMATS:
        raise ValueError(f"format must be one of {', '.join(FORMATS)}")
    rows = await DATASETS[dataset](session, org_id)
    content, media = _render(rows, fmt, dataset)
    ext = {"json": "json", "md": "md", "csv": "csv"}[fmt]
    return content, media, f"{dataset}.{ext}"
