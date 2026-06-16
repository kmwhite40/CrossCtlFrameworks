"""Load the CMMC L2 scoring matrix into ``ccf.scoring_controls``.

Idempotent upsert keyed on ``control_id`` so re-running picks up workbook edits
without duplicating rows. Source defaults to the committed ``seed.json`` but may
be pointed at a fresh workbook export.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import ScoringControl
from .parser import load_seed, parse_workbook

_FIELDS = (
    "nist_id",
    "domain",
    "title",
    "point_value",
    "scoring_bucket",
    "scoring_notes",
    "requirement",
    "objectives",
    "objective_parts",
    "examine_cases",
    "interview_cases",
    "test_cases",
    "considerations",
    "key_references",
    "guide_page",
    "pdf_page",
    "source",
    "m365_coverage_status",
    "m365_primary_services",
    "m365_secondary_services",
    "m365_implementation_statement",
    "m365_inheritance",
    "recommended_customer_evidence",
    "recommended_provider_evidence",
    "evidence_notes",
    "m365_source",
)


def _records(source: str | Path | None) -> list[dict[str, Any]]:
    if source is None:
        return load_seed()
    path = Path(source)
    if path.suffix.lower() in {".xlsx", ".xlsm"}:
        return parse_workbook(path)
    return load_seed(path)


async def seed_scoring_controls(
    session: AsyncSession, source: str | Path | None = None
) -> dict[str, int]:
    """Upsert scoring controls. Returns ``{"created": n, "updated": m}``."""
    records = _records(source)
    existing = {
        c.control_id: c for c in (await session.execute(select(ScoringControl))).scalars().all()
    }

    created = updated = 0
    for order, rec in enumerate(records):
        cid = rec["control_id"]
        row = existing.get(cid)
        if row is None:
            row = ScoringControl(control_id=cid)
            session.add(row)
            created += 1
        else:
            updated += 1
        for field in _FIELDS:
            setattr(row, field, rec.get(field))
        row.sort_order = order

    await session.commit()
    return {"created": created, "updated": updated, "total": len(records)}
