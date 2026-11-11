"""Load and query the FedRAMP 20x KSI catalog.

The catalog is FedRAMP's: indicator IDs, names, statements, themes and control
mappings are read from the vendored Consolidated Rules dataset
(:mod:`ccf.fedramp20x.rules`). The one Concord-authored part is the
machine-readable validation ``rule`` (``rules_data/ksi_rules.json``); an
indicator with no authored rule evaluates as ``manual``.

``seed_ksis`` upserts on ``identifier`` and **retires** -- never deletes --
any row the dataset no longer defines. Every per-system KSI table references
``ccf.ksis`` with ``ON DELETE CASCADE``, so a delete would take a customer's
history with it. Retired rows stay readable for history and are excluded from
every list, score, package and deliverable: read the catalog through
:func:`current_ksis` / :func:`current_ksi_ids`, the only definition of
"current" in the codebase.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import KSI
from .methods import validate_methods
from .rules import RulesDatasetError, ksi_records, load_rule_overlay, load_rules

# Fields copied from a catalog record onto the KSI row.
_FIELDS = (
    "category",
    "category_name",
    "name",
    "description",
    "expected_outcome",
    "validation_method",
    "validation_frequency",
    "automation_level",
    "evidence_required",
    "nist_refs",
    "cmmc_refs",
    "provider_services",
    "statement_by_class",
    "methods",
    "rule",
    "sort_order",
    "source",
)

#: What an indicator with no Concord-authored rule carries. ``manual`` is the
#: honest default: nothing has been written that could evaluate it.
_UNAUTHORED = {
    "rule": {"kind": "manual"},
    "validation_method": "manual",
    "validation_frequency": None,
    "automation_level": "manual",
    "evidence_required": True,
}

_OVERLAY_FIELDS = ("rule", "validation_method", "validation_frequency", "automation_level")


def load_records(
    rules_dir: str | Path | None = None, overlay_path: str | Path | None = None
) -> list[dict[str, Any]]:
    """The current catalog: FedRAMP's indicators, plus Concord's rules where authored."""
    records = ksi_records(load_rules(rules_dir))
    known = {r["identifier"] for r in records}
    overlay = load_rule_overlay(overlay_path)
    stray = sorted(set(overlay) - known)
    if stray:
        # A rule keyed to an indicator FedRAMP does not define would evaluate
        # nothing and silently vanish; refuse it instead.
        raise RulesDatasetError(f"ksi_rules.json has rules for undefined indicators: {stray}")
    for i, rec in enumerate(records):
        rec.update(_UNAUTHORED)
        authored = overlay.get(rec["identifier"]) or {}
        rec.update({k: authored[k] for k in _OVERLAY_FIELDS if k in authored})
        rec["methods"] = validate_methods(rec["identifier"], authored.get("methods"))
        if rec["methods"] and rec["automation_level"] == "manual":
            # Automated checks contribute evidence; the verdict is still a
            # person's. Not "automated", which readiness counts as coverage.
            rec["automation_level"] = "partial"
        rec["sort_order"] = i
    return records


async def seed_ksis(
    session: AsyncSession,
    rules_dir: str | Path | None = None,
    overlay_path: str | Path | None = None,
) -> dict[str, int]:
    """Upsert the catalog and retire what it no longer defines.

    Returns ``{'created', 'updated', 'retired', 'total'}``; ``retired`` counts
    rows newly retired by this call. A row that reappears is un-retired.
    """
    records = load_records(rules_dir, overlay_path)
    existing = {k.identifier: k for k in (await session.execute(select(KSI))).scalars().all()}
    created = updated = retired = 0
    for rec in records:
        ident = rec["identifier"]
        row = existing.get(ident)
        if row is None:
            row = KSI(identifier=ident)
            session.add(row)
            created += 1
        else:
            updated += 1
        for field in _FIELDS:
            if field in rec:
                setattr(row, field, rec[field])
        row.retired_at = None
    wanted = {r["identifier"] for r in records}
    now = datetime.now(UTC)
    for ident, row in existing.items():
        if ident not in wanted and row.retired_at is None:
            row.retired_at = now
            retired += 1
    await session.flush()
    return {"created": created, "updated": updated, "retired": retired, "total": len(records)}


def current_ksis() -> Select[tuple[KSI]]:
    """``SELECT`` over the KSIs the catalog currently defines, in catalog order."""
    return select(KSI).where(KSI.retired_at.is_(None)).order_by(KSI.sort_order, KSI.identifier)


def current_ksi_ids() -> Select[tuple[int]]:
    """Subquery of current KSI primary keys, for filtering per-system tables."""
    return select(KSI.id).where(KSI.retired_at.is_(None))


async def list_ksis(session: AsyncSession, category: str | None = None) -> list[KSI]:
    stmt = current_ksis()
    if category:
        stmt = stmt.where(KSI.category == category)
    return list((await session.execute(stmt)).scalars().all())


def control_index(ksis: list[KSI]) -> dict[str, list[str]]:
    """Reverse KSI→control traceability: NIST control id -> [KSI identifiers].

    Answers "which KSIs does this control support?" for the control detail view.
    """
    index: dict[str, list[str]] = {}
    for k in ksis:
        for cid in list(k.nist_refs or []):
            index.setdefault(str(cid), []).append(k.identifier)
    return index
