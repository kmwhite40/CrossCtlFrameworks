"""Load and query the FedRAMP 20x KSI catalog.

The catalog ships as ``data/fedramp_20x_ksi_catalog.json`` (repo) so it can be
updated as FedRAMP 20x evolves without a code change. ``seed_ksis`` performs an
idempotent upsert keyed on ``identifier`` — the same pattern as the CMMC scoring
seed — so re-running picks up catalog edits without duplicating rows.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..models import KSI

CATALOG_FILENAME = "fedramp_20x_ksi_catalog.json"

# Fields copied verbatim from a catalog record onto the KSI row.
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
    "rule",
    "sort_order",
    "source",
)


def _candidate_paths() -> list[Path]:
    """Ordered locations to look for the catalog.

    The repo ``data/`` copy is the human-editable override and wins when present;
    the packaged ``ksi_catalog.json`` (shipped in the wheel/Docker image) is the
    always-available fallback so seeding works even when ``data/`` is absent.
    """
    settings = get_settings()
    # src/ccf/fedramp20x/catalog.py -> parents[3] == repo root
    repo_root = Path(__file__).resolve().parents[3]
    return [
        repo_root / "data" / CATALOG_FILENAME,
        settings.data_dir / CATALOG_FILENAME,
        Path.cwd() / "data" / CATALOG_FILENAME,
        Path(__file__).with_name("ksi_catalog.json"),  # packaged fallback
    ]


def catalog_path(path: str | Path | None = None) -> Path:
    """Resolve the catalog file path, raising if none of the candidates exist."""
    if path is not None:
        return Path(path)
    for candidate in _candidate_paths():
        if candidate.is_file():
            return candidate
    tried = ", ".join(str(p) for p in _candidate_paths())
    raise FileNotFoundError(f"FedRAMP 20x KSI catalog not found. Looked in: {tried}")


def load_catalog(path: str | Path | None = None) -> dict[str, Any]:
    """Load the raw catalog document (version, categories, ksis)."""
    doc: dict[str, Any] = json.loads(catalog_path(path).read_text(encoding="utf-8"))
    return doc


def load_records(path: str | Path | None = None) -> list[dict[str, Any]]:
    """Return the KSI records with the category display name denormalized on each."""
    doc = load_catalog(path)
    cat_names = {c["key"]: c["name"] for c in doc.get("categories", [])}
    version = doc.get("version")
    records: list[dict[str, Any]] = []
    for i, ksi in enumerate(doc.get("ksis", [])):
        rec = dict(ksi)
        rec.setdefault("category_name", cat_names.get(rec.get("category", ""), rec.get("category")))
        rec.setdefault("sort_order", i)
        rec.setdefault("source", f"fedramp-20x-catalog:{version}" if version else "fedramp-20x")
        records.append(rec)
    return records


async def seed_ksis(session: AsyncSession, path: str | Path | None = None) -> dict[str, int]:
    """Idempotently upsert the KSI catalog. Returns {'created', 'updated', 'total'}."""
    records = load_records(path)
    existing = {k.identifier: k for k in (await session.execute(select(KSI))).scalars().all()}
    created = updated = 0
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
    await session.flush()
    return {"created": created, "updated": updated, "total": len(records)}


async def list_ksis(session: AsyncSession, category: str | None = None) -> list[KSI]:
    stmt = select(KSI).order_by(KSI.sort_order, KSI.identifier)
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
