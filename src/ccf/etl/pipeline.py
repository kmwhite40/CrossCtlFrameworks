"""Workbook ingestion pipeline.

Loads every sheet of the NIST Cross Mappings workbook into Postgres:

  * `SP.800-53Ar5_assessment` -> ccf.controls + ccf.framework_mappings
  * All other sheets          -> ccf.worksheets + ccf.worksheet_rows (generic landing)

Records the run (source hash, status, per-sheet stats) in ccf.ingestion_runs.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import openpyxl
from slugify import slugify
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..logging import get_logger
from ..models import (
    Control,
    ControlFamily,
    Framework,
    FrameworkMapping,
    IngestionRun,
    Worksheet,
    WorksheetRow,
)
from .frameworks import FRAMEWORKS, CORE_HEADERS, classify_header

log = get_logger(__name__)

ASSESSMENT_SHEET = "SP.800-53Ar5_assessment"
BOOL_STRINGS_TRUE = {"x", "yes", "y", "true", "t", "1"}
BOOL_STRINGS_FALSE = {"no", "n", "false", "f", "0"}

FAMILY_RE = re.compile(r"\(([A-Z]{2,3})\)\s*(.*)")


def _clean(v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, str):
        s = v.strip()
        return s or None
    return v


def _coerce_bool(v: Any) -> bool | None:
    cleaned = _clean(v)
    if cleaned is None:
        return None
    s = str(cleaned).strip().lower()
    if s in BOOL_STRINGS_TRUE:
        return True
    if s in BOOL_STRINGS_FALSE:
        return False
    return None


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


async def _seed_frameworks(session: AsyncSession) -> dict[str, int]:
    existing = {
        f.code: f.id
        for f in (await session.execute(select(Framework))).scalars().all()
    }
    for spec in FRAMEWORKS:
        if spec.code in existing:
            continue
        fw = Framework(
            code=spec.code, name=spec.name,
            family=spec.family, description=spec.description,
        )
        session.add(fw)
    # OTHER bucket
    if "OTHER" not in existing:
        session.add(Framework(code="OTHER", name="Other / Misc",
                              family="Other", description="Unclassified columns"))
    await session.flush()
    return {
        f.code: f.id
        for f in (await session.execute(select(Framework))).scalars().all()
    }


async def _ensure_family(session: AsyncSession, raw: str | None,
                          cache: dict[str, int]) -> int | None:
    if not raw:
        return None
    m = FAMILY_RE.match(raw.strip())
    if m:
        code, name = m.group(1), m.group(2).strip().title() or raw
    else:
        code, name = raw[:16].upper(), raw
    if code in cache:
        return cache[code]
    obj = (
        await session.execute(select(ControlFamily).where(ControlFamily.code == code))
    ).scalar_one_or_none()
    if obj is None:
        obj = ControlFamily(code=code, name=name)
        session.add(obj)
        await session.flush()
    cache[code] = obj.id
    return obj.id


def _iter_sheet_rows(ws: Any) -> Iterable[tuple[int, list[str], tuple[Any, ...]]]:
    headers: list[str] = []
    for i, row in enumerate(ws.iter_rows(values_only=True)):
        if i == 0:
            headers = [
                str(h) if h is not None else f"col_{idx}"
                for idx, h in enumerate(row)
            ]
            continue
        if not any(c is not None and str(c).strip() for c in row):
            continue
        yield i, headers, row


async def _ingest_assessment(
    session: AsyncSession,
    ws: Any,
    framework_ids: dict[str, int],
) -> dict[str, int]:
    stats = {"rows": 0, "mappings": 0, "skipped": 0}
    family_cache: dict[str, int] = {}

    # Wipe prior snapshot so every ingest is deterministic.
    await session.execute(delete(FrameworkMapping))
    await session.execute(delete(Control))

    core_map = {
        # identifier is set explicitly on Control() (may be suffixed for dupes)
        "Sequence Control": "sequence_control",
        "sort-as": "sort_as",
        "Rev 5 Assurance Control?": "assurance_control",
        "NIST SP 800-53R5  Control": "control_number",
        "AP Acronym (from IGAP Control Export on RMF KS)": "ap_acronym",
        "OPD?": "opd",
        "control-name": "control_name",
        "Security Control Description": "description",
        "Security Control Discussion": "discussion",
        "NIST SP 800-53 Rev. 5 related controls": "related_controls",
        "Owner": "owner",
        "Overall Control Type": "overall_control_type",
        "Implemented By": "implemented_by",
        "assessment-objective": "assessment_objective",
        "EXAMINE": "examine",
        "INTERVIEW": "interview",
        "TEST": "test",
        "FISMA Low": "fisma_low",
        "FISMA Mod": "fisma_mod",
        "FISMA High": "fisma_high",
    }
    bool_fields = {"opd", "fisma_low", "fisma_mod", "fisma_high"}

    batch: list[Control] = []
    mapping_batch: list[FrameworkMapping] = []
    seen_identifiers: set[str] = set()

    for row_idx, headers, row in _iter_sheet_rows(ws):
        record = dict(zip(headers, row))
        identifier = _clean(record.get("identifier"))
        if not identifier:
            stats["skipped"] += 1
            continue
        identifier = str(identifier)
        # The workbook has repeated identifiers for multi-objective rows; keep
        # each row distinct by suffixing with the source row index.
        if identifier in seen_identifiers:
            identifier = f"{identifier}#row{row_idx}"
        seen_identifiers.add(identifier)

        family_id = await _ensure_family(session, _clean(record.get("family")), family_cache)

        ctl = Control(
            identifier=identifier,
            family_id=family_id,
            source_row=row_idx,
            audit_payload={k: v for k, v in record.items() if _clean(v) is not None},
        )
        for header, attr in core_map.items():
            val = record.get(header)
            if attr in bool_fields:
                setattr(ctl, attr, _coerce_bool(val))
            else:
                cleaned = _clean(val)
                setattr(ctl, attr, str(cleaned) if cleaned is not None else None)
        session.add(ctl)
        await session.flush()  # need id for mappings
        stats["rows"] += 1

        for header, value in record.items():
            if header in CORE_HEADERS:
                continue
            v = _clean(value)
            if v is None:
                continue
            fw_code = classify_header(header) or "OTHER"
            mapping_batch.append(FrameworkMapping(
                control_id=ctl.id,
                framework_id=framework_ids.get(fw_code),
                column_key=header,
                value=str(v),
            ))
            stats["mappings"] += 1

        if len(mapping_batch) >= 500:
            session.add_all(mapping_batch)
            await session.flush()
            mapping_batch.clear()

    if mapping_batch:
        session.add_all(mapping_batch)
        await session.flush()

    await session.execute(text("""
        UPDATE ccf.controls SET search_vector =
          setweight(to_tsvector('english', coalesce(identifier,'')), 'A') ||
          setweight(to_tsvector('english', coalesce(control_name,'')), 'A') ||
          setweight(to_tsvector('english', coalesce(assessment_objective,'')), 'B') ||
          setweight(to_tsvector('english', coalesce(description,'')), 'C') ||
          setweight(to_tsvector('english', coalesce(discussion,'')), 'D')
    """))
    return stats


async def _ingest_generic_sheet(
    session: AsyncSession, sheet_name: str, ws: Any,
) -> dict[str, int]:
    stats = {"rows": 0}
    slug = slugify(sheet_name, max_length=240) or f"sheet-{abs(hash(sheet_name))}"

    existing = (
        await session.execute(select(Worksheet).where(Worksheet.name == sheet_name))
    ).scalar_one_or_none()
    if existing is not None:
        await session.delete(existing)
        await session.flush()

    headers: list[str] = []
    rows_out: list[WorksheetRow] = []
    for i, row in enumerate(ws.iter_rows(values_only=True)):
        if i == 0:
            headers = [
                str(h) if h is not None else f"col_{idx}"
                for idx, h in enumerate(row)
            ]
            continue
        if not any(c is not None and str(c).strip() for c in row):
            continue
        payload = {
            h: (v if isinstance(v, (int, float, bool)) else str(v).strip())
            for h, v in zip(headers, row)
            if v is not None and str(v).strip()
        }
        if not payload:
            continue
        rows_out.append(WorksheetRow(row_index=i, payload=payload))
        stats["rows"] += 1

    sheet = Worksheet(
        name=sheet_name,
        slug=slug,
        headers=headers,
        row_count=stats["rows"],
        rows=rows_out,
    )
    session.add(sheet)
    await session.flush()
    return stats


async def ingest_workbook(session: AsyncSession, xlsx_path: Path) -> IngestionRun:
    log.info("ingest.start", path=str(xlsx_path))
    run = IngestionRun(source_file=str(xlsx_path), sha256=_sha256(xlsx_path))
    session.add(run)
    await session.flush()

    wb = openpyxl.load_workbook(xlsx_path, read_only=True, data_only=True)
    try:
        framework_ids = await _seed_frameworks(session)

        per_sheet: dict[str, dict[str, int]] = {}
        for sheet_name in wb.sheetnames:
            ws = wb[sheet_name]
            if sheet_name == ASSESSMENT_SHEET:
                per_sheet[sheet_name] = await _ingest_assessment(
                    session, ws, framework_ids,
                )
            else:
                per_sheet[sheet_name] = await _ingest_generic_sheet(session, sheet_name, ws)
            log.info("ingest.sheet", sheet=sheet_name, **per_sheet[sheet_name])

        run.finished_at = datetime.now(timezone.utc)
        run.status = "succeeded"
        run.stats = {"sheets": per_sheet}
        await session.flush()
        return run
    except Exception:
        run.finished_at = datetime.now(timezone.utc)
        run.status = "failed"
        await session.flush()
        raise
    finally:
        wb.close()
