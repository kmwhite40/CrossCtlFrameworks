"""Workbook ingestion pipeline.

Flow per run:
  1. SHA-256 the source; upsert ccf_audit.workbook_versions (content-addressed).
  2. Open a ccf.ingestion_runs row linked to the version.
  3. Validate assessment-tab headers against contracts/headers.v1_1.json.
  4. Ingest assessment -> ccf.controls + ccf.framework_mappings.
     Rows without identifier are quarantined in ccf_audit.rejected_rows.
  5. Snapshot the authoritative row set into ccf_audit.control_history and
     ccf_audit.mapping_history (one snapshot per workbook version).
  6. Ingest every other sheet into ccf.worksheets / ccf.worksheet_rows.
  7. Refresh the controls.search_vector column.
  8. Close the run with per-sheet stats.
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
    ControlHistory,
    Framework,
    FrameworkMapping,
    IngestionRun,
    MappingHistory,
    RejectedRow,
    WorkbookVersion,
    Worksheet,
    WorksheetRow,
)
from .frameworks import FRAMEWORKS, CORE_HEADERS, classify_header
from .validate import HeaderContractError, load_contract, validate_headers

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


async def _upsert_workbook_version(
    session: AsyncSession, xlsx_path: Path, sha: str
) -> WorkbookVersion:
    existing = (
        await session.execute(
            select(WorkbookVersion).where(WorkbookVersion.sha256 == sha)
        )
    ).scalar_one_or_none()
    if existing:
        return existing
    wv = WorkbookVersion(
        sha256=sha,
        source_path=str(xlsx_path),
        size_bytes=xlsx_path.stat().st_size,
    )
    session.add(wv)
    await session.flush()
    return wv


async def _seed_frameworks(session: AsyncSession) -> dict[str, int]:
    existing = {
        f.code: f.id
        for f in (await session.execute(select(Framework))).scalars().all()
    }
    for spec in FRAMEWORKS:
        if spec.code in existing:
            continue
        session.add(Framework(
            code=spec.code, name=spec.name,
            family=spec.family, description=spec.description,
        ))
    if "OTHER" not in existing:
        session.add(Framework(code="OTHER", name="Other / Misc",
                              family="Other", description="Unclassified columns"))
    await session.flush()
    return {
        f.code: f.id
        for f in (await session.execute(select(Framework))).scalars().all()
    }


async def _ensure_family(
    session: AsyncSession, raw: str | None, cache: dict[str, int]
) -> int | None:
    if not raw:
        return None
    m = FAMILY_RE.match(raw.strip())
    if m:
        code, name = m.group(1), (m.group(2).strip().title() or raw)
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
    run: IngestionRun,
    workbook_version: WorkbookVersion,
) -> dict[str, int]:
    stats = {"rows": 0, "mappings": 0, "rejected": 0}
    family_cache: dict[str, int] = {}

    await session.execute(delete(FrameworkMapping))
    await session.execute(delete(Control))

    core_map = {
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

    mapping_batch: list[FrameworkMapping] = []
    history_mappings: list[MappingHistory] = []
    history_controls: list[ControlHistory] = []
    seen_identifiers: set[str] = set()

    # Validate headers against the contract once.
    first = True
    header_set: set[str] = set()

    for row_idx, headers, row in _iter_sheet_rows(ws):
        if first:
            header_set = set(headers)
            diff = validate_headers(header_set, load_contract())
            if diff.added:
                log.info("ingest.header_drift", new_headers_count=len(diff.added))
            first = False

        record = dict(zip(headers, row))
        identifier = _clean(record.get("identifier"))
        if not identifier:
            session.add(RejectedRow(
                run_id=run.id, sheet=ASSESSMENT_SHEET, row_index=row_idx,
                rule="missing_identifier",
                payload={k: str(v) for k, v in record.items() if v is not None},
            ))
            stats["rejected"] += 1
            continue
        identifier = str(identifier)
        if identifier in seen_identifiers:
            identifier = f"{identifier}#row{row_idx}"
        seen_identifiers.add(identifier)

        family_id = await _ensure_family(
            session, _clean(record.get("family")), family_cache,
        )

        audit_payload = {k: v for k, v in record.items() if _clean(v) is not None}
        ctl = Control(
            identifier=identifier,
            family_id=family_id,
            source_row=row_idx,
            audit_payload=audit_payload,
        )
        for header, attr in core_map.items():
            val = record.get(header)
            if attr in bool_fields:
                setattr(ctl, attr, _coerce_bool(val))
            else:
                cleaned = _clean(val)
                setattr(ctl, attr, str(cleaned) if cleaned is not None else None)
        session.add(ctl)
        await session.flush()
        stats["rows"] += 1

        history_controls.append(ControlHistory(
            identifier=identifier,
            workbook_version_id=workbook_version.id,
            payload=audit_payload,
        ))

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
            history_mappings.append(MappingHistory(
                identifier=identifier,
                workbook_version_id=workbook_version.id,
                column_key=header,
                value=str(v),
            ))
            stats["mappings"] += 1

        if len(mapping_batch) >= 500:
            session.add_all(mapping_batch)
            mapping_batch.clear()
            await session.flush()
        if len(history_mappings) >= 1000:
            session.add_all(history_mappings)
            history_mappings.clear()
            await session.flush()

    if mapping_batch:
        session.add_all(mapping_batch)
    if history_controls:
        session.add_all(history_controls)
    if history_mappings:
        session.add_all(history_mappings)
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
        name=sheet_name, slug=slug, headers=headers,
        row_count=stats["rows"], rows=rows_out,
    )
    session.add(sheet)
    await session.flush()
    return stats


async def ingest_workbook(session: AsyncSession, xlsx_path: Path) -> IngestionRun:
    log.info("ingest.start", path=str(xlsx_path))
    sha = _sha256(xlsx_path)

    workbook_version = await _upsert_workbook_version(session, xlsx_path, sha)

    run = IngestionRun(
        source_file=str(xlsx_path),
        sha256=sha,
        workbook_version_id=workbook_version.id,
    )
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
                    session, ws, framework_ids, run, workbook_version,
                )
            else:
                per_sheet[sheet_name] = await _ingest_generic_sheet(session, sheet_name, ws)
            log.info("ingest.sheet", sheet=sheet_name, **per_sheet[sheet_name])

        run.finished_at = datetime.now(timezone.utc)
        run.status = "succeeded"
        run.stats = {"sheets": per_sheet, "sha256": sha}
        await session.flush()
        return run
    except HeaderContractError as e:
        run.finished_at = datetime.now(timezone.utc)
        run.status = "failed"
        run.stats = {"error": "header_contract", "detail": str(e)}
        await session.flush()
        raise
    except Exception as e:
        run.finished_at = datetime.now(timezone.utc)
        run.status = "failed"
        run.stats = {"error": "exception", "detail": str(e)[:500]}
        await session.flush()
        raise
    finally:
        wb.close()
