"""Catalog currency — poll authoritative upstream sources for control updates.

The static workbook drifts out of date as NIST (and the curated cross-mapping
itself) publishes revisions. This module keeps a registry of authoritative
sources (:class:`~ccf.models.CatalogSource`) and, on a schedule, fetches each
one, content-hashes it, and records whether it changed
(:class:`~ccf.models.CatalogCheck`).

Detection is conditional and idempotent:
  * We send ``If-None-Match`` with the stored ETag; a ``304`` is a no-op.
  * We also compare the SHA-256 of the body, so servers that ignore the ETag
    still don't produce false "changed" events.

For ``oscal_catalog`` sources we go further: we parse the NIST OSCAL JSON,
index every control by a hash of its title + prose, and diff that against the
last successful fetch to produce a concrete changelog (controls added /
modified / removed). For ``xlsx`` sources with ``auto_ingest`` we drop the new
file into ``data_dir`` and re-run :func:`ccf.etl.ingest_workbook`, reusing the
existing provenance/SCD-2 path. By default ``auto_ingest`` is off — drift is
recorded for a human to review and re-ingest through a gated PR, which is the
safer default for a compliance catalog.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..logging import get_logger
from ..models import CatalogCheck, CatalogSource
from .pipeline import ingest_workbook

log = get_logger(__name__)

_UA = "ConcordCatalogPoller/0.1 (+compliance-controls-platform)"
_NIST_RAW = "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov"

# Seeded on `ccf sources-seed`. Authoritative, machine-readable upstreams.
DEFAULT_SOURCES: list[dict[str, Any]] = [
    {
        "key": "nist_800_53_r5_catalog",
        "name": "NIST SP 800-53 Rev. 5 — control catalog (OSCAL)",
        "authority": "NIST",
        "kind": "oscal_catalog",
        "url": f"{_NIST_RAW}/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
        "framework_code": "NIST_800_53_R5",
        "enabled": True,
    },
    {
        "key": "nist_800_53a_r5_assessment",
        "name": "NIST SP 800-53A Rev. 5 — assessment procedures (OSCAL)",
        "authority": "NIST",
        "kind": "oscal_catalog",
        "url": f"{_NIST_RAW}/SP800-53/rev5/json/NIST_SP-800-53A_rev5_catalog.json",
        "framework_code": "NIST_800_53A_R5",
        "enabled": True,
    },
    {
        "key": "nist_800_53_r5_high_baseline",
        "name": "NIST SP 800-53 Rev. 5 — HIGH baseline profile (OSCAL)",
        "authority": "NIST",
        "kind": "generic",
        "url": f"{_NIST_RAW}/SP800-53/rev5/json/NIST_SP-800-53_rev5_HIGH-baseline_profile.json",
        "framework_code": "NIST_800_53_R5",
        "enabled": True,
    },
    {
        "key": "cross_mappings_workbook",
        "name": "Concord cross-mapping workbook (curated)",
        "authority": "Concord",
        "kind": "xlsx",
        # Point this at wherever the workbook is canonically stored (git raw,
        # S3, SharePoint download link). A local file:// path also works.
        "url": "file:///data/NIST Cross Mappings Rev. 1.1.xlsx",
        "framework_code": None,
        "enabled": False,  # off until a canonical URL is set
        "auto_ingest": False,
    },
]


def _sha256_bytes(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


async def _fetch(url: str, etag: str | None) -> tuple[int, bytes | None, str | None]:
    """Return ``(http_status, body_or_None, etag)``.

    ``body`` is ``None`` on a 304 (not modified). Supports ``file://`` and bare
    local paths so the curated workbook can be polled from disk.
    """
    if url.startswith("file://") or url.startswith("/"):
        path = Path(url.removeprefix("file://"))
        data = await _read_file(path)
        return 200, data, None

    headers = {"User-Agent": _UA, "Accept": "application/json, */*"}
    if etag:
        headers["If-None-Match"] = etag
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        resp = await client.get(url, headers=headers)
    if resp.status_code == 304:
        return 304, None, etag
    resp.raise_for_status()
    return resp.status_code, resp.content, resp.headers.get("ETag")


async def _read_file(path: Path) -> bytes:
    return await asyncio.to_thread(path.read_bytes)


# --- OSCAL catalog parsing --------------------------------------------------


def _gather_prose(node: dict[str, Any]) -> list[str]:
    """Recursively collect all ``prose`` strings under an OSCAL part node."""
    out: list[str] = []
    prose = node.get("prose")
    if isinstance(prose, str):
        out.append(prose)
    for part in node.get("parts", []) or []:
        if isinstance(part, dict):
            out.extend(_gather_prose(part))
    return out


def _walk_controls(container: dict[str, Any], acc: dict[str, str]) -> None:
    """Populate ``acc[control_id] = content_hash`` from a catalog/group node."""
    for ctl in container.get("controls", []) or []:
        if not isinstance(ctl, dict):
            continue
        cid = ctl.get("id")
        if cid:
            material = [str(ctl.get("title", ""))]
            for part in ctl.get("parts", []) or []:
                if isinstance(part, dict):
                    material.extend(_gather_prose(part))
            acc[str(cid)] = hashlib.sha256(" ".join(material).encode()).hexdigest()[:16]
        # Control enhancements nest under the control's own "controls".
        _walk_controls(ctl, acc)
    for group in container.get("groups", []) or []:
        if isinstance(group, dict):
            _walk_controls(group, acc)


def parse_oscal_catalog(body: bytes) -> tuple[str | None, dict[str, str]]:
    """Return ``(revision_label, {control_id: content_hash})`` for a catalog."""
    doc = json.loads(body)
    catalog = doc.get("catalog", doc)
    revision = (catalog.get("metadata") or {}).get("version")
    index: dict[str, str] = {}
    _walk_controls(catalog, index)
    return revision, index


def _diff_index(old: dict[str, str], new: dict[str, str]) -> dict[str, list[str]]:
    old_keys, new_keys = set(old), set(new)
    added = sorted(new_keys - old_keys)
    removed = sorted(old_keys - new_keys)
    modified = sorted(k for k in old_keys & new_keys if old[k] != new[k])
    return {"added": added, "modified": modified, "removed": removed}


# --- per-source check -------------------------------------------------------


async def check_source(
    session: AsyncSession,
    source: CatalogSource,
    *,
    data_dir: Path | None = None,
) -> CatalogCheck:
    """Fetch one source, detect drift, and persist a :class:`CatalogCheck`."""
    started = time.monotonic()
    now = datetime.now(UTC)
    check = CatalogCheck(source_id=source.id)
    detail: dict[str, Any] = {}
    try:
        http_status, body, etag = await _fetch(source.url, source.etag)
        check.http_status = http_status
        source.last_checked_at = now
        source.last_error = None

        if body is None:  # 304 Not Modified
            check.status = "unchanged"
            source.last_status = "unchanged"
            detail["message"] = "304 Not Modified"
            check.detail = detail
            check.sha256 = source.last_sha256
            return _finish(session, source, check, started)

        sha = _sha256_bytes(body)
        check.sha256 = sha
        if etag:
            source.etag = etag

        if sha == source.last_sha256:
            check.status = "unchanged"
            source.last_status = "unchanged"
            detail["message"] = "content identical (sha match)"
            check.detail = detail
            return _finish(session, source, check, started)

        # --- content changed ------------------------------------------------
        source.last_changed_at = now
        detail["previous_sha256"] = source.last_sha256

        if source.kind == "oscal_catalog":
            revision, new_index = parse_oscal_catalog(body)
            diff = _diff_index(source.content_index or {}, new_index)
            detail.update(
                revision=revision,
                item_count=len(new_index),
                added=diff["added"][:200],
                modified=diff["modified"][:200],
                removed=diff["removed"][:200],
                counts={k: len(v) for k, v in diff.items()},
            )
            source.revision_label = revision
            source.item_count = len(new_index)
            source.content_index = new_index

        elif source.kind == "xlsx" and source.auto_ingest and data_dir is not None:
            target = data_dir / f"{source.key}.xlsx"
            await _write_file(target, body)
            run = await ingest_workbook(session, target)
            detail.update(
                ingested=True,
                ingestion_run_id=run.id,
                ingestion_status=run.status,
            )
            check.status = "ingested"
            source.last_status = "ingested"
            source.last_sha256 = sha
            check.detail = detail
            return _finish(session, source, check, started)

        check.status = "changed"
        source.last_status = "changed"
        source.last_sha256 = sha
        check.detail = detail
        log.info(
            "catalog.drift",
            source=source.key,
            revision=detail.get("revision"),
            counts=detail.get("counts"),
        )
        from ..governance import bus  # noqa: PLC0415 — lazy to avoid import cycle

        await bus.emit(
            session,
            verb="drifted",
            entity_type="catalog_source",
            entity_id=source.id,
            summary=f"Catalog drift: {source.name} → {source.revision_label or '?'}",
            payload={"counts": detail.get("counts")},
            dispatch=False,
        )
        return _finish(session, source, check, started)

    except Exception as e:  # record and move on to the next source
        check.status = "error"
        source.last_status = "error"
        source.last_checked_at = now
        source.last_error = str(e)[:500]
        detail["error"] = str(e)[:500]
        check.detail = detail
        log.warning("catalog.check_failed", source=source.key, error=str(e)[:200])
        return _finish(session, source, check, started)


def _finish(
    session: AsyncSession, source: CatalogSource, check: CatalogCheck, started: float
) -> CatalogCheck:
    check.duration_ms = int((time.monotonic() - started) * 1000)
    session.add(check)
    session.add(source)
    return check


async def _write_file(path: Path, body: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    await asyncio.to_thread(path.write_bytes, body)


# --- orchestration ----------------------------------------------------------


async def seed_sources(session: AsyncSession) -> int:
    """Upsert :data:`DEFAULT_SOURCES` by ``key``. Returns rows created."""
    existing = {s.key for s in (await session.execute(select(CatalogSource))).scalars().all()}
    created = 0
    for spec in DEFAULT_SOURCES:
        if spec["key"] in existing:
            continue
        session.add(CatalogSource(**spec))
        created += 1
    await session.flush()
    return created


async def poll(
    session: AsyncSession,
    *,
    only_key: str | None = None,
    include_disabled: bool = False,
) -> list[CatalogCheck]:
    """Check every enabled source (or one, via ``only_key``)."""
    settings = get_settings()
    stmt = select(CatalogSource).order_by(CatalogSource.id)
    if only_key:
        stmt = stmt.where(CatalogSource.key == only_key)
    elif not include_disabled:
        stmt = stmt.where(CatalogSource.enabled.is_(True))

    sources = (await session.execute(stmt)).scalars().all()
    checks: list[CatalogCheck] = []
    for src in sources:
        checks.append(await check_source(session, src, data_dir=settings.data_dir))
        await session.flush()
    return checks
