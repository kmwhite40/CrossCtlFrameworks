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
# Two distinct NIST authorities, deliberately not conflated:
#   * usnistgov/oscal-content -- the CONTENT (catalogs, baseline profiles).
#   * usnistgov/OSCAL         -- the SPECIFICATION (the JSON schemas we validate
#     exports against, bundled under ccf/oscal/schemas).
_NIST_RAW = "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov"
_OSCAL_SPEC_RAW = "https://raw.githubusercontent.com/usnistgov/OSCAL/main"

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
        "key": "nist_800_53_r5_low_baseline",
        "name": "NIST SP 800-53B Rev. 5 - LOW baseline (OSCAL profile)",
        "authority": "NIST",
        # A profile is not a catalog: content-hash only, like the HIGH baseline.
        "kind": "generic",
        "url": f"{_NIST_RAW}/SP800-53/rev5/json/NIST_SP-800-53_rev5_LOW-baseline_profile.json",
        "framework_code": "NIST_800_53_R5",
        "enabled": True,
    },
    {
        "key": "nist_800_53_r5_moderate_baseline",
        "name": "NIST SP 800-53B Rev. 5 - MODERATE baseline (OSCAL profile)",
        "authority": "NIST",
        # A profile is not a catalog: content-hash only, like the HIGH baseline.
        "kind": "generic",
        "url": (
            f"{_NIST_RAW}/SP800-53/rev5/json/"
            "NIST_SP-800-53_rev5_MODERATE-baseline_profile.json"
        ),
        "framework_code": "NIST_800_53_R5",
        "enabled": True,
    },
    {
        "key": "nist_csf_2_0_catalog",
        "name": "NIST CSF 2.0 - framework catalog (OSCAL)",
        "authority": "NIST",
        "kind": "oscal_catalog",
        "url": f"{_NIST_RAW}/CSF/v2.0/json/NIST_CSF_v2.0_catalog.json",
        "framework_code": "NIST_CSF_2_0",
        "enabled": True,
    },
    {
        # Filename confirmed against usnistgov/oscal-content: 800-171 uses
        # "NIST_SP800-171" (no hyphen after SP), unlike 800-53's "NIST_SP-800-53".
        "key": "nist_800_171_r3_catalog",
        "name": "NIST SP 800-171 Rev. 3 - CUI requirements catalog (OSCAL)",
        "authority": "NIST",
        "kind": "oscal_catalog",
        "url": f"{_NIST_RAW}/SP800-171/rev3/json/NIST_SP800-171_rev3_catalog.json",
        "framework_code": "NIST_800_171_R3",
        "enabled": True,
    },
    {
        # The OSCAL specification itself, not catalog content. ccf/oscal/schemas
        # pins these by sha256 in a hand-maintained manifest (v1.1.2, retrieved
        # 2026-07-28), which has the same drift blindness the catalog had: a new
        # OSCAL release goes unnoticed until someone looks. Registering it here
        # means drift is at least detected and recorded for a human to act on.
        # Consumed by ccf.oscal.validation, not by the catalog loader, so the
        # kind is content-hash only.
        "key": "nist_oscal_schema_ssp",
        "name": "NIST OSCAL - SSP JSON schema (specification)",
        "authority": "NIST",
        "kind": "generic",
        "url": f"{_OSCAL_SPEC_RAW}/json/schema/oscal_ssp_schema.json",
        "framework_code": None,
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


def diff_content_index(old: dict[str, str], new: dict[str, str]) -> dict[str, list[str]]:
    """Added / modified / removed control ids between two content indexes.

    Public because :mod:`ccf.catalog.diff` reuses it for the control-set half of
    a revision diff rather than recomputing the same set arithmetic -- so the
    poller and the revision differ can never disagree about what "added" means.
    """
    old_keys, new_keys = set(old), set(new)
    added = sorted(new_keys - old_keys)
    removed = sorted(old_keys - new_keys)
    modified = sorted(k for k in old_keys & new_keys if old[k] != new[k])
    return {"added": added, "modified": modified, "removed": removed}


# Retained for existing callers/tests that import the private name.
_diff_index = diff_content_index


_GH_RAW_PREFIX = "https://raw.githubusercontent.com/"
_GH_API = "https://api.github.com"


def parse_commit_url(url: str) -> tuple[str | None, str | None, str | None]:
    """Split a raw.githubusercontent URL into ``(repo, ref, path)``.

    Returns ``(None, None, None)`` for anything that is not a GitHub raw URL --
    ``file://`` sources and other hosts simply have no commit concept, and the
    caller falls back to a content-addressed revision label.
    """
    if not url.startswith(_GH_RAW_PREFIX):
        return None, None, None
    parts = url[len(_GH_RAW_PREFIX) :].split("/")
    if len(parts) < 4:
        return None, None, None
    owner, repo, ref = parts[0], parts[1], parts[2]
    return f"{owner}/{repo}", ref, "/".join(parts[3:])


async def _get_json(url: str) -> Any:
    async with httpx.AsyncClient(timeout=20.0, headers={"User-Agent": _UA}) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        return resp.json()


async def resolve_commit_sha(url: str) -> str | None:
    """The commit that last touched ``url``'s path, for reproducible pinning.

    Best-effort by design. Sources poll a moving ref (``main``) because that is
    what detects drift; the pin is recorded per *revision*, which is where
    reproducibility actually matters. Any failure returns ``None`` and the
    revision falls back to a content-addressed label rather than failing the
    poll -- pinning is a provenance nicety, not a precondition.
    """
    repo, ref, path = parse_commit_url(url)
    if not (repo and ref and path):
        return None
    try:
        payload = await _get_json(
            f"{_GH_API}/repos/{repo}/commits?path={path}&sha={ref}&per_page=1"
        )
        if isinstance(payload, list) and payload:
            sha = payload[0].get("sha")
            return str(sha) if sha else None
    except Exception as exc:  # pinning must never break a poll
        log.debug("catalog.commit_resolution_failed", url=url, error=str(exc)[:200])
    return None


# --- per-source check -------------------------------------------------------


async def check_source(
    session: AsyncSession,
    source: CatalogSource,
    *,
    data_dir: Path | None = None,
    revision_data_root: Path | None = None,
) -> CatalogCheck:
    """Fetch one source, detect drift, and persist a :class:`CatalogCheck`.

    When ``revision_data_root`` is given and the source is an OSCAL catalog,
    changed content is additionally captured as a retained
    :class:`~ccf.models.CatalogRevision` so a human can diff and adopt it.
    Capture never adopts. Omitting the argument -- which every pre-existing
    caller does -- leaves behaviour exactly as it was.
    """
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

        if revision_data_root is not None and source.kind == "oscal_catalog":
            # Capture the changed content as a retained revision. Never adopts --
            # a human does that after reading the impact report.
            # Lazy import: catalog.revisions imports this module for its parser.
            from ..catalog.revisions import materialize_revision  # noqa: PLC0415

            captured = await materialize_revision(
                session,
                source=source,
                documents={Path(source.url).name: body},
                upstream_commit_sha=await resolve_commit_sha(source.url),
                data_root=revision_data_root,
                retrieved_by="poller",
            )
            detail["captured_revision"] = captured.revision
            detail["captured_status"] = captured.status

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
    # Revision capture is opt-in: it writes files, so it needs a durable volume.
    revision_root = (
        settings.data_dir / "oscal" if settings.catalog_capture_revisions else None
    )
    checks: list[CatalogCheck] = []
    for src in sources:
        checks.append(
            await check_source(
                session, src, data_dir=settings.data_dir, revision_data_root=revision_root
            )
        )
        await session.flush()
    return checks
