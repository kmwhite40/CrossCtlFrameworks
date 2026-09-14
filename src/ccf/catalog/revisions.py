"""Catalog revisions -- capture upstream content, then adopt it deliberately.

The currency poller (:mod:`ccf.etl.sources`) detects that an upstream authority
changed. This module captures *that content* as a retained revision: files on
disk with a generated ``MANIFEST.json``, plus a
:class:`~ccf.models.CatalogRevision` row. A human then diffs it, reads its
impact, and adopts it -- at which point :mod:`ccf.catalog.oscal` resolves the
adopted directory.

Nothing here adopts automatically, preserving the poller's ``auto_ingest=False``
principle: drift is recorded for a person to review, because an upstream edit
that silently moved an authorization boundary is the failure mode worth
designing against.

A revision is parse-checked with the real loader *before* its row is committed,
so a malformed upstream document is recorded as ``rejected`` and never becomes
loadable content.
"""

from __future__ import annotations

import hashlib
import shutil
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..etl.sources import parse_oscal_catalog
from ..logging import get_logger
from ..models import CatalogRevision, CatalogSource
from .oscal import OscalManifestError, generate_manifest, load_oscal_catalog

log = get_logger(__name__)

_PRIMARY_CATALOG = "NIST_SP-800-53_rev5_catalog.json"
_MANIFEST_NAME = "MANIFEST.json"


def revision_root(data_root: Path, source_key: str, revision: str) -> Path:
    """Directory holding one revision's materialized content."""
    return data_root / source_key / revision


def _revision_label(upstream_commit_sha: str | None, content_sha256: str) -> str:
    """12-char commit prefix when pinned, else a content-addressed label.

    A host with no commit concept (a plain URL, an offline import) still gets a
    stable, reproducible identity from the content itself.
    """
    if upstream_commit_sha:
        return upstream_commit_sha[:12]
    return f"sha-{content_sha256[:8]}"


def _primary_document(documents: dict[str, bytes]) -> tuple[str, bytes]:
    """The catalog document, preferred over profiles, for version/index parsing."""
    if _PRIMARY_CATALOG in documents:
        return _PRIMARY_CATALOG, documents[_PRIMARY_CATALOG]
    name = sorted(documents)[0]
    return name, documents[name]


async def _existing(
    session: AsyncSession, *, source_id: int, revision: str
) -> CatalogRevision | None:
    return (
        await session.execute(
            select(CatalogRevision).where(
                CatalogRevision.source_id == source_id,
                CatalogRevision.revision == revision,
            )
        )
    ).scalars().first()


async def materialize_revision(
    session: AsyncSession,
    *,
    source: CatalogSource,
    documents: dict[str, bytes],
    upstream_commit_sha: str | None,
    data_root: Path,
    retrieved_by: str | None = None,
) -> CatalogRevision:
    """Write ``documents`` as a retained revision of ``source``.

    Returns the existing row unchanged when this revision was already captured,
    so repeated polls of an unchanged upstream stay a no-op. Never mutates the
    adopted revision -- capture and adoption are separate decisions.
    """
    _, primary_body = _primary_document(documents)
    content_sha256 = hashlib.sha256(primary_body).hexdigest()
    revision = _revision_label(upstream_commit_sha, content_sha256)

    prior = await _existing(session, source_id=source.id, revision=revision)
    if prior is not None:
        return prior

    try:
        oscal_version, content_index = parse_oscal_catalog(primary_body)
    except Exception as exc:  # any parse failure is a rejection, not a crash
        oscal_version, content_index = None, {}
        parse_error: Exception | None = exc
    else:
        parse_error = None

    row = CatalogRevision(
        source_id=source.id,
        revision=revision,
        upstream_commit_sha=upstream_commit_sha,
        upstream_url=source.url,
        oscal_version=oscal_version,
        content_sha256=content_sha256,
        content_index=content_index,
        retrieved_by=retrieved_by,
        status="available",
    )

    d = revision_root(data_root, source.key, revision)
    try:
        if parse_error is not None:
            raise parse_error
        d.mkdir(parents=True, exist_ok=True)
        for name, body in documents.items():
            (d / name).write_bytes(body)
        manifest = generate_manifest(
            d,
            oscal_version=oscal_version or "",
            source_url=source.url,
            upstream_commit_sha=upstream_commit_sha,
            retrieved_at=datetime.now(UTC).date().isoformat(),
        )
        # Parse-check with the real loader before this becomes adoptable content.
        load_oscal_catalog(d)
    except (OscalManifestError, KeyError, ValueError, TypeError, AttributeError) as exc:
        shutil.rmtree(d, ignore_errors=True)
        row.status = "rejected"
        row.notes = f"{type(exc).__name__}: {exc}"
        row.files = {}
        row.content_dir = None
        log.warning(
            "catalog revision rejected",
            source=source.key,
            revision=revision,
            error=str(exc),
        )
    else:
        row.files = manifest["files"]
        row.content_dir = str(d)

    session.add(row)
    await session.flush()
    return row


def _read_payload(payload: Path) -> dict[str, bytes]:
    """OSCAL JSON documents out of a directory or zip, ignoring any manifest."""
    documents: dict[str, bytes] = {}
    if payload.is_dir():
        for p in sorted(payload.glob("*.json")):
            if p.name != _MANIFEST_NAME:
                documents[p.name] = p.read_bytes()
    elif zipfile.is_zipfile(payload):
        with zipfile.ZipFile(payload) as zf:
            for info in zf.infolist():
                name = Path(info.filename).name
                if name.endswith(".json") and name != _MANIFEST_NAME:
                    documents[name] = zf.read(info)
    else:
        raise ValueError(f"payload must be a directory or zip: {payload}")
    return documents


async def import_revision(
    session: AsyncSession,
    *,
    source_key: str,
    payload: Path,
    data_root: Path,
    retrieved_by: str | None = None,
    notes: str | None = None,
) -> CatalogRevision:
    """Offline import for air-gapped environments -- no network.

    ``payload`` is a directory or a zip of OSCAL JSON documents. Any bundled
    ``MANIFEST.json`` is ignored in favour of regenerating one from the bytes
    actually present, so the recorded hashes always describe the landed content
    rather than what an operator asserted about it.
    """
    source = (
        await session.execute(select(CatalogSource).where(CatalogSource.key == source_key))
    ).scalars().first()
    if source is None:
        raise ValueError(f"unknown catalog source: {source_key!r}")

    documents = _read_payload(payload)
    if not documents:
        raise ValueError(f"no OSCAL JSON documents found in {payload}")

    row = await materialize_revision(
        session,
        source=source,
        documents=documents,
        upstream_commit_sha=None,
        data_root=data_root,
        retrieved_by=retrieved_by,
    )
    if notes:
        row.notes = notes if not row.notes else f"{row.notes}; {notes}"
        await session.flush()
    return row
