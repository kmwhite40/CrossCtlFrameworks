"""Poll a tenant's desired-state repository, and adopt what it declares.

GitOps for desired state (CC&E #10). The repository holds the pack manifest,
changes arrive as commits reviewed outside the platform, and the commit sha is
the version identity.

No git client, no clone, no SSH: a manifest is a file, so a raw URL at a ref
plus the commit sha that last touched it is the whole of git's contribution.
The fetch, hashing and commit resolution are :mod:`ccf.etl.sources`' -- a
second conditional-fetch implementation would drift from the one that already
handles a server ignoring ``If-None-Match``.

**Detection is automatic; adoption is not.** Polling is read-only and joins the
scheduler's per-tenant cycle. A changed manifest is stored as
``pending_manifest`` for an operator to review -- with the change-impact report
from :mod:`ccf.packs.impact` -- before it takes effect. ``auto_install`` exists
and defaults to ``False``, mirroring ``CatalogSource.auto_ingest`` and for a
stronger reason: a pack rule *executes* against a customer tenant, and a
platform that silently changes what it asserts about a system because someone
merged a PR is one whose SSP no longer describes a reviewed decision.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..etl.sources import fetch_conditional, resolve_commit_sha, sha256_bytes
from ..logging import get_logger
from ..models_packs import CompliancePack, PackSource
from .catalog import manifest_sha, validate_manifest
from .service import install_pack

log = get_logger(__name__)

#: Every outcome a poll can have. Closed, because each sends an operator
#: somewhere different.
SYNC_OUTCOMES = ("unchanged", "pending", "installed", "invalid", "error")

#: Divergence states between what is installed and what the source declares.
DIVERGENCE_STATES = ("in_sync", "pending_change", "diverged", "unknown")


async def _audit(session: AsyncSession, **kw: Any) -> None:
    from ..api.audit import record_event  # noqa: PLC0415 - avoids an import cycle

    await record_event(session, **kw)


def _result(source: PackSource, status: str, **extra: Any) -> dict[str, Any]:
    return {
        "source_id": source.id,
        "pack_key": source.pack_key,
        "status": status,
        **extra,
    }


async def _record_error(
    session: AsyncSession, source: PackSource, status: str, reason: str
) -> dict[str, Any]:
    """Record a failed poll without disturbing what was already known good."""
    source.last_status = status
    source.last_error = reason[:500]
    source.last_checked_at = datetime.now(UTC)
    await session.flush()
    return _result(source, status, reason=reason[:200])


async def _unchanged(
    session: AsyncSession, source: PackSource, reason: str, *, etag: str | None = None
) -> dict[str, Any]:
    source.last_status = "unchanged"
    source.last_error = None
    if etag:
        source.etag = etag
    await session.flush()
    return _result(source, "unchanged", reason=reason)


def _parse(body: bytes) -> tuple[dict[str, Any] | None, str | None]:
    """The manifest, or the reason it is unusable.

    Both failure modes are ``invalid`` rather than ``error``: unparseable JSON
    and a manifest that fails validation are equally problems someone must fix
    in the repository.
    """
    try:
        manifest = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        return None, f"manifest is not valid JSON: {str(e)[:200]}"
    errors = validate_manifest(manifest)
    if errors:
        return None, "; ".join(errors)[:500]
    return manifest, None


async def check_pack_source(
    session: AsyncSession, source: PackSource, *, actor: str = "scheduler"
) -> dict[str, Any]:
    """Poll one source and record what it found. Never raises.

    Five outcomes, each recorded rather than inferred (see
    :data:`SYNC_OUTCOMES`). ``invalid`` is deliberately distinct from
    ``error``: a manifest that does not validate is a content problem someone
    must fix in the repository, where a transport failure is transient, and
    reporting them identically would send an operator to the wrong place.
    """
    if not source.enabled:
        # Not "checked and unchanged" -- never looked. last_checked_at stays
        # untouched so a disabled source cannot masquerade as a healthy one.
        return _result(source, "unchanged", reason="source disabled")

    try:
        status_code, body, etag = await fetch_conditional(source.url, source.etag)
    except Exception as e:
        log.warning("packs.sync.fetch_failed", source=source.id, error=str(e)[:200])
        return await _record_error(session, source, "error", str(e))

    source.last_checked_at = datetime.now(UTC)
    if status_code == 304 or body is None:
        return await _unchanged(session, source, "not modified")

    digest = sha256_bytes(body)
    # The sha comparison is the belt to the ETag's braces: a server that
    # ignores If-None-Match must not produce a false "changed".
    if digest == source.last_sha256:
        return await _unchanged(session, source, "content identical", etag=etag)

    manifest, problem = _parse(body)
    if manifest is None:
        # Validated before anything is stored or installed: a repository can
        # always be made to contain a manifest this build cannot evaluate, and
        # the answer is to report it, not to run it.
        return await _record_error(session, source, "invalid", problem or "invalid manifest")

    commit = await resolve_commit_sha(source.url)
    canonical = manifest_sha(manifest)
    source.etag = etag or source.etag
    source.last_sha256 = digest
    source.last_manifest_sha = canonical
    source.last_commit_sha = commit
    source.last_error = None

    return await _apply(
        session,
        source,
        manifest,
        digest=digest,
        canonical=canonical,
        commit=commit,
        actor=actor,
    )




async def _apply(
    session: AsyncSession,
    source: PackSource,
    manifest: dict[str, Any],
    *,
    digest: str,
    canonical: str,
    commit: str | None,
    actor: str,
) -> dict[str, Any]:
    """Store the validated manifest for review, or install it.

    The gate lives here: ``auto_install`` off means a changed manifest waits
    for a human, reviewed against the change-impact report, because a pack rule
    executes against a customer tenant.
    """
    if not source.auto_install:
        source.last_status = "pending"
        source.pending_manifest = manifest
        source.pending_sha256 = digest
        source.pending_manifest_sha = canonical
        source.pending_commit_sha = commit
        await session.flush()
        return _result(
            source, "pending", version=str(manifest.get("version", "")), commit=commit
        )

    pack = await install_pack(
        session,
        org_id=source.organization_id,
        manifest=manifest,
        source=f"pack_source:{source.id}",
        actor=actor,
    )
    await _clear_pending(source, status="installed")
    await session.flush()
    await _audit(
        session,
        actor=actor,
        action="update",
        entity_type="pack_source",
        entity_id=str(source.id),
        diff={
            "event": "auto_installed",
            "pack_key": source.pack_key,
            "version": pack.version,
            "sha256": digest,
            "commit": commit,
            "url": source.url,
        },
    )
    await session.flush()
    return _result(source, "installed", version=pack.version, commit=commit)


async def _clear_pending(source: PackSource, *, status: str) -> None:
    source.last_status = status
    source.pending_manifest = {}
    source.pending_sha256 = None
    source.pending_manifest_sha = None
    source.pending_commit_sha = None


async def adopt_pending(
    session: AsyncSession, source: PackSource, *, actor: str
) -> CompliancePack:
    """Install the manifest a poll stored as pending.

    Refuses when nothing is pending rather than re-installing whatever is
    current: a second adopt would write a fresh version record for a decision
    nobody made.
    """
    if not source.pending_manifest:
        raise ValueError("nothing pending for this source")
    manifest = dict(source.pending_manifest)
    digest, commit = source.pending_sha256, source.pending_commit_sha
    pack = await install_pack(
        session,
        org_id=source.organization_id,
        manifest=manifest,
        source=f"pack_source:{source.id}",
        actor=actor,
    )
    await _clear_pending(source, status="installed")
    await session.flush()
    await _audit(
        session,
        actor=actor,
        action="update",
        entity_type="pack_source",
        entity_id=str(source.id),
        diff={
            "event": "adopted",
            "pack_key": source.pack_key,
            "version": pack.version,
            "sha256": digest,
            "commit": commit,
            "url": source.url,
        },
    )
    await session.flush()
    return pack


async def sync_for_org(session: AsyncSession, org_id: int | None) -> dict[str, Any]:
    """Poll every enabled source for one organization."""
    sources = (
        await session.execute(
            select(PackSource)
            .where(PackSource.organization_id == org_id, PackSource.enabled.is_(True))
            .order_by(PackSource.id)
        )
    ).scalars().all()
    results = [await check_pack_source(session, s) for s in sources]
    return {
        "organization_id": org_id,
        "sources": len(results),
        "pending": sum(1 for r in results if r["status"] == "pending"),
        "installed": sum(1 for r in results if r["status"] == "installed"),
        "results": results,
    }


async def divergence(session: AsyncSession, source: PackSource) -> dict[str, Any]:
    """Is what is running what the repository declares?

    The question GitOps exists to answer. ``diverged`` is the state nobody asks
    for and the one that matters: something was installed that this source
    never provided -- a manifest pushed through the API while a source is
    configured, which is how a deployment quietly stops matching its own
    repository.
    """
    pack = (
        await session.execute(
            select(CompliancePack).where(
                CompliancePack.organization_id == source.organization_id,
                CompliancePack.pack_key == source.pack_key,
            )
        )
    ).scalar_one_or_none()

    if source.last_manifest_sha is None:
        return {
            "state": "unknown",
            "reason": "source has never been polled",
            "installed_sha": pack.manifest_sha if pack else None,
            "source_sha": None,
        }
    if source.pending_manifest:
        state, reason = "pending_change", "a fetched change is awaiting review"
    elif pack is None:
        state, reason = "diverged", "the source declares a pack that is not installed"
    elif pack.manifest_sha == source.last_manifest_sha:
        state, reason = "in_sync", "the installed manifest is the one the source declares"
    else:
        state, reason = (
            "diverged",
            "the installed manifest is not the one this source provided",
        )
    return {
        "state": state,
        "reason": reason,
        "installed_sha": pack.manifest_sha if pack else None,
        # The canonical manifest digest, not the raw-bytes one: comparing
        # like with like is the whole point of keeping both.
        "source_sha": source.last_manifest_sha,
        "commit": source.last_commit_sha,
    }
