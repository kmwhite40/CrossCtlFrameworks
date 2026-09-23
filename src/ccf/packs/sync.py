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

import ipaddress
import json
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..etl.sources import FetchTooLargeError, fetch_conditional, resolve_commit_sha, sha256_bytes
from ..logging import get_logger
from ..models_packs import CompliancePack, PackSource
from .catalog import manifest_sha, validate_manifest
from .service import install_pack

log = get_logger(__name__)

#: Every outcome a poll can have. Closed, because each sends an operator
#: somewhere different. ``backoff`` (IMPORTANT 8) means the source is in its
#: failure-backoff window and was deliberately not fetched this cycle.
SYNC_OUTCOMES = ("unchanged", "pending", "installed", "invalid", "error", "backoff")

#: Divergence states between what is installed and what the source declares.
DIVERGENCE_STATES = ("in_sync", "pending_change", "diverged", "unknown")

#: Manifests are small, hand-authored JSON documents -- a few KB, occasionally
#: a few hundred. 2 MiB is generous headroom without buffering an unbounded
#: body in the scheduler process (CRITICAL 3). Distinct from the catalog
#: poller, which fetches legitimately larger NIST OSCAL catalogs uncapped --
#: see ``etl.sources.fetch_conditional``'s docstring.
PACK_SOURCE_MAX_BYTES = 2 * 1024 * 1024

#: Backoff schedule for a source stuck at ``invalid``/``error``: doubles per
#: consecutive failure, capped at one day, so a permanently broken source
#: settles to at most one fetch a day instead of one every scheduler cycle.
_BACKOFF_BASE_SECONDS = 60
_BACKOFF_MAX_SECONDS = 24 * 60 * 60
_BACKOFF_FAILURE_CAP = 12


class PackSourceRejectedError(ValueError):
    """A pack source's URL is not safe to fetch.

    Distinct from a transport failure (``error``): this is a configuration
    problem the operator must fix in the source, exactly like a manifest that
    fails validation, so it is recorded as ``invalid`` rather than ``error``.
    """


def validate_pack_source_url(url: str) -> None:
    """Raise :class:`PackSourceRejectedError` unless ``url`` is safe to poll.

    The gate for PR #17 security review CRITICAL 1 (SSRF + arbitrary local
    file read via a tenant-supplied pack source URL). Applied at BOTH
    registration (``api/routes/packs.py``) and again at every fetch (here, via
    :func:`check_pack_source`), so a row written before this validation
    existed -- or by any future path that bypasses the API route -- can never
    be fetched either.

    ``https://`` only: this alone rejects ``file://``, a bare local path
    (``/etc/passwd``), and every other scheme (``http://``, ``ftp://``,
    ``git://``...). On top of that, the host may not be a loopback,
    link-local (169.254.0.0/16), or RFC1918-private IP literal, nor
    ``localhost`` by name -- ``https://169.254.169.254/...`` (cloud instance
    metadata) and ``https://192.168.1.1/...`` (internal network) are https
    URLs that a scheme check alone would not catch.

    Deliberately does NOT resolve DNS: a full defense against DNS rebinding
    would need to re-validate the resolved address immediately before the
    connection is made, which is what ``follow_redirects=False`` plus this
    same check on every poll already buys for the redirect variant of the
    attack. Resolving here would only add a TOCTOU-prone illusion of safety.
    """
    parsed = urlsplit(url)
    if parsed.scheme != "https":
        raise PackSourceRejectedError(
            f"pack source url must use https; got {parsed.scheme or '(none)'!r}"
        )
    host = parsed.hostname
    if not host:
        raise PackSourceRejectedError(f"pack source url has no host: {url!r}")
    if host.lower() == "localhost" or host.lower().endswith(".localhost"):
        raise PackSourceRejectedError(f"pack source url host is not allowed: {host!r}")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None and (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_private
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        raise PackSourceRejectedError(
            f"pack source url resolves to a disallowed address: {host!r}"
        )


def _backoff_seconds(consecutive_failures: int) -> int:
    if consecutive_failures <= 0:
        return 0
    exp = min(consecutive_failures, _BACKOFF_FAILURE_CAP)
    doubled = _BACKOFF_BASE_SECONDS * (2 ** (exp - 1))
    return int(min(doubled, _BACKOFF_MAX_SECONDS))


async def _audit(
    session: AsyncSession, *, organization_id: int | None, **kw: Any
) -> None:
    """Append a tenant-scoped audit event (see :func:`ccf.api.audit.record_event`).

    ``organization_id`` is required with no default, deliberately: NULL means
    "platform-wide, visible to every tenant" under migration 0044's
    ``tenant_isolation`` policy, so a call site that forgets it would publish
    this event to every organization rather than merely leave it unscoped.
    """
    from ..api.audit import record_event  # noqa: PLC0415 - avoids an import cycle

    await record_event(session, organization_id=organization_id, **kw)


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
    source.consecutive_failures += 1
    await session.flush()
    return _result(source, status, reason=reason[:200])


async def _unchanged(
    session: AsyncSession, source: PackSource, reason: str, *, etag: str | None = None
) -> dict[str, Any]:
    source.last_status = "unchanged"
    source.last_error = None
    source.consecutive_failures = 0
    if etag:
        source.etag = etag
    await session.flush()
    return _result(source, "unchanged", reason=reason)


def _parse(body: bytes) -> tuple[dict[str, Any] | None, str | None]:
    """The manifest, or the reason it is unusable.

    Catches ``Exception`` broadly, not just the decode/JSON errors a
    well-formed-but-hostile document would raise: deeply nested JSON raises
    ``RecursionError`` straight through ``json.loads``, and a source is
    tenant-supplied content this build must survive being handed anything.
    Both failure modes are ``invalid`` rather than ``error``: unparseable (or
    unparseably pathological) JSON and a manifest that fails validation are
    equally problems someone must fix in the repository.
    """
    try:
        manifest = json.loads(body.decode("utf-8"))
    except Exception as e:
        return None, f"manifest is not valid JSON: {str(e)[:200]}"
    try:
        errors = validate_manifest(manifest)
    except Exception as e:
        return None, f"manifest could not be validated: {str(e)[:200]}"
    if errors:
        return None, "; ".join(errors)[:500]
    return manifest, None


async def check_pack_source(  # noqa: PLR0911 - one return per outcome keeps each self-contained
    session: AsyncSession, source: PackSource, *, actor: str = "scheduler"
) -> dict[str, Any]:
    """Poll one source and record what it found. Never raises.

    Six outcomes, each recorded rather than inferred (see
    :data:`SYNC_OUTCOMES`). ``invalid`` is deliberately distinct from
    ``error``: a manifest that does not validate -- or a URL that fails
    :func:`validate_pack_source_url`, or a body over
    :data:`PACK_SOURCE_MAX_BYTES` -- is a content/config problem someone must
    fix in the repository, where a transport failure is transient, and
    reporting them identically would send an operator to the wrong place.

    Every step from the URL check onward is wrapped so that nothing --
    validation, fetch, parse, hash, or install -- can raise out of this
    function: a RecursionError from pathological JSON, a DB error from
    ``install_pack``, all of it is caught and recorded, because one bad
    source must never abort :func:`sync_for_org` for the rest of that org's
    sources or 500 the ``/sync`` endpoint.
    """
    if not source.enabled:
        # Not "checked and unchanged" -- never looked. last_checked_at stays
        # untouched so a disabled source cannot masquerade as a healthy one.
        return _result(source, "unchanged", reason="source disabled")

    wait = _backoff_seconds(source.consecutive_failures)
    if wait and source.last_checked_at is not None:
        due_at = source.last_checked_at + timedelta(seconds=wait)
        now = datetime.now(UTC)
        if now < due_at:
            # Deliberately does not touch last_checked_at or fetch anything:
            # a source stuck at invalid/error must not have its full body
            # re-fetched and re-parsed every scheduler cycle forever
            # (IMPORTANT 8 -- a third-party DoS amplifier driven by tenant
            # config).
            return _result(
                source,
                "backoff",
                reason=(
                    f"{source.consecutive_failures} consecutive failures; "
                    f"next attempt due {due_at.isoformat()}"
                ),
            )

    try:
        validate_pack_source_url(source.url)
    except PackSourceRejectedError as e:
        log.warning("packs.sync.url_rejected", source=source.id, error=str(e)[:200])
        return await _record_error(session, source, "invalid", str(e))

    try:
        status_code, body, etag = await fetch_conditional(
            source.url,
            source.etag,
            # A URL validated safe at registration must not be able to
            # redirect its way to an unvalidated one at fetch time
            # (CRITICAL 1). A byte cap so the scheduler never buffers an
            # unbounded body from a tenant-controlled endpoint (CRITICAL 3).
            follow_redirects=False,
            max_bytes=PACK_SOURCE_MAX_BYTES,
        )
    except FetchTooLargeError as e:
        log.warning("packs.sync.body_too_large", source=source.id, error=str(e)[:200])
        return await _record_error(session, source, "invalid", str(e))
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

    try:
        commit = await resolve_commit_sha(source.url)
        canonical = manifest_sha(manifest)
    except Exception as e:
        log.warning("packs.sync.hash_failed", source=source.id, error=str(e)[:200])
        return await _record_error(session, source, "invalid", f"could not hash manifest: {e}")

    source.etag = etag or source.etag
    source.last_sha256 = digest
    source.last_manifest_sha = canonical
    source.last_commit_sha = commit
    source.last_error = None
    source.consecutive_failures = 0

    try:
        return await _apply(
            session,
            source,
            manifest,
            digest=digest,
            canonical=canonical,
            commit=commit,
            actor=actor,
        )
    except Exception as e:
        log.warning("packs.sync.apply_failed", source=source.id, error=str(e)[:200])
        return await _record_error(session, source, "error", str(e))




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
        organization_id=source.organization_id,
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
        organization_id=source.organization_id,
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
    """Poll every enabled source for one organization. Never raises.

    ``check_pack_source`` is itself exception-safe (IMPORTANT 4), but this
    loop catches anything it might still let through as a second layer: one
    bad source must never abort the cycle for the rest of that org's sources.
    """
    sources = (
        await session.execute(
            select(PackSource)
            .where(PackSource.organization_id == org_id, PackSource.enabled.is_(True))
            .order_by(PackSource.id)
        )
    ).scalars().all()
    results: list[dict[str, Any]] = []
    for s in sources:
        try:
            results.append(await check_pack_source(session, s))
        except Exception as e:
            log.error("packs.sync.unexpected_failure", source=s.id, error=str(e)[:200])
            results.append(await _record_error(session, s, "error", str(e)))
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

    ``unknown`` covers two different situations, and they are told apart
    rather than collapsed: a source that has genuinely never been polled
    (``last_checked_at is None``) versus one that has been polled -- possibly
    for weeks -- but has never once produced a manifest, because every poll
    came back ``invalid`` or ``error``. ``last_manifest_sha is None`` alone
    (the prior check) is true in both cases, and "source has never been
    polled" is false, and misleading, for the second -- this text can reach an
    authorization artifact.
    """
    pack = (
        await session.execute(
            select(CompliancePack).where(
                CompliancePack.organization_id == source.organization_id,
                CompliancePack.pack_key == source.pack_key,
            )
        )
    ).scalar_one_or_none()

    if source.last_checked_at is None:
        return {
            "state": "unknown",
            "reason": "source has never been polled",
            "installed_sha": pack.manifest_sha if pack else None,
            "source_sha": None,
        }
    if source.last_manifest_sha is None:
        return {
            "state": "unknown",
            "reason": (
                "the last poll did not succeed "
                f"(status={source.last_status!r}); no manifest has been "
                "recorded for this source yet"
            ),
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
