"""Persist a CR26 deliverable document, judging it on every write.

The contract is narrow and worth stating: **an invalid document is stored, an
unknown kind is refused.** A draft is necessarily incomplete -- a CPO cannot
carry its assessor before an assessor exists -- so refusing invalid writes
would make authoring impossible, and refusal belongs at export or submit
instead. An unknown *kind* is different: there is no vendored schema to judge
it against, so storing it would mean storing something that can never be
validated at all.

``common`` is excluded from :data:`DELIVERABLE_KINDS`: it is the shared
``$defs`` target the other ten schemas ``$ref``, not a document any system
files, and it has no top-level required fields of its own -- so *any*
document would validate against it, making it a kind whose verdict could
never mean anything. :mod:`ccf.cr26.validation`'s registry still needs
``common`` in :data:`ccf.cr26.validation.CR26_KINDS` to resolve those
``$ref``s; this store does not treat it as filable.

What must hold on every path through this module: no document is stored
without a recorded verdict. There is no way for a call to
:func:`put_document` to write ``document`` and leave ``is_valid`` or
``validation_errors`` stale.

There is one row per ``(system_id, kind, document_key)``, so a second write
with the SAME key **overwrites** the previous document in place and nothing
in this table remembers that it existed. :mod:`ccf.models_cr26` justifies
having no history table by saying change history is :mod:`ccf.api.audit`'s
job -- so every write records an audit event here, ``create`` on the first
and ``update`` on an overwrite.

``document_key`` defaults to ``None`` and every deliverable shipped as of
0081 (``cpo``, ``sdr``, ``ocr``, ``vdr``, ``avi``, ``ver_history``) always
passes ``None`` -- their upsert identity stays exactly ``(system_id, kind)``,
unchanged from before 0081. A non-``None`` key is reserved for a per-instance
deliverable no shipped code writes yet; see :mod:`ccf.models_cr26` and
migration ``0081_cr26_document_key``.
That compensating control is the reason there is no history table; it is not
optional decoration. The event goes through
:func:`ccf.api.audit.record_event` and never by constructing ``AuditLog``
directly, which would silently break its ``prev_hash``/``row_hash`` chain.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import System
from ..models_cr26 import Cr26Document
from .validation import CR26_KINDS, schema_path, validate_document

#: The kinds a system can actually file a document as: every vendored kind
#: except ``common``, which is FedRAMP's shared ``$defs`` target rather than a
#: deliverable a system produces (see module docstring).
DELIVERABLE_KINDS: tuple[str, ...] = tuple(k for k in CR26_KINDS if k != "common")


async def _audit(session: AsyncSession, **kw: Any) -> None:
    from ..api.audit import record_event  # noqa: PLC0415 — avoid import cycle

    await record_event(session, **kw)


def _manifest() -> dict[str, Any]:
    path = Path(__file__).with_name("schemas") / "MANIFEST.json"
    return json.loads(path.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def _versions(kind: str) -> tuple[str, str | None]:
    """The ruleset revision and this schema's own semver, from the manifest.

    Indexes ``manifest["files"]`` directly rather than falling back to ``{}``
    for a missing filename: a vendored file absent from the manifest is a
    packaging failure, not a caller error, and should raise loudly here just
    as :func:`ccf.cr26.validation.vendored_digests` does for the identical
    lookup -- not be swallowed into a quiet ``schema_version=None``.
    """
    manifest = _manifest()
    filename = CR26_KINDS[kind][0]
    entry = manifest["files"][filename]
    return str(manifest["ruleset_version"]), entry.get("schema_version")


async def put_document(
    session: AsyncSession,
    *,
    system_id: int,
    kind: str,
    document: dict[str, Any],
    document_key: str | None = None,
    updated_by: str | None = None,
) -> Cr26Document:
    """Create or replace this system's document of ``(kind, document_key)``,
    judged on write.

    ``document_key`` defaults to ``None``, which is what every shipped
    deliverable passes -- the upsert identity for those six stays exactly
    ``(system_id, kind)``, matching the unique constraint's NULLS NOT
    DISTINCT behaviour (see :mod:`ccf.models_cr26`): a second write with a
    NULL key still overwrites the one NULL-keyed row for that kind, never
    creates a second one.
    """
    if kind not in DELIVERABLE_KINDS:
        if kind in CR26_KINDS:
            raise ValueError(
                f"kind {kind!r} is not a filable CR26 deliverable -- it is the "
                "shared common-definitions schema that the other ten schemas "
                "$ref, not a document any system files"
            )
        raise ValueError(f"unknown CR26 document kind: {kind!r}")
    if schema_path(kind) is None:
        # A known, filable kind with no file on disk is a packaging failure,
        # not a caller mistake -- distinct from the guard above.
        raise RuntimeError(
            f"CR26 schema packaging error: vendored schema missing for kind {kind!r}"
        )

    system = await session.get(System, system_id)
    # A soft-deleted system is not a writable system. DATA-04 sets deleted_at
    # instead of hard-deleting so the CASCADE never fires, which means this
    # table's own ON DELETE CASCADE will never reclaim a row written against
    # one -- the document would be unreachable and permanent. Same one-liner
    # as ccf.enforcement.service and ccf.patching.service.
    if system is None or system.deleted_at is not None:
        raise ValueError(f"unknown system: {system_id!r}")

    report = validate_document(document, kind)
    ruleset_version, schema_version = _versions(kind)

    row = (
        await session.execute(
            select(Cr26Document).where(
                Cr26Document.system_id == system_id,
                Cr26Document.kind == kind,
                # `== document_key` rather than a branch on None: SQLAlchemy
                # compiles `Column == None` to `IS NULL`, so this is exactly
                # `IS NULL` for every shipped deliverable and `= :key` for a
                # keyed one, with no separate code path to keep in sync with
                # the constraint's own NULLS NOT DISTINCT behaviour.
                Cr26Document.document_key == document_key,
            )
        )
    ).scalars().first()
    created = row is None
    if row is None:
        row = Cr26Document(system_id=system_id, kind=kind, document_key=document_key)
        session.add(row)

    # Tenant comes from the system, never from a caller-supplied value.
    row.organization_id = system.organization_id
    row.document = document
    row.ruleset_version = ruleset_version
    row.schema_version = schema_version
    row.is_valid = report.ok
    row.validation_errors = list(report.errors)
    # Unconditional, like every field above: a write that omits updated_by is
    # honestly attributed to no one, rather than silently kept attributed to
    # whoever wrote the row last.
    row.updated_by = updated_by
    await session.flush()

    # The only record that the overwritten document ever existed: this table
    # keeps one row per (system, kind, document_key) on the explicit grounds
    # that change history lives in the audit chain. ``create`` vs ``update``
    # is what makes an overwrite distinguishable from a first write after the
    # fact.
    diff: dict[str, Any] = {
        "system_id": system_id,
        "kind": kind,
        "is_valid": report.ok,
        "updated_by": updated_by,
    }
    # Omitted rather than always-present-as-None: every shipped deliverable
    # passes no key, and this diff shape is asserted verbatim by existing
    # tests -- adding a stray ``"document_key": None`` to it for a code path
    # that never has one would be an unannounced behaviour change of the
    # kind this branch is explicitly not allowed to make.
    if document_key is not None:
        diff["document_key"] = document_key
    await _audit(
        session,
        actor=updated_by or "system",
        action="create" if created else "update",
        entity_type="cr26_document",
        entity_id=str(row.id),
        diff=diff,
    )
    await session.flush()
    return row
