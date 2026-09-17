"""Persist a CR26 deliverable document, judging it on every write.

The contract is narrow and worth stating: **an invalid document is stored, an
unknown kind is refused.** A draft is necessarily incomplete -- a CPO cannot
carry its assessor before an assessor exists -- so refusing invalid writes
would make authoring impossible, and refusal belongs at export or submit
instead. An unknown *kind* is different: there is no vendored schema to judge
it against, so storing it would mean storing something that can never be
validated at all.

What must hold on every path: no document is stored without a recorded
verdict. There is no way to write ``document`` and leave ``is_valid`` stale.
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


def _manifest() -> dict[str, Any]:
    path = Path(__file__).with_name("schemas") / "MANIFEST.json"
    return json.loads(path.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def _versions(kind: str) -> tuple[str, str | None]:
    """The ruleset revision and this schema's own semver, from the manifest."""
    manifest = _manifest()
    filename = CR26_KINDS[kind][0]
    entry = manifest["files"].get(filename, {})
    return str(manifest["ruleset_version"]), entry.get("schema_version")


async def put_document(
    session: AsyncSession,
    *,
    system_id: int,
    kind: str,
    document: dict[str, Any],
    updated_by: str | None = None,
) -> Cr26Document:
    """Create or replace this system's document of ``kind``, judged on write."""
    if kind not in CR26_KINDS or schema_path(kind) is None:
        raise ValueError(f"unknown CR26 document kind: {kind!r}")

    system = await session.get(System, system_id)
    if system is None:
        raise ValueError(f"unknown system: {system_id!r}")

    report = validate_document(document, kind)
    ruleset_version, schema_version = _versions(kind)

    row = (
        await session.execute(
            select(Cr26Document).where(
                Cr26Document.system_id == system_id, Cr26Document.kind == kind
            )
        )
    ).scalars().first()
    if row is None:
        row = Cr26Document(system_id=system_id, kind=kind)
        session.add(row)

    # Tenant comes from the system, never from a caller-supplied value.
    row.organization_id = system.organization_id
    row.document = document
    row.ruleset_version = ruleset_version
    row.schema_version = schema_version
    row.is_valid = report.ok
    row.validation_errors = list(report.errors)
    if updated_by is not None:
        row.updated_by = updated_by
    await session.flush()
    return row
