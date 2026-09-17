"""Every write records a verdict; no write is refused for being invalid.

A draft is necessarily incomplete -- a CPO cannot carry its assessor before an
assessor exists -- so refusing invalid writes makes authoring impossible.
Refusal belongs at export or submit. What must hold is that no document is
ever stored without a recorded verdict.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from ccf.cr26.store import put_document
from ccf.db import session_scope
from ccf.models import Organization, System
from ccf.models_cr26 import Cr26Document

_VALID_SDR = {
    "certificationPackageOverviewUri": "https://example.gov/cpo.json",
    "fedRampRequirements": [{"frrID": "SDR-CSO-FRR", "frrImplementation": ["Implemented."]}],
}


async def _system(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"{name}-system")
        s.add(sysm)
        await s.flush()
        return sysm.id


async def test_a_valid_document_is_stored_and_marked_valid() -> None:
    system_id = await _system("cr26-store-valid")
    async with session_scope() as s:
        row = await put_document(s, system_id=system_id, kind="sdr", document=_VALID_SDR)
        assert row.is_valid is True
        assert row.validation_errors == []
        assert row.ruleset_version == "2026-06-24"
        assert row.schema_version  # the SDR schema's own $schemaVersion


async def test_an_invalid_document_is_stored_not_refused() -> None:
    """The whole point. Authoring a CPO means saving it incomplete for a while."""
    system_id = await _system("cr26-store-invalid")
    async with session_scope() as s:
        row = await put_document(s, system_id=system_id, kind="cpo", document={})
        assert row.is_valid is False
        assert row.validation_errors, "an invalid document must say why"

    async with session_scope() as s:
        got = (
            await s.execute(select(Cr26Document).where(Cr26Document.system_id == system_id))
        ).scalar_one()
        assert got.document == {}
        assert got.is_valid is False


async def test_the_tenant_is_taken_from_the_system() -> None:
    system_id = await _system("cr26-store-tenant")
    async with session_scope() as s:
        row = await put_document(s, system_id=system_id, kind="cpo", document={})
        sysm = await s.get(System, system_id)
        assert row.organization_id == sysm.organization_id


async def test_writing_the_same_kind_twice_updates_rather_than_duplicating() -> None:
    """One row per (system, kind) -- a second write is an edit, not a new row."""
    system_id = await _system("cr26-store-upsert")
    async with session_scope() as s:
        await put_document(s, system_id=system_id, kind="sdr", document={})
    async with session_scope() as s:
        await put_document(s, system_id=system_id, kind="sdr", document=_VALID_SDR)

    async with session_scope() as s:
        rows = (
            await s.execute(select(Cr26Document).where(Cr26Document.system_id == system_id))
        ).scalars().all()
        assert len(rows) == 1
        assert rows[0].is_valid is True, "the verdict must be refreshed, not left stale"


async def test_the_verdict_is_never_left_stale() -> None:
    """The guarantee that matters: no path writes `document` without re-judging
    it. Going valid -> invalid must flip is_valid back.

    Both assertions matter: the column's own default is False, so a check of
    the *second* write alone cannot tell "recomputed False" apart from "never
    set, still at its default" -- the first write's assertion is what forces
    is_valid to have been genuinely computed, not just left at its default.
    """
    system_id = await _system("cr26-store-stale")
    async with session_scope() as s:
        row = await put_document(s, system_id=system_id, kind="sdr", document=_VALID_SDR)
        assert row.is_valid is True
    async with session_scope() as s:
        row = await put_document(s, system_id=system_id, kind="sdr", document={})
        assert row.is_valid is False
        assert row.validation_errors


async def test_an_unknown_kind_is_refused() -> None:
    """Refusing an invalid DOCUMENT would break authoring; refusing an unknown
    KIND is different -- there is no schema to judge it against, so storing it
    would mean storing something that can never be validated."""
    system_id = await _system("cr26-store-badkind")
    async with session_scope() as s:
        with pytest.raises(ValueError, match="kind"):
            await put_document(s, system_id=system_id, kind="not-a-kind", document={})


async def test_an_unknown_system_is_refused() -> None:
    async with session_scope() as s:
        with pytest.raises(ValueError, match="system"):
            await put_document(s, system_id=10**9, kind="cpo", document={})
