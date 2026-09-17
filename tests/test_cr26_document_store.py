"""Every write records a verdict; no write is refused for being invalid.

A draft is necessarily incomplete -- a CPO cannot carry its assessor before an
assessor exists -- so refusing invalid writes makes authoring impossible.
Refusal belongs at export or submit. What must hold is that no document is
ever stored without a recorded verdict.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from ccf.cr26.store import DELIVERABLE_KINDS, put_document
from ccf.db import session_scope
from ccf.models import AuditLog, Organization, System
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
        assert row.schema_version == "1.1.1"  # the SDR schema's own $schemaVersion

    async with session_scope() as s:
        got = (
            await s.execute(select(Cr26Document).where(Cr26Document.system_id == system_id))
        ).scalar_one()
        # Read back from Postgres, not from the object put_document handed
        # back -- {} is the column's own default, so a check against that
        # object alone cannot tell "really stored" from "never assigned".
        assert got.document == _VALID_SDR


async def test_an_invalid_document_is_stored_not_refused() -> None:
    """The whole point. Authoring a CPO means saving it incomplete for a while."""
    system_id = await _system("cr26-store-invalid")
    async with session_scope() as s:
        row = await put_document(s, system_id=system_id, kind="cpo", document={})
        assert row.is_valid is False
        assert row.validation_errors, "an invalid document must say why"
        # Both versions are recorded on the invalid path too, not only the
        # valid one: a stored verdict that cannot say what it was judged
        # against is not a verdict anyone can act on a year later.
        assert row.ruleset_version == "2026-06-24"
        assert row.schema_version == "0.1.4"  # the CPO schema's own $schemaVersion

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
        assert rows[0].document == _VALID_SDR, "the document itself must be refreshed"
        assert rows[0].validation_errors == [], "stale errors must not survive a clean write"


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


async def test_the_common_definitions_kind_is_refused() -> None:
    """`common` is FedRAMP's shared $defs target, not a filable deliverable --
    it has no required fields of its own, so it could never fail validation
    either. A verdict on it could never mean anything, so it is excluded from
    DELIVERABLE_KINDS and refused here just like a truly unknown kind."""
    assert "common" not in DELIVERABLE_KINDS
    system_id = await _system("cr26-store-common")
    async with session_scope() as s:
        with pytest.raises(ValueError, match="deliverable"):
            await put_document(s, system_id=system_id, kind="common", document={})


async def test_updated_by_is_recorded_and_never_left_stale() -> None:
    """A second write that omits updated_by must not keep attributing the row
    to whoever wrote it last -- assignment is unconditional, like every other
    field, so an omitted author is honestly None rather than a stale name."""
    system_id = await _system("cr26-store-updated-by")
    async with session_scope() as s:
        row = await put_document(
            s, system_id=system_id, kind="sdr", document=_VALID_SDR, updated_by="alice"
        )
        assert row.updated_by == "alice"

    async with session_scope() as s:
        row = await put_document(s, system_id=system_id, kind="sdr", document=_VALID_SDR)
        assert row.updated_by is None, "an omitted author must not inherit the previous one"


async def test_a_soft_deleted_system_is_refused() -> None:
    """DATA-04 sets deleted_at instead of hard-deleting, precisely so the
    CASCADE never fires -- which means a document written against a
    soft-deleted system would be unreachable and permanent. Same guard as
    ccf.enforcement.service and ccf.patching.service."""
    system_id = await _system("cr26-store-soft-deleted")
    async with session_scope() as s:
        system = await s.get(System, system_id)
        assert system is not None
        system.deleted_at = datetime.now(UTC)

    async with session_scope() as s:
        with pytest.raises(ValueError, match="system"):
            await put_document(s, system_id=system_id, kind="cpo", document={})

    async with session_scope() as s:
        rows = (
            await s.execute(select(Cr26Document).where(Cr26Document.system_id == system_id))
        ).scalars().all()
        assert rows == [], "nothing may be written against a soft-deleted system"


async def _events(system_id: int) -> list[AuditLog]:
    async with session_scope() as s:
        rows = (
            await s.execute(
                select(AuditLog)
                .where(AuditLog.entity_type == "cr26_document")
                .order_by(AuditLog.id)
            )
        ).scalars().all()
        return [r for r in rows if r.diff.get("system_id") == system_id]


async def test_every_write_records_an_audit_event_and_an_overwrite_says_so() -> None:
    """There is one row per (system, kind) and a second write overwrites the
    first in place, so nothing in cr26_documents remembers the prior document.
    The justification for having no history table is that change history is the
    audit chain's job -- which only holds if the events are actually written,
    and only helps if a create is distinguishable from an overwrite.
    """
    system_id = await _system("cr26-store-audit")
    async with session_scope() as s:
        await put_document(
            s, system_id=system_id, kind="sdr", document=_VALID_SDR, updated_by="alice"
        )
    async with session_scope() as s:
        await put_document(s, system_id=system_id, kind="sdr", document={}, updated_by="bob")

    events = await _events(system_id)
    assert [e.action for e in events] == ["create", "update"], (
        "a first write is a create and an overwrite is an update"
    )
    first, second = events
    assert first.diff == {
        "system_id": system_id,
        "kind": "sdr",
        "is_valid": True,
        "updated_by": "alice",
    }
    assert second.diff["is_valid"] is False, "the event carries the verdict of its own write"
    assert second.diff["updated_by"] == "bob"
    assert first.actor == "alice" and second.actor == "bob"
    # record_event, not a hand-built AuditLog: only the former chains the hashes.
    assert all(e.prev_hash and e.row_hash for e in events)


async def test_the_audit_event_names_the_row_it_describes() -> None:
    """entity_id has to resolve to the document, or the event cannot be joined
    back to what changed."""
    system_id = await _system("cr26-store-audit-entity")
    async with session_scope() as s:
        row = await put_document(s, system_id=system_id, kind="cpo", document={})
        row_id = row.id

    events = await _events(system_id)
    assert [e.entity_id for e in events] == [str(row_id)]


async def test_a_write_without_an_author_is_still_audited() -> None:
    """updated_by is optional; the event is not. An unattributed write must
    still leave a trace, attributed to "system" like every other service does."""
    system_id = await _system("cr26-store-audit-anon")
    async with session_scope() as s:
        await put_document(s, system_id=system_id, kind="cpo", document={})

    events = await _events(system_id)
    assert len(events) == 1
    assert events[0].actor == "system"
    assert events[0].diff["updated_by"] is None
