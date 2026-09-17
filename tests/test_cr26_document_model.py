"""CR26 deliverable documents: one row per (system, kind).

FedRAMP publishes eleven CR26 deliverables as JSON schemas. The documents are
stored as documents, validated against those schemas, rather than decomposed
into columns -- FedRAMP versions that shape independently and has already
revised the CPO to 0.1.4, so a decomposed copy would drift and need a migration
every time they add a field.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ccf.cr26.validation import CR26_KINDS
from ccf.db import session_scope
from ccf.models import Organization, System
from ccf.models_cr26 import Cr26Document


async def _system(name: str) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=f"{name}-system")
        s.add(sysm)
        await s.flush()
        return org.id, sysm.id


async def test_a_document_round_trips_through_the_database() -> None:
    org_id, system_id = await _system("cr26-doc-roundtrip")
    async with session_scope() as s:
        s.add(
            Cr26Document(
                organization_id=org_id,
                system_id=system_id,
                kind="cpo",
                document={"serviceIdentification": {"serviceName": "Acme"}},
                ruleset_version="2026-06-24",
                schema_version="0.1.4",
                is_valid=False,
                validation_errors=["<root>: 'serviceProperties' is a required property"],
            )
        )

    async with session_scope() as s:
        got = (
            await s.execute(select(Cr26Document).where(Cr26Document.system_id == system_id))
        ).scalar_one()
        # Read back from Postgres, not from the object that was written: the
        # point is that JSONB round-trips, not that Python remembers.
        assert got.document["serviceIdentification"]["serviceName"] == "Acme"
        assert got.is_valid is False
        assert got.validation_errors[0].endswith("is a required property")
        assert got.ruleset_version == "2026-06-24"
        assert got.schema_version == "0.1.4"


async def test_one_current_document_per_system_and_kind() -> None:
    """The documents are self-versioning -- the CPO's own metadata block carries
    version, lastUpdated and updateSource -- so a second row for the same kind
    would be a second record of one fact. History is AuditLog's job."""
    org_id, system_id = await _system("cr26-doc-unique")
    async with session_scope() as s:
        s.add(
            Cr26Document(
                organization_id=org_id, system_id=system_id, kind="cpo",
                document={}, ruleset_version="2026-06-24", is_valid=False,
            )
        )

    with pytest.raises(IntegrityError):
        async with session_scope() as s:
            s.add(
                Cr26Document(
                    organization_id=org_id, system_id=system_id, kind="cpo",
                    document={}, ruleset_version="2026-06-24", is_valid=False,
                )
            )


async def test_two_kinds_coexist_for_one_system() -> None:
    """The uniqueness is per KIND -- a system has a CPO and an SDR at once."""
    org_id, system_id = await _system("cr26-doc-two-kinds")
    async with session_scope() as s:
        for kind in ("cpo", "sdr"):
            s.add(
                Cr26Document(
                    organization_id=org_id, system_id=system_id, kind=kind,
                    document={}, ruleset_version="2026-06-24", is_valid=False,
                )
            )

    async with session_scope() as s:
        kinds = (
            await s.execute(
                select(Cr26Document.kind).where(Cr26Document.system_id == system_id)
            )
        ).scalars().all()
        assert sorted(kinds) == ["cpo", "sdr"]


async def test_every_vendored_kind_is_storable() -> None:
    """A kind vocabulary the column rejects is a vocabulary in name only.

    Iterates CR26_KINDS rather than a hand-copied list, so a schema added
    upstream cannot be silently unstorable.
    """
    assert len(CR26_KINDS) == 11
    org_id, system_id = await _system("cr26-doc-all-kinds")
    async with session_scope() as s:
        for kind in CR26_KINDS:
            s.add(
                Cr26Document(
                    organization_id=org_id, system_id=system_id, kind=kind,
                    document={}, ruleset_version="2026-06-24", is_valid=False,
                )
            )
        await s.flush()
