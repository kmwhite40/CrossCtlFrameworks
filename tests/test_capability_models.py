"""Capability schema: constraints, tenancy, and the evidence parent CHECK."""

from __future__ import annotations

import itertools

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from ccf.db import session_scope
from ccf.models import ControlImplementation, Evidence, Organization
from ccf.models_capability import Capability, CapabilityControl

_SEQ = itertools.count()


async def _org(session) -> Organization:
    org = Organization(name=f"CapOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    return org


async def _cap(session, org_id: int, key: str = "mfa") -> Capability:
    cap = Capability(
        organization_id=org_id, key=key, title="MFA everywhere", status="implemented"
    )
    session.add(cap)
    await session.flush()
    return cap


async def test_capability_key_is_unique_per_org() -> None:
    async with session_scope() as session:
        org = await _org(session)
        await _cap(session, org.id, "dup-key")
        # _cap flushes, so the violation surfaces on the second call itself.
        with pytest.raises(IntegrityError):
            await _cap(session, org.id, "dup-key")
        await session.rollback()


async def test_same_key_allowed_in_different_orgs() -> None:
    async with session_scope() as session:
        a, b = await _org(session), await _org(session)
        await _cap(session, a.id, "shared-key")
        await _cap(session, b.id, "shared-key")
        await session.flush()  # uniqueness is per-org, not global


async def test_control_edge_is_unique() -> None:
    async with session_scope() as session:
        org = await _org(session)
        cap = await _cap(session, org.id, "edge-unique")
        for _ in range(2):
            session.add(
                CapabilityControl(
                    organization_id=org.id, capability_id=cap.id, control_id="AC-2"
                )
            )
        with pytest.raises(IntegrityError):
            await session.flush()
        await session.rollback()


async def test_capability_stores_canonical_control_id() -> None:
    """Canonical form (AC-2), not the zero-padded controls.identifier (AC-01)."""
    async with session_scope() as session:
        org = await _org(session)
        cap = await _cap(session, org.id, "canonical")
        session.add(
            CapabilityControl(organization_id=org.id, capability_id=cap.id, control_id="AC-2")
        )
        await session.flush()
        row = (
            await session.execute(
                select(CapabilityControl).where(CapabilityControl.capability_id == cap.id)
            )
        ).scalars().one()
        assert row.control_id == "AC-2"


async def test_evidence_requires_at_least_one_parent() -> None:
    async with session_scope() as session:
        session.add(Evidence(kind="document", title="orphan", metadata_json={}))
        with pytest.raises(IntegrityError):
            await session.flush()
        await session.rollback()


async def test_evidence_may_be_parented_to_a_capability_alone() -> None:
    async with session_scope() as session:
        org = await _org(session)
        cap = await _cap(session, org.id, "ev-parent")
        session.add(
            Evidence(
                capability_id=cap.id, kind="config_export", title="CA policy", metadata_json={}
            )
        )
        await session.flush()  # no implementation_id needed


async def test_all_five_tables_have_rls_policies() -> None:
    """Tenant-owned tables must be policied, not allowlisted as global."""
    expected = {
        "capabilities",
        "capability_controls",
        "capability_components",
        "capability_risks",
        "capability_ksis",
    }
    async with session_scope() as session:
        rows = (
            await session.execute(
                text(
                    "SELECT c.relname FROM pg_class c "
                    "JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "JOIN pg_policy p ON p.polrelid = c.oid "
                    "WHERE n.nspname = 'ccf' AND p.polname = 'tenant_isolation' "
                    "AND c.relname = ANY(:names)"
                ).bindparams(names=sorted(expected))
            )
        ).scalars().all()
    assert set(rows) == expected


async def test_derived_columns_exist_and_are_nullable() -> None:
    async with session_scope() as session:
        cols = (
            await session.execute(
                text(
                    "SELECT column_name, is_nullable FROM information_schema.columns "
                    "WHERE table_schema='ccf' AND table_name='control_implementations' "
                    "AND column_name IN ('derived_status','derived_at','derived_from')"
                )
            )
        ).all()
        by_name = {c[0]: c[1] for c in cols}
        assert set(by_name) == {"derived_status", "derived_at", "derived_from"}
        assert by_name["derived_status"] == "YES"
        assert by_name["derived_at"] == "YES"
        # derived_from is NOT NULL with a '{}' default so readers never see null.
        assert by_name["derived_from"] == "NO"
        assert hasattr(ControlImplementation, "derived_status")
