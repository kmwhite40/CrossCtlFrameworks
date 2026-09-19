"""``document_key`` (migration 0081): the store can hold more than one
document of the same kind for a system, keyed apart -- while every shipped
deliverable, which always passes no key, keeps exactly one row.

This branch builds no keyed deliverable (the incident report and SCN are
separate work); it only proves the store is ready to hold one, and that
readiness has not disturbed the six that already ship.
"""

from __future__ import annotations

import pytest
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError

from ccf.cr26.store import put_document
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


async def _delete_org(org_id: int) -> None:
    """Cascades to the system and its cr26_documents rows.

    A row left with a non-NULL ``document_key`` is exactly what migration
    0081's ``downgrade()`` refuses to run past (by design -- see its
    docstring), and ``tests/conftest.py``'s session-scoped ``clean_migrated_db``
    downgrades this database to ``base`` at the start of every pytest session.
    A keyed row this module forgets to delete would therefore not just be
    untidy -- it would fail every later session's own startup, at every
    module's expense, until removed by hand. Tests that create one must clean
    it up themselves, the same discipline
    ``tests/test_migration_0080_backfill.py`` uses for its own migration-
    adjacent state.
    """
    async with session_scope() as s:
        await s.execute(delete(Organization).where(Organization.id == org_id))


async def test_two_documents_of_the_same_kind_coexist_with_different_keys() -> None:
    """The point of the change: one system, one kind, two instances -- the
    shape an Initial and a Final incident report will need."""
    org_id, system_id = await _system("cr26-key-coexist")
    try:
        async with session_scope() as s:
            s.add(
                Cr26Document(
                    organization_id=org_id,
                    system_id=system_id,
                    kind="incident",
                    document_key="INC-1",
                    document={},
                    ruleset_version="2026-06-24",
                    is_valid=False,
                )
            )
            s.add(
                Cr26Document(
                    organization_id=org_id,
                    system_id=system_id,
                    kind="incident",
                    document_key="INC-2",
                    document={},
                    ruleset_version="2026-06-24",
                    is_valid=False,
                )
            )
            await s.flush()

        async with session_scope() as s:
            keys = (
                await s.execute(
                    select(Cr26Document.document_key)
                    .where(
                        Cr26Document.system_id == system_id, Cr26Document.kind == "incident"
                    )
                    .order_by(Cr26Document.document_key)
                )
            ).scalars().all()
            assert keys == ["INC-1", "INC-2"]
    finally:
        # See _delete_org: a keyed row left behind breaks the NEXT pytest
        # session's startup, not just this one's tidiness.
        await _delete_org(org_id)


async def test_two_null_keyed_documents_of_the_same_kind_still_conflict() -> None:
    """THE TRAP TEST. Postgres treats NULLs as distinct from one another in an
    ordinary unique constraint -- measured on this server:

        create temp table t (a int, b text, k text, unique (a,b,k));
        insert into t values (1,'sdr',null);
        insert into t values (1,'sdr',null);   -- BOTH ACCEPTED

    A plain ``UNIQUE (system_id, kind, document_key)`` would let a second
    NULL-keyed ``sdr`` (or any shipped kind) row through, destroying the
    one-row invariant every seeder and read helper depends on. This must
    fail if ``postgresql_nulls_not_distinct=True`` is removed from the
    constraint in ``ccf.models_cr26.Cr26Document`` (or the equivalent DDL in
    migration 0081) -- mutate it away and confirm this test goes red.
    """
    org_id, system_id = await _system("cr26-key-null-conflict")
    async with session_scope() as s:
        s.add(
            Cr26Document(
                organization_id=org_id,
                system_id=system_id,
                kind="sdr",
                document_key=None,
                document={},
                ruleset_version="2026-06-24",
                is_valid=False,
            )
        )

    with pytest.raises(IntegrityError):
        async with session_scope() as s:
            s.add(
                Cr26Document(
                    organization_id=org_id,
                    system_id=system_id,
                    kind="sdr",
                    document_key=None,
                    document={},
                    ruleset_version="2026-06-24",
                    is_valid=False,
                )
            )


_SHIPPED_KINDS = ("cpo", "sdr", "ocr", "vdr", "avi", "ver_history")


async def test_each_shipped_kind_keeps_exactly_one_row_after_two_seeds() -> None:
    """put_document with no document_key is what every one of the six shipped
    deliverables' seeders calls. Two writes of the same kind must still
    collapse onto one row, unchanged from before 0081, and the second write's
    body must be exactly what is stored -- no accidental second row holding
    the first write's body instead.
    """
    system_id = (await _system("cr26-key-shipped-idempotent"))[1]
    first_pass = {kind: {"seed": 1, "kind": kind} for kind in _SHIPPED_KINDS}
    second_pass = {kind: {"seed": 2, "kind": kind} for kind in _SHIPPED_KINDS}

    async with session_scope() as s:
        for kind, document in first_pass.items():
            await put_document(s, system_id=system_id, kind=kind, document=document)
    async with session_scope() as s:
        for kind, document in second_pass.items():
            await put_document(s, system_id=system_id, kind=kind, document=document)

    async with session_scope() as s:
        rows = (
            await s.execute(select(Cr26Document).where(Cr26Document.system_id == system_id))
        ).scalars().all()
        by_kind = {row.kind: row for row in rows}
        assert sorted(by_kind) == sorted(_SHIPPED_KINDS), (
            "each shipped kind must have exactly one row, not zero or several"
        )
        for kind in _SHIPPED_KINDS:
            assert by_kind[kind].document_key is None
            assert by_kind[kind].document == second_pass[kind], (
                "the stored document must be the second write's body, not a "
                "stray second row still holding the first"
            )


async def test_a_keyed_write_does_not_touch_the_unkeyed_row_of_the_same_kind() -> None:
    """put_document keyed on (system_id, kind, document_key): writing a keyed
    document of a kind that also has an unkeyed row must not overwrite, nor
    be overwritten by, that unkeyed row."""
    org_id, system_id = await _system("cr26-key-independent")
    try:
        async with session_scope() as s:
            await put_document(s, system_id=system_id, kind="sdr", document={"who": "unkeyed"})
        async with session_scope() as s:
            await put_document(
                s,
                system_id=system_id,
                kind="sdr",
                document_key="ALT-1",
                document={"who": "keyed"},
            )

        async with session_scope() as s:
            rows = (
                await s.execute(
                    select(Cr26Document)
                    .where(Cr26Document.system_id == system_id, Cr26Document.kind == "sdr")
                    .order_by(Cr26Document.document_key.asc().nulls_first())
                )
            ).scalars().all()
            assert len(rows) == 2
            assert rows[0].document_key is None
            assert rows[0].document == {"who": "unkeyed"}
            assert rows[1].document_key == "ALT-1"
            assert rows[1].document == {"who": "keyed"}
    finally:
        # See _delete_org: a keyed row left behind breaks the NEXT pytest
        # session's startup, not just this one's tidiness.
        await _delete_org(org_id)
