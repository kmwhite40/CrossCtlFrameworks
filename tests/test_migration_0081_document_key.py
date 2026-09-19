"""Pin migration 0081's round trip and its downgrade guard.

Runs real upgrades/downgrades against the SHARED test database -- see
``tests/test_migration_0080_backfill.py``'s docstring for the precedent and
why that is safe here: nothing outside this module ever writes a non-NULL
``document_key``, so a downgrade to 0080 only ever drops a column whose value
is NULL on every row any other module could have written -- that NULL-only
state IS the invariant those other modules test, and dropping a column of
nothing but NULLs discards no information. The old two-column constraint the
downgrade restores (``UNIQUE (system_id, kind)``) is therefore already
satisfied by whatever the shared database holds at the moment this module
runs.
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text

from ccf.config import get_settings
from ccf.db import session_scope

_CONSTRAINT_SQL = (
    "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint "
    "WHERE conrelid = 'ccf.cr26_documents'::regclass AND contype = 'u'"
)
_DOCUMENT_KEY_COLUMN_SQL = (
    "SELECT column_name FROM information_schema.columns "
    "WHERE table_schema = 'ccf' AND table_name = 'cr26_documents' "
    "AND column_name = 'document_key'"
)


def _cfg() -> Config:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    return cfg


async def _insert_org_and_system(name: str) -> tuple[int, int]:
    async with session_scope() as s:
        org_id = (
            await s.execute(
                text("INSERT INTO ccf.organizations (name) VALUES (:name) RETURNING id"),
                {"name": name},
            )
        ).scalar_one()
        system_id = (
            await s.execute(
                text(
                    "INSERT INTO ccf.systems (organization_id, name) "
                    "VALUES (:org_id, :name) RETURNING id"
                ),
                {"org_id": org_id, "name": f"{name}-system"},
            )
        ).scalar_one()
        return org_id, system_id


async def _ensure_head(cfg: Config, *, caller: str) -> None:
    """Best-effort return to ``head``, failing loudly and by name if it does
    not work -- otherwise every later module's own migration fixture fails
    with an unrelated-looking error. Same discipline as 0080's pin test.
    """
    try:
        command.upgrade(cfg, "head")
    except Exception as exc:
        raise RuntimeError(
            f"{caller} could not leave the shared test database at head -- "
            f"every other test module's migration fixture will now fail. "
            f"Original error: {exc!r}"
        ) from exc


async def test_migration_0081_round_trips_and_restores_nulls_not_distinct() -> None:
    """With no keyed row present, upgrade -> downgrade -> upgrade must be a
    clean no-op, ending with the exact same NULLS NOT DISTINCT constraint it
    started with."""
    cfg = _cfg()
    command.upgrade(cfg, "head")

    async with session_scope() as s:
        before = (await s.execute(text(_CONSTRAINT_SQL))).all()
    assert before == [
        (
            "uq_cr26_document_system_kind_key",
            "UNIQUE NULLS NOT DISTINCT (system_id, kind, document_key)",
        )
    ], "0081 must be at head with the NULLS NOT DISTINCT constraint before this test starts"

    command.downgrade(cfg, "0080_poam_acceptance_rationale")
    try:
        async with session_scope() as s:
            cols = (await s.execute(text(_DOCUMENT_KEY_COLUMN_SQL))).all()
            assert cols == [], "downgrade must remove document_key"
            cons = (await s.execute(text(_CONSTRAINT_SQL))).all()
            assert cons == [("uq_cr26_document_system_kind", "UNIQUE (system_id, kind)")], (
                "downgrade must restore the pre-0081 two-column constraint"
            )
    finally:
        await _ensure_head(
            cfg, caller="test_migration_0081_round_trips_and_restores_nulls_not_distinct"
        )

    async with session_scope() as s:
        after = (await s.execute(text(_CONSTRAINT_SQL))).all()
    assert after == before, "re-upgrading must restore the identical constraint"


async def test_migration_0081_downgrade_refuses_a_keyed_row() -> None:
    """The trap this migration exists to avoid, from the other end: a filed,
    keyed document (e.g. a future incident report) must never be silently
    destroyed by a downgrade. One non-NULL document_key row must make
    downgrade() raise rather than drop the column -- mutate the guard away
    (delete the ``if keyed:`` check in 0081's ``downgrade()``) and this test
    must fail.
    """
    cfg = _cfg()
    command.upgrade(cfg, "head")

    org_id, system_id = await _insert_org_and_system("Migration0081DowngradeGuard")
    try:
        async with session_scope() as s:
            await s.execute(
                text(
                    "INSERT INTO ccf.cr26_documents "
                    "(organization_id, system_id, kind, document_key, document, "
                    "ruleset_version, is_valid, validation_errors) "
                    "VALUES (:org_id, :system_id, 'incident', 'INC-9001', '{}'::jsonb, "
                    "'2026-06-24', false, '[]'::jsonb)"
                ),
                {"org_id": org_id, "system_id": system_id},
            )

        with pytest.raises(Exception, match="document_key"):
            command.downgrade(cfg, "0080_poam_acceptance_rationale")

        # Refused means no DDL ran: the column and the NULLS NOT DISTINCT
        # constraint must both still be exactly as they were.
        async with session_scope() as s:
            cols = (await s.execute(text(_DOCUMENT_KEY_COLUMN_SQL))).all()
            assert cols, "a refused downgrade must not have dropped document_key"
            cons = (await s.execute(text(_CONSTRAINT_SQL))).all()
            assert cons == [
                (
                    "uq_cr26_document_system_kind_key",
                    "UNIQUE NULLS NOT DISTINCT (system_id, kind, document_key)",
                )
            ], "a refused downgrade must not have touched the constraint either"
    finally:
        async with session_scope() as s:
            # CASCADE takes the system and the cr26_documents row with it.
            await s.execute(
                text("DELETE FROM ccf.organizations WHERE id = :org_id"), {"org_id": org_id}
            )
        await _ensure_head(cfg, caller="test_migration_0081_downgrade_refuses_a_keyed_row")
