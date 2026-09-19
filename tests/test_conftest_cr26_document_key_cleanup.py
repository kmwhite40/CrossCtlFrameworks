"""Direct unit pin for ``tests/conftest.py``'s
``_delete_keyed_cr26_documents_before_wipe``.

The fixture that calls it (``clean_migrated_db``, session-scoped and
autouse) cannot itself be re-invoked from inside a test -- that would
recurse into the very session setup already in progress. The helper it
calls is a plain function, though, and testable on its own: this exercises
it directly against the shared test database at the three real migration
states it has to cope with -- ``head`` (0081, where a keyed row must
actually be deleted), ``0080`` (predates ``document_key`` -- must no-op
rather than raise), and ``base`` (predates the table, and the ``ccf``
schema itself, entirely -- must also no-op).
"""

from __future__ import annotations

from alembic import command
from alembic.config import Config
from sqlalchemy import text

from ccf.config import get_settings
from ccf.db import session_scope
from tests.conftest import _delete_keyed_cr26_documents_before_wipe


def _cfg() -> Config:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    return cfg


async def _ensure_head(cfg: Config, *, caller: str) -> None:
    """Best-effort return to ``head``, failing loudly and by name if it does
    not work -- otherwise every later module's own migration fixture fails
    with an unrelated-looking error. Same discipline as
    ``tests/test_migration_0080_backfill.py`` and
    ``tests/test_migration_0081_document_key.py``.
    """
    try:
        command.upgrade(cfg, "head")
    except Exception as exc:
        raise RuntimeError(
            f"{caller} could not leave the shared test database at head -- "
            f"every other test module's migration fixture will now fail. "
            f"Original error: {exc!r}"
        ) from exc


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


async def test_the_helper_deletes_a_keyed_row_at_head() -> None:
    """The case the helper exists for: at 0081, a row a future incident/SCN
    test left behind must actually be removed, or clean_migrated_db's own
    downgrade(base) a moment later would hit 0081's downgrade guard."""
    cfg = _cfg()
    command.upgrade(cfg, "head")

    org_id, system_id = await _insert_org_and_system("ConftestHelperPinHead")
    try:
        async with session_scope() as s:
            await s.execute(
                text(
                    "INSERT INTO ccf.cr26_documents "
                    "(organization_id, system_id, kind, document_key, document, "
                    "ruleset_version, is_valid, validation_errors) "
                    "VALUES (:org_id, :system_id, 'incident', 'INC-HELPER-1', "
                    "'{}'::jsonb, '2026-06-24', false, '[]'::jsonb)"
                ),
                {"org_id": org_id, "system_id": system_id},
            )

        _delete_keyed_cr26_documents_before_wipe(cfg)

        async with session_scope() as s:
            remaining = (
                await s.execute(
                    text(
                        "SELECT count(*) FROM ccf.cr26_documents "
                        "WHERE system_id = :system_id AND document_key IS NOT NULL"
                    ),
                    {"system_id": system_id},
                )
            ).scalar_one()
            assert remaining == 0, "the helper must delete the keyed row, not skip it"
    finally:
        async with session_scope() as s:
            await s.execute(
                text("DELETE FROM ccf.organizations WHERE id = :org_id"), {"org_id": org_id}
            )


async def test_the_helper_no_ops_at_0080_before_document_key_exists() -> None:
    """A database migrated only up to 0080 has no document_key column at
    all -- the helper must recognise that (via information_schema, not a
    hopeful SELECT) and return without raising."""
    cfg = _cfg()
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "0080_poam_acceptance_rationale")
    try:
        _delete_keyed_cr26_documents_before_wipe(cfg)
    finally:
        await _ensure_head(
            cfg, caller="test_the_helper_no_ops_at_0080_before_document_key_exists"
        )


async def test_the_helper_no_ops_at_base_before_any_table_exists() -> None:
    """A completely unmigrated database has neither cr26_documents nor the
    ccf schema itself -- the helper must still return cleanly rather than
    raise on a missing table or schema."""
    cfg = _cfg()
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")
    try:
        _delete_keyed_cr26_documents_before_wipe(cfg)
    finally:
        await _ensure_head(cfg, caller="test_the_helper_no_ops_at_base_before_any_table_exists")
