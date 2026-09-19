"""Pin migration 0080's backfill (spec §9.1, review round 3's N4).

Adding ``acceptance_rationale`` alone would leave every rationale that
already lived only in a stored ``avi`` document exactly as exposed to the
original defect as before the column existed. The migration also backfills
from those documents on upgrade -- this test proves it by hand-verification
having been the ONLY thing pinning it, which does not survive a refactor.
Deleting ``_backfill_from_avi_documents(op.get_bind())`` from ``upgrade()``
must fail this test.

Runs a real downgrade to 0079 and back to head against the SHARED test
database. ``DROP COLUMN`` destroys EVERY ``poams.acceptance_rationale`` in
that database, including rows other test modules wrote before this one ran
-- not just this test's own -- and the re-upgrade's backfill only recovers
the ones an ``avi`` document can account for; a column-only rationale (set
directly, with no document behind it) would not come back. That is a real
hole, not a hypothetical one, so this module snapshots every non-blank
``acceptance_rationale`` before downgrading and restores whatever the
backfill did not already recover once back at head -- genuine isolation,
not "green because nothing else happens to run after this module in
alphabetical order."

What is NOT protected: a `cr26_documents` row another module wrote (not an
`acceptance_rationale`) is untouched by this module's DDL and needs no
snapshot. And the row this test itself inserts (including a deliberately
malformed ``providerTrackingId: "²"`` document, round 3's N3) is deleted in
a ``finally``, before any attempt to leave the database below head is
tolerated -- a regression in the backfill's digit handling must not poison
every later module's own migration fixture with the same error. If the
database still cannot reach head after that cleanup, the failure is
re-raised as an explicit, clearly-labelled ``RuntimeError`` naming this
module as the cause, rather than surfacing as a wall of unrelated-looking
setup errors elsewhere.
"""

from __future__ import annotations

import json

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import POAM


def _cfg() -> Config:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    return cfg


@pytest.mark.asyncio
async def test_migration_0080_backfills_a_document_only_rationale() -> None:
    cfg = _cfg()
    # Always start from a known-good state: another module may have left the
    # database anywhere at or below head.
    command.upgrade(cfg, "head")

    # Snapshot every rationale ALREADY in the database before the downgrade
    # below drops the column outright -- see the module docstring. This is
    # what makes the "restore whatever the backfill could not see" step
    # further down real rather than assumed.
    async with session_scope() as s:
        snapshot: dict[int, str] = dict(
            (
                await s.execute(
                    text(
                        "SELECT id, acceptance_rationale FROM ccf.poams "
                        "WHERE acceptance_rationale IS NOT NULL "
                        "AND btrim(acceptance_rationale) <> ''"
                    )
                )
            ).all()
        )

    command.downgrade(cfg, "0079_cr26_documents")
    org_id: int | None = None
    try:
        # At 0079, `poams.acceptance_rationale` does not exist yet -- insert
        # via raw SQL, not the ORM, which would try to write a column the
        # table does not have at this revision.
        async with session_scope() as s:
            org_id = (
                await s.execute(
                    text("INSERT INTO ccf.organizations (name) VALUES (:name) RETURNING id"),
                    {"name": "Migration0080BackfillPinOrg"},
                )
            ).scalar_one()
            system_id = (
                await s.execute(
                    text(
                        "INSERT INTO ccf.systems (organization_id, name) "
                        "VALUES (:org_id, :name) RETURNING id"
                    ),
                    {"org_id": org_id, "name": "Migration0080BackfillPinSystem"},
                )
            ).scalar_one()
            poam_id = (
                await s.execute(
                    text(
                        "INSERT INTO ccf.poams (system_id, title, status) "
                        "VALUES (:system_id, :title, 'risk_accepted') RETURNING id"
                    ),
                    {"system_id": system_id, "title": "Legacy accepted vuln"},
                )
            ).scalar_one()

            # Raw SQL, not `put_document`: 0081 added `document_key` to
            # `Cr26Document` and `put_document`'s own upsert query now reads
            # it unconditionally, which does not exist at 0079 either --
            # the ORM model always reflects HEAD's shape, not the shape of
            # whatever revision the database happens to be pinned to right
            # now, so going through it here would raise
            # ``UndefinedColumnError`` before ever reaching 0080's migration
            # under test. Insert the row exactly as `put_document` would
            # (a ``2026-06-24`` ruleset, ``is_valid: false`` -- the backfill
            # only reads `document`, so the verdict fields are inert here).
            #
            # A second entry with `providerTrackingId: "²"` rides along in
            # the SAME document (round 3, N3): `"²".isdigit()` is `True`
            # while `int("²")` raises `ValueError`, and the backfill used to
            # call `int()` after only an `.isdigit()` check -- aborting THIS
            # WHOLE MIGRATION on this one hand-edited entry. It must be
            # skipped harmlessly (no POA&M has that id to write to), not
            # crash the upgrade that is also backfilling the real legacy
            # row below.
            await s.execute(
                text(
                    "INSERT INTO ccf.cr26_documents "
                    "(organization_id, system_id, kind, document, ruleset_version, "
                    "is_valid, validation_errors) "
                    "VALUES (:org_id, :system_id, 'avi', CAST(:document AS jsonb), "
                    "'2026-06-24', false, '[]'::jsonb)"
                ),
                {
                    "org_id": org_id,
                    "system_id": system_id,
                    "document": json.dumps(
                        {
                            "acceptedVulnerabilities": [
                                {
                                    "vulnerabilityDetail": {
                                        "providerTrackingId": str(poam_id)
                                    },
                                    "acceptanceRationale": "Backfill-pin rationale.",
                                },
                                {
                                    "vulnerabilityDetail": {"providerTrackingId": "²"},
                                    "acceptanceRationale": "Must not abort the migration.",
                                },
                            ],
                        }
                    ),
                },
            )

        # The upgrade UNDER TEST runs inside `try`, not in `finally`: if a
        # regression makes it raise, THIS is the exception a reader sees --
        # not a second one from the recovery logic below trying to make
        # sense of a database that already failed to reach head once.
        command.upgrade(cfg, "head")

        async with session_scope() as s:
            row = await s.get(POAM, poam_id)
            assert row is not None
            assert row.acceptance_rationale == "Backfill-pin rationale."
    finally:
        # Delete whatever this test inserted -- including the poisoned "²"
        # document -- BEFORE any further attempt to reach head, whether the
        # block above succeeded or raised. Still safe via raw SQL even if
        # the upgrade above never got that far and the database is still at
        # 0079: cascades to the system, the POA&M and the document (ON
        # DELETE CASCADE), so nothing this test wrote can poison a later
        # module's own upgrade with the same error.
        if org_id is not None:
            async with session_scope() as s:
                await s.execute(
                    text("DELETE FROM ccf.organizations WHERE id = :org_id"),
                    {"org_id": org_id},
                )
        # Idempotent if the `try` block's own upgrade already succeeded
        # (alembic no-ops at head); the recovery path if it did not. If the
        # database STILL cannot reach head now that the poisoning data is
        # gone, fail loudly and name this module as the cause, rather than
        # let it surface as a wall of unrelated setup errors everywhere
        # else that assumes head.
        try:
            command.upgrade(cfg, "head")
        except Exception as exc:
            raise RuntimeError(
                "test_migration_0080_backfill_a_document_only_rationale could "
                "not leave the shared test database at head -- every other "
                "test module's migration fixture will now fail at setup with "
                f"an unrelated-looking error until this is fixed by hand. "
                f"Original error: {exc!r}"
            ) from exc
        else:
            # Only once genuinely back at head: restore any snapshot value
            # the backfill did not itself recover (no `avi` document behind
            # it) -- only where still blank, so this never overwrites a
            # value the backfill (or a concurrent write) already restored,
            # including this test's own POA&M row above.
            if snapshot:
                async with session_scope() as s:
                    for other_poam_id, rationale in snapshot.items():
                        await s.execute(
                            text(
                                "UPDATE ccf.poams SET acceptance_rationale = :rationale "
                                "WHERE id = :poam_id AND (acceptance_rationale IS NULL "
                                "OR btrim(acceptance_rationale) = '')"
                            ),
                            {"poam_id": other_poam_id, "rationale": rationale},
                        )
