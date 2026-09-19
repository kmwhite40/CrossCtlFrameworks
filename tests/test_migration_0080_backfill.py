"""Pin migration 0080's backfill (spec §9.1, review round 3's N4).

Adding ``acceptance_rationale`` alone would leave every rationale that
already lived only in a stored ``avi`` document exactly as exposed to the
original defect as before the column existed. The migration also backfills
from those documents on upgrade -- this test proves it by hand-verification
having been the ONLY thing pinning it, which does not survive a refactor.
Deleting ``_backfill_from_avi_documents(op.get_bind())`` from ``upgrade()``
must fail this test.

Runs a real downgrade to 0079 and back to head against the shared test
database, so it is isolated to this one module and always restores head in a
``finally``, even on assertion failure -- a test that leaves the database
mid-migration would break every other module's fixtures.
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text

from ccf.config import get_settings
from ccf.cr26.store import put_document
from ccf.db import session_scope
from ccf.models import POAM

pytestmark = pytest.mark.usefixtures("fresh_engine")


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
    command.downgrade(cfg, "0079_cr26_documents")
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

            # `put_document` only touches `System` and `Cr26Document`, both
            # already at their final shape at 0079 -- safe through the ORM.
            # A second entry with `providerTrackingId: "²"` rides along in
            # the SAME document (review round 3, N3): `"²".isdigit()` is
            # `True` while `int("²")` raises `ValueError`, and the backfill
            # used to call `int()` after only an `.isdigit()` check --
            # aborting THIS WHOLE MIGRATION on this one hand-edited entry.
            # It must be skipped harmlessly (no POA&M has that id to write
            # to), not crash the upgrade that is also backfilling the real
            # legacy row above.
            await put_document(
                s,
                system_id=system_id,
                kind="avi",
                document={
                    "acceptedVulnerabilities": [
                        {
                            "vulnerabilityDetail": {"providerTrackingId": str(poam_id)},
                            "acceptanceRationale": "Backfill-pin rationale.",
                        },
                        {
                            "vulnerabilityDetail": {"providerTrackingId": "²"},
                            "acceptanceRationale": "Must not abort the migration.",
                        },
                    ],
                },
            )
    finally:
        command.upgrade(cfg, "head")

    async with session_scope() as s:
        row = await s.get(POAM, poam_id)
        assert row is not None
        assert row.acceptance_rationale == "Backfill-pin rationale."
