"""Pin migration 0111's backfill: one snapshot per live system holding a valid OCR.

Earlier quarters were overwritten before snapshots existed, so the backfill
can only capture what is current at upgrade -- and must say so with
``basis = 'backfill'``. A deleted system and a system whose OCR is invalid get
none. Digests must match the portal's own, or the backfilled snapshot would be
served with a digest its JSON does not have.

Round-trips 0111 against the shared database. The downgrade drops both
snapshot tables, including snapshots other modules took; the re-upgrade
recreates them only as backfills. No later module reads another's snapshots.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select

from ccf.config import get_settings
from ccf.cr26 import snapshots
from ccf.db import session_scope
from ccf.models import Organization, System
from ccf.models_cr26 import (
    CertificationSnapshot,
    CertificationSnapshotDocument,
    CertificationSnapshotFiling,
    Cr26Document,
)
from ccf.portal import certification

pytestmark = pytest.mark.usefixtures("fresh_engine")

OCR = {"reportPeriod": {"from": "2026-07-01", "to": "2026-09-30"}, "note": "valid by fiat"}
SDR = {"securityDecisions": [{"practiceId": "KSI-IAM-MFA", "decision": "b"}], "z": 1, "a": 2}


def _cfg() -> Config:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    return cfg


def _doc(org: int, system: int, kind: str, document: dict, *, valid: bool) -> Cr26Document:
    return Cr26Document(
        organization_id=org,
        system_id=system,
        kind=kind,
        document=document,
        ruleset_version="2026.10.13.01",
        schema_version="0.1.1",
        is_valid=valid,
        validation_errors=[] if valid else ["<root>: draft"],
    )


@pytest.mark.asyncio
async def test_migration_0111_backfills_what_is_current_and_says_so() -> None:
    cfg = _cfg()
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "0110_cert_access_requests")
    try:
        tag = uuid.uuid4().hex[:8]
        async with session_scope() as s:
            org = Organization(name=f"m0111-{tag}")
            s.add(org)
            await s.flush()
            live = System(organization_id=org.id, name=f"Live {tag}")
            gone = System(organization_id=org.id, name=f"Gone {tag}", deleted_at=datetime.now(UTC))
            draft = System(organization_id=org.id, name=f"Draft {tag}")
            s.add_all([live, gone, draft])
            await s.flush()
            s.add_all(
                [
                    _doc(org.id, live.id, "ocr", OCR, valid=True),
                    _doc(org.id, live.id, "sdr", SDR, valid=True),
                    _doc(org.id, live.id, "cpo", {"x": 1}, valid=False),
                    _doc(org.id, gone.id, "ocr", OCR, valid=True),
                    _doc(org.id, draft.id, "ocr", OCR, valid=False),
                ]
            )
            ids = {"live": live.id, "gone": gone.id, "draft": draft.id}
    finally:
        command.upgrade(cfg, "head")

    async with session_scope() as s:
        snaps = {
            sys_name: list(
                (
                    await s.execute(
                        select(CertificationSnapshot).where(CertificationSnapshot.system_id == sid)
                    )
                ).scalars()
            )
            for sys_name, sid in ids.items()
        }
        (snap,) = snaps["live"]
        docs = {
            d.kind: d
            for d in (
                await s.execute(
                    select(CertificationSnapshotDocument).where(
                        CertificationSnapshotDocument.snapshot_id == snap.id
                    )
                )
            ).scalars()
        }
    assert snaps["gone"] == [] and snaps["draft"] == []
    assert snap.basis == "backfill" and snap.taken_by == "migration 0111"
    assert str(snap.ocr_period_from) == "2026-07-01" and str(snap.ocr_period_to) == "2026-09-30"
    assert snap.withheld_invalid == [{"kind": "cpo", "document_key": None}]
    assert set(docs) == {"ocr", "sdr"}
    # The migration's own digest must be the portal's, key order and all.
    assert docs["sdr"].sha256 == certification.digest(SDR)
    assert snap.ocr_sha256 == certification.digest(OCR) == docs["ocr"].sha256
    # Its content digest is the one take_for_ocr computes, so a later filing
    # of the same content dedupes onto the backfill instead of copying it.
    assert snap.content_sha256 == snapshots.content_digest(
        [(d.kind, d.document_key, d.sha256) for d in docs.values()]
    )
    async with session_scope() as s:
        filed_by = (
            (
                await s.execute(
                    select(CertificationSnapshotFiling.filed_by).where(
                        CertificationSnapshotFiling.snapshot_id == snap.id
                    )
                )
            )
            .scalars()
            .all()
        )
    assert filed_by == ["migration 0111"]
