"""A promoted acceptance rationale says where it came from.

The CR26 re-seed copies a rationale a person typed into the stored AVI into a
blank ``POAM.acceptance_rationale`` (spec 9.1, kept by owner decision). Now
that the event bus re-seeds automatically, the POA&M records who saved the
AVI it came from, when, and who ran the promotion, in
``acceptance_rationale_provenance`` (shown by the POA&M API beside the
rationale) and as a ``poam rationale_promoted`` event on its timeline. A
rationale written on the POA&M itself carries none of this.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select

from ccf.config import get_settings
from ccf.cr26.store import put_document
from ccf.cr26.ver import seed_avi, seed_ver_history
from ccf.db import session_scope
from ccf.events.derived import CR26_AUTHOR
from ccf.governance import bus
from ccf.models import POAM, Event
from ccf.models_cr26 import Cr26Document
from tests.test_event_derived_consumers import (
    _Client,
    _drain,
    _jobs_since,
    _mark,
    _poam,
    _system,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")

AUTHOR = "carol@acme.gov"


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _authored_avi(system_id: int, entries: dict[int, str]) -> tuple[int, str]:
    """A started VER family whose AVI a person then edited; returns the AVI's
    id and the time it was saved."""
    async with session_scope() as s:
        await seed_ver_history(s, system_id=system_id)
        await put_document(
            s,
            system_id=system_id,
            kind="avi",
            document={
                "acceptedVulnerabilities": [
                    {
                        "vulnerabilityDetail": {"providerTrackingId": str(pid)},
                        "acceptanceRationale": text,
                    }
                    for pid, text in entries.items()
                ]
            },
            updated_by=AUTHOR,
        )
    async with session_scope() as s:
        avi = (
            (
                await s.execute(
                    select(Cr26Document).where(
                        Cr26Document.system_id == system_id,
                        Cr26Document.kind == "avi",
                        Cr26Document.document_key.is_(None),
                    )
                )
            )
            .scalars()
            .one()
        )
        assert avi.updated_by == AUTHOR
        return avi.id, avi.updated_at.isoformat()


async def _row(poam_id: int) -> POAM:
    async with session_scope() as s:
        row = await s.get(POAM, poam_id)
        assert row is not None
        return row


async def _promotion_events(poam_id: int) -> list[Event]:
    async with session_scope() as s:  # unscoped: RLS would hide a mis-filed one
        return list(
            (
                await s.execute(
                    select(Event)
                    .where(
                        Event.entity_type == "poam",
                        Event.entity_id == str(poam_id),
                        Event.verb == "rationale_promoted",
                    )
                    .order_by(Event.id)
                )
            ).scalars()
        )


async def test_an_automatic_reseed_records_the_avis_author_and_the_consumer() -> None:
    org_id, sid = await _system(f"prov-auto-{id(object())}")
    blank = await _poam(sid, status="risk_accepted", acceptance_rationale=None, title="blank")
    typed = await _poam(
        sid, status="risk_accepted", acceptance_rationale="approved by the AO", title="typed"
    )
    avi_id, saved_at = await _authored_avi(
        sid, {blank: "vendor EOL, isolated", typed: "a different reason in the AVI"}
    )
    mark = await _mark()
    async with session_scope() as s:
        await bus.emit(
            s,
            verb="updated",
            entity_type="poam",
            entity_id=blank,
            summary="t",
            org_id=org_id,
            payload={"system_id": sid},
        )
    await _drain(mark)
    job = next(j for j in await _jobs_since(mark) if j.consumer == "cr26_documents")
    assert job.status == "done" and job.result["ver_history"] == "reseeded"

    row = await _row(blank)
    assert row.acceptance_rationale == "vendor EOL, isolated"  # C1 promotion kept
    prov = row.acceptance_rationale_provenance
    assert prov is not None
    assert {k: prov[k] for k in prov if k != "promoted_at"} == {
        "source": "cr26_document",
        "document_kind": "avi",
        "document_id": avi_id,
        "document_updated_by": AUTHOR,
        "document_updated_at": saved_at,
        "promoted_by": CR26_AUTHOR,
    }
    (ev,) = await _promotion_events(blank)
    assert ev.organization_id == org_id and ev.actor == CR26_AUTHOR
    assert ev.payload["document_updated_by"] == AUTHOR and ev.payload["system_id"] == sid
    assert AUTHOR in ev.summary

    # A rationale typed on the POA&M: untouched, and carries none of this.
    kept = await _row(typed)
    assert kept.acceptance_rationale == "approved by the AO"
    assert kept.acceptance_rationale_provenance is None
    assert await _promotion_events(typed) == []


async def test_a_person_seeding_is_named_as_the_promoter_and_the_api_shows_it() -> None:
    org_id, sid = await _system(f"prov-route-{id(object())}")
    blank = await _poam(sid, status="risk_accepted", acceptance_rationale=None, title="blank")
    await _authored_avi(sid, {blank: "compensating control in place"})
    async with _Client(org_id)() as c:
        r = await c.post(f"/api/systems/{sid}/cr26-documents/ver_history/seed")
        assert r.status_code == 200, r.text
        got = (await c.get(f"/api/poams/{blank}")).json()
    assert got["acceptance_rationale"] == "compensating control in place"
    prov = got["acceptance_rationale_provenance"]
    assert prov["document_updated_by"] == AUTHOR
    assert prov["promoted_by"] == "isso@acme.gov"  # the seeder's principal
    # The document's authorship is not the person who ran the seed: the
    # consumer must still treat the re-seeded rows as seeder-written.
    async with session_scope() as s:
        vh = (
            (
                await s.execute(
                    select(Cr26Document).where(
                        Cr26Document.system_id == sid, Cr26Document.kind == "ver_history"
                    )
                )
            )
            .scalars()
            .one()
        )
        assert vh.updated_by is None


async def _promoted(org_id: int, sid: int, text: str) -> int:
    blank = await _poam(sid, status="risk_accepted", acceptance_rationale=None, title="p")
    await _authored_avi(sid, {blank: text})
    async with session_scope() as s:
        await seed_ver_history(s, system_id=sid, updated_by=CR26_AUTHOR)
    assert (await _row(blank)).acceptance_rationale_provenance is not None
    return blank


async def test_typing_a_rationale_on_the_poam_clears_the_provenance() -> None:
    org_id, sid = await _system(f"prov-typed-{id(object())}")
    pid = await _promoted(org_id, sid, "from the AVI")
    async with _Client(org_id)() as c:
        r = await c.patch(f"/api/poams/{pid}", json={"acceptance_rationale": "typed by the ISSO"})
        assert r.status_code == 200, r.text
        body = r.json()
    assert body["acceptance_rationale"] == "typed by the ISSO"
    assert body["acceptance_rationale_provenance"] is None
    assert (await _row(pid)).acceptance_rationale_provenance is None


async def test_resending_the_same_rationale_keeps_the_provenance() -> None:
    """A save-the-whole-form PATCH re-sends the promoted text unchanged: that
    is not someone typing it, so the attribution stays."""
    org_id, sid = await _system(f"prov-same-{id(object())}")
    pid = await _promoted(org_id, sid, "from the AVI")
    async with _Client(org_id)() as c:
        r = await c.patch(f"/api/poams/{pid}", json={"acceptance_rationale": "from the AVI"})
        assert r.status_code == 200, r.text
    prov: dict[str, Any] | None = (await _row(pid)).acceptance_rationale_provenance
    assert prov is not None and prov["document_updated_by"] == AUTHOR


async def test_leaving_risk_accepted_clears_rationale_and_provenance() -> None:
    org_id, sid = await _system(f"prov-reopen-{id(object())}")
    pid = await _promoted(org_id, sid, "from the AVI")
    async with _Client(org_id)() as c:
        r = await c.patch(f"/api/poams/{pid}", json={"status": "open"})
        assert r.status_code == 200, r.text
    row = await _row(pid)
    assert (row.acceptance_rationale, row.acceptance_rationale_provenance) == (None, None)


async def test_a_rationale_created_on_the_poam_has_no_provenance() -> None:
    _org_id, sid = await _system(f"prov-new-{id(object())}")
    pid = await _poam(sid, status="risk_accepted", acceptance_rationale="typed at creation")
    async with session_scope() as s:
        await seed_ver_history(s, system_id=sid, updated_by=CR26_AUTHOR)
    row = await _row(pid)
    assert row.acceptance_rationale == "typed at creation"
    assert row.acceptance_rationale_provenance is None
    assert await _promotion_events(pid) == []


async def test_seeding_the_avi_itself_names_its_author_before_overwriting_it() -> None:
    """The AVI seed reads rationales from the AVI it is about to replace, and
    ``put_document`` then rewrites ``updated_by``: the author is read first."""
    _org_id, sid = await _system(f"prov-avi-{id(object())}")
    blank = await _poam(sid, status="risk_accepted", acceptance_rationale=None, title="blank")
    await _authored_avi(sid, {blank: "isolated segment"})
    now = datetime.now(UTC)
    async with session_scope() as s:
        await seed_avi(
            s,
            system_id=sid,
            period_from=now - timedelta(days=30),
            period_to=now,
            actor="isso@acme.gov",
        )
    prov = (await _row(blank)).acceptance_rationale_provenance
    assert prov is not None
    assert (prov["document_updated_by"], prov["promoted_by"]) == (AUTHOR, "isso@acme.gov")
