"""No CR26 deliverable may carry Concord's pipeline stage. The single most
important test in this change.

``systems.pipeline_stage`` is an operator's own note about where Concord
understands a system to be. It is NOT a status FedRAMP conferred -- FedRAMP has
published no status enumeration at all, and these values only borrow the words
of RFC-0020, a proposal (see
``docs/superpowers/specs/2026-09-21-pipeline-stage-design.md`` §1). A CR26
deliverable is a **federal filing**. A value that is an internal note in the
database and a federal assertion in a filed document is this programme's
claim-versus-rendering defect in its purest form.

None of today's eleven vendored schemas has a status property, so there is
nowhere to render this and no seeder that currently could. **That is a fact
about today's schemas, not a property of the field.** A future vendored schema
could add one, and the seeder written against it would reach for the nearest
status-shaped column on ``System`` -- which is exactly what this field now is.
So the guard is a test rather than a comment.

The document is serialised whole and searched. Checking a list of fields would
only prove that the fields someone thought of are clean; the failure worth
catching is a field nobody thought of.
"""

from __future__ import annotations

import json
from datetime import UTC, date, datetime

import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ccf.constants import PIPELINE_STAGES
from ccf.cr26.cpo import seed_cpo
from ccf.cr26.incident import seed_incident
from ccf.cr26.ocr import seed_ocr
from ccf.cr26.scn import seed_scn
from ccf.cr26.sdr import seed_sdr
from ccf.cr26.store import DELIVERABLE_KINDS, put_document
from ccf.cr26.ver import seed_avi, seed_vdr, seed_ver_history
from ccf.db import session_scope
from ccf.models import Organization, System
from ccf.models_cr26 import Cr26Document

_PERIOD_FROM = date(2026, 1, 1)
_PERIOD_TO = date(2026, 3, 31)

#: Every kind a platform seeder produces, and the call that produces it. A
#: kind reachable only through an author's own ``put_document`` is listed in
#: :data:`_AUTHORED_KINDS` instead -- both are filed documents and both are
#: searched, but only these eight can render a ``System`` column on their own.
_SEEDERS = {
    "cpo": lambda s, sid: seed_cpo(s, system_id=sid),
    "sdr": lambda s, sid: seed_sdr(s, system_id=sid),
    "ocr": lambda s, sid: seed_ocr(
        s, system_id=sid, period_from=_PERIOD_FROM, period_to=_PERIOD_TO
    ),
    "incident": lambda s, sid: seed_incident(
        s, system_id=sid, provider_tracking_id="INC-0001", report_type="initial"
    ),
    "scn": lambda s, sid: seed_scn(
        s, system_id=sid, change_ref="SCN-0001", change_type="Adaptive"
    ),
    "vdr": lambda s, sid: seed_vdr(
        s,
        system_id=sid,
        period_from=datetime(2026, 1, 1, tzinfo=UTC),
        period_to=datetime(2026, 3, 31, tzinfo=UTC),
    ),
    "avi": lambda s, sid: seed_avi(
        s,
        system_id=sid,
        period_from=datetime(2026, 1, 1, tzinfo=UTC),
        period_to=datetime(2026, 3, 31, tzinfo=UTC),
    ),
    "ver_history": lambda s, sid: seed_ver_history(s, system_id=sid),
}

#: The two deliverables no platform seeder writes: they are authored wholesale
#: through :func:`ccf.cr26.store.put_document`. Filed all the same, so filed
#: here too -- but the guard that matters for them is
#: :func:`test_every_seeder_is_wired_into_this_test`, which fails the day one
#: of them gains a seeder that could reach a ``System`` column.
_AUTHORED_KINDS = {
    "advisor": {
        "advisorName": "Example Advisory LLC",
        "advisorWebsite": "https://example.com/advisor",
    },
    "assessor": {
        "assessorName": "Example 3PAO Inc.",
        "assessorWebsite": "https://example.com/assessor",
    },
}


def _stages_in(blob: str) -> list[str]:
    """Every pipeline-stage member appearing anywhere in ``blob``.

    Searches for ALL ten members, not only the one the system is carrying: a
    seeder that rendered a hardcoded stage, or the wrong system's, is just as
    wrong as one that rendered this system's own.
    """
    return [stage for stage in PIPELINE_STAGES if stage in blob]


async def _system_with_stage(session: AsyncSession, stage: str) -> tuple[int, int]:
    """A system carrying ``stage``, named so the name itself cannot match.

    The names are keyed by INDEX, never by the stage's own text. The CPO
    seeder renders ``System.name`` and ``Organization.name`` into
    ``serviceIdentification`` -- measured, by writing this fixture the obvious
    way first and watching all ten cases fail on the fixture's own naming. A
    stage-shaped name would make every assertion below fire on the test's
    scaffolding instead of on what the seeders chose to render.
    """
    index = PIPELINE_STAGES.index(stage)
    org = Organization(name=f"pipeline-filed-org-{index}")
    session.add(org)
    await session.flush()
    sysm = System(
        organization_id=org.id,
        name=f"pipeline-filed-system-{index}",
        baseline="moderate",
        certification_class="B",
        certification_path="program",
        pipeline_stage=stage,
    )
    session.add(sysm)
    await session.flush()
    return org.id, sysm.id


async def _delete_org(org_id: int) -> None:
    """Cascades to the system and every ``cr26_documents`` row it owns.

    This MUST run even when the test fails, and it is not mere tidiness: the
    incident and SCN documents seeded above carry a non-NULL ``document_key``,
    and migration ``0081_cr26_document_key``'s downgrade deliberately refuses
    to run past such a row -- it is a filed federal report. Rows left behind
    here do not fail this test; they fail
    ``tests/test_migration_0081_document_key.py`` later in the same session,
    a long way from the cause. Measured, by omitting this first. Same helper,
    same reason, as ``tests/test_cr26_incident_seed.py``.
    """
    async with session_scope() as s:
        await s.execute(delete(Organization).where(Organization.id == org_id))


async def _seed_everything(session: AsyncSession, system_id: int) -> None:
    for seeder in _SEEDERS.values():
        await seeder(session, system_id)
    for kind, document in _AUTHORED_KINDS.items():
        await put_document(session, system_id=system_id, kind=kind, document=document)


def test_every_seeder_is_wired_into_this_test() -> None:
    """A guard on the guard.

    This test is only as good as the set of documents it produces. A new
    seeder -- or a seeder for one of the two kinds an author writes by hand
    today -- would be exactly the code that learns about a status-shaped
    column, and it must not be able to arrive without landing in
    :data:`_SEEDERS` first. A vacuous pass here is the failure mode that
    matters, so the coverage is asserted rather than assumed.
    """
    import ccf.cr26.cpo  # noqa: PLC0415 - imported for the module scan below
    import ccf.cr26.incident  # noqa: PLC0415
    import ccf.cr26.ocr  # noqa: PLC0415
    import ccf.cr26.scn  # noqa: PLC0415
    import ccf.cr26.sdr  # noqa: PLC0415
    import ccf.cr26.ver  # noqa: PLC0415

    modules = (
        ccf.cr26.cpo,
        ccf.cr26.sdr,
        ccf.cr26.ocr,
        ccf.cr26.incident,
        ccf.cr26.scn,
        ccf.cr26.ver,
    )
    found = {
        name
        for module in modules
        for name in vars(module)
        if name.startswith("seed_") and callable(vars(module)[name])
    }
    assert found == {f"seed_{k}" for k in _SEEDERS}, (
        "a CR26 seeder exists that this test never runs -- wire it into "
        "_SEEDERS, or a stage could reach a filed document unobserved"
    )
    assert set(_SEEDERS) | set(_AUTHORED_KINDS) == set(DELIVERABLE_KINDS)


def test_the_search_detects_a_stage_when_one_is_present() -> None:
    """Prove the detector fires, without committing the violation it hunts.

    A search that could never match would let every assertion below pass
    forever -- the "harness that cannot fail" shape.
    """
    assert _stages_in(json.dumps({"systemStatus": "rev5:continuous-monitoring"})) == [
        "rev5:continuous-monitoring"
    ]
    assert _stages_in(json.dumps({"nested": [{"deep": {"x": "20x:prioritized"}}]})) == [
        "20x:prioritized"
    ]
    assert _stages_in(json.dumps({"certificationType": "Rev5"})) == []


@pytest.mark.parametrize("stage", PIPELINE_STAGES)
async def test_no_stage_reaches_any_cr26_document(stage: str) -> None:
    """Every stage, against every filable deliverable, searched whole."""
    async with session_scope() as s:
        org_id, system_id = await _system_with_stage(s, stage)
        await _seed_everything(s, system_id)

    try:
        await _assert_no_stage_is_filed(system_id, stage)
    finally:
        await _delete_org(org_id)


async def _assert_no_stage_is_filed(system_id: int, stage: str) -> None:
    """Read back what was filed and search every document body whole."""
    async with session_scope() as s:
        # Re-read the stage from the database first. If it were not actually
        # stored, every assertion below would pass on a system that never
        # carried a stage at all -- vacuously, and forever.
        stored_stage = (
            await s.execute(select(System.pipeline_stage).where(System.id == system_id))
        ).scalar_one()
        assert stored_stage == stage

        rows = (
            (
                await s.execute(
                    select(Cr26Document).where(Cr26Document.system_id == system_id)
                )
            )
            .scalars()
            .all()
        )
        assert {row.kind for row in rows} == set(DELIVERABLE_KINDS), (
            "a deliverable kind was not filed, so nothing was searched for it"
        )

        for row in rows:
            body = json.dumps(row.document, sort_keys=True)
            # A document that serialised to nothing would make the search below
            # trivially clean.
            assert len(body) > 2, f"{row.kind} filed an empty document body"
            assert not _stages_in(body), (
                f"CR26 {row.kind} document carries Concord's pipeline stage "
                f"{_stages_in(body)!r}. This field is an operator's internal "
                "note, not a status FedRAMP conferred -- filing it turns a "
                "private note into a federal assertion. See "
                "docs/superpowers/specs/2026-09-21-pipeline-stage-design.md §4."
            )
