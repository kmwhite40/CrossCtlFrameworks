"""The seeder's sample text is machine text, and now says so.

Under CISO-02, ``DRAFT_PREFIX`` in stored narrative text is the *only durable
record* that machine-drafted content has not been human-reviewed, and
``ccf.ssp.statements.is_draft_narrative`` is its documented reader. Every
producer of machine text was supposed to write the marker -- and
``ccf.ssp.platforms.customer_responsibility_statement`` does -- but its
sibling ``sample_statement``, the function ``ccf.ssp.seed._narratives``
calls for every control, wrote it on neither of its two return paths.

Measured on unmodified code: an m365 project seeded through the real
``seed_project_entries`` had 110 entries, of which 27 satisfied
``is_draft_narrative`` -- exactly the ones that happened to carry a
customer-responsibility lead-in. Every fully-inherited control (no lead-in)
reported as human-cleared, so the UI's AI-provenance badge hid machine
origin, and ``generate_statements``' preserve rule listed seed text in
``preserved_authored`` as if a person wrote it.

The tests here drive the real seeder (the same function ``POST /projects``,
``/reseed`` and the UI's create/regenerate routes call) against real rows and
read the stored text back in a fresh session. The throwaway
``ScoringControl`` rows carry no ``[DRAFT]`` anywhere in their fields, so a
fixture cannot supply the string under assertion; and the "regenerated"
checks assert the old text is *gone*, not that some expected string is
present. Seeded rows are removed in ``finally`` -- ``ScoringControl`` is a
global catalog every later test sees.
"""

from __future__ import annotations

import itertools

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Organization, ScoringControl, SSPControlEntry, SSPProject, System
from ccf.ssp.constants import DRAFT_PREFIX
from ccf.ssp.platforms import (
    CLOUD_PLATFORMS,
    NO_CATALOG_NOTE,
    NO_PLATFORM,
    PLATFORM_CHOICES,
    UNRECOGNIZED_PLATFORM_NOTE,
    customer_responsibility_statement,
    sample_statement,
)
from ccf.ssp.seed import seed_project_entries
from ccf.ssp.statements import is_draft_narrative

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()

#: Rendered by ``templates/_ssp_entry.html`` when ``is_draft_entry(e)`` is
#: true -- the same literal ``tests/test_ai_draft_badges.py`` asserts on.
BADGE = "AI-assisted / draft — needs review"

#: The unmistakable start of a ``sample_statement`` body, so a test can tell
#: seed text from a composed statement without depending on the marker.
_SAMPLE_LEAD = "The organization satisfies this objective"


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _rec(domain: str = "AC", **kw: object) -> ScoringControl:
    base: dict[str, object] = dict(
        control_id="AC.L2-3.1.1",
        nist_id="AC-2",
        domain=domain,
        title="Access Control",
        requirement="limit system access to authorized users",
        m365_coverage_status="Customer Responsibility",
    )
    base.update(kw)
    return ScoringControl(**base)


_PART = {"label": "a", "text": "authorized users are identified and access is limited"}
_EMPTY_PART = {"label": "a", "text": ""}


# --- the unit: both return paths, the full literal, once, at position 0 ------


@pytest.mark.parametrize("platform", CLOUD_PLATFORMS)
@pytest.mark.parametrize("part", [_PART, _EMPTY_PART], ids=["objective", "no-objective"])
def test_catalogued_platform_path_carries_the_marker(platform: str, part: dict[str, str]) -> None:
    """The main-body path: a platform with a service catalog. Both sub-branches
    (an objective to restate, or none) end at the same ``return``."""
    text = sample_statement(platform, _rec(), part)
    assert text.startswith(DRAFT_PREFIX), text
    assert text.count(DRAFT_PREFIX) == 1, text
    assert NO_CATALOG_NOTE not in text  # proves this was the catalogued path


@pytest.mark.parametrize("part", [_PART, _EMPTY_PART], ids=["objective", "no-objective"])
def test_absence_note_path_carries_the_marker(part: dict[str, str]) -> None:
    """The ``catalog_absence_note`` path, taken for :data:`NO_PLATFORM` (an
    empty catalog). "Sample" text with no catalog behind it is still
    machine-composed; there is no path on which it is not a draft."""
    text = sample_statement(NO_PLATFORM, _rec(), part)
    assert text.startswith(DRAFT_PREFIX), text
    assert text.count(DRAFT_PREFIX) == 1, text
    assert NO_CATALOG_NOTE in text  # proves this was the absence path


def test_absence_note_path_for_an_unrecognized_platform_carries_the_marker() -> None:
    """The same path, reached the other way: ``normalize_platform`` returns
    ``None`` for a code Concord does not know."""
    text = sample_statement("gcp", _rec(), _PART)
    assert text.startswith(DRAFT_PREFIX), text
    assert text.count(DRAFT_PREFIX) == 1, text
    assert UNRECOGNIZED_PLATFORM_NOTE.format(declared="gcp") in text


@pytest.mark.parametrize("platform", [*PLATFORM_CHOICES, "gcp"])
def test_customer_responsibility_statement_is_unchanged(platform: str) -> None:
    """Already marked before this fix, on all three of its paths; still marked,
    still exactly once, still at position 0. The byte-for-byte pin for the
    m365 text lives in ``tests/test_ssp_platforms.py``."""
    text = customer_responsibility_statement(platform, _rec())
    assert text.startswith(DRAFT_PREFIX), text
    assert text.count(DRAFT_PREFIX) == 1, text


# --- the seeder: real rows, read back ------------------------------------------


async def _seed_controls(session, prefix: str) -> tuple[str, str]:
    """Two throwaway catalog rows on an m365 project: AC is "Customer
    Responsibility" (gets the marked lead-in *and* sample parts), PE is
    "Microsoft Coverage" (no lead-in -- every part is ``sample_statement``
    text, which is the case that used to read as human-cleared). Neither row
    carries ``[DRAFT]`` in any field."""
    ac_id, pe_id = f"AC.{prefix}-3.1.1", f"PE.{prefix}-3.10.1"
    session.add_all(
        [
            ScoringControl(
                control_id=ac_id,
                nist_id=f"AC-{prefix}-1",
                domain="AC",
                title="Access Control",
                point_value="5",
                requirement="limit system access to authorized users",
                objective_parts=[
                    {"label": "a", "text": "authorized users are identified"},
                    {"label": "b", "text": "system access is limited to authorized users"},
                ],
                m365_coverage_status="Customer Responsibility",
                sort_order=1,
            ),
            ScoringControl(
                control_id=pe_id,
                nist_id=f"PE-{prefix}-1",
                domain="PE",
                title="Physical Access",
                point_value="1",
                requirement="limit physical access to organizational systems",
                objective_parts=[
                    {"label": "a", "text": "authorized individuals are identified"},
                    {"label": "b", "text": "physical access is limited"},
                ],
                m365_coverage_status="Microsoft Coverage",
                sort_order=2,
            ),
        ]
    )
    await session.flush()
    return ac_id, pe_id


async def _seed_project(
    *, platform: str = "m365", with_system: bool = False
) -> tuple[int, int, int | None, str, str]:
    """Catalog rows + org (+ system) + project, seeded through the real
    ``seed_project_entries``. Returns ``(org_id, proj_id, sys_id, ac_id, pe_id)``."""
    prefix = f"SDM{next(_SEQ)}"
    async with session_scope() as s:
        ac_id, pe_id = await _seed_controls(s, prefix)
        org = Organization(name=f"Seeder Marker Org {prefix}")
        s.add(org)
        await s.flush()
        sys_id: int | None = None
        if with_system:
            sys_ = System(organization_id=org.id, name=f"Seeder Marker Sys {prefix}")
            s.add(sys_)
            await s.flush()
            sys_id = sys_.id
        proj = SSPProject(
            organization_id=org.id,
            system_id=sys_id,
            customer_name="Seeder Marker",
            system_name="Seeder Marker Sys",
            platform=platform,
        )
        s.add(proj)
        await s.flush()
        await seed_project_entries(s, proj)
        return org.id, proj.id, sys_id, ac_id, pe_id


async def _cleanup(org_id: int | None, proj_id: int | None, *control_ids: str) -> None:
    async with session_scope() as s:
        if proj_id is not None:
            await s.execute(delete(SSPProject).where(SSPProject.id == proj_id))
        if org_id is not None:
            await s.execute(delete(Organization).where(Organization.id == org_id))
        if control_ids:
            await s.execute(
                delete(ScoringControl).where(ScoringControl.control_id.in_(control_ids))
            )


async def _entries(proj_id: int) -> dict[str, SSPControlEntry]:
    """What is actually stored, read back in a fresh session."""
    async with session_scope() as s:
        rows = (
            (await s.execute(select(SSPControlEntry).where(SSPControlEntry.project_id == proj_id)))
            .scalars()
            .all()
        )
        return {r.control_id: r for r in rows}


def _texts(entry: SSPControlEntry) -> list[str]:
    return [(p or {}).get("text") or "" for p in entry.part_narratives or []]


# --- 1. the defect, in the failing direction ---------------------------------


async def test_seeded_entry_is_a_draft_narrative() -> None:
    """An entry the seeder wrote with no customer lead-in -- every part of it
    is ``sample_statement`` text -- satisfies ``is_draft_narrative``. Before
    the fix it did not: the badge called it human-authored."""
    org_id = proj_id = None
    ac_id = pe_id = ""
    try:
        org_id, proj_id, _sys, ac_id, pe_id = await _seed_project()
        stored = await _entries(proj_id)
        pe = stored[pe_id]
        assert pe.part_narratives, pe
        labels = [p["label"] for p in pe.part_narratives]
        assert "Customer Responsibility" not in labels, labels
        assert is_draft_narrative(pe.part_narratives), _texts(pe)
    finally:
        await _cleanup(org_id, proj_id, ac_id, pe_id)


# --- 3. exactly once, at position 0, everywhere seeded text lands -------------


async def test_no_seeded_part_carries_the_marker_twice() -> None:
    """Every part of every seeded entry -- sample parts and the marked
    customer-responsibility lead-in alike -- carries the marker exactly once,
    at position 0. Catches a caller that prepends its own copy as surely as a
    producer that writes two."""
    org_id = proj_id = None
    ac_id = pe_id = ""
    try:
        org_id, proj_id, _sys, ac_id, pe_id = await _seed_project()
        stored = await _entries(proj_id)
        # Only this test's rows: other tests may have seeded the global catalog.
        assert {ac_id, pe_id} <= set(stored)
        checked = 0
        for control_id, entry in stored.items():
            for text in _texts(entry):
                assert text.count(DRAFT_PREFIX) == 1, (control_id, text)
                assert text.index(DRAFT_PREFIX) == 0, (control_id, text)
                checked += 1
        # The AC entry has the lead-in plus two sample parts; PE has two parts.
        assert checked >= 5
        labels = [p["label"] for p in stored[ac_id].part_narratives]
        assert labels[0] == "Customer Responsibility", labels
    finally:
        await _cleanup(org_id, proj_id, ac_id, pe_id)


# --- 5. provenance end to end: the seeded entry wears the badge ---------------


def _entry_segments(html: str, project_id: int) -> list[str]:
    marker = f'action="/ssp/{project_id}/entry/'
    return html.split(marker)[1:]


async def test_seeded_entry_shows_the_ai_badge_in_the_ui() -> None:
    """Through the real rendered page: ``ui.py``'s ``is_draft_entry`` (which is
    ``is_draft_narrative``) decides the badge per entry. Both seeded entries
    wear it; before the fix the fully-inherited PE entry did not."""
    org_id = proj_id = None
    ac_id = pe_id = ""
    try:
        org_id, proj_id, _sys, ac_id, pe_id = await _seed_project()
        async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
            r = await c.get(f"/ssp/{proj_id}")
            assert r.status_code == 200
        segments = _entry_segments(r.text, proj_id)
        assert segments
        by_control = {}
        for seg in segments:
            head = seg.split("</form>")[0]
            for cid in (ac_id, pe_id):
                if cid in head:
                    by_control[cid] = seg
        assert set(by_control) == {ac_id, pe_id}, list(by_control)
        assert BADGE in by_control[pe_id]
        assert BADGE in by_control[ac_id]
        # Per entry, not once per page: at least as many badges as seeded entries.
        assert r.text.count(BADGE) >= len(segments)
    finally:
        await _cleanup(org_id, proj_id, ac_id, pe_id)


# --- 6. reseed carries the marker, on both paths, through the real seeder -----


async def test_reseed_carries_the_marker_on_the_absence_path() -> None:
    """``seed_project_entries(overwrite=True, platform=...)`` is what
    ``POST /projects/{id}/reseed`` and the UI's regenerate route call.
    Switching to :data:`NO_PLATFORM` regenerates every part through the
    absence-note path: the m365 text is gone, the absence note is stated, and
    the marker is there exactly once at position 0 on every part."""
    org_id = proj_id = None
    ac_id = pe_id = ""
    try:
        org_id, proj_id, _sys, ac_id, pe_id = await _seed_project()
        before = _texts((await _entries(proj_id))[pe_id])
        assert any("Microsoft" in t for t in before), before
        async with session_scope() as s:
            proj = await s.get(SSPProject, proj_id)
            assert proj is not None
            proj.platform = NO_PLATFORM  # what the reseed route does before seeding
            await s.flush()
            touched = await seed_project_entries(
                s, proj, overwrite=True, platform=proj.platform
            )
        assert touched >= 2
        stored = await _entries(proj_id)
        for control_id in (ac_id, pe_id):
            for text in _texts(stored[control_id]):
                assert text.count(DRAFT_PREFIX) == 1, (control_id, text)
                assert text.index(DRAFT_PREFIX) == 0, (control_id, text)
            assert is_draft_narrative(stored[control_id].part_narratives)
        after = _texts(stored[pe_id])
        assert not any("Microsoft" in t for t in after), after
        assert all(NO_CATALOG_NOTE in t for t in after), after
    finally:
        await _cleanup(org_id, proj_id, ac_id, pe_id)


async def test_reseed_carries_the_marker_on_the_catalogued_path() -> None:
    """The other direction: a reseed onto a catalogued platform (aws_govcloud)
    regenerates through the main-body path, and the marker survives it."""
    org_id = proj_id = None
    ac_id = pe_id = ""
    try:
        org_id, proj_id, _sys, ac_id, pe_id = await _seed_project(platform=NO_PLATFORM)
        before = _texts((await _entries(proj_id))[pe_id])
        assert all(NO_CATALOG_NOTE in t for t in before), before
        async with session_scope() as s:
            proj = await s.get(SSPProject, proj_id)
            assert proj is not None
            proj.platform = "aws_govcloud"
            await s.flush()
            await seed_project_entries(s, proj, overwrite=True, platform=proj.platform)
        stored = await _entries(proj_id)
        after = _texts(stored[pe_id])
        assert not any(NO_CATALOG_NOTE in t for t in after), after
        assert all(t.startswith(_SAMPLE_LEAD, len(DRAFT_PREFIX)) for t in after), after
        for text in after:
            assert text.count(DRAFT_PREFIX) == 1, text
            assert text.index(DRAFT_PREFIX) == 0, text
        assert is_draft_narrative(stored[pe_id].part_narratives)
    finally:
        await _cleanup(org_id, proj_id, ac_id, pe_id)
