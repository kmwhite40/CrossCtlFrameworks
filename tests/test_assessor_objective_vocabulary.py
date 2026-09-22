"""The assessor UI's per-objective finding dropdown must be able to say every
verdict the column can hold -- and a save must never change one silently.

``AssessmentControlResult.objective_findings`` carries TWO vocabularies:

- ``ccf.assessment.seed.FINDINGS`` -- what the seeder and this form write
  (``not_assessed | satisfied | other_than_satisfied | not_applicable``);
- ``ccf.models_assessment_engine.OBJECTIVE_VERDICTS`` -- what the assessment
  engine writes into the same JSONB on acceptance
  (``satisfied | not_satisfied | not_applicable | insufficient_evidence``).

The objective ``<select>`` was built from the first list only, so an objective
holding ``not_satisfied`` or ``insufficient_evidence`` rendered with no
matching ``<option>``; a browser then selects the first one, and the next save
wrote ``not_assessed`` over a real failure or a real "the evidence did not
settle this". Since 8dd6437 that value reaches the OSCAL SAR an assessor
ingests, so merely opening the page and pressing Save downgraded a federal
finding.

Every test here goes through the RENDERED PAGE rather than posting a
hand-written form body: the defect lives in what the browser submits after
reading the options, and a test that invents the body cannot see it (the
existing round-trip test in ``test_oscal_sar_objectives.py`` posts one field
by hand and passes against the bug).

Owns the ``ZOV-`` control-id namespace. No migration: every column read here
already exists.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import date
from html.parser import HTMLParser
from typing import Any

import pytest
import pytest_asyncio  # noqa: F401
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from ccf.api.main import create_app
from ccf.api.routes import ui as ui_routes
from ccf.assessment.seed import FINDINGS
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import (
    Assessment,
    AssessmentControlResult,
    Organization,
    System,
)
from ccf.models_assessment_engine import OBJECTIVE_VERDICTS

pytestmark = pytest.mark.usefixtures("fresh_engine")

#: This module's own control-id namespace (``ZP-``/``ZK-``/``ZQ-``/``ZN-``/
#: ``ZAE-``/``AEJ-``/``ZV-`` are taken by sibling modules).
_CONTROL = "ZOV-01"

#: Every spelling the JSONB column is actually written with, from both
#: writers. Built from the real constants so a future member of either is
#: covered here without editing this file.
_VOCABULARY: tuple[str, ...] = tuple(sorted({*FINDINGS, *OBJECTIVE_VERDICTS}))


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


# ---------------------------------------------------------------------------
# A browser, reduced to the one thing that matters: what it SUBMITS.
# ---------------------------------------------------------------------------


class _BrowserForm(HTMLParser):
    """The body a browser would POST for one ``<form action=...>`` of a page.

    The rule that makes this a real reproduction: for a ``<select>`` with no
    ``selected`` option, a browser submits the FIRST option. That is the whole
    defect -- the server never sees the value it rendered from.
    """

    def __init__(self, action: str) -> None:
        super().__init__(convert_charrefs=True)
        self._action = action
        self._inside = False
        self.fields: dict[str, str] = {}
        self.options: dict[str, list[str]] = {}
        self._select: str | None = None
        self._selected: str | None = None
        self._textarea: str | None = None
        self._buf: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if tag == "form":
            self._inside = a.get("action") == self._action
            return
        if not self._inside:
            return
        if tag == "select":
            self._select = a.get("name")
            self._selected = None
            if self._select is not None:
                self.options[self._select] = []
        elif tag == "option" and self._select is not None:
            value = a.get("value") or ""
            self.options[self._select].append(value)
            if "selected" in a and self._selected is None:
                self._selected = value
        elif tag == "textarea":
            self._textarea = a.get("name")
            self._buf = []
        elif tag == "input":
            name = a.get("name")
            if name is None:
                return
            if a.get("type") == "checkbox":
                if "checked" in a:
                    self.fields[name] = a.get("value") or "on"
            else:
                self.fields[name] = a.get("value") or ""

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._inside = False
            return
        if not self._inside:
            return
        if tag == "select" and self._select is not None:
            opts = self.options[self._select]
            if self._selected is not None:
                self.fields[self._select] = self._selected
            else:
                self.fields[self._select] = opts[0] if opts else ""
            self._select = None
        elif tag == "textarea" and self._textarea is not None:
            self.fields[self._textarea] = "".join(self._buf)
            self._textarea = None

    def handle_data(self, data: str) -> None:
        if self._inside and self._textarea is not None:
            self._buf.append(data)


def _read_form(html: str, action: str) -> _BrowserForm:
    parser = _BrowserForm(action)
    parser.feed(html)
    return parser


# ---------------------------------------------------------------------------
# Fixture: one assessment carrying one control result with objective findings.
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _fixture(org_name: str, parts: list[dict[str, Any]]) -> AsyncIterator[tuple[int, int]]:
    """``(assessment_id, result_id)``; every seeded row removed afterwards."""
    async with session_scope() as s:
        org = Organization(name=org_name)
        s.add(org)
        await s.flush()
        sysrow = System(organization_id=org.id, name=f"{org_name} system")
        s.add(sysrow)
        await s.flush()
        assessment = Assessment(
            system_id=sysrow.id,
            name=f"{org_name} assessment",
            kind="internal",
            assessor="Jane 3PAO",
            started_on=date.today(),
        )
        s.add(assessment)
        await s.flush()
        row = AssessmentControlResult(
            assessment_id=assessment.id,
            control_id=_CONTROL,
            nist_id="ZOV-1",
            domain="AC",
            title="Objective vocabulary fixture",
            requirement="Objective-grain findings round-trip through the form.",
            finding="not_assessed",
            objective_findings=parts,
            sort_order=0,
        )
        s.add(row)
        await s.flush()
        ids = (assessment.id, row.id, sysrow.id, org.id)
    try:
        yield ids[0], ids[1]
    finally:
        async with session_scope() as s:
            await s.execute(
                delete(AssessmentControlResult).where(
                    AssessmentControlResult.assessment_id == ids[0]
                )
            )
            await s.execute(delete(Assessment).where(Assessment.id == ids[0]))
            await s.execute(delete(System).where(System.id == ids[2]))
            await s.execute(delete(Organization).where(Organization.id == ids[3]))


async def _page(assessment_id: int) -> str:
    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get(f"/assessments/{assessment_id}")
    assert r.status_code == 200, r.text
    return r.text


async def _save(assessment_id: int, result_id: int, data: dict[str, str]) -> int:
    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post(f"/assessments/{assessment_id}/result/{result_id}", data=data)
    return r.status_code


async def _row(result_id: int) -> AssessmentControlResult:
    async with session_scope() as s:
        row = (
            await s.execute(
                select(AssessmentControlResult).where(AssessmentControlResult.id == result_id)
            )
        ).scalar_one()
        s.expunge(row)
        return row


def _by_label(row: AssessmentControlResult) -> dict[str, dict[str, Any]]:
    return {p["label"]: p for p in row.objective_findings or []}


async def _browser_round_trip(assessment_id: int, result_id: int) -> tuple[int, _BrowserForm]:
    """Render the page, submit exactly what a browser would, return both."""
    action = f"/assessments/{assessment_id}/result/{result_id}"
    form = _read_form(await _page(assessment_id), action)
    return await _save(assessment_id, result_id, form.fields), form


# ---------------------------------------------------------------------------
# 1-2. The defect: an engine verdict does not survive opening the page.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_insufficient_evidence_survives_the_page_and_a_save() -> None:
    """"The evidence did not settle this" is not "nobody looked"."""
    parts = [
        {
            "label": "[a]",
            "text": "the policy is reviewed at a defined frequency;",
            "finding": "insufficient_evidence",
            "rationale": "Review cadence could not be determined.",
        }
    ]
    async with _fixture("Objective Vocab Insufficient Org", parts) as (aid, rid):
        status, form = await _browser_round_trip(aid, rid)
        assert status == 200
        # The verdict survived the page and the save...
        parts_after = _by_label(await _row(rid))
        assert parts_after["[a]"]["finding"] == "insufficient_evidence"
        assert parts_after["[a]"]["rationale"] == "Review cadence could not be determined."
        # ...because the page could say it, so the browser submitted it back.
        assert "insufficient_evidence" in form.options["obj::[a]"], form.options["obj::[a]"]
        assert form.fields["obj::[a]"] == "insufficient_evidence"


@pytest.mark.asyncio
async def test_not_satisfied_survives_the_page_and_a_save() -> None:
    """A real failure is not downgraded to "not assessed" by a Save."""
    parts = [
        {
            "label": "[b]",
            "text": "an official to manage the policy is designated;",
            "finding": "not_satisfied",
            "rationale": "No designated official named in the policy.",
        }
    ]
    async with _fixture("Objective Vocab NotSatisfied Org", parts) as (aid, rid):
        status, form = await _browser_round_trip(aid, rid)
        assert status == 200
        assert _by_label(await _row(rid))["[b]"]["finding"] == "not_satisfied"
        assert "not_satisfied" in form.options["obj::[b]"], form.options["obj::[b]"]
        assert form.fields["obj::[b]"] == "not_satisfied"


# ---------------------------------------------------------------------------
# 3. A value the form cannot offer is never silently substituted.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_stored_value_outside_both_vocabularies_is_rendered_not_rewritten() -> None:
    """The column is free JSONB. A spelling neither constant lists still has
    to survive being looked at -- the page offers it as its own option rather
    than replacing it with the first one that fits."""
    parts = [{"label": "[c]", "text": "legacy import;", "finding": "partially_satisfied"}]
    async with _fixture("Objective Vocab Legacy Org", parts) as (aid, rid):
        status, form = await _browser_round_trip(aid, rid)
        assert status == 200
        assert _by_label(await _row(rid))["[c]"]["finding"] == "partially_satisfied"
        assert "partially_satisfied" in form.options["obj::[c]"], form.options["obj::[c]"]
        assert form.fields["obj::[c]"] == "partially_satisfied"


@pytest.mark.asyncio
async def test_a_posted_value_the_form_could_not_offer_is_refused_and_nothing_is_written() -> None:
    """The save refuses rather than substituting. A 200 with a different value
    stored than the one posted is the defect shape this repo keeps finding
    (``rollup.roll_up`` returns ``None``; ``trust_corroboration`` reports
    ``unsupported``) -- so does a 200 that quietly keeps the old value.

    And a refusal writes NOTHING: the notes posted alongside must not land."""
    parts = [{"label": "[d]", "text": "authorizations are documented;", "finding": "satisfied"}]
    async with _fixture("Objective Vocab Refusal Org", parts) as (aid, rid):
        form = _read_form(await _page(aid), f"/assessments/{aid}/result/{rid}")
        body = dict(form.fields)
        body["obj::[d]"] = "definitely-not-a-finding"
        body["assessor_note"] = "this note must not be written"
        status = await _save(aid, rid, body)
        assert status == 422, status
        row = await _row(rid)
        assert _by_label(row)["[d]"]["finding"] == "satisfied"
        assert row.assessor_note is None
        assert row.observed_on is None


# ---------------------------------------------------------------------------
# 4. Every member of both real vocabularies, offered and round-tripped.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("verdict", _VOCABULARY)
@pytest.mark.asyncio
async def test_every_vocabulary_member_is_offered_saved_and_left_alone(verdict: str) -> None:
    """Parametrized over ``FINDINGS | OBJECTIVE_VERDICTS`` themselves, so a
    future member of either is covered without touching this test.

    Three properties per member: the form OFFERS it on an untouched objective,
    an assessor selecting it STORES it, and a later save that does not touch it
    LEAVES it."""
    parts = [{"label": "[a]", "text": "the objective;", "finding": "not_assessed"}]
    async with _fixture(f"Objective Vocab {verdict} Org", parts) as (aid, rid):
        form = _read_form(await _page(aid), f"/assessments/{aid}/result/{rid}")
        assert verdict in form.options["obj::[a]"], form.options["obj::[a]"]

        chosen = dict(form.fields)
        chosen["obj::[a]"] = verdict
        assert await _save(aid, rid, chosen) == 200
        assert _by_label(await _row(rid))["[a]"]["finding"] == verdict

        status, second = await _browser_round_trip(aid, rid)
        assert second.fields["obj::[a]"] == verdict
        assert status == 200
        assert _by_label(await _row(rid))["[a]"]["finding"] == verdict


# ---------------------------------------------------------------------------
# 5. The control-level path is untouched.
# ---------------------------------------------------------------------------


def test_control_level_finding_vocabulary_is_unchanged() -> None:
    """Asserted by equality, not by membership: the control grain keeps its
    four-value list and its labels exactly."""
    assert FINDINGS == ("not_assessed", "satisfied", "other_than_satisfied", "not_applicable")
    assert ui_routes._FINDING_META == [
        ("not_assessed", "Not assessed", "chip--ghost"),
        ("satisfied", "Satisfied", "chip--ok"),
        ("other_than_satisfied", "Other than satisfied", "chip--err"),
        ("not_applicable", "N/A", "chip--info"),
    ]


@pytest.mark.asyncio
async def test_control_level_select_and_save_are_unchanged() -> None:
    """The control ``<select>`` still offers exactly FINDINGS, and the
    control-level save still coerces an unknown finding to ``not_assessed``
    (pre-existing behaviour, asserted by equality so a change is visible)."""
    parts = [{"label": "[a]", "text": "the objective;", "finding": "satisfied"}]
    async with _fixture("Objective Vocab Control Org", parts) as (aid, rid):
        form = _read_form(await _page(aid), f"/assessments/{aid}/result/{rid}")
        assert form.options["finding"] == [
            "not_assessed",
            "satisfied",
            "other_than_satisfied",
            "not_applicable",
        ]

        body = dict(form.fields)
        body["finding"] = "other_than_satisfied"
        assert await _save(aid, rid, body) == 200
        assert (await _row(rid)).finding == "other_than_satisfied"

        body["finding"] = "insufficient_evidence"  # not a control-grain value
        assert await _save(aid, rid, body) == 200
        assert (await _row(rid)).finding == "not_assessed"


# ---------------------------------------------------------------------------
# 6. A deliberate selection is honoured exactly.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_explicit_selection_is_stored_and_its_neighbours_are_not() -> None:
    parts = [
        {"label": "[a]", "text": "first;", "finding": "insufficient_evidence", "rationale": "r1"},
        {"label": "[b]", "text": "second;", "finding": "satisfied", "rationale": "r2"},
        {"label": "[c]", "text": "third;", "finding": "not_satisfied", "gaps": ["g"]},
    ]
    async with _fixture("Objective Vocab Explicit Org", parts) as (aid, rid):
        form = _read_form(await _page(aid), f"/assessments/{aid}/result/{rid}")
        body = dict(form.fields)
        body["obj::[b]"] = "not_satisfied"  # the one thing the assessor touched
        body["assessor_note"] = "Contractor roster reviewed."
        body["reviewed"] = "on"
        assert await _save(aid, rid, body) == 200

        row = await _row(rid)
        after = _by_label(row)
        assert after["[b]"]["finding"] == "not_satisfied"
        assert after["[b]"]["rationale"] == "r2"
        assert after["[a]"]["finding"] == "insufficient_evidence"
        assert after["[a]"]["rationale"] == "r1"
        assert after["[c]"]["finding"] == "not_satisfied"
        assert after["[c]"]["gaps"] == ["g"]
        assert row.assessor_note == "Contractor roster reviewed."
        assert row.reviewed is True
