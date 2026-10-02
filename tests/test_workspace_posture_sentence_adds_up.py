"""The workspace posture step claimed a total and named three of five buckets.

The sentence read::

    "{passing} satisfied, {failing} failing, {unaddressed} not yet addressed of
     {total} {unit}s in {framework}."

``of {total}`` is an accounting claim: it tells a reader that the three numbers
before it describe the whole framework. They do not. ``framework_posture``
partitions into five -- passing, failing, documented, manual_review, unaddressed --
and this named three, so a reader subtracting them from the total got a remainder
that belongs to nothing on the page.

The two it dropped are the two that matter most to somebody deciding what to do
next: ``documented`` is work already claimed and owed evidence, and
``manual_review`` is work that has to be scheduled. Leaving them out of a sentence
that says "of {total}" quietly reassigns them to "not yet addressed" in the
reader's head, which is the opposite of what either means.

Same defect family as the ``/dashboard`` and ``/posture`` ones, in its arithmetic
form rather than its labelling form: a set of numbers presented as a partition
that is not one.
"""

from __future__ import annotations

import itertools
import re
from typing import Any

from sqlalchemy import select

from ccf.analytics.workspace import customer_workspace
from ccf.catalog.crosswalk import CROSSWALK_COLUMN, CROSSWALK_FRAMEWORK
from ccf.db import session_scope
from ccf.governance.control_tests import record_result
from ccf.models import (
    Control,
    Framework,
    FrameworkMapping,
    Organization,
    ScoringControl,
    ScoringStatus,
    System,
    SystemProfile,
)
from ccf.models_grc import ControlTest
from ccf.scoring.seed import seed_scoring_controls

_SEQ = itertools.count()

#: 800-53 control -> the 800-171 requirement the crosswalk maps it to. Seeded,
#: because the test database carries no catalog and without these rows every
#: verdict lands on no requirement.
_CROSSWALK = {
    "AC-02": "3.1.1 Limit system access to authorized users",
    "IA-02": "3.5.1 Identify system users",
    "AU-02": "3.3.1 Create and retain system audit logs",
}


def _bucket_numbers(detail: str) -> list[int]:
    """The numbers the sentence attributes to buckets.

    Only the segment before `" of "`. The framework label itself contains digits
    ("NIST SP 800-171 Rev. 2 (110 requirements)"), and a naive scan of the whole
    string picks those up -- which is a flaw in reading the sentence, not in the
    sentence.
    """
    head = detail.split(" of ", 1)[0]
    return [int(x) for x in re.findall(r"\b(\d+)\b", head)]


def _posture_step(w: dict[str, Any]) -> dict[str, Any]:
    step = next((s for s in w["steps"] if s.get("key") == "posture"), None)
    assert step is not None, f"no posture step in {[s.get('key') for s in w['steps']]}"
    return step


async def _workspace_with(
    statuses: list[tuple[str, str, str]], *, claimed: list[str] | None = None
) -> dict[str, Any]:
    """An 800-171 system carrying one control test per entry.

    800-171 rather than a FIPS-199 baseline because the workspace step reports in
    the framework's own unit, and the requirement denominator is the one a reader
    is most likely to try to add up.
    """
    n = next(_SEQ)
    async with session_scope() as session:
        await seed_scoring_controls(session)
        org = Organization(name=f"WsOrg{n}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"WsSys{n}", baseline=None)
        session.add(sys_)
        await session.flush()
        session.add(
            SystemProfile(
                system_id=sys_.id,
                answers={},
                environment_type="cloud",
                cloud_platform="m365_gcc_high",
                frameworks=["NIST_800_171"],
            )
        )
        # The crosswalk, or every verdict reaches no requirement and the
        # sentence reads "110 not yet addressed" whatever the fixture says --
        # which would make the arithmetic hold vacuously.
        framework = (
            await session.execute(
                select(Framework).where(Framework.code == CROSSWALK_FRAMEWORK)
            )
        ).scalars().first()
        if framework is None:
            framework = Framework(code=CROSSWALK_FRAMEWORK, name="NIST SP 800-171 Rev. 2")
            session.add(framework)
            await session.flush()
        for identifier, requirement in _CROSSWALK.items():
            control = (
                await session.execute(select(Control).where(Control.identifier == identifier))
            ).scalars().first()
            if control is None:
                control = Control(
                    identifier=identifier,
                    sequence_control=identifier,
                    fisma_mod=True,
                    fisma_high=True,
                )
                session.add(control)
                await session.flush()
            exists = (
                await session.execute(
                    select(FrameworkMapping).where(
                        FrameworkMapping.control_id == control.id,
                        FrameworkMapping.column_key == CROSSWALK_COLUMN,
                    )
                )
            ).scalars().first()
            if exists is None:
                session.add(
                    FrameworkMapping(
                        control_id=control.id,
                        framework_id=framework.id,
                        column_key=CROSSWALK_COLUMN,
                        value=requirement,
                    )
                )
        await session.flush()
        for status, control_id, key in statuses:
            test = ControlTest(
                organization_id=org.id,
                system_id=sys_.id,
                control_id=control_id,
                control_ids=[control_id],
                name=key,
                method="connector",
                source="generated",
                check_key=key,
                check_source="platform",
            )
            session.add(test)
            await session.flush()
            await record_result(
                session, test, status=status, detail=status, open_remediation=False
            )
        # A *claimed* implementation, which is what makes a requirement
        # `documented` -- neither satisfied by a scan nor untouched. Needed because
        # the sentence has to account for it, and a fixture that never produces
        # one cannot tell whether it does: dropping `documented` from the sentence
        # passed every other test in this file until this existed.
        #
        # `source` must not be "derived": a state the intake derivation computed
        # from a platform placemat is not somebody's claim about this system, and
        # `framework_posture` deliberately excludes those.
        for nist_id in claimed or []:
            sc = (
                await session.execute(
                    select(ScoringControl).where(ScoringControl.nist_id == nist_id)
                )
            ).scalars().first()
            assert sc is not None, f"{nist_id} is not in the seeded requirement matrix"
            session.add(
                ScoringStatus(
                    system_id=sys_.id,
                    scoring_control_id=sc.id,
                    state="implemented",
                    source="assessed",
                )
            )
        await session.flush()
        return await customer_workspace(session, org.id)


async def test_the_sentence_accounts_for_every_unit_it_claims_a_total_for() -> None:
    """Parse the numbers the step prints and check they sum to the total it cites.

    Asserted by parsing rather than by comparing against the posture payload,
    because the defect is in what the *sentence* accounts for: a version that
    computed all five buckets correctly and still printed three would pass a
    payload comparison and fail this.
    """
    w = await _workspace_with(
        [
            ("pass", "AC-02", "ws.passing"),
            ("fail", "IA-02", "ws.failing"),
            ("manual_review_required", "AU-02", "ws.unjudged"),
        ]
    )
    detail = _posture_step(w)["detail"]
    parts = _bucket_numbers(detail)
    assert parts, f"no bucket numbers in the posture detail: {detail!r}"
    total = w["posture"]["total"]
    assert sum(parts) == total, (
        f"the posture step says {parts} of {total}, which does not add up -- "
        f"{total - sum(parts)} {'unit' if total - sum(parts) == 1 else 'units'} "
        f"belong to no number on the page.\n  detail: {detail!r}"
    )


async def test_the_sentence_names_the_bucket_that_needs_a_human() -> None:
    """A requirement Concord could not judge is schedulable work.

    Omitted, it reads to the customer as "not yet addressed" -- which says nobody
    has looked, when Concord looked and said so.
    """
    w = await _workspace_with(
        [
            ("pass", "AC-02", "ws.passing"),
            ("manual_review_required", "AU-02", "ws.unjudged"),
        ]
    )
    detail = _posture_step(w)["detail"].lower()
    assert "judge" in detail or "manual" in detail or "review" in detail, (
        f"the posture step does not mention the manual-review bucket: {detail!r}"
    )


async def test_a_documented_requirement_is_not_silently_dropped() -> None:
    """``documented`` is a claim owed evidence, and the sentence must place it.

    It is neither satisfied by a scan nor untouched, so folding it into either
    neighbour misstates it: into "satisfied" it becomes evidence nobody produced,
    and into "not yet addressed" it loses the claim somebody made.

    Found by mutation: removing this bucket from the sentence passed every other
    test here, because no fixture produced a documented requirement. It needs a
    *claimed* ScoringStatus, which is what this one seeds.
    """
    w = await _workspace_with(
        [("pass", "AC-02", "ws.passing")], claimed=["3.4.1"]
    )
    posture = w["posture"]
    assert posture["documented"], "the fixture produced no documented requirement"
    detail = _posture_step(w)["detail"]
    assert "documented" in detail, (
        f"a claimed requirement is not accounted for in the sentence: {detail!r}"
    )
    assert sum(_bucket_numbers(detail)) == posture["total"], detail


async def test_a_system_with_no_results_still_adds_up() -> None:
    """Every requirement unaddressed is the common first-run state, and the
    arithmetic has to hold there too -- it is the case where a missing bucket is
    least visible, because the remainder equals the total."""
    w = await _workspace_with([])
    step = _posture_step(w)
    if step["state"] == "blocked":
        # No framework resolved: the step says why, which is tested elsewhere.
        assert step["detail"]
        return
    assert sum(_bucket_numbers(step["detail"])) == w["posture"]["total"], step["detail"]


async def test_the_step_still_names_the_framework_and_unit() -> None:
    """The fix must not strip the context that makes the numbers meaningful: 110
    requirements and 288 controls are different denominators."""
    w = await _workspace_with([("pass", "AC-02", "ws.passing")])
    detail = _posture_step(w)["detail"]
    assert "requirement" in detail
    assert "800-171" in detail or "171" in detail


async def test_the_fixture_actually_produces_a_spread_of_buckets() -> None:
    """Guard on the harness, not the code.

    Every assertion above is satisfied trivially if all 110 requirements land in
    one bucket -- which is what happened on the first attempt, because the fixture
    seeded no crosswalk and every verdict reached no requirement. A sum that holds
    because there is only one number is not evidence the sentence partitions
    anything.
    """
    w = await _workspace_with(
        [
            ("pass", "AC-02", "ws.passing"),
            ("fail", "IA-02", "ws.failing"),
            ("manual_review_required", "AU-02", "ws.unjudged"),
        ]
    )
    detail = _posture_step(w)["detail"]
    parts = _bucket_numbers(detail)
    non_zero = [n for n in parts if n]
    assert len(non_zero) >= 4, (
        "the fixture does not exercise a spread of buckets, so the arithmetic "
        f"assertions above hold vacuously: {detail!r}"
    )
    assert "satisfied" in detail
    assert "failing" in detail
    assert "could not be judged" in detail
    assert "not yet addressed" in detail
