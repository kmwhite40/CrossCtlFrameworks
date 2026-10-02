"""`/dashboard` counted "could not assess" as "passing", in green, on sign-in.

``compliance_gaps`` split every control test two ways::

    if result.status == "fail":
        gaps.append(entry)
    else:
        clean.append(entry)

and reported ``"passing": len(clean)``. So a control whose latest verdict was
``manual_review_required`` -- Concord saying it could not judge -- or ``warn``, or
``not_applicable`` -- nothing in scope -- was counted as passing and listed under
a green "clean" heading. Measured before the fix: five control tests, one of them
passing, and the page reported **four passing**.

This is the same defect family as the ``/posture`` bucket hole and strictly worse.
There, an unassessable control fell into "not yet addressed", which *understates*
coverage and makes a tenant look worse than it is. Here it lands in "passing",
which **overstates compliance**, on the page the docstring calls "what this
organization has to fix, first thing on sign-in". An operator reading it is told
there is nothing to do about a control nobody has confirmed.

The AWS attestation ingest made it reachable in volume rather than in principle:
Security Hub's ``NOT_AVAILABLE`` becomes ``manual_review_required`` and its
``WARNING`` becomes ``warn``, so an account where Security Hub could not evaluate
a few hundred controls would have driven the green number up.

The fix is a partition rather than a rename: four buckets that sum to
``assessed``, so the page is addable and a reader can check it.
"""

from __future__ import annotations

import itertools
from typing import Any

from ccf.analytics.gaps import compliance_gaps
from ccf.db import session_scope
from ccf.governance.control_tests import record_result
from ccf.governance.insights import executive
from ccf.models import Organization, System
from ccf.models_grc import ControlTest

_SEQ = itertools.count()

#: One control test per verdict the vocabulary admits, so every status is
#: exercised rather than the two anybody remembers.
SCENARIO: tuple[tuple[str, str], ...] = (
    ("pass", "check.that.passed"),
    ("fail", "check.that.failed"),
    ("warn", "check.that.warned"),
    ("manual_review_required", "check.we.could.not.judge"),
    ("not_applicable", "check.with.nothing.in.scope"),
    ("not_tested", "check.never.run"),
)


async def _org_with(statuses: tuple[tuple[str, str], ...]) -> tuple[int, dict[str, Any]]:
    n = next(_SEQ)
    async with session_scope() as session:
        org = Organization(name=f"GapsOrg{n}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"GapsSys{n}")
        session.add(sys_)
        await session.flush()
        for status, key in statuses:
            test = ControlTest(
                organization_id=org.id,
                system_id=sys_.id,
                control_id="AC-3",
                control_ids=["AC-3"],
                name=key,
                method="connector",
                source="generated",
                check_key=key,
                check_source="platform",
            )
            session.add(test)
            await session.flush()
            # `open_remediation=False` so the fixture does not also open six
            # POA&Ms; this test is about the counts, and the remediation path has
            # its own tests.
            await record_result(
                session, test, status=status, detail=status, open_remediation=False
            )
        return org.id, await compliance_gaps(session, org.id)


# --------------------------------------------------------------------------
# The defect
# --------------------------------------------------------------------------


async def test_only_a_passing_check_counts_as_passing() -> None:
    _, g = await _org_with(SCENARIO)
    assert g["assessed"] == 6
    assert g["passing"] == 1, (
        "a verdict other than `pass` was counted as passing: "
        f"clean holds {[c['status'] for c in g['clean']]}"
    )
    assert g["failing"] == 1


async def test_the_clean_list_holds_only_checks_that_passed() -> None:
    """The count and the list must agree, because the page renders both -- a
    green badge over the list length beside the `passing` number."""
    _, g = await _org_with(SCENARIO)
    assert [c["status"] for c in g["clean"]] == ["pass"]


async def test_a_verdict_concord_could_not_judge_is_its_own_bucket() -> None:
    """`warn` and `manual_review_required` together, the same grouping
    ``framework_posture`` uses and for the same reason: what is actionable about
    them is identical, a human has to look."""
    _, g = await _org_with(SCENARIO)
    assert g["manual_review"] == 2
    assert {r["status"] for r in g["review"]} == {"warn", "manual_review_required"}


async def test_nothing_in_scope_is_distinguished_from_a_pass() -> None:
    """`not_applicable` is the rollup's answer for a check that evaluated zero
    resources. Counting it as passing asserts something no scan observed."""
    _, g = await _org_with(SCENARIO)
    assert g["not_in_scope"] == 2  # not_applicable + not_tested


async def test_the_buckets_partition_what_was_assessed() -> None:
    """The property that makes the page checkable by the person reading it.

    Without it a reader cannot tell a miscount from a bucket they did not know
    about, which is exactly how `manual_review_required` hid inside `passing`.
    """
    _, g = await _org_with(SCENARIO)
    total = g["passing"] + g["failing"] + g["manual_review"] + g["not_in_scope"]
    assert total == g["assessed"], (
        f"{total} != {g['assessed']}: the buckets do not partition what was "
        "assessed, so one of them is holding something twice or not at all"
    )


async def test_an_all_unassessable_org_reports_no_passing_controls() -> None:
    """The shape an AWS account with Security Hub half-enabled produces.

    Every control reports NOT_AVAILABLE, which becomes
    `manual_review_required` -- and before the fix this page showed every one of
    them as a passing control in green.
    """
    _, g = await _org_with(
        tuple(("manual_review_required", f"check.{i}") for i in range(12))
    )
    assert g["assessed"] == 12
    assert g["passing"] == 0
    assert g["manual_review"] == 12
    assert g["clean"] == []


async def test_a_genuinely_clean_org_still_reads_as_clean() -> None:
    """The other direction: the fix must not make a healthy tenant look broken."""
    _, g = await _org_with((("pass", "a"), ("pass", "b"), ("pass", "c")))
    assert g["passing"] == 3
    assert g["failing"] == 0
    assert g["manual_review"] == 0
    assert g["not_in_scope"] == 0
    assert len(g["clean"]) == 3


async def test_an_org_with_nothing_assessed_reports_every_bucket_as_zero() -> None:
    """Present and zero, never absent: the template reads these unconditionally,
    and a missing key renders as nothing, which reads as "no problem"."""
    async with session_scope() as session:
        org = Organization(name=f"GapsEmptyOrg{next(_SEQ)}")
        session.add(org)
        await session.flush()
        g = await compliance_gaps(session, org.id)

    for key in ("passing", "failing", "manual_review", "not_in_scope", "assessed"):
        assert g[key] == 0, key
    for key in ("clean", "gaps", "review"):
        assert g[key] == [], key


async def test_the_empty_shape_and_the_populated_shape_have_the_same_keys() -> None:
    """The early-return empty dict is a second definition of this payload, and a
    key added to one and not the other is a KeyError in a template -- which is a
    500 on the page an operator lands on at sign-in."""
    async with session_scope() as session:
        org = Organization(name=f"GapsShapeOrg{next(_SEQ)}")
        session.add(org)
        await session.flush()
        empty = await compliance_gaps(session, org.id)
    _, populated = await _org_with(SCENARIO)
    assert set(empty) == set(populated)


async def test_a_review_row_carries_what_it_needs_to_be_acted_on() -> None:
    """These are the actionable ones -- somebody has to go and look -- so a bare
    count would be the same mistake in a quieter form."""
    _, g = await _org_with(SCENARIO)
    row = next(r for r in g["review"] if r["status"] == "manual_review_required")
    assert row["check"] == "check.we.could.not.judge"
    assert row["control_id"] == "AC-3"
    assert row["system"]
    assert row["detail"]


async def test_the_executive_rollup_carries_the_whole_partition() -> None:
    """The same numbers reach leadership, so the same partition has to hold there.

    ``governance.insights`` passes assessed, failing and passing into the
    executive view. While ``passing`` meant "everything that did not fail" those
    three added up by accident; now that it means ``pass``, a consumer computing
    ``assessed - failing - passing`` has a remainder, and it needs somewhere to go
    other than a reader's assumption.

    This is the aggregation-layer version of the defect: a dashboard that
    disagrees with its source is worse than no dashboard, and an executive summary
    whose numbers do not account for each other is the same thing one level up.
    """
    org_id, _ = await _org_with(SCENARIO)
    async with session_scope() as session:
        out = await executive(session, org_id=org_id)
    ct = out["control_tests"]

    assert ct["passing"] == 1
    assert ct["failing"] == 1
    assert ct["manual_review"] == 2
    assert ct["not_in_scope"] == 2
    total = ct["passing"] + ct["failing"] + ct["manual_review"] + ct["not_in_scope"]
    assert total == ct["assessed"], (
        f"the executive rollup does not account for {ct['assessed'] - total} of "
        f"the {ct['assessed']} controls it says were assessed"
    )
