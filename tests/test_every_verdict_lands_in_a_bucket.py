"""No verdict may fall out of the posture buckets into "nobody has looked".

``framework_posture`` buckets a control by the verdicts its tests carry:
``fail`` -> failing, ``pass`` -> passing, ``manual_review_required`` ->
manual_review, a claimed implementation -> documented, and everything left ->
unaddressed. The last clause is a remainder, not a decision, so **any status the
enumeration does not name is silently reported as "not yet addressed"** -- the
page saying nobody has looked at a control Concord looked at and had something to
say about.

That has already happened once. ``manual_review_required`` was unnamed, and 22 of
one live system's controls sat in "not yet addressed" carrying an explicit
"could not assess" verdict.

It was about to happen again. ``warn`` is in ``VALIDATION_STATUSES``, is ranked
between ``manual_review_required`` and ``fail`` by ``posture.drift``, alerts in
``record_result`` exactly as ``fail`` does -- and is named nowhere in
``framework_posture``. Nothing emitted it until the Security Hub ingest mapped
AWS's ``WARNING`` onto it, which would have put "some information is missing or
this check is not supported for your configuration" into the bucket that means
nobody has looked.

So this file does not test ``warn``. It tests **every** member of
``VALIDATION_STATUSES``, with an explicit expectation per status and a reason, so
the next status added to the vocabulary fails here rather than quietly joining
the remainder.
"""

from __future__ import annotations

import itertools

import pytest
from sqlalchemy import select

from ccf.analytics.framework_posture import framework_posture, system_framework_posture
from ccf.catalog.crosswalk import CROSSWALK_COLUMN, CROSSWALK_FRAMEWORK
from ccf.db import session_scope
from ccf.fedramp20x import VALIDATION_STATUSES
from ccf.models import (
    Control,
    Framework,
    FrameworkMapping,
    Organization,
    System,
    SystemProfile,
)
from ccf.models_grc import ControlTest
from ccf.posture.attested import CHECK_SOURCE as ATTESTED_SOURCE
from ccf.scoring.seed import seed_scoring_controls

_SEQ = itertools.count()

#: status -> the bucket a control carrying only that status must land in, and why.
#:
#: Exhaustive over ``VALIDATION_STATUSES`` and asserted to be, below. An entry
#: here is a decision about what the product tells a reader, so each carries the
#: argument for it rather than only the answer.
EXPECTED_BUCKET: dict[str, tuple[str, str]] = {
    "pass": (
        "passing",
        "a check read the environment and the expectation held, which is the one "
        "status that credits a control as satisfied",
    ),
    "fail": (
        "failing",
        "a check read the environment and the expectation did not hold, which "
        "outranks every other status for the same control",
    ),
    "warn": (
        "manual_review",
        "Concord looked and the result is not clean but not a confirmed failure. "
        "It cannot be `passing` -- nothing was satisfied -- and it must not be "
        "`failing`, because reporting AWS's WARNING ('some information is "
        "missing or this check is not supported for your configuration') as a "
        "failed control overstates a finding in a document a regulator acts on. "
        "What is true of it is what is true of manual_review: a human has to "
        "look.",
    ),
    "manual_review_required": (
        "manual_review",
        "Concord assessed the control and could not judge it. The bucket exists "
        "because sweeping these into `unaddressed` said nobody had looked.",
    ),
    "not_applicable": (
        "unaddressed",
        "nothing was in scope, so the control carries no evidence either way. "
        "`roll_up_findings` returns this for a check that evaluated zero "
        "resources, and an empty scan is genuinely 'nothing has looked at this' "
        "rather than a judgement to report.",
    ),
    "not_tested": (
        "unaddressed",
        "the same reasoning as not_applicable: a status that explicitly says no "
        "test ran, so there is no judgement to report and nothing to schedule.",
    ),
}


def test_the_expectation_table_covers_the_whole_vocabulary() -> None:
    """The half of the guard that catches a *new* status.

    Without this, adding a seventh member to ``VALIDATION_STATUSES`` would leave
    it untested here and unnamed in ``framework_posture`` -- the exact way `warn`
    and `manual_review_required` each got missed.
    """
    assert set(EXPECTED_BUCKET) == set(VALIDATION_STATUSES), (
        "VALIDATION_STATUSES and this table disagree. Add the new status here "
        "with the bucket it belongs in and the argument for that choice, and "
        "name it in framework_posture: "
        f"missing={set(VALIDATION_STATUSES) - set(EXPECTED_BUCKET)}, "
        f"stale={set(EXPECTED_BUCKET) - set(VALIDATION_STATUSES)}"
    )


def test_every_reason_is_an_argument_not_a_label() -> None:
    for status, (_, reason) in EXPECTED_BUCKET.items():
        assert len(reason.split()) >= 10, f"{status}: reason too thin to evaluate"


async def _one_control_one_status(status: str) -> dict[str, object]:
    n = next(_SEQ)
    async with session_scope() as session:
        existing = (
            await session.execute(select(Control).where(Control.identifier == "AC-03"))
        ).scalars().first()
        if existing is None:
            session.add(
                Control(identifier="AC-03", sequence_control="AC-03", fisma_mod=True)
            )
        else:
            existing.fisma_mod = True
        await session.flush()
        org = Organization(name=f"BucketOrg{n}")
        session.add(org)
        await session.flush()
        sys_ = System(
            organization_id=org.id, name=f"BucketSys{n}", baseline="moderate"
        )
        session.add(sys_)
        await session.flush()
        session.add(
            ControlTest(
                organization_id=org.id,
                system_id=sys_.id,
                control_id="AC-3",
                control_ids=["AC-3"],
                name=f"a check returning {status}",
                method="connector",
                source="generated",
                check_key=f"demo.bucket.{status}",
                check_source="platform",
                last_status=status,
            )
        )
        await session.flush()
        return await framework_posture(session, system_id=sys_.id, org_id=None)


@pytest.mark.parametrize("status", sorted(VALIDATION_STATUSES))
async def test_a_control_carrying_one_status_lands_where_it_should(status: str) -> None:
    """Named per status, so a regression says which verdict went missing."""
    bucket, reason = EXPECTED_BUCKET[status]
    out = await _one_control_one_status(status)

    assert "AC-3" in out[bucket], (
        f"a control whose only verdict is {status!r} is not in {bucket!r}. "
        f"It should be, because: {reason}\n"
        f"passing={out['passing']} failing={out['failing']} "
        f"manual_review={out['manual_review']} unaddressed={out['unaddressed']}"
    )
    for other in ("passing", "failing", "manual_review"):
        if other != bucket:
            assert "AC-3" not in out[other], (
                f"{status!r} landed in {other!r} as well as {bucket!r}"
            )


@pytest.mark.parametrize("status", ["warn", "manual_review_required"])
async def test_a_judged_verdict_is_never_reported_as_unlooked_at(status: str) -> None:
    """The defect stated directly, for the two statuses that mean "we looked".

    Separate from the table-driven test above on purpose: that one would still
    pass if someone moved `warn` to `unaddressed` and updated the table to match.
    This one says `unaddressed` is wrong for a verdict Concord produced, whatever
    the table says.
    """
    out = await _one_control_one_status(status)
    assert "AC-3" not in out["unaddressed"], (
        f"a control Concord assessed as {status!r} is reported as 'not yet "
        "addressed', which tells a reader nobody has looked at it"
    )


@pytest.mark.parametrize("status", sorted(VALIDATION_STATUSES))
async def test_the_buckets_still_partition_the_baseline(status: str) -> None:
    """Whatever the status, the five buckets must sum to the total.

    This is the property that makes the page checkable, and it is the one a fix
    for the above is most likely to break -- counting `warn` in two buckets would
    satisfy every assertion in this file except this one.
    """
    out = await _one_control_one_status(status)
    buckets = (
        len(out["passing"])
        + len(out["failing"])
        + len(out["documented"])
        + len(out["manual_review"])
        + len(out["unaddressed"])
    )
    assert buckets == out["total"], (
        f"with one {status!r} control the buckets sum to {buckets}, not "
        f"{out['total']}"
    )


# --------------------------------------------------------------------------
# The same guard over the 800-171 view, which has its own bucket enumeration
# --------------------------------------------------------------------------


async def _one_requirement_one_status(status: str) -> dict[str, object]:
    """A 171-denominated system whose single verdict reaches 3.3.1 via AU-11.

    The crosswalk route, because ``aws.securityhub.*`` keys carry no authored
    practice mapping and that is the route an attested verdict actually takes.
    """
    n = next(_SEQ)
    async with session_scope() as session:
        await seed_scoring_controls(session)
        framework = (
            await session.execute(
                select(Framework).where(Framework.code == CROSSWALK_FRAMEWORK)
            )
        ).scalars().first()
        if framework is None:
            framework = Framework(code=CROSSWALK_FRAMEWORK, name="NIST SP 800-171 Rev. 2")
            session.add(framework)
            await session.flush()
        control = (
            await session.execute(select(Control).where(Control.identifier == "AU-11"))
        ).scalars().first()
        if control is None:
            control = Control(identifier="AU-11")
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
                    value="3.3.1 Create and retain system audit logs",
                )
            )
        org = Organization(name=f"Bucket171Org{n}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"Bucket171Sys{n}", baseline=None)
        session.add(sys_)
        await session.flush()
        session.add(
            SystemProfile(
                system_id=sys_.id,
                answers={},
                environment_type="cloud",
                cloud_platform="aws_govcloud",
                frameworks=["NIST_800_171"],
            )
        )
        session.add(
            ControlTest(
                organization_id=org.id,
                system_id=sys_.id,
                control_id="AU-11",
                control_ids=["AU-11"],
                name=f"a check returning {status}",
                method="connector",
                source="generated",
                check_key=f"aws.securityhub.CloudWatch.16::{status}",
                check_source=ATTESTED_SOURCE,
                last_status=status,
            )
        )
        await session.flush()
        return await system_framework_posture(session, org_id=org.id, system_id=sys_.id)


@pytest.mark.parametrize("status", ["warn", "manual_review_required"])
async def test_the_171_view_does_not_report_a_judged_verdict_as_unlooked_at(
    status: str,
) -> None:
    """Found by mutation: the baseline guard above does not reach this path.

    The 800-171 view has its own bucket enumeration over its own denominator, so
    removing `warn` from one and not the other left the 171 page still reporting
    an assessed requirement as "not yet addressed" with every test passing.
    """
    out = await _one_requirement_one_status(status)
    assert "3.3.1" in out["manual_review"], (
        f"a requirement assessed as {status!r} is not in manual_review: "
        f"manual_review={out['manual_review'][:5]} "
        f"unaddressed(first 5)={out['unaddressed'][:5]}"
    )
    assert "3.3.1" not in out["unaddressed"]


@pytest.mark.parametrize("status", ["warn", "pass", "fail", "manual_review_required"])
async def test_the_171_buckets_partition_whatever_the_status(status: str) -> None:
    out = await _one_requirement_one_status(status)
    buckets = (
        len(out["passing"])
        + len(out["failing"])
        + len(out["documented"])
        + len(out["manual_review"])
        + len(out["unaddressed"])
    )
    assert buckets == out["total"], f"{buckets} != {out['total']} with a {status!r}"
