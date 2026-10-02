"""A control AWS vouches for and Concord never checked must say so.

Attested rows reach the posture rollups with no change to them, because
``framework_posture`` reads ``ControlTest`` rows and does not filter on
``check_source``. That is the point of landing them on the same spine -- but it
means a control whose only passing evidence is AWS's own attestation is counted
in ``passing`` beside controls Concord assessed itself, and nothing on the page
distinguishes the two.

That difference matters to the one reader who matters. An attestation is AWS
saying "our control S3.8 passed, and we relate S3.8 to AC-3". It is real
evidence, and it is not Concord having assessed AC-3: Concord chose neither the
evaluator nor the mapping, and the control may have eleven other parts nothing
looked at. ``trust_tier`` already encodes that ranking for a single verdict; this
is the same fact stated over a whole framework, so a reader can see how much of
the green on the page is Concord's own work.

Reported as a *note* beside the five buckets, exactly as ``partially_evidenced``
is, rather than as a sixth bucket. The five still partition the framework and
still sum to the total; a sixth would break the one property that makes the page
addable.
"""

from __future__ import annotations

import itertools
from typing import Any

from sqlalchemy import select

from ccf.analytics.framework_posture import (
    framework_posture,
    system_framework_posture,
)
from ccf.catalog.crosswalk import CROSSWALK_COLUMN, CROSSWALK_FRAMEWORK
from ccf.db import session_scope
from ccf.models import (
    Control,
    Framework,
    FrameworkMapping,
    Organization,
    System,
    SystemProfile,
)
from ccf.models_grc import ControlTest
from ccf.posture.attested import CHECK_SOURCE
from ccf.scoring.seed import seed_scoring_controls

_SEQ = itertools.count()


async def _moderate_system(session: Any, controls: list[str]) -> System:
    """A system on the FIPS-199 Moderate baseline with a known control set.

    Seeded with ``fisma_mod`` rows rather than a framework profile: the baseline
    path is the one the 800-53 numbers come from, and a fixture that declares a
    framework never executes it -- the gap two earlier mutations walked straight
    through.

    ``fisma_high`` is set alongside ``fisma_mod`` because FIPS-199 baselines nest
    (Low ⊂ Moderate ⊂ High). Setting Moderate alone puts a control in Moderate
    and not in High, which breaks that invariant for the whole shared catalog --
    and the break surfaces in
    ``test_framework_posture.py::test_each_baseline_is_a_distinct_and_growing_set``
    rather than here. It is order-dependent: if an earlier test already created
    the identifier with High set, flipping ``fisma_mod`` on the existing row is
    harmless, so the failure comes and goes with collection order. That is the
    shape that makes an unrelated module look broken.
    """
    n = next(_SEQ)
    org = Organization(name=f"AttestedOnlyOrg{n}")
    session.add(org)
    await session.flush()
    sys_ = System(organization_id=org.id, name=f"AttestedOnlySys{n}", baseline="moderate")
    session.add(sys_)
    await session.flush()
    for identifier in controls:
        existing = (
            await session.execute(select(Control).where(Control.identifier == identifier))
        ).scalars().first()
        if existing is None:
            session.add(
                Control(
                    identifier=identifier,
                    sequence_control=identifier,
                    fisma_mod=True,
                    # See the note in `_moderate_system`'s docstring: Moderate
                    # implies High, or the shared catalog stops nesting.
                    fisma_high=True,
                )
            )
        else:
            existing.fisma_mod = True
            existing.fisma_high = True
    await session.flush()
    return sys_


def _test_row(
    sys_: System, *, control_id: str, check_key: str, check_source: str, status: str
) -> ControlTest:
    return ControlTest(
        organization_id=sys_.organization_id,
        system_id=sys_.id,
        control_id=control_id,
        control_ids=[control_id],
        name=check_key,
        method="connector",
        source="generated",
        check_key=check_key,
        check_source=check_source,
        last_status=status,
    )


async def test_a_control_only_aws_vouches_for_is_named() -> None:
    async with session_scope() as session:
        sys_ = await _moderate_system(session, ["AC-03", "AU-11"])
        session.add(
            _test_row(
                sys_,
                control_id="AC-3",
                check_key="aws.s3.public_access_blocked",
                check_source="platform",
                status="pass",
            )
        )
        session.add(
            _test_row(
                sys_,
                control_id="AU-11",
                check_key="aws.securityhub.CloudWatch.16::AU-11",
                check_source=CHECK_SOURCE,
                status="pass",
            )
        )
        await session.flush()
        out = await framework_posture(session, system_id=sys_.id, org_id=None)

    assert "AC-3" in out["passing"]
    assert "AU-11" in out["passing"], "an attestation must still count as evidence"
    assert out["provider_attested_only"] == ["AU-11"], (
        "the control Concord never checked itself is not distinguished from the "
        f"one it did: {out['provider_attested_only']}"
    )


async def test_a_control_concord_also_checks_is_not_listed() -> None:
    """The note is "only AWS", not "AWS at all".

    If an attestation agreeing with Concord's own passing check appeared here,
    the note would grow with coverage and stop meaning anything.
    """
    async with session_scope() as session:
        sys_ = await _moderate_system(session, ["AC-03"])
        session.add(
            _test_row(
                sys_,
                control_id="AC-3",
                check_key="aws.s3.public_access_blocked",
                check_source="platform",
                status="pass",
            )
        )
        session.add(
            _test_row(
                sys_,
                control_id="AC-3",
                check_key="aws.securityhub.S3.8::AC-3",
                check_source=CHECK_SOURCE,
                status="pass",
            )
        )
        await session.flush()
        out = await framework_posture(session, system_id=sys_.id, org_id=None)

    assert "AC-3" in out["passing"]
    assert out["provider_attested_only"] == []


async def test_a_failing_control_is_not_listed_however_it_was_assessed() -> None:
    """The note qualifies ``passing``. A failing control is already actionable
    and does not need its provenance caveated."""
    async with session_scope() as session:
        sys_ = await _moderate_system(session, ["AC-03"])
        session.add(
            _test_row(
                sys_,
                control_id="AC-3",
                check_key="aws.securityhub.S3.8::AC-3",
                check_source=CHECK_SOURCE,
                status="fail",
            )
        )
        await session.flush()
        out = await framework_posture(session, system_id=sys_.id, org_id=None)

    assert "AC-3" in out["failing"]
    assert out["provider_attested_only"] == []


async def test_a_control_that_also_fails_is_not_caveated_as_attested_only() -> None:
    """Found by mutation: the note is restricted to ``passing``.

    AWS attests AC-3 passing; one of Concord's own checks fails it. Failing
    outranks everything, so AC-3 belongs in ``failing`` -- and a note saying "only
    AWS vouches for this" beside a control Concord is actively reporting as broken
    reads as a provenance caveat on a passing control. Dropping the ``& passing``
    restriction passed every other test in this file, because no other test had
    an attested pass and a real failure on the same control.
    """
    async with session_scope() as session:
        sys_ = await _moderate_system(session, ["AC-03"])
        session.add(
            _test_row(
                sys_,
                control_id="AC-3",
                check_key="aws.securityhub.S3.8::AC-3",
                check_source=CHECK_SOURCE,
                status="pass",
            )
        )
        session.add(
            _test_row(
                sys_,
                control_id="AC-3",
                check_key="aws.s3.public_access_blocked",
                check_source="platform",
                status="fail",
            )
        )
        await session.flush()
        out = await framework_posture(session, system_id=sys_.id, org_id=None)

    assert "AC-3" in out["failing"]
    assert "AC-3" not in out["passing"]
    assert out["provider_attested_only"] == []


async def test_the_note_does_not_change_the_buckets_or_the_total() -> None:
    """The five buckets must still partition the framework.

    A note that quietly became a sixth bucket would stop the page adding up,
    which is the property that makes every number on it checkable.
    """
    async with session_scope() as session:
        sys_ = await _moderate_system(session, ["AC-03", "AU-11", "SC-07"])
        session.add(
            _test_row(
                sys_,
                control_id="AU-11",
                check_key="aws.securityhub.CloudWatch.16::AU-11",
                check_source=CHECK_SOURCE,
                status="pass",
            )
        )
        await session.flush()
        out = await framework_posture(session, system_id=sys_.id, org_id=None)

    buckets = (
        len(out["passing"])
        + len(out["failing"])
        + len(out["documented"])
        + len(out["manual_review"])
        + len(out["unaddressed"])
    )
    assert buckets == out["total"], (
        f"the buckets no longer partition the baseline: {buckets} != {out['total']}"
    )
    assert set(out["provider_attested_only"]) <= set(out["passing"])


async def test_an_attested_manual_review_is_not_counted_as_vouched_for() -> None:
    """``NOT_AVAILABLE`` becomes ``manual_review_required``, which is AWS saying
    it could not evaluate the control. That is the opposite of vouching for it."""
    async with session_scope() as session:
        sys_ = await _moderate_system(session, ["AC-03"])
        session.add(
            _test_row(
                sys_,
                control_id="AC-3",
                check_key="aws.securityhub.S3.8::AC-3",
                check_source=CHECK_SOURCE,
                status="manual_review_required",
            )
        )
        await session.flush()
        out = await framework_posture(session, system_id=sys_.id, org_id=None)

    assert "AC-3" in out["manual_review"]
    assert out["provider_attested_only"] == []


async def test_a_system_with_no_tests_reports_an_empty_note() -> None:
    """Present and empty, never absent: a template reading a missing key would
    render nothing and look identical to "nothing is attested-only"."""
    async with session_scope() as session:
        sys_ = await _moderate_system(session, ["AC-03"])
        out = await framework_posture(session, system_id=sys_.id, org_id=None)

    assert out["provider_attested_only"] == []


async def test_the_empty_shape_carries_the_key_too() -> None:
    """A system with no baseline at all takes the ``_empty`` path."""
    async with session_scope() as session:
        n = next(_SEQ)
        org = Organization(name=f"NoBaselineOrg{n}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"NoBaselineSys{n}")
        session.add(sys_)
        await session.flush()
        out = await framework_posture(session, system_id=sys_.id, org_id=None)

    assert out["provider_attested_only"] == []


# --------------------------------------------------------------------------
# The same fact in the 800-171 view, which measures in different units
# --------------------------------------------------------------------------


async def test_the_171_view_names_an_attested_only_requirement() -> None:
    """The two views must agree about provenance, in their own denominators.

    The 800-171 path reaches an attested row through the catalog crosswalk --
    ``aws.securityhub.*`` keys are not in ``CHECK_PRACTICES``, so the crosswalk
    is the only map they have, which is the same route an authored control test
    takes. The provenance has to survive that expansion: the row's
    ``check_source`` is not recoverable after the crosswalk runs, so if it were
    not carried alongside, every attested pass would read as Concord's own.
    """
    async with session_scope() as session:
        await seed_scoring_controls(session)
        framework = (
            await session.execute(
                select(Framework).where(Framework.code == CROSSWALK_FRAMEWORK)
            )
        ).scalars().first()
        if framework is None:
            framework = Framework(
                code=CROSSWALK_FRAMEWORK, name="NIST SP 800-171 Rev. 2"
            )
            session.add(framework)
            await session.flush()
        for identifier, value in (
            ("AU-11", "3.3.1 Create and retain system audit logs"),
        ):
            control = (
                await session.execute(
                    select(Control).where(Control.identifier == identifier)
                )
            ).scalars().first()
            if control is None:
                control = Control(identifier=identifier)
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
                        value=value,
                    )
                )
        n = next(_SEQ)
        org = Organization(name=f"Attested171Org{n}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"Attested171Sys{n}", baseline=None)
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
        # AU-11 credited only by AWS; IA-2 credited by one of Concord's own.
        session.add(
            _test_row(
                sys_,
                control_id="AU-11",
                check_key="aws.securityhub.CloudWatch.16::AU-11",
                check_source=CHECK_SOURCE,
                status="pass",
            )
        )
        session.add(
            _test_row(
                sys_,
                control_id="IA-2",
                check_key="aws.iam.root_mfa_enabled",
                check_source="platform",
                status="pass",
            )
        )
        await session.flush()
        out = await system_framework_posture(session, org_id=org.id, system_id=sys_.id)

    assert out["framework"] == "nist_800_171"
    # Both routes exercised, which is what makes this worth having: the attested
    # row reaches 3.3.1 through the crosswalk (no authored mapping exists for
    # `aws.securityhub.*` keys), while Concord's own root-MFA check reaches 3.5.3
    # through its authored `CHECK_PRACTICES` entry -- not 3.5.1, which is the
    # looser crosswalk answer that mapping exists to avoid.
    assert "3.3.1" in out["passing"]
    assert "3.5.3" in out["passing"]
    assert out["provider_attested_only"] == ["3.3.1"], (
        "provenance was lost crossing the 800-171 crosswalk: "
        f"{out['provider_attested_only']}"
    )


async def test_the_171_buckets_still_partition_the_framework() -> None:
    """The same addability property, in the view with the larger denominator."""
    async with session_scope() as session:
        await seed_scoring_controls(session)
        n = next(_SEQ)
        org = Organization(name=f"Attested171SumOrg{n}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"Attested171SumSys{n}", baseline=None)
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
        await session.flush()
        out = await system_framework_posture(session, org_id=org.id, system_id=sys_.id)

    buckets = (
        len(out["passing"])
        + len(out["failing"])
        + len(out["documented"])
        + len(out["manual_review"])
        + len(out["unaddressed"])
    )
    assert buckets == out["total"], f"{buckets} != {out['total']}"
    assert out["provider_attested_only"] == []


async def test_the_171_note_is_only_about_requirements_concord_did_not_reach() -> None:
    """The 800-171 half of "only AWS", not "AWS at all".

    Found by mutation: dropping ``- passed_by_concord`` from the 171 note passed
    every test, because no 171 test had a requirement credited by both an
    attestation and one of Concord's own checks. 3.3.1 is credited by both here;
    only the requirement Concord never reached may be listed.
    """
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
        for identifier, value in (
            ("AU-11", "3.3.1 Create and retain system audit logs"),
            ("CP-09", "3.8.9 Protect the confidentiality of backups"),
        ):
            control = (
                await session.execute(
                    select(Control).where(Control.identifier == identifier)
                )
            ).scalars().first()
            if control is None:
                control = Control(identifier=identifier)
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
                        value=value,
                    )
                )
        n = next(_SEQ)
        org = Organization(name=f"Attested171BothOrg{n}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"Attested171BothSys{n}", baseline=None)
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
        # 3.3.1: AWS attests it AND a pack check of Concord's reaches it.
        session.add(
            _test_row(
                sys_,
                control_id="AU-11",
                check_key="aws.securityhub.CloudWatch.16::AU-11",
                check_source=CHECK_SOURCE,
                status="pass",
            )
        )
        session.add(
            _test_row(
                sys_,
                control_id="AU-11",
                check_key="org.retention.rule",
                check_source="pack:tenant-pack",
                status="pass",
            )
        )
        # 3.8.9: AWS alone.
        session.add(
            _test_row(
                sys_,
                control_id="CP-9",
                check_key="aws.securityhub.Backup.1::CP-9",
                check_source=CHECK_SOURCE,
                status="pass",
            )
        )
        await session.flush()
        out = await system_framework_posture(session, org_id=org.id, system_id=sys_.id)

    assert "3.3.1" in out["passing"]
    assert "3.8.9" in out["passing"]
    assert out["provider_attested_only"] == ["3.8.9"], (
        "a requirement Concord's own pack check also reached was caveated as "
        f"attested-only: {out['provider_attested_only']}"
    )


async def test_a_blank_control_id_does_not_crash_the_posture_page() -> None:
    """Found by reviewing my own commit, not by a failing test.

    The attested-only note was computed as
    ``pass_attribution(control_id)[0] if control_id else None``. A whitespace-only
    ``control_id`` is **truthy**, so the guard let it through, and
    ``pass_attribution`` strips it to ``""`` and returns ``[]`` -- an ``IndexError``
    that 500s ``/posture`` for the whole system. The code it replaced iterated the
    list and was therefore safe; indexing it was the regression.

    ``ControlTest.control_id`` is NOT NULL but not non-empty, and an authored test
    takes whatever the API is handed, so one such row is enough. Reading the
    credited control off the list the loop already built is both safe and shorter.
    """
    async with session_scope() as session:
        sys_ = await _moderate_system(session, ["AC-03"])
        for control_id, status in (("   ", "pass"), ("", "pass"), ("\t", "pass")):
            session.add(
                ControlTest(
                    organization_id=sys_.organization_id,
                    system_id=sys_.id,
                    control_id=control_id,
                    control_ids=[control_id],
                    name=f"blank-{len(control_id)}",
                    method="manual",
                    source="authored",
                    last_status=status,
                )
            )
        session.add(
            _test_row(
                sys_,
                control_id="AC-3",
                check_key="aws.securityhub.S3.8::AC-3",
                check_source=CHECK_SOURCE,
                status="pass",
            )
        )
        await session.flush()
        out = await framework_posture(session, system_id=sys_.id, org_id=None)

    # The real row is still credited, and the blank ones contribute nothing.
    assert "AC-3" in out["passing"]
    assert out["provider_attested_only"] == ["AC-3"]
