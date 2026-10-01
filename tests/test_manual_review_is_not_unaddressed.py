""""Could not assess this" is not "nobody has looked at this".

Found by reading the compliance-posture page. For a live system it said:

    3 satisfied · 9 failing · 0 documented only · 276 not yet addressed

The platform had in fact recorded a verdict for far more than twelve of those
288 controls. Eighteen carried an explicit ``manual_review_required`` -- Concord
looked, could not judge, and said so -- and they were being displayed inside
"not yet addressed", which means nobody has looked.

That is the wrong way round in the way that matters. ``manual_review_required``
is the **actionable** bucket: it names the controls needing human evidence, which
is work somebody has to schedule. Burying them among the hundreds nobody has
touched guarantees they are never scheduled, and it understates how much of the
baseline the platform has actually reached.

Both framework paths had it: the FIPS-199 baseline view and the 800-171
requirement view compute `failing`, `passing`, `documented` and then sweep
everything else into `unaddressed`, so a verdict that is neither pass nor fail
disappears into the remainder.

The buckets still sum to the total. That is asserted here, because a fifth
bucket carved out of a remainder is exactly where a denominator silently stops
closing.
"""

from __future__ import annotations

import itertools
from datetime import UTC, datetime

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select

from ccf.analytics.framework_posture import system_framework_posture
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Control, Organization, System, SystemProfile
from ccf.models_grc import ControlTest
from ccf.scoring.seed import seed_scoring_controls

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _system_with(verdicts: list[tuple[str, str, str]]) -> tuple[int, int]:
    """verdicts: (check_key, primary control id, status). Returns (org, system)."""
    tag = next(_SEQ)
    async with session_scope() as session:
        await seed_scoring_controls(session)
    async with session_scope() as session:
        org = Organization(name=f"ManualReview Org {tag}")
        session.add(org)
        await session.flush()
        system = System(organization_id=org.id, name=f"mr-{tag}")
        session.add(system)
        await session.flush()
        session.add(
            SystemProfile(
                system_id=system.id,
                answers={},
                environment_type="cloud",
                cloud_platform="m365_gcc_high",
                frameworks=["NIST_800_171"],
                derivation={},
            )
        )
        for check_key, control_id, status in verdicts:
            session.add(
                ControlTest(
                    organization_id=org.id,
                    system_id=system.id,
                    name=check_key,
                    check_key=check_key,
                    source="generated",
                    control_id=control_id,
                    control_ids=[control_id],
                    last_status=status,
                    last_tested_at=datetime.now(UTC),
                    method="api",
                )
            )
        return int(org.id), int(system.id)


@pytest.mark.asyncio
async def test_a_manual_review_verdict_is_its_own_bucket() -> None:
    """The reported defect, on the 800-171 view."""
    org_id, system_id = await _system_with(
        [("m365.identity.stale_accounts", "AC-2", "manual_review_required")]
    )
    async with session_scope() as session:
        out = await system_framework_posture(session, org_id=org_id, system_id=system_id)

    # stale_accounts maps to IA.L2-3.5.6 -> requirement 3.5.6.
    assert "3.5.6" in out["manual_review"], (
        "a recorded manual_review_required verdict must be reported as such"
    )
    assert "3.5.6" not in out["unaddressed"], (
        "'not yet addressed' means nobody looked; this was looked at and could "
        "not be judged"
    )
    assert "3.5.6" not in out["passing"]
    assert "3.5.6" not in out["failing"]


@pytest.mark.asyncio
async def test_the_buckets_still_sum_to_the_total() -> None:
    """A fifth bucket carved out of a remainder is where a denominator stops closing."""
    org_id, system_id = await _system_with(
        [
            ("m365.identity.stale_accounts", "AC-2", "manual_review_required"),
            ("m365.identity.mfa_registered", "IA-2", "fail"),
            ("m365.audit.signin_records_current", "AU-2", "pass"),
        ]
    )
    async with session_scope() as session:
        out = await system_framework_posture(session, org_id=org_id, system_id=system_id)

    buckets = ("passing", "failing", "documented", "manual_review", "unaddressed")
    counted = sum(len(out[b]) for b in buckets)
    assert counted == out["total"], (
        f"{counted} across {buckets} but total is {out['total']} -- the buckets "
        "no longer partition the framework"
    )
    # And they are genuinely disjoint, not merely the right size.
    seen: set[str] = set()
    for bucket in buckets:
        overlap = seen & set(out[bucket])
        assert overlap == set(), f"{bucket} overlaps an earlier bucket: {sorted(overlap)}"
        seen |= set(out[bucket])


@pytest.mark.asyncio
async def test_a_failing_verdict_still_outranks_manual_review() -> None:
    """Two checks on one requirement, one failing: the requirement is failing.

    Manual review must not dilute a finding. The precedence is the same one the
    module already applies to a documented claim -- the customer is being told
    what to fix.
    """
    org_id, system_id = await _system_with(
        [
            ("m365.identity.mfa_registered", "IA-2", "fail"),
            ("m365.policy.legacy_auth_blocked", "IA-2", "manual_review_required"),
        ]
    )
    async with session_scope() as session:
        out = await system_framework_posture(session, org_id=org_id, system_id=system_id)

    # Both map to IA.L2-3.5.3 -> 3.5.3.
    assert "3.5.3" in out["failing"]
    assert "3.5.3" not in out["manual_review"]


@pytest.mark.asyncio
async def test_a_pass_outranks_manual_review_from_another_check() -> None:
    """A requirement with a pass and a manual review is not 'unassessable'.

    Previously `passing` required `statuses == {"pass"}` exactly, so any other
    verdict on the same requirement knocked it out of both buckets and into the
    remainder -- satisfied by one check and reported as untouched.
    """
    org_id, system_id = await _system_with(
        [
            ("m365.audit.signin_records_current", "AU-2", "pass"),
            ("m365.audit.directory_changes_recorded", "AU-2", "manual_review_required"),
        ]
    )
    async with session_scope() as session:
        out = await system_framework_posture(session, org_id=org_id, system_id=system_id)

    # Both map primarily to AU.L2-3.3.1 -> 3.3.1.
    assert "3.3.1" in out["passing"], (
        "a requirement a check passed is not untouched because another check "
        "could not be judged"
    )
    assert "3.3.1" not in out["unaddressed"]


@pytest.mark.asyncio
async def test_a_requirement_nothing_touched_is_still_unaddressed() -> None:
    """The bucket must not become empty; it is the one a customer most needs."""
    org_id, system_id = await _system_with(
        [("m365.identity.stale_accounts", "AC-2", "manual_review_required")]
    )
    async with session_scope() as session:
        out = await system_framework_posture(session, org_id=org_id, system_id=system_id)

    assert out["unaddressed"], "most of the 110 requirements are genuinely untouched"
    assert "3.1.1" in out["unaddressed"], "nothing in this fixture reaches 3.1.1"


@pytest.mark.asyncio
async def test_the_baseline_path_has_the_bucket_too() -> None:
    """The FIPS-199 view, which the cases above do not reach.

    Every fixture so far declares a framework in its intake profile and carries
    no baseline, so `resolve_applied_framework` routes it to the 800-171 path --
    and emptying the *baseline* path's manual-review bucket passed all of them.
    A mutation surviving is the only reason this test exists.

    The baseline needs catalog rows carrying FIPS-199 membership, which the test
    database does not load, so two are seeded here. That is also why this path
    had no coverage: it is the one that needs a catalog.
    """
    tag = next(_SEQ)
    async with session_scope() as session:
        for identifier in ("AC-02", "IA-02"):
            existing = (
                await session.execute(select(Control).where(Control.identifier == identifier))
            ).scalar_one_or_none()
            if existing is None:
                session.add(
                    Control(identifier=identifier, sequence_control=identifier, fisma_mod=True)
                )
            else:
                existing.fisma_mod = True
        await session.flush()

    async with session_scope() as session:
        org = Organization(name=f"Baseline Org {tag}")
        session.add(org)
        await session.flush()
        system = System(organization_id=org.id, name=f"base-{tag}", baseline="moderate")
        session.add(system)
        await session.flush()
        session.add(
            ControlTest(
                organization_id=org.id,
                system_id=system.id,
                name="m365.identity.stale_accounts",
                check_key="m365.identity.stale_accounts",
                source="generated",
                control_id="AC-2",
                control_ids=["AC-2"],
                last_status="manual_review_required",
                last_tested_at=datetime.now(UTC),
                method="api",
            )
        )
        await session.flush()
        out = await system_framework_posture(session, org_id=org.id, system_id=system.id)

    assert out["denominator"] == "fips199_baseline", (
        f"this test must exercise the baseline path, got {out['denominator']!r}"
    )
    assert out["total"], "the seeded baseline must resolve to controls"
    assert "AC-2" in out["manual_review"], (
        "the baseline path reported a manual-review verdict as something else"
    )
    assert "AC-2" not in out["unaddressed"]

    buckets = ("passing", "failing", "documented", "manual_review", "unaddressed")
    assert sum(len(out[b]) for b in buckets) == out["total"]


@pytest.mark.asyncio
async def test_a_control_a_passing_check_declares_is_named_not_merely_untouched() -> None:
    """The other half of "not yet addressed" that was not true.

    A passing check credits only its **primary** control -- deliberately, so one
    narrow check cannot mark several controls satisfied. `ccf.posture.evidence`
    owns that asymmetry and it is not changed here.

    But the controls it also declares then appeared nowhere at all, and the page
    called them "not yet addressed" alongside the hundreds nothing had touched.
    On the live system that was eight controls with passing machine evidence
    against them.

    So they are named, as a note *inside* `unaddressed` rather than as a sixth
    bucket: the five still partition the framework, and this says which part of
    the remainder has evidence that does not amount to credit. An SSP author
    writing AC-17 is better off knowing a passing check touches it.
    """
    org_id, system_id = await _system_with(
        # phishing_resistant_mfa declares IA.L2-3.5.4 then IA.L2-3.5.3; a pass
        # credits 3.5.4 only.
        [("m365.identity.phishing_resistant_mfa", "IA-2(11)", "pass")]
    )
    async with session_scope() as session:
        out = await system_framework_posture(session, org_id=org_id, system_id=system_id)

    assert "3.5.4" in out["passing"], "the primary practice is credited"
    assert "3.5.3" in out["partially_evidenced"], (
        "a practice a passing check declares must be named rather than left "
        "indistinguishable from one nothing has touched"
    )
    assert "3.5.3" in out["unaddressed"], (
        "it is still not credited -- this is a note on the remainder, not a "
        "sixth bucket, or the buckets would stop partitioning"
    )
    # Nothing touches 3.1.1 at all, so it must not appear.
    assert "3.1.1" not in out["partially_evidenced"]
    assert "3.1.1" in out["unaddressed"]


@pytest.mark.asyncio
async def test_a_credited_or_failing_control_is_not_also_partially_evidenced() -> None:
    """The note describes the remainder, so it may not name anything accounted for."""
    org_id, system_id = await _system_with(
        [
            ("m365.identity.phishing_resistant_mfa", "IA-2(11)", "pass"),
            ("m365.identity.mfa_registered", "IA-2", "fail"),
        ]
    )
    async with session_scope() as session:
        out = await system_framework_posture(session, org_id=org_id, system_id=system_id)

    assert "3.5.3" in out["failing"], "the failing check reaches it"
    assert "3.5.3" not in out["partially_evidenced"], (
        "a control already reported as failing must not also be noted as "
        "merely partially evidenced"
    )
    for bucket in ("passing", "failing", "documented", "manual_review"):
        overlap = set(out["partially_evidenced"]) & set(out[bucket])
        assert overlap == set(), f"partially_evidenced overlaps {bucket}: {sorted(overlap)}"


@pytest.mark.asyncio
async def test_the_baseline_path_note_excludes_credited_controls_too() -> None:
    """Second mutation to walk through the 800-171-only fixtures.

    The overlap assertion above runs on the requirement path, so mutating the
    *baseline* path's note to stop excluding credited controls passed every
    case. Both paths compute this, so both need the assertion.
    """
    tag = next(_SEQ)
    async with session_scope() as session:
        for identifier in ("AC-02", "IA-02"):
            existing = (
                await session.execute(select(Control).where(Control.identifier == identifier))
            ).scalar_one_or_none()
            if existing is None:
                session.add(
                    Control(identifier=identifier, sequence_control=identifier, fisma_mod=True)
                )
            else:
                existing.fisma_mod = True
        await session.flush()

    async with session_scope() as session:
        org = Organization(name=f"Baseline Note Org {tag}")
        session.add(org)
        await session.flush()
        system = System(organization_id=org.id, name=f"basenote-{tag}", baseline="moderate")
        session.add(system)
        await session.flush()
        # Primary IA-2 is credited; AC-2 is declared but not credited.
        session.add(
            ControlTest(
                organization_id=org.id,
                system_id=system.id,
                name="m365.identity.mfa_registered",
                check_key="m365.identity.mfa_registered",
                source="generated",
                control_id="IA-2",
                control_ids=["IA-2", "AC-2"],
                last_status="pass",
                last_tested_at=datetime.now(UTC),
                method="api",
            )
        )
        await session.flush()
        out = await system_framework_posture(session, org_id=org.id, system_id=system.id)

    assert out["denominator"] == "fips199_baseline"
    assert "IA-2" in out["passing"], "the primary control is credited"
    assert "AC-2" in out["partially_evidenced"], "the declared one is named"
    assert "IA-2" not in out["partially_evidenced"], (
        "a credited control must not also be noted as merely partially evidenced"
    )
    for bucket in ("passing", "failing", "documented", "manual_review"):
        overlap = set(out["partially_evidenced"]) & set(out[bucket])
        assert overlap == set(), f"partially_evidenced overlaps {bucket}: {sorted(overlap)}"
