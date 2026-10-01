"""A provider attestation is neither Concord's check nor a tenant's pack rule.

``effective_verdict`` had two trust tiers: ``check_source == "platform"`` and
everything else, which it reported to the reader as "pack-sourced". That split
was correct while there were only two kinds of generated test. Provider-attested
results (:mod:`ccf.posture.attested` -- AWS Security Hub asserting its own
800-53 mapping) are a third kind, and filing them in the second tier breaks two
things at once:

**Provenance.** The reason string would tell an assessor the believed verdict
came from a tenant-installed pack when it came from AWS. A value that validates
and is wrong, in the field a reader uses to decide how much to trust the row.

**Precedence.** Within one tier the rule is "most recent wins". A tenant pack
rule with a weakened parameter would therefore outrank AWS's attestation for the
same control by running after it -- exactly the defect CRITICAL 2 (PR #13
review) closed between platform and pack, reopened one tier down.

So the ordering is **platform > attested > pack**:

* Concord's own check outranks everything, because Concord authored both the
  evaluator and the control attribution and is accountable for both.
* A provider attestation outranks a tenant's pack rule, because AWS evaluating
  its own account is not the tenant self-attesting about itself.
* A pack rule is still believed when it is the only fresh evidence -- the rule
  is "prefer the higher tier when it exists", never "ignore the lower one".
"""

from __future__ import annotations

import itertools
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from ccf.db import session_scope
from ccf.governance.control_tests import record_result
from ccf.models import Organization, System
from ccf.models_grc import ControlTest, ControlTestResult
from ccf.posture.attested import CHECK_SOURCE as ATTESTED_SOURCE
from ccf.posture.checks import platform_check_keys
from ccf.posture.scan import effective_verdict, trust_tier

_SEQ = itertools.count()


async def _system(session: object) -> System:
    n = next(_SEQ)
    org = Organization(name=f"TrustTierOrg{n}")
    session.add(org)  # type: ignore[attr-defined]
    await session.flush()  # type: ignore[attr-defined]
    sys_ = System(organization_id=org.id, name=f"TrustTierSys{n}")
    session.add(sys_)  # type: ignore[attr-defined]
    await session.flush()  # type: ignore[attr-defined]
    return sys_


async def _generated_result(
    session: object,
    *,
    system_id: int,
    organization_id: int,
    check_key: str,
    check_source: str,
    control_id: str,
    status: str,
    run_at: datetime | None = None,
) -> ControlTest:
    """One generated ControlTest carrying one recorded result.

    Written through ``record_result`` -- the only writer of results -- so the
    rows are shaped exactly as a scan would shape them.
    """
    test = ControlTest(
        organization_id=organization_id,
        system_id=system_id,
        control_id=control_id,
        control_ids=[control_id],
        name=check_key,
        method="connector",
        source="generated",
        check_key=check_key,
        check_source=check_source,
        expected="whatever this check expects",
    )
    session.add(test)  # type: ignore[attr-defined]
    await session.flush()  # type: ignore[attr-defined]
    result = await record_result(
        session,  # type: ignore[arg-type]
        test,
        status=status,
        detail=f"{check_source} says {status}",
        actor="test",
    )
    if run_at is not None:
        result.run_at = run_at
        await session.flush()  # type: ignore[attr-defined]
    return test


# --------------------------------------------------------------------------
# trust_tier: the ordering, stated directly
# --------------------------------------------------------------------------


def _test_row(check_source: str | None, *, check_key: str = "x", source: str = "generated"):
    return ControlTest(
        control_id="AC-3",
        name="n",
        check_key=check_key,
        check_source=check_source,
        source=source,
    )


def test_the_three_tiers_are_strictly_ordered() -> None:
    platform = trust_tier(_test_row("platform"))
    attested = trust_tier(_test_row(ATTESTED_SOURCE))
    pack = trust_tier(_test_row("pack:some-pack"))
    assert platform < attested < pack, (
        f"platform={platform} attested={attested} pack={pack}; the ordering is "
        "platform > attested > pack and it is what keeps a tenant pack from "
        "outranking a provider attestation on recency alone"
    )


def test_an_unrecognised_check_source_is_least_trusted() -> None:
    """A tier assigned by a default must be the cautious one.

    A future ``check_source`` nobody taught this function about must not land
    above a provider attestation by accident. It lands at the bottom, where the
    worst case is that it is believed only when nothing else is fresh.
    """
    assert trust_tier(_test_row("something-nobody-added-here")) == trust_tier(
        _test_row("pack:some-pack")
    )


def test_a_null_check_source_still_self_heals_to_platform() -> None:
    """Migration 0070 added ``check_source`` with no backfill.

    A pre-0070 generated row whose key is still a registered platform check is
    platform-tier, by live-data inference rather than a migration-time guess --
    the behaviour ``_is_platform_sourced`` documented and this must not lose.
    """
    known = next(iter(platform_check_keys()))
    assert trust_tier(_test_row(None, check_key=known)) == trust_tier(
        _test_row("platform")
    )


def test_a_null_check_source_on_an_unknown_key_is_not_promoted() -> None:
    assert trust_tier(_test_row(None, check_key="org.nothing.registered")) == trust_tier(
        _test_row("pack:p")
    )


# --------------------------------------------------------------------------
# effective_verdict: the precedence that ordering buys
# --------------------------------------------------------------------------


async def test_an_attestation_outranks_a_more_recent_pack_result() -> None:
    """The CRITICAL 2 defect, one tier down.

    AWS attests AC-3 failing. A tenant pack rule for the same control passes,
    and runs afterwards, so "most recent wins" would surface the pass. It must
    not: a tenant's own rule about its own account does not overturn the
    provider's evaluation of that account.
    """
    async with session_scope() as session:
        sys_ = await _system(session)
        now = datetime.now(UTC)
        await _generated_result(
            session,
            system_id=sys_.id,
            organization_id=sys_.organization_id,
            check_key="aws.securityhub.S3.8::AC-3",
            check_source=ATTESTED_SOURCE,
            control_id="AC-3",
            status="fail",
            run_at=now - timedelta(hours=2),
        )
        await _generated_result(
            session,
            system_id=sys_.id,
            organization_id=sys_.organization_id,
            check_key="org.buckets.lenient",
            check_source="pack:lenient-pack",
            control_id="AC-3",
            status="pass",
            run_at=now,
        )
        out = await effective_verdict(session, system_id=sys_.id, control_id="AC-3")

    assert out["verdict"] == "fail", "a tenant pack overturned a provider attestation"
    assert out["check_source"] == ATTESTED_SOURCE


async def test_concord_s_own_check_still_outranks_an_attestation() -> None:
    """The top of the order is unchanged.

    Concord authored both the evaluator and the control attribution for its own
    checks and is accountable for them; an attestation extends coverage into
    controls Concord has no check for, and never overrides one it does.
    """
    async with session_scope() as session:
        sys_ = await _system(session)
        now = datetime.now(UTC)
        await _generated_result(
            session,
            system_id=sys_.id,
            organization_id=sys_.organization_id,
            check_key="aws.s3.public_access_blocked",
            check_source="platform",
            control_id="AC-3",
            status="fail",
            run_at=now - timedelta(hours=2),
        )
        await _generated_result(
            session,
            system_id=sys_.id,
            organization_id=sys_.organization_id,
            check_key="aws.securityhub.S3.8::AC-3",
            check_source=ATTESTED_SOURCE,
            control_id="AC-3",
            status="pass",
            run_at=now,
        )
        out = await effective_verdict(session, system_id=sys_.id, control_id="AC-3")

    assert out["verdict"] == "fail"
    assert out["check_source"] == "platform"


async def test_an_attestation_is_believed_when_it_is_the_only_evidence() -> None:
    """The whole point: reaching controls Concord has no check for.

    If an attested result were merely ranked and never surfaced, the ingest
    would add rows and change nothing a reader sees.
    """
    async with session_scope() as session:
        sys_ = await _system(session)
        await _generated_result(
            session,
            system_id=sys_.id,
            organization_id=sys_.organization_id,
            check_key="aws.securityhub.CloudWatch.16::AU-11",
            check_source=ATTESTED_SOURCE,
            control_id="AU-11",
            status="pass",
            run_at=datetime.now(UTC),
        )
        out = await effective_verdict(session, system_id=sys_.id, control_id="AU-11")

    assert out["verdict"] == "pass"
    assert out["check_source"] == ATTESTED_SOURCE


async def test_the_reason_names_the_tier_that_was_actually_believed() -> None:
    """The provenance half of the defect.

    Before the third tier existed, this sentence read "most recent pack-sourced
    result used" over a verdict AWS supplied. An assessor reading that was told
    the evidence came from the tenant.
    """
    async with session_scope() as session:
        sys_ = await _system(session)
        await _generated_result(
            session,
            system_id=sys_.id,
            organization_id=sys_.organization_id,
            check_key="aws.securityhub.S3.8::AC-3",
            check_source=ATTESTED_SOURCE,
            control_id="AC-3",
            status="fail",
            run_at=datetime.now(UTC),
        )
        attested = await effective_verdict(session, system_id=sys_.id, control_id="AC-3")

    assert "pack" not in attested["reason"], (
        f"a provider attestation was described as pack-sourced: {attested['reason']!r}"
    )
    assert "attested" in attested["reason"] or "provider" in attested["reason"], (
        f"the reason does not say where the verdict came from: {attested['reason']!r}"
    )


async def test_a_pack_result_is_still_described_as_a_pack_result() -> None:
    """The other direction, so the fix did not just relabel every tier."""
    async with session_scope() as session:
        sys_ = await _system(session)
        await _generated_result(
            session,
            system_id=sys_.id,
            organization_id=sys_.organization_id,
            check_key="org.only.rule",
            check_source="pack:only-pack",
            control_id="AC-3",
            status="warn",
            run_at=datetime.now(UTC),
        )
        out = await effective_verdict(session, system_id=sys_.id, control_id="AC-3")

    assert out["check_source"] == "pack:only-pack"
    assert "pack" in out["reason"]


async def test_most_recent_still_wins_inside_one_tier() -> None:
    """Precedence is across tiers only. Two attestations for one control --
    which happens whenever two Security Hub controls relate to the same
    requirement -- still resolve by recency, as two platform results do."""
    async with session_scope() as session:
        sys_ = await _system(session)
        now = datetime.now(UTC)
        await _generated_result(
            session,
            system_id=sys_.id,
            organization_id=sys_.organization_id,
            check_key="aws.securityhub.S3.8::AC-3",
            check_source=ATTESTED_SOURCE,
            control_id="AC-3",
            status="pass",
            run_at=now - timedelta(hours=3),
        )
        await _generated_result(
            session,
            system_id=sys_.id,
            organization_id=sys_.organization_id,
            check_key="aws.securityhub.S3.2::AC-3",
            check_source=ATTESTED_SOURCE,
            control_id="AC-3",
            status="fail",
            run_at=now,
        )
        out = await effective_verdict(session, system_id=sys_.id, control_id="AC-3")

    assert out["verdict"] == "fail"
    assert out["check_source"] == ATTESTED_SOURCE


async def test_a_stale_attestation_is_absent_like_any_other_stale_result() -> None:
    """``STALE_AFTER_DAYS`` is not tier-dependent. A provider attestation from
    four months ago is not current evidence, and must not displace a fresh pack
    result just because its tier is higher."""
    async with session_scope() as session:
        sys_ = await _system(session)
        now = datetime.now(UTC)
        await _generated_result(
            session,
            system_id=sys_.id,
            organization_id=sys_.organization_id,
            check_key="aws.securityhub.S3.8::AC-3",
            check_source=ATTESTED_SOURCE,
            control_id="AC-3",
            status="fail",
            run_at=now - timedelta(days=120),
        )
        await _generated_result(
            session,
            system_id=sys_.id,
            organization_id=sys_.organization_id,
            check_key="org.only.rule",
            check_source="pack:only-pack",
            control_id="AC-3",
            status="pass",
            run_at=now,
        )
        out = await effective_verdict(session, system_id=sys_.id, control_id="AC-3")

    assert out["verdict"] == "pass"
    assert out["check_source"] == "pack:only-pack"


async def test_an_authored_test_is_still_excluded_whatever_its_tier() -> None:
    """A human-run manual test is not a check that read the environment.

    ``source == "generated"`` is the filter, and it sits outside the tiering --
    a tier is how much to trust a scan, not permission to count a hand-typed
    verdict as one.
    """
    async with session_scope() as session:
        sys_ = await _system(session)
        test = ControlTest(
            organization_id=sys_.organization_id,
            system_id=sys_.id,
            control_id="AC-3",
            name="hand-written",
            method="manual",
            source="authored",
            check_source=ATTESTED_SOURCE,
        )
        session.add(test)
        await session.flush()
        await record_result(session, test, status="pass", actor="human")
        out = await effective_verdict(session, system_id=sys_.id, control_id="AC-3")

    assert out["source"] is None
    assert out["verdict"] is None


async def test_the_tier_is_derived_from_the_stored_row_not_the_key_shape() -> None:
    """A row's trust must not be inferable from its key spelling.

    If tiering keyed on ``check_key.startswith("aws.securityhub.")``, a tenant
    pack could claim provider trust by naming its rule that way. Packs cannot
    collide on a *platform* key (``packs.catalog`` refuses that), but these keys
    are not in the registry, so nothing else would stop it.
    """
    async with session_scope() as session:
        sys_ = await _system(session)
        now = datetime.now(UTC)
        await _generated_result(
            session,
            system_id=sys_.id,
            organization_id=sys_.organization_id,
            check_key="aws.securityhub.S3.8::AC-3",
            check_source="pack:impersonator",
            control_id="AC-3",
            status="pass",
            run_at=now,
        )
        await _generated_result(
            session,
            system_id=sys_.id,
            organization_id=sys_.organization_id,
            check_key="org.real.attestation",
            check_source=ATTESTED_SOURCE,
            control_id="AC-3",
            status="fail",
            run_at=now - timedelta(hours=2),
        )
        out = await effective_verdict(session, system_id=sys_.id, control_id="AC-3")

    assert out["verdict"] == "fail", "a pack borrowed provider trust from its key name"
    assert out["check_source"] == ATTESTED_SOURCE


async def test_every_recorded_result_is_still_reachable_for_a_reader() -> None:
    """Precedence picks what is *believed*; it must not delete the rest.

    The drilldown shows every control test for a control. If the tiering had
    been implemented by refusing to write lower-tier rows, this would be empty.
    """
    async with session_scope() as session:
        sys_ = await _system(session)
        now = datetime.now(UTC)
        for key, src, status in (
            ("aws.securityhub.S3.8::AC-3", ATTESTED_SOURCE, "fail"),
            ("org.only.rule", "pack:only-pack", "pass"),
        ):
            await _generated_result(
                session,
                system_id=sys_.id,
                organization_id=sys_.organization_id,
                check_key=key,
                check_source=src,
                control_id="AC-3",
                status=status,
                run_at=now,
            )
        rows = (
            await session.execute(
                select(ControlTest.check_source)
                .join(ControlTestResult, ControlTestResult.control_test_id == ControlTest.id)
                .where(ControlTest.system_id == sys_.id)
            )
        ).scalars().all()

    assert set(rows) == {ATTESTED_SOURCE, "pack:only-pack"}
