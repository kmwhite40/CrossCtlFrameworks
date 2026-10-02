"""An M365 environment must not be assessed against AWS checks.

``scan_all_providers`` iterated **every** registered provider and, for each one
that was not ready, recorded a ``manual_review_required`` result for every one of
its checks. Measured on a live Microsoft-only organization whose single
configured connector is ``msgraph``:

| connector | rows | status |
|---|---|---|
| ``aws_govcloud`` | 13 | manual_review_required |
| ``azure_arm`` | 5 | manual_review_required |
| ``gcp`` | 3 | manual_review_required |
| ``puppetdb`` | 2 | manual_review_required |
| ``msgraph`` | 19 | 14 pass, 5 fail |

So 23 of 42 control tests were for clouds the organization does not have, every
one of them sitting in the "Need a human" bucket — which must only hold
schedulable work. There is no human action for "enable Amazon Inspector" on a
tenant with no AWS, and those rows were most of the ``manual_review`` count on
``/posture``.

The original intent was sound: a check that did not run must not vanish silently.
What it conflated is two different facts —

* **in scope, no usable credential** → real work ("bind a credential"), so
  ``manual_review_required`` is right;
* **not in scope at all** → nothing anyone can do, and a row asserts that Concord
  looked at an AWS control on a system that has no AWS.

Scope is resolved per environment from two maps that already exist, composed
rather than replaced: ``readiness._CONNECTOR_PLATFORM`` (connector → platform)
and ``automation.PLATFORM_TO_SSP`` (the intake's ``cloud_platform`` answer →
platform). A connector is in scope when the organization has a ``ConnectorConfig``
row for it — configured *or* half-configured, because finishing it is real work —
or when the system's declared platform maps to it.
"""

from __future__ import annotations

import itertools

import pytest
from sqlalchemy import func, select

from ccf.db import session_scope
from ccf.governance.control_tests import record_result
from ccf.models import Organization, System, SystemProfile
from ccf.models_grc import ConnectorConfig, ControlTest
from ccf.posture.checks import known_providers
from ccf.posture.scan_all import scan_all_providers
from ccf.posture.scope import provider_scope

_SEQ = itertools.count()


async def _system(
    *, cloud_platform: str | None, configured: tuple[str, ...] = ()
) -> tuple[int, int]:
    n = next(_SEQ)
    async with session_scope() as session:
        org = Organization(name=f"ScopeOrg{n}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"ScopeSys{n}", baseline="moderate")
        session.add(sys_)
        await session.flush()
        if cloud_platform is not None:
            session.add(
                SystemProfile(
                    system_id=sys_.id,
                    answers={},
                    environment_type="cloud",
                    cloud_platform=cloud_platform,
                )
            )
        for connector_type in configured:
            session.add(
                ConnectorConfig(
                    organization_id=org.id,
                    name=f"{connector_type} for ScopeOrg{n}",
                    connector_type=connector_type,
                )
            )
        await session.flush()
        return org.id, sys_.id


async def _scope(**kw) -> dict[str, bool]:
    _org_id, system_id = await _system(**kw)
    async with session_scope() as session:
        system = await session.get(System, system_id)
        out = await provider_scope(session, system=system)
    return {k: v.in_scope for k, v in out.items()}


# --------------------------------------------------------------------------
# The environments the product actually sees
# --------------------------------------------------------------------------


async def test_a_microsoft_environment_is_not_in_aws_scope() -> None:
    """The reported defect, stated directly."""
    scope = await _scope(cloud_platform="m365_gcc_high", configured=("msgraph",))
    assert scope["msgraph"] is True
    assert scope["aws_govcloud"] is False
    assert scope["gcp"] is False
    assert scope["puppetdb"] is False


async def test_an_aws_environment_is_not_in_microsoft_scope() -> None:
    """The mirror, so the rule is a distinction rather than a Microsoft default."""
    scope = await _scope(cloud_platform="aws_govcloud", configured=("aws_govcloud",))
    assert scope["aws_govcloud"] is True
    assert scope["msgraph"] is False
    assert scope["gcp"] is False


async def test_an_azure_environment_reaches_the_arm_connector() -> None:
    """``azure_gov`` is the intake's answer and ``azure`` is the platform behind
    ``azure_arm`` -- the two maps have to compose, not match by string."""
    scope = await _scope(cloud_platform="azure_gov")
    assert scope["azure_arm"] is True
    assert scope["aws_govcloud"] is False
    assert scope["msgraph"] is False


async def test_a_gcp_environment_reaches_the_gcp_connector() -> None:
    scope = await _scope(cloud_platform="gcp")
    assert scope["gcp"] is True
    assert scope["msgraph"] is False


# --------------------------------------------------------------------------
# A configured connector is in scope whatever the platform says
# --------------------------------------------------------------------------


async def test_the_declared_environment_wins_over_an_off_platform_connector() -> None:
    """The defect the user reported: an M365 environment assessed against AWS.

    The organization has an AWS connector bound -- for its *other* system. This
    system says it is M365, so it is measured against M365 and nothing else.
    Letting an org-wide setting widen it is exactly how a Microsoft tenant came to
    hold thirteen AWS verdicts.
    """
    scope = await _scope(
        cloud_platform="m365_gcc_high", configured=("msgraph", "aws_govcloud")
    )
    assert scope["msgraph"] is True
    assert scope["aws_govcloud"] is False
    assert scope["gcp"] is False
    assert scope["azure_arm"] is False


@pytest.mark.parametrize(
    ("declared", "connector"),
    [
        ("m365_gcc_high", "msgraph"),
        ("azure_gov", "azure_arm"),
        ("aws_govcloud", "aws_govcloud"),
        ("gcp", "gcp"),
    ],
)
async def test_each_environment_measures_exactly_its_own_connector(
    declared: str, connector: str
) -> None:
    """The four choices, each with every other cloud connector configured.

    Every off-platform connector is bound, so a scope that consulted the
    organization's configuration at all would widen here.
    """
    cloud = ("msgraph", "azure_arm", "aws_govcloud", "gcp")
    scope = await _scope(cloud_platform=declared, configured=cloud)
    in_scope = sorted(k for k in cloud if scope[k])
    assert in_scope == [connector], (declared, in_scope)


async def test_a_configured_connector_is_the_fallback_when_nothing_is_declared() -> None:
    """No environment chosen: the operator's configuration is the only signal left.

    A ``ConnectorConfig`` row with no credential still counts -- somebody started
    binding it, and ``manual_review_required`` exists to keep saying so. Scope
    keys on the row existing, not on the credential being usable.
    """
    scope = await _scope(cloud_platform=None, configured=("aws_govcloud",))
    assert scope["aws_govcloud"] is True
    assert scope["msgraph"] is False


async def test_puppetdb_is_only_ever_in_scope_when_configured() -> None:
    """It maps to no cloud platform, so a questionnaire answer can never imply it."""
    assert (await _scope(cloud_platform="aws_govcloud"))["puppetdb"] is False
    assert (await _scope(cloud_platform=None, configured=("puppetdb",)))["puppetdb"] is True


# --------------------------------------------------------------------------
# The answers that are not a platform
# --------------------------------------------------------------------------


async def test_a_system_that_declares_no_cloud_has_no_cloud_provider_in_scope() -> None:
    """``none`` is a deliberate answer, not a missing one.

    ``onboarding.NO_CLOUD`` exists because a customer who said they run no cloud
    once received a Microsoft 365 SSP. The same answer must not pull in a
    connector here.
    """
    scope = await _scope(cloud_platform="none")
    assert not any(scope.values()), scope


async def test_an_undeclared_platform_puts_nothing_in_scope_by_guesswork() -> None:
    """No profile at all -- the state the live system 33 is in.

    Nothing is assumed: an undeclared platform with no configured connector means
    Concord cannot say which clouds this system has, and inventing one is how an
    M365 tenant came to hold thirteen AWS verdicts. The reason says what to do.
    """
    _org_id, system_id = await _system(cloud_platform=None)
    async with session_scope() as session:
        system = await session.get(System, system_id)
        out = await provider_scope(session, system=system)

    assert not any(s.in_scope for s in out.values())
    reason = out["aws_govcloud"].reason
    assert "declare" in reason.lower() or "configure" in reason.lower(), reason


async def test_an_unrecognised_platform_code_is_not_silently_a_platform() -> None:
    """A typo must not resolve to a provider. The same refusal
    ``microsoft_endpoints`` makes for an unrecognised cloud."""
    scope = await _scope(cloud_platform="azure_govcloud_typo")
    assert not any(scope.values()), scope


@pytest.mark.parametrize("wrong_vocabulary", ["m365", "azure"])
async def test_a_platform_code_in_the_intake_field_does_not_resolve(
    wrong_vocabulary: str,
) -> None:
    """The two vocabularies must compose, not coincide.

    ``cloud_platform`` holds the *intake questionnaire* answer
    (``m365_gcc_high``, ``azure_gov``); ``m365`` and ``azure`` are the *platform*
    codes on the other side of ``PLATFORM_TO_SSP``. Found by mutation: returning
    the raw string for an unrecognised code passed every other test here, because
    a typo matches no connector either way -- but a platform code written into
    the intake field would match one directly, putting a connector in scope
    through string coincidence rather than through the map.

    ``aws_govcloud`` and ``gcp`` are deliberately not parametrized: they are the
    same token in both vocabularies, so they cannot distinguish the two paths.
    """
    scope = await _scope(cloud_platform=wrong_vocabulary)
    assert not any(scope.values()), (
        f"{wrong_vocabulary!r} is a platform code, not an intake answer, and must "
        f"not resolve by coincidence: {scope}"
    )


# --------------------------------------------------------------------------
# What the caller is told
# --------------------------------------------------------------------------


async def test_every_registered_provider_gets_an_answer() -> None:
    """The map is exhaustive, so a caller never has to decide what a missing key
    means -- the question that produced this defect in the first place."""
    _org_id, system_id = await _system(cloud_platform="m365_gcc_high")
    async with session_scope() as session:
        system = await session.get(System, system_id)
        out = await provider_scope(session, system=system)

    assert set(out) == set(known_providers()), (
        f"missing {sorted(set(known_providers()) - set(out))}"
    )


async def test_every_answer_carries_a_reason_a_reader_can_act_on() -> None:
    """In both directions. "Out of scope" with no reason is the silent refusal
    this codebase keeps having to fix."""
    _org_id, system_id = await _system(
        cloud_platform="m365_gcc_high", configured=("msgraph",)
    )
    async with session_scope() as session:
        system = await session.get(System, system_id)
        out = await provider_scope(session, system=system)

    for key, scope in out.items():
        assert scope.reason, f"{key} has no reason"
        assert len(scope.reason.split()) >= 5, f"{key}: {scope.reason!r}"
        assert scope.connector == key


async def test_an_excluded_configured_connector_says_how_to_measure_it() -> None:
    """The operator bound msgraph and it is not being assessed here.

    That surprises somebody, so the reason must name the environment that
    excluded it and the setting that would change it -- not merely "out of scope".
    """
    _org_id, system_id = await _system(
        cloud_platform="aws_govcloud", configured=("msgraph",)
    )
    async with session_scope() as session:
        system = await session.get(System, system_id)
        out = await provider_scope(session, system=system)

    assert out["msgraph"].in_scope is False
    assert "aws_govcloud" in out["msgraph"].reason
    assert "change the system's environment" in out["msgraph"].reason.lower()
    assert out["aws_govcloud"].in_scope is True
    assert "aws_govcloud" in out["aws_govcloud"].reason


async def test_the_fallback_reason_says_to_declare_the_environment() -> None:
    """A configured connector honoured only because nothing was declared must say
    so: the reader should know the decisive setting is unset."""
    _org_id, system_id = await _system(cloud_platform=None, configured=("msgraph",))
    async with session_scope() as session:
        system = await session.get(System, system_id)
        out = await provider_scope(session, system=system)

    reason = out["msgraph"].reason.lower()
    assert out["msgraph"].in_scope is True
    assert "configured" in reason
    assert "declares no environment" in reason


async def test_scope_is_per_system_not_per_organization() -> None:
    """The point of the user's request: one organization, two environments.

    An organization running a Microsoft system and an AWS system must get
    different answers for each, or the distinction is useless.
    """
    n = next(_SEQ)
    async with session_scope() as session:
        org = Organization(name=f"MixedOrg{n}")
        session.add(org)
        await session.flush()
        ms = System(organization_id=org.id, name=f"ms-{n}", baseline="moderate")
        aws = System(organization_id=org.id, name=f"aws-{n}", baseline="moderate")
        session.add_all([ms, aws])
        await session.flush()
        session.add(
            SystemProfile(
                system_id=ms.id,
                answers={},
                environment_type="cloud",
                cloud_platform="m365_gcc_high",
            )
        )
        session.add(
            SystemProfile(
                system_id=aws.id,
                answers={},
                environment_type="cloud",
                cloud_platform="aws_govcloud",
            )
        )
        await session.flush()
        ms_scope = await provider_scope(session, system=ms)
        aws_scope = await provider_scope(session, system=aws)

    assert ms_scope["msgraph"].in_scope is True
    assert ms_scope["aws_govcloud"].in_scope is False
    assert aws_scope["aws_govcloud"].in_scope is True
    assert aws_scope["msgraph"].in_scope is False


# ---------------------------------------------------------------------------
# Through the scan: nothing written, and what was already written is retired
# ---------------------------------------------------------------------------


async def _scan(org_id: int, system_id: int) -> dict:
    async with session_scope() as session:
        return await scan_all_providers(
            session, system_id=system_id, organization_id=org_id, commit=False
        )


async def test_a_microsoft_system_gets_no_aws_control_tests() -> None:
    """The defect, through the real entry point.

    `scan_all_providers` is what the scan-all route and the scheduler both call,
    so this is the behaviour a tenant actually gets.
    """
    org_id, system_id = await _system(
        cloud_platform="m365_gcc_high", configured=("msgraph",)
    )
    out = await _scan(org_id, system_id)

    async with session_scope() as session:
        rows = (
            await session.execute(
                select(ControlTest.connector_type, func.count())
                .where(ControlTest.system_id == system_id)
                .group_by(ControlTest.connector_type)
            )
        ).all()
    by_connector = {str(c): n for c, n in rows}

    assert "aws_govcloud" not in by_connector, by_connector
    assert "gcp" not in by_connector, by_connector
    assert "puppetdb" not in by_connector, by_connector
    out_of_scope = {p["connector"] for p in out["providers_out_of_scope"]}
    assert {"aws_govcloud", "gcp", "puppetdb"} <= out_of_scope, out_of_scope
    for entry in out["providers_out_of_scope"]:
        assert entry["reason"], entry


async def test_an_in_scope_provider_without_a_credential_still_needs_a_human() -> None:
    """The half that must not be lost.

    An operator who configured a connector and has not finished binding it has
    real work to do, and `manual_review_required` is how the product says so.
    Narrowing scope must not silence that.
    """
    # An AWS environment whose AWS connector row exists but has no credential.
    org_id, system_id = await _system(
        cloud_platform="aws_govcloud", configured=("aws_govcloud",)
    )
    await _scan(org_id, system_id)

    async with session_scope() as session:
        rows = (
            await session.execute(
                select(ControlTest.last_status, func.count())
                .where(
                    ControlTest.system_id == system_id,
                    ControlTest.connector_type == "aws_govcloud",
                )
                .group_by(ControlTest.last_status)
            )
        ).all()
    by_status = {str(s): n for s, n in rows}
    assert by_status.get("manual_review_required", 0) > 0, by_status


async def test_rows_a_previous_scan_wrote_are_retired() -> None:
    """Not writing new ones is only half the fix.

    Nothing refreshes an out-of-scope row, and `framework_posture` reads
    `last_status` without regard to age -- so thirteen AWS verdicts would sit on a
    Microsoft tenant's posture page for ever.
    """
    org_id, system_id = await _system(
        cloud_platform="m365_gcc_high", configured=("msgraph",)
    )
    # Exactly what the old scan left behind.
    async with session_scope() as session:
        test = ControlTest(
            organization_id=org_id,
            system_id=system_id,
            control_id="RA-5",
            control_ids=["RA-5"],
            name="aws.inspector.enabled",
            method="connector",
            source="generated",
            check_key="aws.inspector.enabled",
            check_source="platform",
            connector_type="aws_govcloud",
        )
        session.add(test)
        await session.flush()
        await record_result(
            session, test, status="manual_review_required", detail="not configured"
        )

    out = await _scan(org_id, system_id)

    async with session_scope() as session:
        left = (
            await session.execute(
                select(func.count())
                .select_from(ControlTest)
                .where(
                    ControlTest.system_id == system_id,
                    ControlTest.connector_type == "aws_govcloud",
                )
            )
        ).scalar_one()

    assert left == 0, "the out-of-scope row survived the scan"
    assert [r["check_key"] for r in out["retired_checks"]] == ["aws.inspector.enabled"]


async def test_a_row_that_once_held_a_real_verdict_is_kept() -> None:
    """History is not destroyed to tidy a page.

    A provider that genuinely ran and later left scope -- the customer
    decommissioned an AWS account -- keeps its recorded verdicts. The retirement
    is for rows that never assessed anything.
    """
    org_id, system_id = await _system(
        cloud_platform="m365_gcc_high", configured=("msgraph",)
    )
    async with session_scope() as session:
        test = ControlTest(
            organization_id=org_id,
            system_id=system_id,
            control_id="SC-28",
            control_ids=["SC-28"],
            name="aws.s3.default_encryption",
            method="connector",
            source="generated",
            check_key="aws.s3.default_encryption",
            check_source="platform",
            connector_type="aws_govcloud",
        )
        session.add(test)
        await session.flush()
        # It really ran once.
        await record_result(session, test, status="pass", detail="encrypted")
        await record_result(
            session, test, status="manual_review_required", detail="no longer configured"
        )

    out = await _scan(org_id, system_id)

    async with session_scope() as session:
        left = (
            await session.execute(
                select(func.count())
                .select_from(ControlTest)
                .where(
                    ControlTest.system_id == system_id,
                    ControlTest.check_key == "aws.s3.default_encryption",
                )
            )
        ).scalar_one()

    assert left == 1, "a row that once passed was destroyed"
    assert out["retired_checks"] == []


async def test_an_authored_test_is_never_retired() -> None:
    """A human's own test is not the platform's to remove, whatever its
    connector_type says."""
    org_id, system_id = await _system(
        cloud_platform="m365_gcc_high", configured=("msgraph",)
    )
    async with session_scope() as session:
        session.add(
            ControlTest(
                organization_id=org_id,
                system_id=system_id,
                control_id="RA-5",
                name="a human wrote this",
                method="manual",
                source="authored",
                connector_type="aws_govcloud",
                last_status="manual_review_required",
            )
        )
        await session.flush()

    out = await _scan(org_id, system_id)

    async with session_scope() as session:
        left = (
            await session.execute(
                select(func.count())
                .select_from(ControlTest)
                .where(
                    ControlTest.system_id == system_id,
                    ControlTest.source == "authored",
                )
            )
        ).scalar_one()

    assert left == 1, "an authored test was retired"
    assert out["retired_checks"] == []


async def test_retirement_reports_every_row_it_removes_across_providers() -> None:
    """The report must account for all of them, not just the first provider.

    Observed on live data: a scan deleted 23 rows across four out-of-scope
    providers and reported 13 -- the aws_govcloud count alone. A retirement that
    removes evidence it does not name is the silent deletion
    `retire_out_of_scope_checks` documents refusing to do.
    """
    org_id, system_id = await _system(
        cloud_platform="m365_gcc_high", configured=("msgraph",)
    )
    seeded = {"aws_govcloud": 4, "gcp": 3, "azure_arm": 2, "puppetdb": 1}
    async with session_scope() as session:
        for connector, n in seeded.items():
            for i in range(n):
                test = ControlTest(
                    organization_id=org_id,
                    system_id=system_id,
                    control_id="AC-3",
                    control_ids=["AC-3"],
                    name=f"{connector}.check{i}",
                    method="connector",
                    source="generated",
                    check_key=f"{connector}.check{i}",
                    check_source="platform",
                    connector_type=connector,
                )
                session.add(test)
                await session.flush()
                await record_result(
                    session, test, status="manual_review_required", detail="x"
                )

    out = await _scan(org_id, system_id)

    async with session_scope() as session:
        left = (
            await session.execute(
                select(func.count())
                .select_from(ControlTest)
                .where(
                    ControlTest.system_id == system_id,
                    ControlTest.connector_type.notin_(("msgraph",)),
                )
            )
        ).scalar_one()

    assert left == 0, f"{left} out-of-scope rows survived"
    reported = len(out["retired_checks"])
    assert reported == sum(seeded.values()), (
        f"removed {sum(seeded.values())} rows and reported {reported}; "
        f"by connector: "
        f"{ {c: sum(1 for r in out['retired_checks'] if r['connector'] == c) for c in seeded} }"
    )
    by_connector = {
        c: sum(1 for r in out["retired_checks"] if r["connector"] == c) for c in seeded
    }
    assert by_connector == seeded, by_connector
