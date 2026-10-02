"""Which providers a given environment is actually assessed against.

``scan_all_providers`` used to iterate every registered provider and, for each
one that was not ready, record a ``manual_review_required`` result for every one
of its checks. Measured on a live Microsoft-only organization whose single
configured connector is ``msgraph``: 13 ``aws_govcloud`` rows, 3 ``gcp``, 2
``puppetdb`` and 5 ``azure_arm``, against 19 real ``msgraph`` rows. Twenty-three
of forty-two control tests were for clouds the organization does not have, all of
them in the bucket ``/dashboard`` labels "Need a human".

The original intent was right -- a check that did not run must not vanish
silently -- but it conflated two facts:

* **in scope, no usable credential.** Real work: bind one. ``manual_review_required``
  is the correct record, and it is kept.
* **not in scope at all.** Nothing anyone can do, and the row asserts that Concord
  assessed an Amazon Inspector control on a tenant with no AWS. There is no human
  action, so it does not belong in a human's queue -- and with no row at all the
  control simply lands in ``unaddressed``, which is true: Concord has no evidence
  for it.

Scope is resolved **per system**, because one organization runs both kinds of
environment. Two maps that already exist are composed rather than replaced:
:data:`ccf.connectors.readiness._CONNECTOR_PLATFORM` (connector -> platform) and
:data:`ccf.governance.automation.PLATFORM_TO_SSP` (the intake questionnaire's
``cloud_platform`` answer -> platform). A third hand-maintained table mapping
answers straight to connectors is exactly how two tables come to disagree.

**The system's declared environment decides.** One platform per system is the
product's model -- the intake questionnaire offers exactly one of
``m365_gcc_high``, ``azure_gov``, ``aws_govcloud``, ``gcp`` and ``none`` -- so a
system that says it is M365 is measured against M365, and not also against AWS
because some *other* system in the organization has an AWS connector bound. An
organization running both kinds of environment is the normal case, and a scope
widened by an org-wide setting cannot express it.

When a system declares **no** environment, a configured connector is the only
evidence of intent left and is honoured as a fallback; the reason returned says to
declare the environment, because that is the setting that actually decides.

``puppetdb`` maps to no cloud platform -- it is infrastructure the customer runs --
so no environment can imply it and it is assessed only when configured.

Nothing else is inferred. ``none`` is a deliberate answer ("this system uses no
cloud") and pulls in nothing: the same answer ``onboarding.NO_CLOUD`` exists for,
after a customer who said they run no cloud received a Microsoft 365 SSP.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..connectors.readiness import _CONNECTOR_PLATFORM
from ..governance.automation import PLATFORM_TO_SSP
from ..models import System, SystemProfile
from ..models_grc import ConnectorConfig, ControlTest, ControlTestResult
from ..models_waivers import Waiver
from ..ssp.constants import NO_PLATFORM
from .checks import known_providers
from .latest import OUT_OF_SCOPE_EVIDENCE_REF

#: Result statuses that mean a check never actually assessed anything, so a row
#: carrying only these holds no history worth keeping.
_NEVER_ASSESSED: frozenset[str] = frozenset({"manual_review_required", "not_tested"})


@dataclass(frozen=True)
class ProviderScope:
    """Whether one provider is assessed for one system, and why."""

    connector: str
    in_scope: bool
    reason: str


def _platform_for_system(cloud_platform: str | None) -> str | None:
    """The platform an intake answer denotes, or ``None``.

    ``None`` for an absent answer, for ``none`` (a deliberate "no cloud"), and for
    an unrecognised code -- a typo must not resolve to a provider, the same
    refusal :func:`ccf.connectors.clouds.microsoft_endpoints` makes rather than
    guessing which sovereign cloud a misspelling meant.
    """
    if not cloud_platform:
        return None
    platform = PLATFORM_TO_SSP.get(str(cloud_platform).strip())
    # NO_PLATFORM is what `none` maps to; it is not a provider's platform.
    if not platform or platform not in set(_CONNECTOR_PLATFORM.values()):
        return None
    return platform


async def provider_scope(
    session: AsyncSession, *, system: System
) -> dict[str, ProviderScope]:
    """One answer per registered provider, with the reason.

    Exhaustive over :func:`~ccf.posture.checks.known_providers`, so a caller never
    has to decide what a missing key means -- the ambiguity that produced the
    defect this module exists to fix.

    Configured connectors are read from the **system's own** organization, not
    from the caller's. Scope is a property of the environment; who is asking is an
    authorization question, settled before this is reached
    (``require_system_in_scope``). Taking a caller-supplied org id let the two
    disagree -- and a scope that varies by caller is a scope that can be widened
    by one.
    """
    configured: set[str] = set()
    if system.organization_id is not None:
        configured = {
            str(row)
            for row in (
                await session.execute(
                    select(ConnectorConfig.connector_type).where(
                        ConnectorConfig.organization_id == system.organization_id
                    )
                )
            ).scalars()
            if row
        }

    profile = (
        await session.execute(
            select(SystemProfile).where(SystemProfile.system_id == system.id)
        )
    ).scalars().first()
    declared = profile.cloud_platform if profile is not None else None
    platform = _platform_for_system(declared)
    # "No cloud" is a declared environment, not an absent one. `_platform_for_system`
    # returns None for both, and the fallback below honours configured connectors
    # when nothing is declared -- so a system set to "No cloud" in an organization
    # with any connector bound was assessed against all of them, and choosing No
    # cloud on the system page changed nothing.
    declared_no_cloud = (
        bool(declared) and PLATFORM_TO_SSP.get(str(declared).strip()) == NO_PLATFORM
    )

    out: dict[str, ProviderScope] = {}
    for connector in sorted(known_providers()):
        connector_platform = _CONNECTOR_PLATFORM.get(connector)

        # A connector that maps to no cloud platform -- puppetdb is infrastructure
        # the customer runs -- can never be implied by an environment, so it is
        # assessed only when somebody configures it. Decided first, because
        # neither branch below has anything to say about it.
        if connector_platform is None:
            in_scope = connector in configured
            out[connector] = ProviderScope(
                connector,
                in_scope,
                (
                    f"this organization has configured the {connector} connector"
                    if in_scope
                    else f"{connector} maps to no cloud platform, so it is "
                    "assessed only when this organization configures it"
                ),
            )
            continue

        if declared_no_cloud:
            out[connector] = ProviderScope(
                connector,
                False,
                f"this system's environment is {declared!r} (no cloud), so no cloud "
                f"connector is assessed; change the system's environment to measure "
                f"{connector_platform}",
            )
            continue

        if platform is not None:
            # **The declared environment decides.** One platform per system is the
            # product's model -- the intake questionnaire asks for exactly one --
            # so a system that says it is M365 is measured against M365 and not
            # also against AWS because some *other* system in the organization has
            # an AWS connector bound. An organization running both kinds of
            # environment is the normal case, and a scope widened by an org-wide
            # setting cannot express it.
            matches = connector_platform == platform
            out[connector] = ProviderScope(
                connector,
                matches,
                (
                    f"this system's environment is {declared!r}, which is the "
                    f"{connector_platform} platform this connector assesses"
                    if matches
                    else f"this system's environment is {declared!r}; {connector} "
                    f"assesses {connector_platform}, so its checks do not apply. "
                    "Change the system's environment to measure it instead"
                ),
            )
            continue

        # Nothing declared. A configured connector is the only evidence of intent
        # left, so it is honoured as a fallback -- but the reason says to declare
        # the environment, because that is the setting that actually decides.
        if connector in configured:
            out[connector] = ProviderScope(
                connector,
                True,
                f"this organization has configured the {connector} connector and "
                "this system declares no environment; set the system's environment "
                "to choose what is measured",
            )
            continue
        out[connector] = ProviderScope(
            connector,
            False,
            "this system declares no environment, so Concord cannot tell whether "
            f"it uses {connector_platform}; set the system's environment or "
            f"configure the {connector} connector",
        )
    return out


__all__ = [
    "ProviderScope",
    "apply_provider_scope",
    "provider_scope",
    "retire_out_of_scope_checks",
    "withdraw_out_of_scope_checks",
]


async def retire_out_of_scope_checks(
    session: AsyncSession, *, system_id: int, connector_key: str
) -> list[dict[str, str]]:
    """Remove generated rows for a provider this system is no longer assessed by.

    A row a previous scan wrote keeps claiming a verdict for ever: nothing
    refreshes it, and ``framework_posture`` reads ``last_status`` without regard
    to age, so thirteen AWS ``manual_review_required`` rows would sit on a
    Microsoft tenant's posture page indefinitely. Not writing new ones is only
    half the fix.

    **Deliberately narrow.** A row is retired only when all of:

    * it is ``source == "generated"`` -- never a human's authored test;
    * every result it ever recorded is ``manual_review_required`` or
      ``not_tested``, so nothing that once held a real verdict is destroyed.
      A provider that genuinely ran and later left scope keeps its history;
    * no waiver references its ``check_key``. A waiver is a recorded risk
      acceptance with an owner, and orphaning one silently is the shape
      ``packs.impact`` reports rather than performs.

    Anything it declines is left in place and reported by the caller, because
    deleting evidence quietly is worse than leaving it. Deletion cascades to the
    row's results (``ControlTest.results`` is ``delete-orphan``), which is the
    point: the claim goes with the row.
    """
    tests = (
        (
            await session.execute(
                select(ControlTest).where(
                    ControlTest.system_id == system_id,
                    ControlTest.connector_type == connector_key,
                    ControlTest.source == "generated",
                )
            )
        )
        .scalars()
        .all()
    )
    if not tests:
        return []

    retired: list[dict[str, str]] = []
    for test in tests:
        statuses = set(
            (
                await session.execute(
                    select(ControlTestResult.status).where(
                        ControlTestResult.control_test_id == test.id
                    )
                )
            )
            .scalars()
            .all()
        )
        if statuses - _NEVER_ASSESSED:
            continue
        waived = (
            await session.execute(
                select(Waiver.id).where(Waiver.check_key == test.check_key).limit(1)
            )
        ).scalar_one_or_none()
        if waived is not None:
            continue
        retired.append(
            {
                "check_key": str(test.check_key or ""),
                "control_id": str(test.control_id or ""),
                "connector": connector_key,
            }
        )
        await session.delete(test)
    if retired:
        await session.flush()
    return retired


async def withdraw_out_of_scope_checks(
    session: AsyncSession,
    *,
    system_id: int,
    connector_key: str,
    reason: str,
    actor: str,
) -> list[dict[str, str]]:
    """Record that a check no longer applies, for rows retirement declined.

    :func:`retire_out_of_scope_checks` deletes only rows that never held a real
    verdict, which leaves the dangerous case: a system scanned as AWS and then
    re-declared as Microsoft 365 kept its AWS ``pass`` rows, nothing refreshes
    them (the scan skips out-of-scope providers), and every posture reader went on
    crediting controls from them.

    Fixed on the write side, not in the readers. About fifteen places read a
    verdict -- framework posture, gaps, findings, the dashboard, SSP completeness
    and sync, FedRAMP 20x validation, the live-audit evaluations -- and two of
    them build their own notion of "latest". A scope filter in each would be
    fifteen copies of one rule, and the sixteenth reader would not have it.
    Recording the change as the check's current result reaches all of them
    through whatever path each already uses.

    The result is ``not_applicable``: existing vocabulary, credited by nothing,
    and -- deliberately, in ``record_result`` -- never treated as a recovery, so a
    POA&M opened by an earlier ``fail`` stays open. A weakness that left scope was
    not fixed. History is kept; the earlier results remain beneath this one, and
    if the system's environment changes back, the next scan records a real
    verdict over it.

    Generated rows only, as for retirement: a human's authored test is theirs.
    Idempotent -- a row whose latest result is already this withdrawal is left
    alone, so repeated scans do not stack results.
    """
    from ..governance.control_tests import record_result  # noqa: PLC0415

    tests = (
        (
            await session.execute(
                select(ControlTest).where(
                    ControlTest.system_id == system_id,
                    ControlTest.connector_type == connector_key,
                    ControlTest.source == "generated",
                )
            )
        )
        .scalars()
        .all()
    )
    withdrawn: list[dict[str, str]] = []
    for test in tests:
        latest_ref = (
            await session.execute(
                select(ControlTestResult.evidence_ref)
                .where(ControlTestResult.control_test_id == test.id)
                .order_by(ControlTestResult.run_at.desc(), ControlTestResult.id.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if latest_ref == OUT_OF_SCOPE_EVIDENCE_REF:
            continue
        await record_result(
            session,
            test,
            status="not_applicable",
            detail=f"Not assessed for this system: {reason}",
            evidence_ref=OUT_OF_SCOPE_EVIDENCE_REF,
            actor=actor,
            open_remediation=False,
        )
        withdrawn.append(
            {
                "check_key": str(test.check_key or ""),
                "control_id": str(test.control_id or ""),
                "connector": connector_key,
            }
        )
    return withdrawn


async def apply_provider_scope(
    session: AsyncSession, *, system: System, actor: str
) -> dict[str, Any]:
    """Bring a system's existing checks into line with its scope.

    For every provider the system is not measured against: retire the rows that
    never held a verdict, then withdraw the rest. One function, called by the scan
    and by the environment selector, so the page is right the moment the
    environment changes rather than after the next scan.
    """
    scope = await provider_scope(session, system=system)
    out_of_scope: list[dict[str, str]] = []
    retired: list[dict[str, str]] = []
    withdrawn: list[dict[str, str]] = []
    for key in sorted(known_providers()):
        provider = scope.get(key)
        if provider is None or provider.in_scope:
            continue
        out_of_scope.append({"connector": key, "reason": provider.reason})
        retired.extend(
            await retire_out_of_scope_checks(session, system_id=system.id, connector_key=key)
        )
        withdrawn.extend(
            await withdraw_out_of_scope_checks(
                session,
                system_id=system.id,
                connector_key=key,
                reason=provider.reason,
                actor=actor,
            )
        )
    return {
        "scope": scope,
        "out_of_scope": out_of_scope,
        "retired": retired,
        "withdrawn": withdrawn,
    }
