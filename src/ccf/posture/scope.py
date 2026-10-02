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

A connector is in scope when **either**:

1. the organization has a ``ConnectorConfig`` row for it -- configured or
   half-configured, because finishing one is real work and that is the case
   ``manual_review_required`` exists for; **or**
2. the system's declared ``cloud_platform`` maps to its platform.

Nothing is inferred otherwise. An undeclared platform with no configured
connector means Concord cannot say which clouds the system has, and guessing is
how an M365 tenant came to hold thirteen AWS verdicts. ``none`` is a deliberate
answer ("this system uses no cloud") and pulls in nothing -- the same answer
``onboarding.NO_CLOUD`` exists for, after a customer who said they run no cloud
received a Microsoft 365 SSP.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..connectors.readiness import _CONNECTOR_PLATFORM
from ..governance.automation import PLATFORM_TO_SSP
from ..models import System, SystemProfile
from ..models_grc import ConnectorConfig, ControlTest, ControlTestResult
from ..models_waivers import Waiver
from .checks import known_providers

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

    out: dict[str, ProviderScope] = {}
    for connector in sorted(known_providers()):
        connector_platform = _CONNECTOR_PLATFORM.get(connector)
        if connector in configured:
            out[connector] = ProviderScope(
                connector,
                True,
                f"this organization has configured the {connector} connector, so "
                "its checks are assessed whatever the system's declared platform",
            )
            continue
        if connector_platform is not None and connector_platform == platform:
            out[connector] = ProviderScope(
                connector,
                True,
                f"the system declares cloud platform {declared!r}, which is the "
                f"{connector_platform} platform this connector assesses",
            )
            continue
        if connector_platform is None:
            out[connector] = ProviderScope(
                connector,
                False,
                f"{connector} maps to no cloud platform, so it is assessed only "
                "when this organization configures it",
            )
            continue
        if platform is None:
            out[connector] = ProviderScope(
                connector,
                False,
                "this system declares no recognised cloud platform, so Concord "
                f"cannot tell whether it uses {connector_platform}; declare the "
                f"platform on the system or configure the {connector} connector",
            )
            continue
        out[connector] = ProviderScope(
            connector,
            False,
            f"this system is a {platform} environment and {connector} assesses "
            f"{connector_platform}, so its checks do not apply here",
        )
    return out


__all__ = ["ProviderScope", "provider_scope", "retire_out_of_scope_checks"]


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
