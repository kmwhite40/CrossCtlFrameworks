"""Plan building: every refusal, decided before anyone is asked to approve."""

from __future__ import annotations

import pytest

from ccf.enforcement.types import (
    PROVIDER_REGISTRY,
    RemediationStep,
    StepOutcome,
    build_steps,
    provider_for,
)
from ccf.posture.types import ResourceFinding


class _Provider:
    """A double that records what it was asked to do."""

    key = "fake"
    write_credential_type = "fake_write"
    required_permissions = ("Fake.Write.All",)
    handled_checks = ("fake.check",)

    def __init__(self, *, reversible: bool = True, write_ok: bool = True) -> None:
        self.reversible = reversible
        self.write_ok = write_ok
        self.applied: list[str] = []
        self.reversed: list[str] = []
        self.planned: list[str] = []

    async def is_write_configured(self) -> bool:
        return self.write_ok

    async def plan(self, findings) -> list[RemediationStep]:
        self.planned = [f.resource_id for f in findings]
        return [
            RemediationStep(
                resource_id=f.resource_id,
                resource_type=f.resource_type,
                action="disable_account",
                description=f"disable {f.resource_id}",
                # An unreadable current state is the "cannot be undone" case.
                current_state={"enabled": True} if self.reversible else {},
                target_state={"enabled": False},
            )
            for f in findings
        ]

    async def apply(self, step: RemediationStep) -> StepOutcome:
        self.applied.append(step.resource_id)
        return StepOutcome(resource_id=step.resource_id, status="applied", detail="ok")

    async def reverse(self, step: RemediationStep) -> StepOutcome:
        self.reversed.append(step.resource_id)
        return StepOutcome(resource_id=step.resource_id, status="applied", detail="undone")


def _findings(n: int, verdict: str = "fail") -> list[ResourceFinding]:
    return [
        ResourceFinding(
            resource_id=f"user-{i}@acme.gov",
            resource_type="entra_user",
            verdict=verdict,
            observed="stale",
        )
        for i in range(n)
    ]


@pytest.mark.asyncio
async def test_a_plan_within_the_blast_radius_is_built() -> None:
    provider = _Provider()
    steps, refusal = await build_steps(_findings(3), provider, max_resources=10)
    assert refusal is None
    assert [s.resource_id for s in steps] == [f"user-{i}@acme.gov" for i in range(3)]
    assert provider.applied == [], "planning must never write"


@pytest.mark.asyncio
async def test_a_plan_exceeding_the_blast_radius_is_refused_with_the_numbers() -> None:
    """Refused at plan time: an operator must never hold an approvable plan
    that will be rejected when applied."""
    provider = _Provider()
    steps, refusal = await build_steps(_findings(11), provider, max_resources=10)
    assert steps == []
    assert refusal == "11 resources exceeds the enforcement limit of 10"
    assert provider.applied == []


@pytest.mark.asyncio
async def test_the_boundary_is_inclusive() -> None:
    provider = _Provider()
    _steps, refusal = await build_steps(_findings(10), provider, max_resources=10)
    assert refusal is None


@pytest.mark.asyncio
async def test_only_narrows_a_plan_to_named_resources() -> None:
    """The intended path for "just this one account"."""
    provider = _Provider()
    steps, refusal = await build_steps(
        _findings(5), provider, max_resources=10, only=("user-2@acme.gov",)
    )
    assert refusal is None
    assert [s.resource_id for s in steps] == ["user-2@acme.gov"]


@pytest.mark.asyncio
async def test_only_naming_an_absent_resource_refuses_rather_than_planning_nothing() -> None:
    provider = _Provider()
    steps, refusal = await build_steps(
        _findings(3), provider, max_resources=10, only=("nobody@acme.gov",)
    )
    assert steps == []
    assert refusal == "no resources to remediate"


@pytest.mark.asyncio
async def test_a_step_without_reversal_data_is_excluded() -> None:
    """It could not be undone, so it is not offered."""
    provider = _Provider(reversible=False)
    steps, refusal = await build_steps(_findings(3), provider, max_resources=10)
    assert steps == []
    assert refusal == "no resources to remediate"


@pytest.mark.asyncio
async def test_a_plan_with_no_steps_is_refused_not_empty() -> None:
    """An approvable plan that would do nothing invites an approval that means
    nothing."""
    provider = _Provider()
    steps, refusal = await build_steps([], provider, max_resources=10)
    assert steps == []
    assert refusal == "no resources to remediate"


@pytest.mark.asyncio
async def test_only_findings_needing_cover_are_planned() -> None:
    """A passing resource has nothing to remediate, and planning one would mean
    writing to something that was already correct."""
    provider = _Provider()
    findings = [
        ResourceFinding("broken@acme.gov", "entra_user", "fail", "stale"),
        ResourceFinding("fine@acme.gov", "entra_user", "pass", "recent"),
        ResourceFinding("na@acme.gov", "entra_user", "not_applicable", "disabled"),
    ]
    steps, refusal = await build_steps(findings, provider, max_resources=10)
    assert refusal is None
    assert [s.resource_id for s in steps] == ["broken@acme.gov"]
    assert provider.planned == ["broken@acme.gov"], "the provider saw only the failure"


@pytest.mark.asyncio
async def test_a_warn_finding_is_planned() -> None:
    """warn needs cover, so it is remediable."""
    provider = _Provider()
    steps, _ = await build_steps(
        [ResourceFinding("warned@acme.gov", "entra_user", "warn", "close")],
        provider,
        max_resources=10,
    )
    assert [s.resource_id for s in steps] == ["warned@acme.gov"]


@pytest.mark.asyncio
async def test_a_zero_blast_radius_refuses_everything() -> None:
    """A deployment can switch enforcement off entirely by setting it to zero."""
    provider = _Provider()
    steps, refusal = await build_steps(_findings(1), provider, max_resources=0)
    assert steps == []
    assert refusal is not None
    assert provider.applied == []


# ── the registry ─────────────────────────────────────────────────────────────


def test_a_check_maps_to_at_most_one_provider() -> None:
    """Two providers claiming one check would make the applied change depend on
    registry order."""
    seen: dict[str, str] = {}
    for provider in PROVIDER_REGISTRY:
        for check_key in getattr(provider, "handled_checks", ()):
            assert check_key not in seen, (
                f"{check_key} claimed by both {seen.get(check_key)} and {provider.key}"
            )
            seen[check_key] = provider.key


def test_an_unhandled_check_has_no_provider() -> None:
    assert provider_for("nothing.handles.this") is None
