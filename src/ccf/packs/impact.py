"""What adopting a desired-state change would affect in this deployment.

:mod:`ccf.packs.diff` says what changed in a pack's declared posture rules.
This says what that *means here*: which controls the change touches, which
authored capabilities reach those controls, which generated checks it would
retire, and which formal acceptances it would leave orphaned.

Deliberately the same shape as :mod:`ccf.catalog.impact`, which answers the
identical question for a catalog revision. The subject differs -- desired state
rather than upstream content -- and nothing else does, so the ingredients are
borrowed rather than rebuilt: ``packs.diff`` supplies the change,
``posture.checks`` says what a platform evaluator evidences, and
``capability.service`` traverses the graph.

Read-only and side-effect free: computed for a human to review before adoption,
never applied.

Two of the four findings are ones nobody would think to look for, which is why
they are here:

* **checks retired.** A removed rule leaves a generated ``ControlTest``.
  ``posture/scan.py`` already states that such a test must be DEACTIVATED and
  never deleted, because validation history is the product -- and the check's
  *current* status belongs in the report, since retiring a failing check is a
  materially different decision from retiring a passing one.
* **waivers orphaned.** A waiver keyed on ``check_key`` outlives the removal of
  the check it accepts, leaving a formal acceptance of a finding that can no
  longer be produced. That is precisely the stale governance artefact an
  assessor finds instead of the platform.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..capability.service import capabilities_for_control
from ..models_grc import ControlTest
from ..models_waivers import Waiver
from ..posture.checks import CHECK_REGISTRY, PostureCheck
from .diff import UNKNOWN_BASELINE, PostureRuleDiff


@dataclass
class ConfigChangeImpact:
    """Per-deployment consequences of adopting one desired-state change."""

    controls_affected: list[dict[str, Any]] = field(default_factory=list)
    capabilities_affected: list[dict[str, Any]] = field(default_factory=list)
    checks_retired: list[dict[str, Any]] = field(default_factory=list)
    waivers_orphaned: list[dict[str, Any]] = field(default_factory=list)
    #: Rule keys whose controls could not be determined -- a Form A rule naming
    #: an evaluator this build does not have. Reported rather than silently
    #: dropped: the pack may target a newer platform version, and an operator
    #: should see that the impact is incomplete.
    unresolved: list[str] = field(default_factory=list)
    #: Why the impact is empty, when it is empty for a reason rather than
    #: because nothing changed.
    reason: str | None = None

    def is_empty(self) -> bool:
        return not (
            self.controls_affected
            or self.capabilities_affected
            or self.checks_retired
            or self.waivers_orphaned
            or self.unresolved
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "controls_affected": self.controls_affected,
            "capabilities_affected": self.capabilities_affected,
            "checks_retired": self.checks_retired,
            "waivers_orphaned": self.waivers_orphaned,
            "unresolved": self.unresolved,
            "reason": self.reason,
            "empty": self.is_empty(),
        }


def _platform_check(evaluator_key: str) -> PostureCheck | None:
    for checks in CHECK_REGISTRY.values():
        for check in checks:
            if check.key == evaluator_key:
                return check
    return None


def _control_ids_for(definition: dict[str, Any]) -> tuple[str, ...] | None:
    """The controls a rule evidences, or ``None`` when they cannot be resolved.

    Form B declares them. Form A restates nothing -- a parameterized threshold
    does not change what the check evidences -- so the named platform
    evaluator's controls apply.
    """
    declared = definition.get("control_ids")
    if isinstance(declared, list) and declared:
        return tuple(str(c) for c in declared if isinstance(c, str) and c)
    evaluator = definition.get("evaluator")
    if isinstance(evaluator, str) and evaluator:
        check = _platform_check(evaluator)
        if check is None:
            return None
        return check.control_ids
    return None


async def build_config_change_impact(
    session: AsyncSession, *, org_id: int | None, diff: PostureRuleDiff
) -> ConfigChangeImpact:
    """Compute what adopting the change behind ``diff`` would affect.

    An unknown baseline -- a pack version installed before manifests were
    retained -- produces an empty impact with the reason stated, never a
    speculative one. ``packs.diff`` refuses to fabricate a change from missing
    history, and inventing consequences for it here would undo that.
    """
    impact = ConfigChangeImpact()
    if diff.baseline == UNKNOWN_BASELINE:
        impact.reason = "no retained manifest to compare"
        return impact
    if not diff.has_changes:
        return impact

    # `definitions` carries (before, after) for every rule in the diff. The
    # side that describes what a control would be evidenced BY is the newer one
    # for an addition or a change, and the older one for a removal -- a removed
    # rule has no "after" to read controls from.
    changes: list[tuple[str, str, dict[str, Any]]] = []
    for key in diff.added:
        changes.append((key, "added", diff.definitions.get(key, ({}, {}))[1]))
    for key in diff.removed:
        changes.append((key, "removed", diff.definitions.get(key, ({}, {}))[0]))
    for key in diff.changed:
        changes.append((key, "changed", diff.definitions.get(key, ({}, {}))[1]))

    by_control: dict[str, dict[str, Any]] = {}
    for key, change, definition in changes:
        control_ids = _control_ids_for(definition)
        if control_ids is None:
            impact.unresolved.append(key)
            continue
        for control_id in control_ids:
            row = by_control.setdefault(
                control_id, {"control_id": control_id, "change": change, "rule_keys": []}
            )
            row["rule_keys"].append(key)
    impact.controls_affected = [by_control[c] for c in sorted(by_control)]
    impact.unresolved.sort()

    # Capabilities reaching any affected control -- how a rule change reaches
    # authored SSP prose, which P4a made capability-derived.
    by_capability: dict[str, dict[str, Any]] = {}
    for control_id in sorted(by_control):
        for cap in await capabilities_for_control(session, control_id=control_id):
            if org_id is not None and cap.organization_id != org_id:
                continue
            entry = by_capability.setdefault(
                cap.key,
                {"capability_key": cap.key, "title": cap.title, "controls": []},
            )
            if control_id not in entry["controls"]:
                entry["controls"].append(control_id)
    impact.capabilities_affected = [by_capability[k] for k in sorted(by_capability)]

    if not diff.removed:
        return impact

    tests = (
        await session.execute(
            select(ControlTest)
            .where(
                ControlTest.organization_id == org_id,
                ControlTest.check_key.in_(diff.removed),
            )
            .order_by(ControlTest.id)
        )
    ).scalars().all()
    impact.checks_retired = [
        {
            "test_id": t.id,
            "check_key": t.check_key,
            "control_id": t.control_id,
            "system_id": t.system_id,
            "last_status": t.last_status,
            "name": t.name,
        }
        for t in tests
    ]

    waivers = (
        await session.execute(
            select(Waiver)
            .where(
                Waiver.organization_id == org_id,
                Waiver.check_key.in_(diff.removed),
            )
            .order_by(Waiver.id)
        )
    ).scalars().all()
    impact.waivers_orphaned = [
        {
            "waiver_id": w.id,
            "check_key": w.check_key,
            "resource_id": w.resource_id,
            "status": w.status,
            "expires_on": w.expires_on.isoformat() if w.expires_on else None,
            "system_id": w.system_id,
        }
        for w in waivers
    ]
    return impact
