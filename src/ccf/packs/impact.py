"""What adopting a desired-state change would affect in this deployment.

:mod:`ccf.packs.diff` says what changed in a pack's declared posture rules.
This says what that *means here*: which controls the change touches, which
authored capabilities reach those controls, which generated checks it would
retire, and which formal acceptances -- and open remediation, in a Task or a
POA&M -- it would leave orphaned.

Deliberately the same shape as :mod:`ccf.catalog.impact`, which answers the
identical question for a catalog revision. The subject differs -- desired state
rather than upstream content -- and nothing else does, so the ingredients are
borrowed rather than rebuilt: ``packs.diff`` supplies the change,
``posture.checks`` says what a platform evaluator evidences, and
``capability.service`` traverses the graph.

Read-only and side-effect free: computed for a human to review before adoption,
never applied.

Four of the findings are ones nobody would think to look for, which is why
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
* **tasks orphaned** and **POA&Ms orphaned.** ``governance.control_tests``
  opens a remediation Task and a POA&M for a failing test, and closes either
  only on a future ``pass`` on that same test. Retirement makes that
  impossible, so without this a POA&M keyed to a check that can no longer run
  simply never closes -- an authorization package's worst shape of stale
  finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..capability.service import capabilities_for_controls
from ..constants import POAM_ACTIVE_STATUSES
from ..models import POAM, Task
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
    #: Open remediation Tasks a retiring check's ControlTest still owns
    #: (``ctltest-fix:{test.id}``) -- they close only on a future ``pass`` on
    #: that test, which retirement makes impossible (IMPORTANT 2).
    tasks_orphaned: list[dict[str, Any]] = field(default_factory=list)
    #: Open POA&Ms the same retiring tests still own (``source_ref=
    #: control_test:{test.id}``) -- the same defect, worse in an authorization
    #: package: a POA&M that can never close (IMPORTANT 2).
    poams_orphaned: list[dict[str, Any]] = field(default_factory=list)
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
            or self.tasks_orphaned
            or self.poams_orphaned
            or self.unresolved
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "controls_affected": self.controls_affected,
            "capabilities_affected": self.capabilities_affected,
            "checks_retired": self.checks_retired,
            "waivers_orphaned": self.waivers_orphaned,
            "tasks_orphaned": self.tasks_orphaned,
            "poams_orphaned": self.poams_orphaned,
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
    session: AsyncSession, *, org_id: int | None, pack_key: str, diff: PostureRuleDiff
) -> ConfigChangeImpact:
    """Compute what adopting the change behind ``diff`` would affect.

    An unknown baseline -- a pack version installed before manifests were
    retained -- produces an empty impact with the reason stated, never a
    speculative one. ``packs.diff`` refuses to fabricate a change from missing
    history, and inventing consequences for it here would undo that.

    ``org_id=None`` means unscoped -- every organization, never "no
    organization" -- the same convention :class:`ccf.auth.Principal` already
    documents for an unscoped principal (auth disabled, or a global admin).
    It is applied the same way to every query below: a pack installed by such
    a principal (``pack.organization_id`` is nullable, and is exactly this)
    is a deployment-wide artifact, so its impact is deployment-wide too.
    Reporting only ``organization_id IS NULL`` rows -- which is what an
    unconditional filter does -- would silently hide every real tenant's
    retiring checks and orphaned waivers (CRITICAL 1). The capability
    disclosure this implies (every tenant's capabilities, not just one) is
    then intentional, not accidental: only an unscoped principal can retrieve
    an org-less pack's impact at all (``routes.packs._require`` filters a
    scoped principal's query on ``organization_id == principal.org_id``,
    which a NULL row never matches), so a caller who can see this deployment-
    wide impact is already the same caller who can see deployment-wide pack
    listings elsewhere in this router.
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

    # Keyed by (control, change kind), not by control alone. One rule removed
    # and another re-parameterized can touch the same control, and collapsing
    # that into a single row would tell an operator the control loses all
    # coverage when a tightened rule still evidences it -- the exact misreading
    # an impact report exists to prevent.
    by_control: dict[tuple[str, str], dict[str, Any]] = {}
    for key, change, definition in changes:
        control_ids = _control_ids_for(definition)
        if control_ids is None:
            impact.unresolved.append(key)
            continue
        for control_id in control_ids:
            row = by_control.setdefault(
                (control_id, change),
                {"control_id": control_id, "change": change, "rule_keys": []},
            )
            if key not in row["rule_keys"]:
                row["rule_keys"].append(key)
    impact.controls_affected = [by_control[k] for k in sorted(by_control)]
    impact.unresolved.sort()

    # Capabilities reaching any affected control -- how a rule change reaches
    # authored SSP prose, which P4a made capability-derived. One query for
    # every affected control (IMPORTANT 6), not one per control: a diff
    # touching 40 controls otherwise issues 40 full Capability x
    # CapabilityControl scans on an authenticated GET.
    affected_control_ids = sorted({control_id for control_id, _change in by_control})
    caps_by_control = await capabilities_for_controls(
        session, control_ids=affected_control_ids, org_id=org_id
    )
    by_capability: dict[str, dict[str, Any]] = {}
    for control_id in affected_control_ids:
        for cap in caps_by_control.get(control_id, []):
            entry = by_capability.setdefault(
                cap.key,
                {"capability_key": cap.key, "title": cap.title, "controls": []},
            )
            if control_id not in entry["controls"]:
                entry["controls"].append(control_id)
    impact.capabilities_affected = [by_capability[k] for k in sorted(by_capability)]

    if not diff.removed:
        return impact

    # Scoped to *this pack's* checks, not check_key alone (IMPORTANT 3): a
    # platform check or a different pack's check can share a key, and without
    # this a rule this pack never owned would be reported as retiring.
    # A NULL check_source (a 'generated' row from before migration 0070, not
    # yet rescanned) is deliberately excluded rather than guessed at, the same
    # self-healing tradeoff posture.scan._is_platform_sourced documents: the
    # row acquires a real check_source on its next scan.
    check_source = f"pack:{pack_key}"
    tests_stmt = (
        select(ControlTest)
        .where(
            ControlTest.check_key.in_(diff.removed),
            ControlTest.check_source == check_source,
        )
        .order_by(ControlTest.id)
    )
    if org_id is not None:
        tests_stmt = tests_stmt.where(ControlTest.organization_id == org_id)
    tests = (await session.execute(tests_stmt)).scalars().all()
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

    # A waiver carries no check_source of its own -- joined to the
    # ControlTest it accepts (system_id, check_key), the same pair
    # ControlTest.uq_control_test_system_check keys on, to inherit the same
    # pack scoping.
    waivers_stmt = (
        select(Waiver)
        .join(
            ControlTest,
            and_(
                ControlTest.system_id == Waiver.system_id,
                ControlTest.check_key == Waiver.check_key,
            ),
        )
        .where(
            Waiver.check_key.in_(diff.removed),
            ControlTest.check_source == check_source,
        )
        .order_by(Waiver.id)
    )
    if org_id is not None:
        waivers_stmt = waivers_stmt.where(Waiver.organization_id == org_id)
    waivers = (await session.execute(waivers_stmt)).scalars().all()
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

    # A retiring test's remediation Task and POA&M close only on a future
    # `pass` on that test -- impossible once it is retired (IMPORTANT 2). Both
    # are looked up by the exact dedupe keys governance.control_tests uses to
    # open them, so this never reports a Task/POA&M the retirement did not
    # actually orphan.
    if tests:
        task_dedupes = [f"ctltest-fix:{t.id}" for t in tests]
        open_tasks = (
            await session.execute(
                select(Task).where(
                    Task.dedupe_key.in_(task_dedupes), Task.status == "open"
                )
            )
        ).scalars().all()
        impact.tasks_orphaned = [
            {
                "task_id": t.id,
                "title": t.title,
                "system_id": t.system_id,
                "control_test_id": int(t.entity_id) if t.entity_id else None,
            }
            for t in open_tasks
        ]

        poam_refs = [f"control_test:{t.id}" for t in tests]
        open_poams = (
            await session.execute(
                select(POAM).where(
                    POAM.source == "control_test",
                    POAM.source_ref.in_(poam_refs),
                    POAM.status.in_(POAM_ACTIVE_STATUSES),
                )
            )
        ).scalars().all()
        impact.poams_orphaned = [
            {
                "poam_id": p.id,
                "title": p.title,
                "system_id": p.system_id,
                "status": p.status,
                "control_test_id": (
                    int(p.source_ref.split(":", 1)[1])
                    if p.source_ref and ":" in p.source_ref
                    else None
                ),
            }
            for p in open_poams
        ]

    return impact
