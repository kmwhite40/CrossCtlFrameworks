"""Posture measured against a framework baseline, not against what we happened to check.

The gap report answers "of the controls Concord assessed, which failed".
That is the wrong denominator for a compliance tool: a tenant with six
machine-tested controls and eight failures reads as "8 of 14" when the
baseline it is being held to has 288. The number an assessor and a customer
both need is *coverage of the baseline* -- what is satisfied, what failed,
and what has not been addressed at all.

The baseline is computable from data already loaded: ``ccf.controls`` carries
``fisma_low`` / ``fisma_mod`` / ``fisma_high`` membership flags. What it does
**not** carry is one row per control -- rows are assessment objectives and ODP
placeholders (``AC-02f.[01]``, ``AC-06(01)_ODP_02``), so counting them
overstates a baseline roughly fourfold. :func:`fold_to_control` reduces a row
identifier to the control it belongs to, keeping enhancements distinct because
a baseline names them separately.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..catalog.crosswalk import (
    CROSSWALK_COLUMN,
    CROSSWALK_FRAMEWORK,
    practices_for_controls,
)
from ..models import (
    Control,
    ControlImplementation,
    Framework,
    FrameworkMapping,
    ScoringControl,
    ScoringStatus,
    System,
    SystemProfile,
)
from ..models_grc import ControlTest
from ..posture.attested import CHECK_SOURCE as ATTESTED_CHECK_SOURCE
from ..posture.evidence import (
    non_passing_attribution,
    non_passing_practice_attribution,
    pass_attribution,
    pass_practice_attribution,
)
from ..posture.practices import UNMAPPED
from ..scoring.engine import MET_STATES

#: Baseline name -> the catalog column that records membership.
BASELINE_COLUMNS = {
    "low": Control.fisma_low,
    "moderate": Control.fisma_mod,
    "high": Control.fisma_high,
}

#: A catalog row identifier reduced to its control: `AC-02f.[01]` -> `AC-2`,
#: `AC-02(03)(c)` -> `AC-2(3)`. Enhancements survive; objective suffixes and
#: ODP markers do not.
_FOLD = re.compile(r"^([A-Z]{2,3})-0*(\d+)(?:\(0*(\d+)\))?")

#: Implementation statuses that count as the control being addressed.
ADDRESSED_STATUSES = frozenset({"implemented", "inherited", "partially_implemented"})


def fold_to_control(identifier: str) -> str | None:
    """The control a catalog row belongs to, or ``None`` if it names no control."""
    if not identifier:
        return None
    cleaned = identifier.strip().upper().split("_ODP")[0]
    m = _FOLD.match(cleaned)
    if not m:
        return None
    family, number, enhancement = m.group(1), int(m.group(2)), m.group(3)
    return f"{family}-{number}({int(enhancement)})" if enhancement else f"{family}-{number}"


async def baseline_controls(session: AsyncSession, baseline: str) -> set[str]:
    """Every control in a FIPS-199 baseline, folded and deduplicated."""
    column = BASELINE_COLUMNS.get((baseline or "").lower())
    if column is None:
        return set()
    identifiers = (
        await session.execute(select(Control.identifier).where(column.is_(True)))
    ).scalars().all()
    return {c for c in (fold_to_control(i) for i in identifiers) if c}


async def framework_posture(
    session: AsyncSession, *, org_id: int | None, system_id: int
) -> dict[str, Any]:
    """Where one system stands against its declared baseline.

    A control is *satisfied* when a machine test passed or an implementation
    record claims it; *failing* when a machine test failed; and otherwise
    *unaddressed* -- which is the category the product had no way to show, and
    the one a customer most needs, because it is everything nobody has looked
    at yet.
    """
    system = await session.get(System, system_id)
    if system is None or (org_id is not None and system.organization_id != org_id):
        return _empty(None)
    # `baseline` is an enum member at runtime and `str | None` to the checker;
    # getattr covers both without asserting either.
    raw: object = system.baseline
    baseline = str(getattr(raw, "value", raw) or "")
    controls = await baseline_controls(session, baseline)
    if not controls:
        return _empty(baseline or None)

    tested: dict[str, set[str]] = {}
    #: Controls a *passing* check declares but does not credit. A pass credits
    #: only its primary control -- see `ccf.posture.evidence` -- so the rest had
    #: appeared nowhere, and the page called them "not yet addressed" beside the
    #: controls nothing had touched. Tracked to name them, not to credit them.
    declared_by_a_pass: set[str] = set()
    #: Controls credited by a passing *provider attestation* and, separately, by
    #: one of Concord's own checks. The note below is the difference: AWS saying
    #: its control S3.8 passed and that it relates S3.8 to AC-3 is real evidence
    #: and is not Concord having assessed AC-3 -- Concord chose neither the
    #: evaluator nor the mapping. `posture.scan.trust_tier` ranks that for one
    #: verdict; this states it across a whole framework, so a reader can see how
    #: much of the green is Concord's own work.
    passed_by_attestation: set[str] = set()
    passed_by_concord: set[str] = set()
    for control_id, control_ids, status, check_source in (
        await session.execute(
            select(
                ControlTest.control_id,
                ControlTest.control_ids,
                ControlTest.last_status,
                ControlTest.check_source,
            ).where(
                ControlTest.system_id == system_id,
                ControlTest.control_id.is_not(None),
                ControlTest.last_status.is_not(None),
            )
        )
    ).all():
        # A failing check is a finding against every control it declares; a
        # passing one credits only its primary control. `ccf.posture.evidence`
        # owns that asymmetry and explains it.
        attributed = (
            pass_attribution(control_id)
            if status == "pass"
            else non_passing_attribution(control_id, control_ids)
        )
        for attributed_id in attributed:
            folded = fold_to_control(attributed_id)
            if folded:
                tested.setdefault(folded, set()).add(status)
        if status == "pass":
            for declared in non_passing_attribution(control_id, control_ids):
                folded = fold_to_control(declared)
                if folded:
                    declared_by_a_pass.add(folded)
            # Keyed off the credited control, not the declared tuple: the note
            # qualifies what appears in `passing`, and only a primary control is
            # credited by a pass.
            credited = fold_to_control(pass_attribution(control_id)[0]) if control_id else None
            if credited:
                if check_source == ATTESTED_CHECK_SOURCE:
                    passed_by_attestation.add(credited)
                else:
                    passed_by_concord.add(credited)

    implemented = {
        folded
        for identifier, status in (
            await session.execute(
                select(Control.identifier, ControlImplementation.status)
                .join(Control, Control.id == ControlImplementation.control_id)
                .where(ControlImplementation.system_id == system_id)
            )
        ).all()
        if status in ADDRESSED_STATUSES and (folded := fold_to_control(identifier))
    }

    # A control with any failing test is failing, whatever else claims it: a
    # documented implementation does not survive evidence that it is not
    # operating. That is the opposite precedence from the KSI rule, which only
    # ever *adds* satisfaction -- there, a rule must not overrule an assessor;
    # here, the customer is being told what to fix.
    failing = {c for c, statuses in tested.items() if "fail" in statuses} & controls
    # `"pass" in statuses` rather than `statuses == {"pass"}`. The equality form
    # meant any other verdict on the same control -- most often a
    # `manual_review_required` from a second check -- knocked it out of
    # `passing` *and* out of `failing`, so a control one check had satisfied was
    # reported as untouched. Failing still outranks everything, above.
    passing = {c for c, statuses in tested.items() if "pass" in statuses} & controls - failing
    # Looked at and could not be judged. Reported on its own because it is the
    # actionable bucket -- these are the controls needing human evidence -- and
    # because sweeping it into `unaddressed` said nobody had looked when Concord
    # had looked and said so.
    manual_review = (
        {c for c, statuses in tested.items() if "manual_review_required" in statuses}
        & controls
    ) - failing - passing
    documented = (implemented & controls) - failing - passing - manual_review
    unaddressed = controls - failing - passing - documented - manual_review
    # A note on the remainder rather than a sixth bucket: the five above still
    # partition the framework, and this says which part of `unaddressed` carries
    # passing machine evidence that does not amount to credit.
    partially_evidenced = (declared_by_a_pass & controls) & unaddressed
    # "Only AWS", not "AWS at all": an attestation agreeing with Concord's own
    # passing check is not a caveat, and listing it would make the note grow
    # with coverage until it meant nothing.
    provider_attested_only = (passed_by_attestation - passed_by_concord) & passing

    return {
        "baseline": baseline,
        "total": len(controls),
        "passing": sorted(passing),
        "failing": sorted(failing),
        "documented": sorted(documented),
        "manual_review": sorted(manual_review),
        "unaddressed": sorted(unaddressed),
        "partially_evidenced": sorted(partially_evidenced),
        "provider_attested_only": sorted(provider_attested_only),
        "addressed_pct": round(100 * (len(passing) + len(documented)) / len(controls), 1),
        "assessed_pct": round(100 * (len(passing) + len(failing)) / len(controls), 1),
    }


def _empty(baseline: str | None) -> dict[str, Any]:
    return {
        "baseline": baseline,
        "total": 0,
        "passing": [],
        "failing": [],
        "documented": [],
        "manual_review": [],
        "unaddressed": [],
        "partially_evidenced": [],
        "provider_attested_only": [],
        "addressed_pct": 0.0,
        "assessed_pct": 0.0,
    }


# ---------------------------------------------------------------------------
# Which framework applies, and the same answer in that framework's own terms
# ---------------------------------------------------------------------------
#
# `framework_posture` above answers for a FIPS-199 baseline, which is the only
# framework it can express: the denominator comes from `Control.fisma_*`. That
# left the systems most likely to be scanned answering nothing at all. The
# system this was found on declares `NIST_800_171` in its intake profile and
# has **no** FIPS-199 baseline, so the function returned its empty shape -- zero
# controls, zero failing, 0.0% -- which reads on a page and over an API as
# "nothing wrong" rather than "this framework is not one I can measure".
#
# So: resolve the framework a system is actually held to, then answer in that
# framework's units. 800-171 and CMMC Level 2 assess the same 110 requirements,
# and Concord already holds them one row per requirement in `scoring_controls`,
# so the denominator needs no invention. Placing 800-53-keyed scan results onto
# those requirements does need a crosswalk, and `catalog.crosswalk` uses the
# sourced one, reporting what it could not map.


#: Framework codes an intake profile may declare that mean the 110 NIST SP
#: 800-171 requirements. CMMC Level 2 assesses exactly those requirements, so
#: the two share a denominator -- they differ in who assesses and how it is
#: scored, not in what is required.
_NIST_171_CODES = frozenset({"NIST_800_171", "NIST_800_171_R2", "CMMC_L2", "CMMC"})


@dataclass(frozen=True)
class AppliedFramework:
    """The framework a system is held to, and how Concord knows.

    ``source`` is carried because the two ways of knowing are not equally
    strong: a FIPS-199 baseline on the system record is an authorization
    decision, while a framework named in an intake questionnaire is an
    intention someone typed. A consumer that cites this is entitled to know
    which it is reading.
    """

    key: str
    label: str
    #: ``"fips199_baseline"`` or ``"nist_800_171"`` -- what the denominator is.
    denominator: str
    source: str
    baseline: str | None = None


async def resolve_applied_framework(
    session: AsyncSession, system: System
) -> AppliedFramework | None:
    """The framework this system is measured against, or ``None`` if none is set.

    A declared FIPS-199 baseline wins: it is the authorization boundary's own
    categorization, and a system carrying one is being held to 800-53 whatever
    else a questionnaire said. Only when there is no baseline does the intake
    profile's framework list decide.

    ``None`` means no framework is declared -- which a caller must report as
    exactly that. It is the case that produced the original defect: an
    unmeasurable system rendering as a clean one.
    """
    # `baseline` is an enum member at runtime and `str | None` to the checker;
    # getattr covers both without asserting either.
    raw: object = system.baseline
    baseline = str(getattr(raw, "value", raw) or "")
    if baseline.lower() in BASELINE_COLUMNS:
        return AppliedFramework(
            key=f"fedramp_{baseline.lower()}",
            label=f"NIST SP 800-53 Rev. 5, FedRAMP/FISMA {baseline.title()} baseline",
            denominator="fips199_baseline",
            source="system.baseline",
            baseline=baseline.lower(),
        )
    declared = (
        await session.execute(
            select(SystemProfile.frameworks).where(SystemProfile.system_id == system.id)
        )
    ).scalars().first() or []
    for code in declared:
        if str(code).strip().upper() in _NIST_171_CODES:
            return AppliedFramework(
                key="nist_800_171",
                label="NIST SP 800-171 Rev. 2 (110 requirements)",
                denominator="nist_800_171",
                source="profile.frameworks",
            )
    return None


async def _nist_171_posture(
    session: AsyncSession, *, system_id: int, applied: AppliedFramework
) -> dict[str, Any]:
    """Posture against the 110 requirements, from scan results and claimed states.

    Precedence matches the 800-53 path deliberately: a requirement any failing
    test bears on is failing, whatever else claims it. A documented state that
    machine evidence contradicts is not a satisfied requirement.

    Two things are reported that the baseline path has no equivalent for:
    ``unmapped_checks`` names checks whose verdict places no requirement,
    and ``unreachable`` names requirements no 800-53 control maps to at all --
    the ceiling on what any scan can evidence here.
    """
    practices = {
        nist_id: control_id
        for nist_id, control_id in (
            await session.execute(
                select(ScoringControl.nist_id, ScoringControl.control_id).where(
                    ScoringControl.nist_id.is_not(None)
                )
            )
        ).all()
    }
    if not practices:
        return _empty_framework(applied, reason="the 800-171 requirement matrix is not loaded")

    # `tested` used to be built here and never read -- three writes, no reader,
    # and the crosswalk write below used a `status` leaked from the loop above it
    # rather than the row's own. Removed rather than fixed: a dict nobody reads
    # cannot be verified by anything, so the wrong value in it would have stayed
    # wrong until some later reader trusted it. `by_requirement` is the one this
    # path actually measures from.
    #
    # Requirements a verdict bears on come from the check's **authored** mapping,
    # not from the catalog crosswalk.
    #
    # Both existed, and they disagreed. On a live system the dashboard called
    # 3.1.1, 3.1.5, 3.1.6, 3.5.1 and 3.5.3 failing while the SSP reported 3.1.1,
    # 3.1.5, 3.5.3 and 3.5.6 -- two surfaces, one system, different answers. The
    # crosswalk is a *relatedness* map: `IA-2` relates to 3.5.1 ("Identify system
    # users"), 3.5.2 and 3.5.3, so a failing MFA-registration check marked 3.5.1
    # failing, a requirement it never observed. `CHECK_PRACTICES` says what the
    # check asserts and quotes the requirement text beside each entry.
    #
    # This narrows what is reported as failing, which is the point: the narrower
    # set is the one the evidence supports. Checks `practices.UNMAPPED`
    # deliberately excludes now reach nothing and are named in `unmapped_checks`,
    # rather than acquiring requirements through a looser map.
    #
    # The crosswalk keeps `unreachable` below, which is a different question and
    # still its own: which requirements no 800-53 control maps to at all -- the
    # ceiling on what any scan could evidence, a fact about the catalog rather
    # than about which checks are registered.
    unmapped_checks: set[str] = set()
    declared_by_a_pass: set[str] = set()
    by_requirement: dict[str, set[str]] = {}
    needs_crosswalk: dict[str, set[str]] = {}
    #: See the baseline path: which passing evidence is AWS's own attestation and
    #: which is Concord's own check, so the note below can say "only AWS" rather
    #: than "AWS at all".
    passed_by_attestation: set[str] = set()
    passed_by_concord: set[str] = set()
    #: control id -> the check_sources whose *passing* verdicts reached it, kept
    #: beside `needs_crosswalk` because the crosswalk expansion happens after
    #: this loop and the row's source is not recoverable there.
    crosswalk_pass_sources: dict[str, set[str]] = {}
    for check_key, control_id, control_ids, status, check_source in (
        await session.execute(
            select(
                ControlTest.check_key,
                ControlTest.control_id,
                ControlTest.control_ids,
                ControlTest.last_status,
                ControlTest.check_source,
            ).where(
                ControlTest.system_id == system_id,
                ControlTest.control_id.is_not(None),
                ControlTest.last_status.is_not(None),
            )
        )
    ).all():
        # Named apart from the `practices` mapping above, which is the
        # requirement matrix rather than this row's attribution.
        declared = (
            pass_practice_attribution(check_key)
            if status == "pass"
            else non_passing_practice_attribution(check_key)
        )
        if declared:
            if status == "pass":
                # Every practice the check declares, not only the credited one.
                for practice in non_passing_practice_attribution(check_key):
                    declared_by_a_pass.add(
                        practice.split("-", 1)[1] if "-" in practice else practice
                    )
            for practice in declared:
                # `CHECK_PRACTICES` is keyed by practice id (`IA.L2-3.5.3`); this
                # view's denominator is the requirement number (`3.5.3`).
                requirement = practice.split("-", 1)[1] if "-" in practice else practice
                by_requirement.setdefault(requirement, set()).add(status)
                if status == "pass":
                    target = (
                        passed_by_attestation
                        if check_source == ATTESTED_CHECK_SOURCE
                        else passed_by_concord
                    )
                    target.add(requirement)
            continue
        if check_key and str(check_key) in UNMAPPED:
            # A deliberate exclusion. Falling through to the crosswalk here would
            # undo the decision recorded in `practices.UNMAPPED` -- that no
            # requirement matches what the check measures without an argument in
            # between -- by reaching one through a looser map.
            unmapped_checks.add(str(check_key))
            continue
        # Everything else: an authored (human) control test, or a check from a
        # pack, neither of which is in the authored table at all. The crosswalk is
        # the only mapping that exists for them, so it is used here and only here.
        attributed = (
            pass_attribution(control_id)
            if status == "pass"
            else non_passing_attribution(control_id, control_ids)
        )
        for attributed_id in attributed:
            needs_crosswalk.setdefault(attributed_id, set()).add(status)
            if status == "pass":
                # Belt and braces, and recorded as such: mutating this guard away
                # is not independently observable, because the note below is
                # restricted to `passing` and a requirement cannot be passing
                # without some row having actually passed it. Kept because the set
                # is named `crosswalk_pass_sources` and a reader should be able to
                # trust that, not because a test fails without it.
                crosswalk_pass_sources.setdefault(attributed_id, set()).add(
                    str(check_source or "")
                )

    mapped, unmappable = await practices_for_controls(session, set(needs_crosswalk))
    for control_id, statuses in needs_crosswalk.items():
        sources = crosswalk_pass_sources.get(control_id, set())
        for requirement in mapped.get(control_id, ()):  # unplaceable contribute nothing
            by_requirement.setdefault(requirement, set()).update(statuses)
            if ATTESTED_CHECK_SOURCE in sources:
                passed_by_attestation.add(requirement)
            if sources - {ATTESTED_CHECK_SOURCE}:
                passed_by_concord.add(requirement)

    # A claimed implementation state, from the SPRS matrix. Only an *assessed*
    # state counts: a state the intake derivation computed from a platform
    # placemat is not somebody's claim about this system (see migration 0089),
    # and crediting it here would put the same unassessed credit into a second
    # report.
    claimed = {
        nist_id
        for nist_id, state, source in (
            await session.execute(
                select(ScoringControl.nist_id, ScoringStatus.state, ScoringStatus.source)
                .join(ScoringStatus, ScoringStatus.scoring_control_id == ScoringControl.id)
                .where(ScoringStatus.system_id == system_id)
            )
        ).all()
        if nist_id and source != "derived" and state in _CLAIMED_STATES
    }

    total = set(practices)
    failing = {r for r, statuses in by_requirement.items() if "fail" in statuses} & total
    # See the baseline path above: the equality form reported a requirement one
    # check had passed as untouched whenever another check could not be judged.
    passing = (
        {r for r, statuses in by_requirement.items() if "pass" in statuses} & total
    ) - failing
    manual_review = (
        {
            r
            for r, statuses in by_requirement.items()
            if "manual_review_required" in statuses
        }
        & total
    ) - failing - passing
    documented = (claimed & total) - failing - passing - manual_review
    unaddressed = total - failing - passing - documented - manual_review
    partially_evidenced = declared_by_a_pass & unaddressed
    provider_attested_only = (passed_by_attestation - passed_by_concord) & passing
    reachable = set((await _crosswalk_reachable(session)) & total)

    return {
        "framework": applied.key,
        "framework_label": applied.label,
        "framework_source": applied.source,
        "denominator": applied.denominator,
        "unit": "requirement",
        "baseline": None,
        "total": len(total),
        "passing": sorted(passing, key=_requirement_sort),
        "failing": sorted(failing, key=_requirement_sort),
        "documented": sorted(documented, key=_requirement_sort),
        "manual_review": sorted(manual_review, key=_requirement_sort),
        "unaddressed": sorted(unaddressed, key=_requirement_sort),
        "partially_evidenced": sorted(partially_evidenced, key=_requirement_sort),
        "provider_attested_only": sorted(provider_attested_only, key=_requirement_sort),
        "addressed_pct": round(100 * (len(passing) + len(documented)) / len(total), 1),
        "assessed_pct": round(100 * (len(passing) + len(failing)) / len(total), 1),
        # The honest limits of this view, beside the numbers rather than in a
        # footnote somebody has to go and find.
        "unmapped_checks": sorted(unmapped_checks),
        "unmappable_controls": sorted(unmappable),
        "unreachable": sorted(total - reachable, key=_requirement_sort),
        "practice_ids": {r: practices[r] for r in sorted(total, key=_requirement_sort)},
        "reason": None,
    }


#: SPRS states that count as the requirement being claimed as in place. Mirrors
#: ``scoring.engine._MET`` plus ``partial``, which is what `ssp_present` already
#: treats as present -- restating the set here would let the two drift.
_CLAIMED_STATES = MET_STATES | {"partial"}


def _requirement_sort(requirement: str) -> tuple[int, ...]:
    """``3.10.2`` sorts after ``3.9.1``, which a string sort gets wrong."""
    try:
        return tuple(int(p) for p in requirement.split("."))
    except ValueError:
        return (0,)


async def _crosswalk_reachable(session: AsyncSession) -> set[str]:
    """Every 800-171 requirement some 800-53 control maps to."""
    rows = (
        await session.execute(
            select(Control.identifier)
            .join(FrameworkMapping, FrameworkMapping.control_id == Control.id)
            .join(Framework, Framework.id == FrameworkMapping.framework_id)
            .where(
                Framework.code == CROSSWALK_FRAMEWORK,
                FrameworkMapping.column_key == CROSSWALK_COLUMN,
            )
        )
    ).scalars().all()
    mapped, _ = await practices_for_controls(session, set(rows))
    return {r for reqs in mapped.values() for r in reqs}


def _empty_framework(
    applied: AppliedFramework | None, *, reason: str
) -> dict[str, Any]:
    """No measurable framework -- and the payload says why, in the payload.

    Never zeros alone. A consumer reading ``failing: []`` with no explanation
    concludes nothing is wrong, which is precisely the reading that made this
    worth fixing.
    """
    return {
        "framework": applied.key if applied else None,
        "framework_label": applied.label if applied else None,
        "framework_source": applied.source if applied else None,
        "denominator": applied.denominator if applied else None,
        "unit": None,
        "baseline": applied.baseline if applied else None,
        "total": 0,
        "passing": [],
        "failing": [],
        "documented": [],
        "manual_review": [],
        "unaddressed": [],
        "partially_evidenced": [],
        "addressed_pct": 0.0,
        "assessed_pct": 0.0,
        "unmapped_checks": [],
        "unreachable": [],
        "practice_ids": {},
        "reason": reason,
    }


async def system_framework_posture(
    session: AsyncSession, *, org_id: int | None, system_id: int
) -> dict[str, Any]:
    """One system's scan results, expressed in its own framework's units.

    The API's per-system answer. Resolves the framework first, then measures in
    that framework -- so an 800-171 system is reported over 110 requirements and
    a Moderate system over its 800-53 baseline, rather than one shape being
    forced onto both.
    """
    system = await session.get(System, system_id)
    if system is None or (org_id is not None and system.organization_id != org_id):
        # No name to give: naming a system across a tenant boundary would
        # confirm it exists. `system_id` is the caller's own input, so echoing
        # it discloses nothing.
        return {
            **_empty_framework(None, reason="system not found"),
            "system_id": system_id,
            "system": None,
        }

    # Every path below returns through here, so `system_id` and `system` are on
    # the payload whatever happened. They were once set only after the branches,
    # and the early returns skipped them -- which put entries into the
    # organization-wide list that a consumer could not attribute to a system.
    def _answer(payload: dict[str, Any]) -> dict[str, Any]:
        return {**payload, "system_id": system_id, "system": system.name}

    applied = await resolve_applied_framework(session, system)
    if applied is None:
        return _answer(
            _empty_framework(
                None,
                reason=(
                    "no framework is declared for this system: set a FIPS-199 baseline, "
                    "or name a framework in its intake profile"
                ),
            )
        )
    if applied.denominator == "nist_800_171":
        return _answer(
            await _nist_171_posture(session, system_id=system_id, applied=applied)
        )
    base = await framework_posture(session, org_id=org_id, system_id=system_id)
    if not base["total"]:
        return _answer(
            _empty_framework(
                applied,
                reason=(
                    f"the {applied.baseline} baseline resolves to no controls: "
                    "the 800-53 catalog is not loaded with FIPS-199 membership"
                ),
            )
        )
    return _answer(
        {
            **base,
            "framework": applied.key,
            "framework_label": applied.label,
            "framework_source": applied.source,
            "denominator": applied.denominator,
            "unit": "control",
            "unmapped_checks": [],
            "unreachable": [],
            "practice_ids": {},
            "reason": None,
        }
    )


async def org_framework_posture(
    session: AsyncSession, org_id: int | None
) -> dict[str, Any]:
    """Every live system in the organization, each in its own framework's units.

    ``org_id`` of ``None`` returns the empty shape. That is a **contract**, not
    a security boundary, and the difference is worth stating plainly: because
    ``systems.organization_id`` is ``NOT NULL`` and SQLAlchemy renders
    ``== None`` as ``IS NULL``, deleting the guard makes this return *nothing*
    rather than everything. Mutation testing said so, against an earlier version
    of this docstring that claimed the guard stopped a caller with no
    organization from reading every tenant's posture. It does not, and nothing
    should be read as protected by it. What actually scopes the answer is the
    ``organization_id`` predicate on the query below and the per-system check
    inside :func:`system_framework_posture`.

    There is deliberately **no cross-system total**. Two systems on different
    frameworks have different denominators and different units, and adding a
    requirement count to a control count produces a number that means nothing
    while looking authoritative. What is summed is per framework.
    """
    if org_id is None:
        return {"systems": [], "by_framework": {}, "systems_without_a_framework": []}
    systems = (
        await session.execute(
            select(System)
            .where(System.organization_id == org_id, System.deleted_at.is_(None))
            .order_by(System.id)
        )
    ).scalars().all()

    out: list[dict[str, Any]] = []
    by_framework: dict[str, dict[str, Any]] = {}
    undeclared: list[dict[str, Any]] = []
    for system in systems:
        entry = await system_framework_posture(session, org_id=org_id, system_id=system.id)
        out.append(entry)
        if entry["framework"] is None:
            undeclared.append(
                {"system_id": system.id, "system": system.name, "reason": entry["reason"]}
            )
            continue
        bucket = by_framework.setdefault(
            entry["framework"],
            {
                "label": entry["framework_label"],
                "unit": entry["unit"],
                "systems": 0,
                "total": 0,
                "passing": 0,
                "failing": 0,
                "documented": 0,
                "unaddressed": 0,
            },
        )
        bucket["systems"] += 1
        bucket["total"] += entry["total"]
        for key in ("passing", "failing", "documented", "unaddressed"):
            bucket[key] += len(entry[key])
    return {
        "systems": out,
        "by_framework": by_framework,
        "systems_without_a_framework": undeclared,
    }


__all__ = [
    "ADDRESSED_STATUSES",
    "BASELINE_COLUMNS",
    "AppliedFramework",
    "baseline_controls",
    "fold_to_control",
    "framework_posture",
    "org_framework_posture",
    "resolve_applied_framework",
    "system_framework_posture",
]
