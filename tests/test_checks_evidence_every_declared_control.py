"""A check is evidence about every control it declares, not only the first.

``PostureCheck.control_ids`` is documented as "what it evidences" -- a tuple.
A scan wrote only ``control_ids[0]`` onto the ``ControlTest``, so every other
control a check bears on was invisible to the rollups. The MFA check declares
``IA-2`` and ``IA-2(1)``; ``IA-2(1)`` never failed, never passed, and showed as
unaddressed. The error ran in the direction that looks better: the platform
reported less coverage than it had, and reported clean controls that a failing
check had something to say about.

Migration 0092 records the full tuple. :mod:`ccf.posture.evidence` decides what
a verdict does with it, and the rule is asymmetric on purpose:

* a **non-passing** verdict (``fail``, ``warn``, ``manual_review_required``)
  reaches every declared control -- none of those is evidence of satisfaction;
* a **passing** verdict credits the primary control only -- one narrow check
  must not mark several controls satisfied.

The asymmetry is the part worth attacking, so it is tested from both sides.
"""

from __future__ import annotations

import itertools
from datetime import UTC, datetime

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select

from ccf.analytics.framework_posture import framework_posture
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.fedramp20x.validation import build_context
from ccf.models import Control, Organization, SSPControlEntry, SSPProject, System
from ccf.models_grc import ControlTest, ControlTestResult
from ccf.posture.evidence import (
    evidenced_controls,
    non_passing_attribution,
    pass_attribution,
)
from ccf.ssp.sync import project_scan_sync

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


# ---------------------------------------------------------------------------
# The rule itself
# ---------------------------------------------------------------------------


def test_a_non_passing_verdict_reaches_every_declared_control() -> None:
    assert non_passing_attribution("AC-3", ["AC-3", "AC-6"]) == ["AC-3", "AC-6"]


def test_a_passing_verdict_credits_only_the_primary_control() -> None:
    """The asymmetry. Restricted guest invites are weak evidence for AC-6."""
    assert pass_attribution("AC-3") == ["AC-3"]


def test_pass_attribution_cannot_be_widened_by_its_caller() -> None:
    """There is no parameter to pass the tuple to, so no call site can."""
    import inspect  # noqa: PLC0415

    assert list(inspect.signature(pass_attribution).parameters) == ["control_id"]


def test_a_null_tuple_means_the_primary_control_alone() -> None:
    """Authored tests and rows written before migration 0092 both land here."""
    assert evidenced_controls("AC-2", None) == ["AC-2"]
    assert evidenced_controls("AC-2", []) == ["AC-2"]


def test_the_primary_control_comes_first_and_repeats_collapse() -> None:
    assert evidenced_controls("IA-2", ["IA-2", "IA-2(1)", "IA-2"]) == ["IA-2", "IA-2(1)"]


def test_a_tuple_that_omits_the_primary_is_reported_not_reconciled() -> None:
    """A scan/registry disagreement is data, not something to quietly fix.

    Dropping either side would hide the disagreement. The caller asked what the
    row is evidence about, not which of two records to believe.
    """
    assert evidenced_controls("AC-2", ["AC-17"]) == ["AC-2", "AC-17"]


def test_blank_entries_are_not_controls() -> None:
    assert evidenced_controls("AC-2", ["", "  ", "AC-6"]) == ["AC-2", "AC-6"]
    assert evidenced_controls(None, ["AC-6"]) == ["AC-6"]
    assert evidenced_controls("", None) == []


# ---------------------------------------------------------------------------
# The rule, reaching the rollup a customer reads
# ---------------------------------------------------------------------------


async def _system_with_test(
    *, control_id: str, control_ids: list[str] | None, status: str
) -> tuple[int, int]:
    """A Moderate-baseline system carrying exactly one recorded control test."""
    tag = f"{next(_SEQ)}"
    async with session_scope() as s:
        for identifier in ("AC-03", "AC-06"):
            if (
                await s.execute(select(Control).where(Control.identifier == identifier))
            ).scalar_one_or_none() is None:
                s.add(Control(identifier=identifier, fisma_mod=True))
        org = Organization(name=f"Evidence Org {tag}")
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name=f"Evidence Sys {tag}", baseline="moderate")
        s.add(system)
        await s.flush()
        s.add(
            ControlTest(
                organization_id=org.id,
                system_id=system.id,
                control_id=control_id,
                control_ids=control_ids,
                name="guest invitations are restricted",
                method="connector",
                source="generated",
                check_key="m365.policy.guest_invites_restricted",
                last_status=status,
            )
        )
        await s.flush()
        return org.id, system.id


async def _cleanup(org_id: int) -> None:
    async with session_scope() as s:
        await s.execute(delete(Organization).where(Organization.id == org_id))


@pytest.mark.asyncio
async def test_a_failing_check_fails_every_control_it_declares() -> None:
    org_id, system_id = await _system_with_test(
        control_id="AC-3", control_ids=["AC-3", "AC-6"], status="fail"
    )
    try:
        async with session_scope() as s:
            posture = await framework_posture(s, org_id=org_id, system_id=system_id)
        assert "AC-3" in posture["failing"]
        assert "AC-6" in posture["failing"], (
            "the second declared control is where the understatement lived"
        )
        assert "AC-6" not in posture["unaddressed"]
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_a_passing_check_leaves_its_supporting_controls_unaddressed() -> None:
    """The half that must NOT widen.

    If this ever starts passing AC-6, one narrow tenant setting is marking a
    least-privilege control satisfied in a document an assessor samples.
    """
    org_id, system_id = await _system_with_test(
        control_id="AC-3", control_ids=["AC-3", "AC-6"], status="pass"
    )
    try:
        async with session_scope() as s:
            posture = await framework_posture(s, org_id=org_id, system_id=system_id)
        assert "AC-3" in posture["passing"]
        assert "AC-6" not in posture["passing"]
        assert "AC-6" in posture["unaddressed"]
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_a_check_that_could_not_be_judged_does_not_leave_controls_clean() -> None:
    """`manual_review_required` reaches the whole tuple for the same reason."""
    org_id, system_id = await _system_with_test(
        control_id="AC-3", control_ids=["AC-3", "AC-6"], status="manual_review_required"
    )
    try:
        async with session_scope() as s:
            posture = await framework_posture(s, org_id=org_id, system_id=system_id)
        for control in ("AC-3", "AC-6"):
            assert control not in posture["passing"], control
            assert control not in posture["failing"], control
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_a_row_written_before_the_column_existed_still_reports() -> None:
    """A null `control_ids` must degrade to the primary control, not to nothing."""
    org_id, system_id = await _system_with_test(
        control_id="AC-3", control_ids=None, status="fail"
    )
    try:
        async with session_scope() as s:
            posture = await framework_posture(s, org_id=org_id, system_id=system_id)
        assert "AC-3" in posture["failing"]
    finally:
        await _cleanup(org_id)


# ---------------------------------------------------------------------------
# One rule, every view
# ---------------------------------------------------------------------------
#
# Four places answer "which controls does this scan say something about": the
# framework posture rollup, the SSP statement generator, the SSP evidence sync,
# and the FedRAMP 20x readiness context. They were not answering alike -- the
# posture rollup treated a supporting control as touched while the others did
# not, so the same scan produced a finding against AC-6 on one page and a clean
# AC-6 on another. A reader has no way to tell which is the product's position.
#
# An allowlist guard rather than four assertions: a fifth consumer added later
# is caught without anyone remembering to add a test for it.


def test_every_control_test_rollup_goes_through_the_one_attribution_rule() -> None:
    """Any module folding `ControlTest.control_id` into a per-control view.

    A module that reads the column for some other purpose -- ordering a list,
    filtering by a control the user picked, naming one row -- is not rolling up
    and is listed as an exception with the reason. Adding a name to that list
    is the moment to ask whether it really is one.

    Parsed rather than grepped. A substring scan for the function name passes
    on ``import non_passing_attribution as _npa``, which is the first thing a
    refactor does -- the grep version of this guard was written first and a
    mutation walked straight through it. This resolves the binding through the
    import node and then requires an actual call, so a module that imports the
    rule and never uses it fails too.
    """
    import ast  # noqa: PLC0415
    import pathlib  # noqa: PLC0415

    #: module -> why it reads `control_id` without attributing evidence.
    not_a_rollup = {
        "api/routes/grc.py": "filters a listing by a control the caller named",
        "api/routes/ui_grc.py": "orders a listing",
        "api/routes/posture.py": "renders one test row, not a per-control view",
        "governance/control_tests.py": "names the control in a POA&M title",
        "posture/scan.py": "finds the row for one check",
        "posture/evaluations.py": "orders a listing",
        "analytics/gaps.py": "orders a listing worst-first",
        "api/routes/waivers.py": "matches a waiver to one test",
        "ssp/completeness_query.py": "counts tests per SSP entry, not evidence",
    }
    rule_names = {"non_passing_attribution", "pass_attribution"}

    def calls_the_rule(tree: ast.Module) -> bool:
        bound: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").endswith(
                "posture.evidence"
            ):
                bound |= {a.asname or a.name for a in node.names if a.name in rule_names}
        if not bound:
            return False
        return any(
            isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in bound
            for n in ast.walk(tree)
        )

    src = pathlib.Path(__file__).resolve().parents[1] / "src" / "ccf"
    offenders = []
    for path in sorted(src.rglob("*.py")):
        rel = str(path.relative_to(src))
        if rel in not_a_rollup or rel == "posture/evidence.py":
            continue
        text = path.read_text()
        if "ControlTest.control_id" not in text:
            continue
        if not calls_the_rule(ast.parse(text)):
            offenders.append(rel)

    assert not offenders, (
        "these modules fold ControlTest.control_id into a per-control view without "
        f"calling ccf.posture.evidence: {offenders}. Either route them through it "
        "or add them to not_a_rollup with the reason."
    )


# ---------------------------------------------------------------------------
# The two views that were wired last, asserted by behaviour
# ---------------------------------------------------------------------------
#
# The guard above is structural: it proves these modules call the rule, not
# that calling it changed what they report. A structural guard on its own is
# the failure mode where every module imports the right function and the page
# still says the wrong thing.


async def _scene_with_supporting_control(status: str) -> tuple[int, int, int]:
    """A system, an SSP project, and one check declaring AC-3 **and** AC-6.

    ``AC-6`` is the supporting control throughout: it is never the primary, so
    before ``ccf.posture.evidence`` no view could say anything about it.
    """
    tag = f"{next(_SEQ)}"
    async with session_scope() as s:
        org = Organization(name=f"Views Org {tag}")
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name=f"Views Sys {tag}", baseline="moderate")
        s.add(system)
        await s.flush()
        project = SSPProject(
            organization_id=org.id,
            system_id=system.id,
            customer_name=f"Views {tag}",
            platform="m365",
        )
        s.add(project)
        await s.flush()
        for control_id in ("AC-3", "AC-6"):
            s.add(
                SSPControlEntry(
                    project_id=project.id,
                    control_id=control_id,
                    nist_id=control_id,
                    domain="AC",
                    requirement="restrict access",
                )
            )
        test = ControlTest(
            organization_id=org.id,
            system_id=system.id,
            control_id="AC-3",
            control_ids=["AC-3", "AC-6"],
            name="guest invitations are restricted",
            method="connector",
            source="generated",
            check_key="m365.policy.guest_invites_restricted",
            last_status=status,
        )
        s.add(test)
        await s.flush()
        s.add(
            ControlTestResult(
                control_test_id=test.id,
                status=status,
                run_at=datetime.now(UTC),
                evaluated=1,
                failing=1 if status != "pass" else 0,
            )
        )
        await s.flush()
        return org.id, system.id, project.id


@pytest.mark.asyncio
async def test_the_ssp_evidence_sync_reports_the_supporting_control() -> None:
    org_id, _system_id, project_id = await _scene_with_supporting_control("fail")
    try:
        async with session_scope() as s:
            project = await s.get(SSPProject, project_id)
            out = await project_scan_sync(s, project)
        by_control = {c["control_id"]: c for c in out["controls"]}
        assert by_control["AC-3"]["open_findings"], "the primary control regressed"
        assert by_control["AC-6"]["open_findings"], (
            "the supporting control shows no finding, so this page and the SSP "
            "statement disagree about the same scan"
        )
        assert by_control["AC-6"]["ssp_impact"] == "open_poam_or_finding"
        assert out["summary"]["with_open_findings"] == 2
        assert out["summary"]["ssp_blockers"] == 2
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_the_ssp_evidence_sync_does_not_credit_a_supporting_control() -> None:
    """The half that must not widen, at the level a reader sees."""
    org_id, _system_id, project_id = await _scene_with_supporting_control("pass")
    try:
        async with session_scope() as s:
            project = await s.get(SSPProject, project_id)
            out = await project_scan_sync(s, project)
        by_control = {c["control_id"]: c for c in out["controls"]}
        assert by_control["AC-3"]["passing_evidence"]
        assert not by_control["AC-6"]["passing_evidence"], (
            "one narrow tenant setting just claimed automated evidence for a "
            "least-privilege control"
        )
        assert by_control["AC-6"]["ssp_impact"] == "no_scan_evidence"
        assert out["summary"]["with_passing_evidence"] == 1
    finally:
        await _cleanup(org_id)


async def _readiness_scene(*, second_check_status: str) -> tuple[int, int]:
    """Two checks. One passes **on** AC-6; one fails and merely declares it.

    This shape is what makes the assertion mean anything. A scene with only the
    failing check proves nothing: AC-6 ends up uncredited whether the rule runs
    or not, because nothing credited it in the first place. The first version
    of this test was exactly that, and a mutation narrowing the attribution
    back to the primary control walked through it untouched.
    """
    tag = f"{next(_SEQ)}"
    async with session_scope() as s:
        org = Organization(name=f"Readiness Org {tag}")
        s.add(org)
        await s.flush()
        system = System(
            organization_id=org.id, name=f"Readiness Sys {tag}", baseline="moderate"
        )
        s.add(system)
        await s.flush()
        # Credits AC-6 directly.
        s.add(
            ControlTest(
                organization_id=org.id,
                system_id=system.id,
                control_id="AC-6",
                control_ids=["AC-6", "AC-6(1)"],
                name="default user permissions are restricted",
                method="connector",
                source="generated",
                check_key="m365.policy.default_user_permissions_restricted",
                last_status="pass",
            )
        )
        # Declares AC-6 only as a supporting control.
        s.add(
            ControlTest(
                organization_id=org.id,
                system_id=system.id,
                control_id="AC-3",
                control_ids=["AC-3", "AC-6"],
                name="guest invitations are restricted",
                method="connector",
                source="generated",
                check_key="m365.policy.guest_invites_restricted",
                last_status=second_check_status,
            )
        )
        await s.flush()
        return org.id, system.id


@pytest.mark.asyncio
async def test_readiness_withholds_credit_when_another_check_contradicts_it() -> None:
    """AC-6 passes on its own check and fails as a supporting control.

    The readiness number must lose the credit. Otherwise the FedRAMP 20x view
    reports AC-6 satisfied while the posture page reports it failing, from one
    scan -- and nothing tells a reader which is the product's position.
    """
    org_id, system_id = await _readiness_scene(second_check_status="fail")
    try:
        async with session_scope() as s:
            ctx = await build_context(s, system_id)
        assert ctx.control_tests.get("AC-6") != "pass", (
            "readiness credited a control that a failing check declares"
        )
        assert ctx.control_tests.get("AC-3") != "pass"
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_readiness_keeps_the_credit_when_nothing_contradicts_it() -> None:
    """The control case: with the other check passing, AC-6 stays credited.

    Without this, a rule that simply refused to credit anything would satisfy
    the test above.
    """
    org_id, system_id = await _readiness_scene(second_check_status="pass")
    try:
        async with session_scope() as s:
            ctx = await build_context(s, system_id)
        assert ctx.control_tests.get("AC-6") == "pass"
        assert ctx.control_tests.get("AC-3") == "pass"
    finally:
        await _cleanup(org_id)


@pytest.mark.asyncio
async def test_readiness_still_credits_the_primary_control_on_a_pass() -> None:
    """Guards the direction: the rule must not withhold credit that was earned."""
    org_id, system_id, _project = await _scene_with_supporting_control("pass")
    try:
        async with session_scope() as s:
            ctx = await build_context(s, system_id)
        assert ctx.control_tests.get("AC-3") == "pass"
        assert ctx.control_tests.get("AC-6") != "pass"
    finally:
        await _cleanup(org_id)
