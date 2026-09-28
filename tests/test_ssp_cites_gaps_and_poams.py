"""An SSP discloses what the platform found wrong, not only what it verified.

Statement generation already cited *passing* control tests -- "verified by
automated testing on <date>". The other half was missing, and its absence had a
direction: a control whose scan failed this morning produced a statement
describing an implementation, with the failure visible nowhere in the document an
assessor reads, and "Implemented" still in the status column beside it.

Three separate facts, deliberately kept apart:

* a **passing** test is evidence and is cited (already worked);
* a **failing or warning** test is an open finding, cited with its POA&M, and it
  downgrades a claimed "Implemented";
* a **manual_review_required** verdict is neither -- Concord could not judge the
  control, so the honest sentence is that it rests on manual evidence.
"""

from __future__ import annotations

import pytest

from ccf.ssp.completeness import BLOCKING_POAM_SEVERITIES, assess
from ccf.ssp.statements import DRAFT_PREFIX, _gap_clause, compose


def _compose(**kw: object) -> tuple[str, bool]:
    base: dict[str, object] = {
        "control_id": "IA-2",
        "requirement": "identify system users",
        "responsibility": "customer",
        "source": "platform:m365",
        "environment": "Microsoft 365 GCC High",
        "services": "Entra ID",
        "mark_draft": False,
    }
    base.update(kw)
    return compose(**base)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# The clause itself
# ---------------------------------------------------------------------------


def test_a_failing_check_is_cited_as_an_open_finding_with_its_poam() -> None:
    clause, blocks = _gap_clause(
        [{"check": "Every user has MFA", "observed_on": "2026-09-26", "poam_id": "12"}],
        None,
    )
    assert "Open finding" in clause
    assert "Every user has MFA failed on 2026-09-26" in clause
    assert "POA&M #12" in clause
    assert blocks is True


def test_a_finding_with_no_poam_says_so_rather_than_going_quiet() -> None:
    """The absence of a POA&M is itself the reportable fact.

    A finding nobody has opened a plan for is the gap an assessor samples on;
    rendering it the same as a tracked one would hide exactly the difference.
    """
    clause, _ = _gap_clause(
        [{"check": "Legacy auth blocked", "observed_on": "2026-09-26"}], None
    )
    assert "no POA&M on file" in clause
    assert "POA&M #" not in clause


def test_an_unassessable_check_is_not_reported_as_a_failure() -> None:
    """Concord could not judge it. Calling that a failure invents a finding."""
    clause, blocks = _gap_clause(None, [{"check": "Audit retention"}])
    assert "Open finding" not in clause
    assert "Not machine-verified" in clause
    assert "rests on manual evidence" in clause
    assert blocks is True


def test_no_gaps_produces_no_clause_at_all() -> None:
    assert _gap_clause(None, None) == ("", False)
    assert _gap_clause([], []) == ("", False)


def test_a_finding_missing_its_date_is_not_cited_undated() -> None:
    """Machine evidence with no date is a claim about an unknown moment.

    The verification clause already refuses to cite one; the finding clause has
    to refuse on the same terms or the document would carry one dated claim and
    one undated one under the same heading.
    """
    clause, blocks = _gap_clause([{"check": "Something", "observed_on": ""}], None)
    assert clause == ""
    assert blocks is False


# ---------------------------------------------------------------------------
# What it does to the statement
# ---------------------------------------------------------------------------


def test_a_statement_with_an_open_finding_does_not_read_as_implemented() -> None:
    text, needs_review = _compose(
        failing=[{"check": "MFA registered", "observed_on": "2026-09-26", "poam_id": "7"}]
    )
    assert "Open finding" in text
    assert "not fully operating as described" in text
    assert needs_review is True


def test_a_finding_forces_review_even_on_an_inherited_control() -> None:
    """An inherited control whose test fails is a contradiction, not a detail.

    Inherited statements are the ones that would otherwise read as already
    evidenced, so this is where silence would do the most damage.
    """
    text, needs_review = _compose(
        responsibility="inherited",
        failing=[{"check": "Physical access", "observed_on": "2026-09-26"}],
    )
    assert "Open finding" in text
    assert needs_review is True


def test_a_finding_forces_review_even_on_a_not_applicable_control() -> None:
    """A control scoped out of the boundary should have nothing to fail."""
    text, needs_review = _compose(
        responsibility="not_applicable",
        failing=[{"check": "Wireless access", "observed_on": "2026-09-26"}],
    )
    assert "Open finding" in text
    assert needs_review is True


def test_findings_are_cited_even_when_captured_configuration_is_suppressed() -> None:
    """`include_captured` is a presentation choice about parameter detail.

    A finding is not presentation. A document that could be asked to omit its own
    open findings would be the wrong document.
    """
    text, _ = _compose(
        include_captured=False,
        captured=[{"odp_key": "mfa", "value": "on", "connector": "msgraph"}],
        verified=[{"check": "Something passing", "observed_on": "2026-09-26"}],
        failing=[{"check": "MFA registered", "observed_on": "2026-09-26"}],
    )
    assert "captured from" not in text, "captured configuration was not suppressed"
    assert "Verified by automated testing" not in text
    assert "Open finding" in text, "an open finding was suppressed with the parameters"


def test_a_finding_marks_the_statement_a_draft_when_drafting_is_on() -> None:
    text, _ = _compose(
        responsibility="inherited",
        mark_draft=True,
        failing=[{"check": "MFA registered", "observed_on": "2026-09-26"}],
    )
    assert text.startswith(DRAFT_PREFIX)


def test_a_clean_control_is_byte_identical_to_before_this_existed() -> None:
    """Every existing call passes neither argument; none may change."""
    with_args, review_a = _compose(failing=None, unassessed=None)
    without, review_b = _compose()
    assert with_args == without
    assert review_a == review_b


def test_passing_and_failing_checks_on_one_control_are_both_disclosed() -> None:
    """A control can have one check passing and another failing.

    Citing only the pass would be the most flattering possible reading of a
    control that is partly broken.
    """
    text, _ = _compose(
        verified=[{"check": "Legacy auth blocked", "observed_on": "2026-09-25"}],
        failing=[{"check": "MFA registered", "observed_on": "2026-09-26"}],
    )
    assert "Verified by automated testing" in text
    assert "Open finding" in text
    assert text.index("Verified by automated testing") < text.index("Open finding")


# ---------------------------------------------------------------------------
# The readiness gate
# ---------------------------------------------------------------------------


def test_an_unmeasured_gate_does_not_read_as_a_cleared_one() -> None:
    """No machine evidence means the conditions could not be observed.

    An empty `readiness_blockers` would otherwise say the same thing as
    "everything checked out" -- the misreading bare zeros produce everywhere in
    this codebase. `readiness_measured` carries the difference, and mutation
    testing is what showed the first version of this test could not tell them
    apart: with the inertness removed, all-zero counts still produced an empty
    list and the test stayed green.
    """
    unmeasured = assess({}, [])
    assert unmeasured["readiness_blockers"] == []
    assert unmeasured["readiness_measured"] is False
    assert unmeasured["not_yet_gated"], "an unmeasured dimension is not disclosed"
    assert "no system linked" in unmeasured["not_yet_gated"][0]

    clean = assess({}, [], machine_evidence={"controls_with_open_findings": 0})
    assert clean["readiness_blockers"] == []
    assert clean["readiness_measured"] is True


def test_an_open_finding_blocks_readiness_without_moving_the_score() -> None:
    """A condition, not a fraction.

    Folding an open finding into a percentage would let a well-filled document
    average it away -- which is backwards: the more complete the package, the
    more an unclosed finding matters.
    """
    plain = assess({}, [])
    gated = assess({}, [], machine_evidence={"controls_with_open_findings": 2})
    assert gated["score"] == plain["score"]
    assert gated["ready"] is False
    assert any("open finding" in b for b in gated["readiness_blockers"])


@pytest.mark.parametrize("severity", BLOCKING_POAM_SEVERITIES)
def test_an_open_high_or_critical_poam_blocks_readiness(severity) -> None:
    gated = assess({}, [], machine_evidence={"open_poams_by_severity": {severity: 1}})
    assert any(severity in b for b in gated["readiness_blockers"])
    assert gated["ready"] is False


def test_a_low_severity_poam_does_not_block_readiness() -> None:
    """Every open POA&M blocking would make the gate unclearable in practice."""
    gated = assess(
        {}, [], machine_evidence={"open_poams_by_severity": {"low": 40, "moderate": 9}}
    )
    assert gated["readiness_blockers"] == []


def test_an_unassessable_control_blocks_readiness() -> None:
    gated = assess({}, [], machine_evidence={"controls_not_machine_verified": 1})
    assert any("could not be assessed" in b for b in gated["readiness_blockers"])


def test_missing_shared_responsibility_template_coverage_blocks_readiness() -> None:
    gated = assess(
        {},
        [],
        machine_evidence={
            "missing_responsibility_templates": [
                {"control_id": "AC.L2-3.1.1", "platform": "aws_govcloud"}
            ]
        },
    )
    assert gated["not_yet_gated"] == []
    assert any("shared-responsibility template" in b for b in gated["readiness_blockers"])


def test_a_complete_document_with_nothing_outstanding_is_ready() -> None:
    """The gate must be clearable, or it is not a gate but a wall."""
    entry = {
        "control_id": "AC-1",
        "implementation_status": ["Not Applicable"],
        "control_origination": ["Service Provider Corporate"],
        "responsible_role": "System Owner",
        "part_narratives": [{"label": "Implementation", "text": "A real written response."}],
        "odp_values": {},
    }
    meta = {
        "system_type": "SaaS",
        "fips199": {"overall": "moderate"},
        "authorization_boundary": "Described.",
        "roles": {
            "system_owner": {"name": "A"},
            "isso": {"name": "B"},
            "authorizing_official": {"name": "C"},
        },
    }
    report = assess(
        meta,
        [entry],
        machine_evidence={
            "controls_with_open_findings": 0,
            "controls_not_machine_verified": 0,
            "open_poams_by_severity": {"low": 3},
        },
    )
    assert report["readiness_blockers"] == []
    assert report["ready"] is True, report

    # And the same document stops being ready the moment a blocker appears. The
    # positive case alone could not prove the gate contributes anything: every
    # other `ready is False` assertion in this file is on a document that is
    # incomplete anyway, so `ready` was already False for a different reason and
    # the gate's own effect was unfalsifiable. Mutation testing said so.
    blocked = assess(
        meta,
        [entry],
        machine_evidence={
            "controls_with_open_findings": 1,
            "controls_not_machine_verified": 0,
            "open_poams_by_severity": {},
        },
    )
    assert blocked["controls_total"] == report["controls_total"]
    assert blocked["score"] == report["score"], "a blocker moved the completeness score"
    assert blocked["readiness_blockers"], "the finding produced no blocker"
    assert blocked["ready"] is False, "an otherwise-complete SSP ignored an open finding"
