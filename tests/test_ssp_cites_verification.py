"""An SSP statement cites what Concord actually tested.

Statements could already fold in captured *configuration* -- a parameter read
from the tenant -- but not whether the control had been **tested**. So a
system whose scans proved legacy authentication blocked said nothing about it,
and the strongest evidence the platform held never reached the document an
assessor reads.
"""

from __future__ import annotations

import pytest

from ccf.ssp.statements import compose

_BASE = {
    "control_id": "AC-17",
    "requirement": "Remote access is authorized and monitored",
    "responsibility": "customer",
    "source": None,
    "environment": "Microsoft 365",
    "services": "Entra ID",
}


def _verified(**over):
    v = {"check": "Legacy authentication is blocked", "observed_on": "2026-09-25"}
    v.update(over)
    return [v]


def test_a_passing_test_is_cited_with_its_date() -> None:
    """Machine evidence with no date is a claim about an unknown moment: an
    assessor has to know whether it was verified today or in March."""
    text, _ = compose(**_BASE, verified=_verified())
    assert "Verified by automated testing against the live environment" in text
    assert "Legacy authentication is blocked" in text
    assert "2026-09-25" in text


def test_a_statement_with_no_testing_says_nothing_about_it() -> None:
    """Both directions, so a clause that always rendered would pass above."""
    text, _ = compose(**_BASE)
    assert "Verified by automated testing" not in text


def test_an_undated_result_is_not_cited() -> None:
    """A citation without a date is not evidence an assessor can use, and
    rendering the check name alone would imply a verification it cannot place."""
    text, _ = compose(**_BASE, verified=_verified(observed_on=""))
    assert "Verified by automated testing" not in text


def test_several_passing_tests_are_all_named() -> None:
    text, _ = compose(
        **_BASE,
        verified=[
            {"check": "Legacy authentication is blocked", "observed_on": "2026-09-25"},
            {"check": "A phishing-resistant method is enabled", "observed_on": "2026-09-24"},
        ],
    )
    assert "Legacy authentication is blocked" in text
    assert "A phishing-resistant method is enabled" in text


def test_verification_is_cited_even_in_the_concise_style() -> None:
    """A concise statement may drop parameter detail, but "we tested this and
    it passed" is the strongest thing the platform can say about a control."""
    text, _ = compose(**_BASE, style="concise", verified=_verified())
    assert "Verified by automated testing" in text


def test_withholding_captures_also_withholds_verification() -> None:
    """`include_captured=False` means "no live evidence in this document", and
    a verification citation is live evidence."""
    text, _ = compose(**_BASE, include_captured=False, verified=_verified())
    assert "Verified by automated testing" not in text


@pytest.mark.asyncio
async def test_a_failing_test_is_never_cited_as_evidence() -> None:
    """A failing test is a finding and belongs in a POA&M.

    An SSP citing its own failures as evidence of implementation would be
    worse than one that stayed silent, so the generator indexes only passing
    tests. Asserted against the generator's query rather than the clause,
    because the clause has no way to know a result failed -- the filter is the
    guard, and it is the one that could be widened by accident.
    """
    import inspect  # noqa: PLC0415

    from ccf.governance import automation  # noqa: PLC0415

    source = inspect.getsource(automation.generate_statements)
    assert 'ControlTest.last_status == "pass"' in source, (
        "the statement generator no longer restricts citations to passing tests"
    )


@pytest.mark.asyncio
async def test_only_this_organizations_live_systems_are_cited() -> None:
    """A citation drawn from another tenant, or from a deleted system, would
    put someone else's evidence into this customer's authorization package."""
    import inspect  # noqa: PLC0415

    from ccf.governance import automation  # noqa: PLC0415

    source = inspect.getsource(automation.generate_statements)
    assert "System.organization_id == project.organization_id" in source
    assert "System.deleted_at.is_(None)" in source
