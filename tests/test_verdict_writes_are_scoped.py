"""Nobody types a verdict onto someone else's control, or onto a scan's.

Two defects of one shape. A control-test result could be written by a caller
in another organization, because the write paths had no organization predicate
while their read siblings did -- and it could be written by hand onto a test
whose verdict comes from a posture scan, replacing machine evidence with a
typed value indistinguishable from it afterwards.

Every tenancy assertion runs on an unscoped ``session_scope()`` session: RLS is
permissive when ``ccf.current_tenant()`` is NULL, so a refusal observed there
is the code's own predicate and not the database policy.
"""

from __future__ import annotations

import uuid

import pytest

from ccf.db import session_scope
from ccf.governance import control_tests
from ccf.governance.control_tests import ScanOwnedTestError, record_result
from ccf.models import Organization, System
from ccf.models_grc import ControlTest

pytestmark = pytest.mark.usefixtures("fresh_engine")


async def _test_row(*, check_key: str | None) -> tuple[int, int]:
    tag = uuid.uuid4().hex[:8]
    async with session_scope() as s:
        org = Organization(name=f"Verdict Org {tag}")
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name=f"Sys {tag}")
        s.add(system)
        await s.flush()
        t = ControlTest(
            organization_id=org.id,
            system_id=system.id,
            control_id="IA-2",
            name="Every user has an MFA method registered",
            method="automated",
            check_key=check_key,
            last_status="fail",
        )
        s.add(t)
        await s.flush()
        return org.id, t.id


def test_a_scan_owned_test_is_identified_by_its_check_key() -> None:
    """A scan-owned test's result is evidence; a typed value replacing it is
    indistinguishable afterwards."""
    from ccf.governance.control_tests import scan_owned

    assert scan_owned(ControlTest(check_key="m365.identity.mfa_registered")) is True
    assert scan_owned(ControlTest(check_key=None)) is False


def test_both_write_routes_refuse_a_verdict_on_a_scan_owned_test() -> None:
    """Guarded at the HTTP boundary, not inside `record_result`.

    The threat is a person typing a verdict, and only the routes know their
    input came from one -- a scan, the scheduler and the tests are all
    legitimate internal writers. Guarding the writer meant inferring the
    caller from its payload, which refused a scan reporting an empty fleet or
    a resourceless tenant-level failure: a scan being told its own result was
    hand-typed.
    """
    import inspect

    from ccf.api.routes import grc, ui_grc

    for fn in (grc.run_control_test, ui_grc.control_tests_run):
        assert "scan_owned" in inspect.getsource(fn), (
            f"{fn.__name__} accepts a typed verdict on a scan-owned test"
        )


def test_the_writer_itself_stays_open_to_internal_callers() -> None:
    """`record_result` must not refuse: the scan, the scheduler and the
    recovery path all go through it, and a guard there breaks them."""
    import inspect

    assert "ScanOwnedTestError" not in inspect.getsource(record_result)


def test_both_write_routes_go_through_the_single_writer() -> None:
    """`record_result` is documented as deliberately the only writer.

    The JSON route built a `ControlTestResult` directly, so alerting,
    remediation-task creation, recovery and the scan-owned check all behaved
    differently depending on which door the result came through.
    """
    import inspect

    from ccf.api.routes import grc, ui_grc

    for fn in (grc.run_control_test, ui_grc.control_tests_run):
        source = inspect.getsource(fn)
        assert "record_result" in source, f"{fn.__name__} bypasses the single writer"
        assert "ControlTestResult(" not in source, (
            f"{fn.__name__} still constructs a result itself"
        )


def test_both_write_routes_check_the_organization() -> None:
    """Their read siblings always did; the write paths did not."""
    import inspect

    from ccf.api.routes import grc, ui_grc

    assert "t.organization_id != principal.org_id" in inspect.getsource(grc.run_control_test)
    assert "test.organization_id != org" in inspect.getsource(ui_grc.control_tests_run)


def test_the_other_tenant_writes_check_the_organization() -> None:
    """Offboarding a person and tripping an AI kill switch are consequential
    enough that neither should rest on RLS alone."""
    import inspect

    from ccf.api.routes import grc, ui_grc

    assert "p.organization_id != org" in inspect.getsource(ui_grc.personnel_offboard)
    assert "agent.organization_id != org" in inspect.getsource(ui_grc.ai_agents_kill_ui)
    assert "f.organization_id != principal.org_id" in inspect.getsource(grc.update_finding)
