"""Regression: a capability-parented (NULL implementation_id) Evidence row must
not silently zero out ``implemented_without_evidence`` for every tenant.

``x NOT IN (subquery containing NULL)`` is UNKNOWN, never TRUE, in SQL. Since
0067 made ``Evidence.implementation_id`` nullable, a single capability-parented
evidence row anywhere in the database poisons the unguarded subquery in
``governance/insights.py::data_quality`` for *every* organization, not just its
own -- the subquery is not org-scoped. This test is self-contained (its own
``session_scope()``, its own org/system/control) and cleans up on every exit
path so it cannot be masked by ordering against
``test_capability_models.py::test_evidence_may_be_parented_to_a_capability_alone``,
which commits exactly such a row to the shared database without cleanup.
"""

from __future__ import annotations

import itertools

from sqlalchemy import delete

from ccf.db import session_scope
from ccf.governance import insights
from ccf.models import Control, ControlImplementation, Evidence, Organization, System
from ccf.models_capability import Capability

_SEQ = itertools.count()


async def test_capability_parented_null_evidence_does_not_hide_missing_evidence() -> None:
    async with session_scope() as session:
        org = Organization(name=f"NullEvRegOrg-{next(_SEQ)}")
        session.add(org)
        await session.flush()
        sys_ = System(organization_id=org.id, name=f"NullEvRegSys-{next(_SEQ)}")
        session.add(sys_)
        await session.flush()
        ctl = Control(identifier=f"ZZ-{next(_SEQ)}")
        session.add(ctl)
        await session.flush()
        impl = ControlImplementation(system_id=sys_.id, control_id=ctl.id, status="implemented")
        session.add(impl)
        await session.flush()
        impl_id = impl.id
        org_id = org.id

        # A capability-parented evidence row, in a *different* org, whose only
        # parent is the capability (implementation_id IS NULL). This is what
        # 0067 permits and what the buggy NOT IN treats as poisoning every
        # tenant's count, not just this one's.
        cap = Capability(organization_id=org.id, key=f"null-ev-cap-{next(_SEQ)}", title="Cap")
        session.add(cap)
        await session.flush()
        null_ev = Evidence(
            capability_id=cap.id, kind="config_export", title="capability evidence",
            metadata_json={},
        )
        session.add(null_ev)
        await session.flush()
        null_ev_id = null_ev.id

    try:
        async with session_scope() as session:
            dq = await insights.data_quality(session, org_id=org_id)
        check = next(c for c in dq["checks"] if c["check"] == "implemented_without_evidence")
        # The implemented control above has no evidence at all -- the check
        # must still see it, regardless of the unrelated NULL-parented row
        # that exists elsewhere in the database.
        assert check["count"] >= 1, (
            "implemented_without_evidence must not be silently zeroed by a "
            "capability-parented (NULL implementation_id) evidence row"
        )
    finally:
        async with session_scope() as session:
            await session.execute(delete(Evidence).where(Evidence.id == null_ev_id))
            await session.execute(
                delete(ControlImplementation).where(ControlImplementation.id == impl_id)
            )
