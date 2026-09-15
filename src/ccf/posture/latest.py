"""One definition of "the latest result", shared by every current-state read.

``0068``'s resource table is append-only history. Read as if it were current
state it answers a different question, and that is not hypothetical: the
``/failing-resources`` endpoint shipped documenting itself as returning
resources *currently* failing while actually returning every resource that had
ever failed, stale observation text included.

The fix is not a filter bolted onto one query. It is having **one** definition
of "latest" that every caller meaning current state joins, so a second,
divergent notion cannot appear the next time someone reads this table.
"""

from __future__ import annotations

from sqlalchemy import Subquery, func, select

from ..models_grc import ControlTestResult


def latest_result_ids() -> Subquery:
    """``(control_test_id, result_id)`` for the most recent result per test.

    ``MAX(id)`` rather than ``MAX(run_at)`` deliberately: two scans in the same
    second tie on ``run_at``, and a tie makes "latest" ambiguous -- which is
    the class of ambiguity that let an append-only table be read as current
    state in the first place. Ids are monotonic per insert and cannot tie.

    Returned as a subquery to be joined, not a list of ids to be passed around:
    the join keeps the whole question in one statement, so a caller cannot
    accidentally scope it to a stale snapshot.
    """
    return (
        select(
            ControlTestResult.control_test_id.label("control_test_id"),
            func.max(ControlTestResult.id).label("result_id"),
        )
        .group_by(ControlTestResult.control_test_id)
        .subquery()
    )
