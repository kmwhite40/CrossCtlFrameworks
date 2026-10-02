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

from sqlalchemy import Subquery, or_, select

from ..models_grc import ControlTest, ControlTestResult

#: ``evidence_ref`` of the result recorded when a check leaves a system's scope
#: (``ccf.posture.scope.withdraw_out_of_scope_checks``). Defined here because the
#: definition of "latest" below has to recognise it, and ``scope`` imports this
#: module rather than the other way round.
OUT_OF_SCOPE_EVIDENCE_REF = "ccf:scope:outside-environment"


def latest_result_ids() -> Subquery:
    """``(control_test_id, result_id)`` for the most recent *informative* result
    per test.

    Picked via a correlated subquery -- one per ``ControlTest``, ordered by
    ``run_at``/``id`` descending, ``LIMIT 1`` -- rather than ``GROUP BY
    MAX(id)`` over the whole result table. The two agree today because
    ``record_result`` never accepts a caller-supplied ``run_at`` (it is always
    ``server_default now()``), so ``run_at`` and ``id`` order identically. They
    would diverge the moment a backfill inserts a result with an older
    ``run_at``, and the correlated form is also the one an index can drive
    directly: ``ix_control_test_results_test_run`` (control_test_id, run_at)
    serves the per-test ``LIMIT 1`` instead of a full-table aggregate.
    ``run_at DESC, id DESC`` breaks a same-instant tie deterministically --
    ids are monotonic per insert and cannot tie.

    ``evaluated == 0`` results (a connector outcome that found nothing -- a
    permissions error, an empty page) are excluded from consideration. Such a
    result carries no resource rows, and letting it become "latest" would make
    ``/failing-resources`` go silent and misreport a collection outage as a
    clean scan, with every prior resource then classified ``disappeared`` and,
    on the next good scan, ``appeared`` -- permanently losing the intervening
    regressed/recovered signal. A test whose only results are all empty simply
    has no entry here, which is correct: there is nothing informative to
    protect or report.

    **One zero-resource result is informative:** the one recorded when a check
    leaves the system's scope (:data:`OUT_OF_SCOPE_EVIDENCE_REF`). It is not an
    outage, it is a determination -- this environment is not measured by that
    provider -- and skipping it would fall back to the last verdict from before
    the environment changed, so an AWS ``pass`` would go on crediting a system
    that is now Microsoft 365. It is matched on the marker rather than on
    ``not_applicable``, because a scan whose collection page came back empty
    also rolls up to ``not_applicable`` with nothing evaluated, and that is
    exactly the outage this exclusion exists for.

    Returned as a subquery to be joined, not a list of ids to be passed around:
    the join keeps the whole question in one statement, so a caller cannot
    accidentally scope it to a stale snapshot.
    """
    latest_id = (
        select(ControlTestResult.id)
        .where(
            ControlTestResult.control_test_id == ControlTest.id,
            or_(
                ControlTestResult.evaluated > 0,
                ControlTestResult.evidence_ref == OUT_OF_SCOPE_EVIDENCE_REF,
            ),
        )
        .order_by(ControlTestResult.run_at.desc(), ControlTestResult.id.desc())
        .limit(1)
        .correlate(ControlTest)
        .scalar_subquery()
    )
    return (
        select(
            ControlTest.id.label("control_test_id"),
            latest_id.label("result_id"),
        )
        .where(latest_id.is_not(None))
        .subquery()
    )
