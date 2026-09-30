"""The cycle summary has numbers in it, and says when a step failed.

`scheduler.cycle` is the one line an operator reads to know whether last night's
automation did its job. It was built as::

    {k: (v if isinstance(v, int) else "ok") for k, v in out.items()}

and every result the cycle produces except ``catalog_checks`` is a dict or a
list, so the line read ``collection=ok conmon=ok control_tests=ok ...`` whatever
had happened. Found by turning the scheduler on: the first real cycle logged
all-ok, and only a hand-written probe showed that every step had returned rich
counts the summary threw away.

Three things the old line could not distinguish, each of which an operator needs
to:

* a cycle that evaluated 400 control tests from one that evaluated none;
* a cycle that opened twelve POA&Ms from one that opened none;
* a cycle where a step **failed for every organization** from a clean one --
  each per-tenant step is savepointed, so a failure logs its own warning and
  then contributes nothing to the results, leaving the summary saying ``ok``
  about work that did not happen.

The third is the one worth the most here, so it is tested hardest. A warning
scrolled past above the summary helps only somebody who already suspects
something is wrong.
"""

from __future__ import annotations

from typing import Any

import pytest

from ccf.governance.scheduler import cycle_summary


def _out(**overrides: Any) -> dict[str, Any]:
    """A cycle result in the shape ``run_cycle`` actually returns.

    The keys came from printing a real cycle's result against the dev stack. The
    *types* did not, on the first attempt, and that is the lesson worth keeping:
    ``fedramp20x.drift_events`` was written here as a list because a field with
    that name reads like one, the summary duly called ``len()`` on it, all
    fifteen tests passed, and the production cycle raised ``TypeError`` the first
    time a system actually had drift. Reading the key names and assuming the
    value shapes is how a fixture certifies the wrong contract.
    """
    base: dict[str, Any] = {
        "catalog_checks": 2,
        "step_failures": [],
        "collection": {
            "organizations_processed": [1, 2],
            "connectors_run": ["2:msgraph"],
            "captured": 14,
            "drift": 1,
        },
        "assurance_graph": {"organizations_processed": [1, 2], "nodes": 120, "edges": 340},
        "pack_sync": {
            "organizations_processed": [1, 2],
            "sources": 3,
            "pending": 1,
            "installed": 0,
        },
        "conmon": [
            {
                "organization_id": 1,
                "controls_checked": 40,
                "findings": 6,
                "poams_created": 2,
                "poams_recovered": 1,
                "tasks_created": 3,
                "by_status": {},
                "run_id": 9,
                "notifications_created": 0,
            },
            {
                "organization_id": 2,
                "controls_checked": 60,
                "findings": 9,
                "poams_created": 4,
                "poams_recovered": 0,
                "tasks_created": 1,
                "by_status": {},
                "run_id": 10,
                "notifications_created": 0,
            },
        ],
        "control_tests": [
            {"organization_id": 1, "evaluated": 12, "pass": 8, "fail": 3, "warn": 1},
            {"organization_id": 2, "evaluated": 20, "pass": 15, "fail": 5, "warn": 0},
        ],
        "capability_derive": {
            "organizations_processed": [1, 2],
            "systems": 7,
            "rows_annotated": 55,
        },
        "digest": {},
        # `drift_events` is an int. The first version of this fixture made it a
        # list of dicts, which is what `monitoring.scan` looks like it should
        # return and is not what it does -- so the summary used `len()` on it,
        # every test here passed, and the production cycle crashed as soon as a
        # system actually had drift.
        "fedramp20x": {"systems_scanned": 9, "drift_events": 1, "systems": [1] * 9},
        "global_failures": [],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# The numbers reach the line
# ---------------------------------------------------------------------------


def test_the_summary_carries_the_counts_rather_than_the_word_ok() -> None:
    s = cycle_summary(_out())
    assert s["tests_evaluated"] == 32
    assert s["tests_failed"] == 8
    assert s["tests_warned"] == 1
    assert s["conmon_controls"] == 100
    assert s["conmon_findings"] == 15
    assert s["poams_created"] == 6
    assert s["poams_recovered"] == 1
    assert s["tasks_created"] == 4
    assert s["captured"] == 14
    assert s["connectors_run"] == 1
    assert s["assurance_nodes"] == 120
    assert s["assurance_edges"] == 340
    assert s["fedramp_scanned"] == 9
    assert s["fedramp_drift"] == 1
    assert s["orgs"] == 2
    assert "ok" not in s.values()


def test_a_cycle_that_did_nothing_is_visibly_different_from_one_that_worked() -> None:
    """The distinction the old line could not make.

    An empty cycle is not necessarily wrong -- a tenant with no connector bound
    and nothing due has nothing to do. It has to *look* different, so that a
    deployment which has quietly stopped scanning is visible without anybody
    running a query.
    """
    busy = cycle_summary(_out())
    idle = cycle_summary(
        _out(
            conmon=[],
            control_tests=[],
            collection={
                "organizations_processed": [],
                "connectors_run": [],
                "captured": 0,
                "drift": 0,
            },
            assurance_graph={"organizations_processed": [], "nodes": 0, "edges": 0},
            fedramp20x={"systems_scanned": 0, "drift_events": [], "systems": []},
        )
    )
    assert busy != idle
    assert idle["tests_evaluated"] == 0
    assert idle["conmon_controls"] == 0
    assert idle["captured"] == 0
    assert idle["orgs"] == 0
    # And still reports zero failures: nothing broke, there was just nothing
    # to do. Conflating the two would make an idle deployment look broken and
    # train an operator to ignore the field.
    assert idle["failures"] == 0


# ---------------------------------------------------------------------------
# The case it was blind to
# ---------------------------------------------------------------------------


def test_a_step_that_failed_for_every_org_is_not_reported_as_ok() -> None:
    """The defect, stated as a test.

    Collection raised for both organizations. Each failure was savepointed and
    logged, and neither appears in ``collection`` -- so the results are
    byte-identical to a cycle where collection had nothing to do. Only
    ``step_failures`` separates them.
    """
    failed = cycle_summary(
        _out(
            step_failures=[
                {"organization_id": "1", "step": "collection"},
                {"organization_id": "2", "step": "collection"},
            ],
            collection={
                "organizations_processed": [],
                "connectors_run": [],
                "captured": 0,
                "drift": 0,
            },
        )
    )
    assert failed["failures"] == 2
    assert failed["failed_steps"] == ["collection@1", "collection@2"]


def test_a_failed_global_step_is_named_too() -> None:
    s = cycle_summary(_out(global_failures=["digest", "poll_sources"]))
    assert s["failures"] == 2
    assert s["failed_global_steps"] == ["digest", "poll_sources"]


def test_per_tenant_and_global_failures_are_added_not_shadowed() -> None:
    """Two kinds of failure, one count. Reporting either alone hides the other."""
    s = cycle_summary(
        _out(
            step_failures=[{"organization_id": "1", "step": "conmon"}],
            global_failures=["digest"],
        )
    )
    assert s["failures"] == 2
    assert s["failed_steps"] == ["conmon@1"]
    assert s["failed_global_steps"] == ["digest"]


def test_the_failure_count_is_present_on_a_clean_cycle() -> None:
    """`failures=0` is what makes `failures=7` legible when it arrives.

    A field that appears only on the bad path is one nobody has a habit of
    reading, so it is emitted always -- unlike the *names*, which would be noise
    on every clean cycle.
    """
    s = cycle_summary(_out())
    assert s["failures"] == 0
    assert "failed_steps" not in s
    assert "failed_global_steps" not in s


def test_a_skipped_cycle_says_only_that() -> None:
    """Another replica held the advisory lock. No counts exist to report.

    Emitting the usual fields as zeros here would be the original defect
    inverted: a line that looks like a cycle which ran and found nothing.
    """
    s = cycle_summary({"skipped": "another instance holds the scheduler lock"})
    assert s == {"skipped": "another instance holds the scheduler lock"}


# ---------------------------------------------------------------------------
# Robustness: the summary must not be what breaks the cycle
# ---------------------------------------------------------------------------


def test_a_missing_or_partial_result_does_not_raise() -> None:
    """A step that failed leaves its key absent, and this runs after the failures.

    Raising here would turn a contained per-step failure into a lost cycle --
    the summary is the last thing ``run_cycle`` does, and an exception in it
    escapes into ``_loop``'s handler, so the whole cycle would log as failed.
    """
    assert cycle_summary({})["failures"] == 0
    assert cycle_summary({"conmon": [], "control_tests": []})["tests_evaluated"] == 0
    # A row missing the field the summary sums.
    partial = cycle_summary({"control_tests": [{"organization_id": 1}]})
    assert partial["tests_evaluated"] == 0


@pytest.mark.parametrize("bad", [None, "", {}, "not-a-number", object()])
def test_an_unusable_count_is_zero_and_never_raises(bad: object) -> None:
    """The summary may not be the thing that destroys the report.

    It runs last in ``run_cycle``, after everything is committed, so an
    exception here escapes into ``_loop``'s handler and the whole cycle logs as
    failed -- work that actually succeeded, reported as a failure, which is
    worse than the bad field it was strict about.

    Zero, and a ``scheduler.summary_field_unusable`` warning naming the field.
    Silence would leave a step under-reporting forever with nothing to notice;
    an earlier draft of this test asserted a ``ValueError`` here, which
    contradicted the robustness argument in its own docstring.
    """
    assert cycle_summary({"control_tests": [{"evaluated": bad}]})["tests_evaluated"] == 0


def test_an_unusable_count_is_logged_rather_than_swallowed() -> None:
    """Counting it as zero is only half the answer; saying so is the other half."""
    import structlog  # noqa: PLC0415

    with structlog.testing.capture_logs() as logs:
        cycle_summary(
            {"control_tests": [{"organization_id": 7, "evaluated": "not-a-number"}]}
        )
    events = [entry for entry in logs if entry["event"] == "scheduler.summary_field_unusable"]
    assert events, "an unusable count was silently read as zero"
    assert events[0]["field"] == "evaluated"
    assert events[0]["organization_id"] == "7"


def test_a_usable_count_logs_no_warning() -> None:
    """The warning must mark a real anomaly, not fire on every cycle.

    A warning that appears on healthy traffic trains whoever reads it to ignore
    the one occurrence that matters -- the mutation a test asserting only
    "something was logged" would miss.
    """
    import structlog  # noqa: PLC0415

    with structlog.testing.capture_logs() as logs:
        cycle_summary(_out())
    assert not [e for e in logs if e["event"] == "scheduler.summary_field_unusable"]


# ---------------------------------------------------------------------------
# The wiring, which the tests above do not establish
# ---------------------------------------------------------------------------
#
# Everything above calls `cycle_summary` directly. That proves the function is
# right and says nothing about whether `run_cycle` uses it -- so reverting the
# log call to the old `{k: v if isinstance(v, int) else "ok"}` passed all of
# them. The defect was fully reintroducible with the whole file green, which is
# the failure mode where a fix has tests and the product does not have the fix.


@pytest.mark.asyncio
async def test_run_cycle_logs_the_summary_and_not_the_word_ok(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Drive the real cycle and read the line an operator would read.

    The cycle runs against an empty test database, so every count is zero --
    which is the point: zeros are what the old line could not distinguish from
    work, and `failures` is what it could not distinguish from silence.

    Only ``poll_sources`` is stubbed, because it fetches upstream catalogs over
    HTTP and the suite refuses network. Everything else -- the per-tenant loop,
    the savepoints, the digest, the FedRAMP scan and the log call itself -- is
    the real thing, which is the whole point: what is under test is that
    ``run_cycle`` routes its results through ``cycle_summary``, and stubbing any
    more of it would start testing the stub.
    """
    import structlog  # noqa: PLC0415

    from ccf.governance import scheduler  # noqa: PLC0415

    async def _no_upstream_fetch(*_a: object, **_k: object) -> list[object]:
        return []

    monkeypatch.setattr(scheduler, "poll_sources", _no_upstream_fetch)

    with structlog.testing.capture_logs() as logs:
        await scheduler.run_cycle()

    lines = [entry for entry in logs if entry["event"] == "scheduler.cycle"]
    assert lines, "the cycle logged no summary at all"
    line = lines[-1]

    # The field that only the summary emits, and the one the old line could
    # never have produced.
    assert "failures" in line, (
        "scheduler.cycle carries no failure count -- it is not going through "
        "cycle_summary, so a step that failed for every organization reads clean"
    )
    assert "tests_evaluated" in line
    assert "conmon_findings" in line

    # And the literal the old implementation produced for every non-int result
    # must not appear as a value anywhere on the line.
    assert "ok" not in line.values(), (
        f"scheduler.cycle still flattens results to 'ok': {line}"
    )


def test_the_summary_never_assumes_a_list_where_a_step_returns_a_scalar() -> None:
    """The slip this file already made once, as a standing guard.

    ``cycle_summary`` reads fields out of dicts other modules build. A field
    whose name reads like a collection but holds a count -- ``drift_events`` --
    got ``len()`` called on it: every hand-written test passed, because the
    fixture had invented a list, and the production cycle raised ``TypeError``
    the first time a system had non-zero drift. It survived in isolation too,
    since ``0 or []`` is falsy and a zero took the list branch harmlessly.

    So every field is exercised with **both** shapes. Whatever the summary does
    with a value, it may not be something that only works for one of them.
    """
    scalar_shaped = {
        "catalog_checks": 3,
        "collection": {
            "organizations_processed": [1],
            "connectors_run": ["1:msgraph"],
            "captured": 2,
            "drift": 0,
        },
        "assurance_graph": {"organizations_processed": [1], "nodes": 5, "edges": 7},
        "pack_sync": {"organizations_processed": [1], "sources": 1, "pending": 0, "installed": 0},
        "conmon": [{"organization_id": 1, "controls_checked": 1, "findings": 1}],
        "control_tests": [{"organization_id": 1, "evaluated": 1, "fail": 1, "warn": 0}],
        "capability_derive": {"organizations_processed": [1], "systems": 1, "rows_annotated": 1},
        "fedramp20x": {"systems_scanned": 1, "drift_events": 4, "systems": [1]},
        "step_failures": [],
        "global_failures": [],
    }
    assert cycle_summary(scalar_shaped)["fedramp_drift"] == 4

    # And the shape the real module returns on its early-exit path, where the
    # same field is a zero rather than absent.
    early_exit = dict(scalar_shaped, fedramp20x={"systems_scanned": 0, "drift_events": 0})
    assert cycle_summary(early_exit)["fedramp_drift"] == 0


def test_the_summary_matches_what_the_real_modules_return() -> None:
    """Read the producers' own return shapes instead of trusting this file.

    A fixture is a claim about somebody else's contract. This asserts the claim
    against the source: ``monitoring.scan``'s early-exit literal is the one place
    the shape is written down unambiguously, so if ``drift_events`` ever becomes
    a list the fixture above and the summary both have to change, and this fails
    until they do.
    """
    import inspect  # noqa: PLC0415

    from ccf.fedramp20x import monitoring  # noqa: PLC0415

    source = inspect.getsource(monitoring.scan)
    assert '"drift_events": 0' in source, (
        "monitoring.scan no longer returns drift_events as a scalar; "
        "cycle_summary reads it with int() and the fixture in this file assumes it"
    )
