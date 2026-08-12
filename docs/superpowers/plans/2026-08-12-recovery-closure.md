# Recovery Closure — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `control_tests.record_result` (`src/ccf/governance/control_tests.py:269`) opens a remediation `Task` and a `POAM` when a control test fails or warns, via `_alert_on_failure`. It does nothing at all on `pass` — a control that failed once and has since been fixed keeps an open POA&M until a human closes it by hand, and the same gap exists in conmon's `_upsert_task`/`_upsert_poam` (`src/ccf/governance/conmon.py:200-296`) for the at-risk/overdue path. No test covers the transition either: `tests/test_grc_integration.py:182-219` drives a test straight to `pass` and asserts only `last_status`. The consequence is not merely untidy — a POA&M list nobody trusts is a POA&M list nobody reads, and this one feeds authorization packages. Found by the continuous-verification drift gap analysis; it is Concord's own defect, not a missing ATO Bot capability (that delta is closed).

**The decision this plan implements, and does not soften:** on recovery, **resolve the `Task`, close neither the `Task` nor the `POAM` automatically for the POA&M — the POA&M is surfaced, never auto-closed.** The two objects warrant different treatment because the data model already says so. A `Task` (`models.py:1035`) is an internal work item with a free `String(16)` status vocabulary and no formal gate — nothing downstream cites it, so resolving one automatically when its triggering condition clears is uncontroversial. A `POAM` has a closure gate (`api/routes/poams.py:216`, `_require_closure_gate`): all milestones complete, or dated closure evidence on/after `identified_on`, plus a separation-of-duties `Approval` when auth is enabled — because closing a POA&M is an assertion, in an authorization package, that a weakness is remediated. A single passing control test is not that assertion: it is one observation, possibly of a narrow assertion, possibly transient. This is deliberately asymmetric with `src/ccf/ingest/scanners.py:397`, which *does* auto-close a POA&M absent from the latest scan — a vulnerability missing from a scan is direct evidence the weakness is gone, where a control test passing once is weaker evidence that may cover only part of what the POA&M describes. So on recovery the POA&M gains a **recorded observation** (a dated, result-id-stamped note, mirroring the exact append pattern `scanners.py:410-412` already uses for its own closure note) plus a **notification** via `governance.bus.notify` — the same mechanism `_alert_on_failure` and `conmon.scan` already use for "needs a human's attention," already queryable/markable-read through the existing `/api/notifications` endpoint. No new table, field, or POA&M status value.

**A verified trap this plan designs around.** `record_result` assigns `test.last_status = status` at `control_tests.py:289`, **before** the alert branch at line 292. The previous status must be captured before that assignment or the fail→pass transition is undetectable — read as correct, and is not. Task 1's tests are written to fail if that capture is moved after the assignment.

**A second trap found while reading the code, not in the original design note.** `record_result`'s own docstring claims "shared by the manual UI run action and the scheduler auto-run so the alert + remediation-task behaviour is identical regardless of trigger" — but `run_due` (`control_tests.py:306-353`, the scheduler's own due-test evaluator, invoked every cycle by `governance/scheduler.py:105`) does not call `record_result` at all. It duplicates the same four steps (create `ControlTestResult`, set `last_status`/`last_tested_at`, alert on fail/warn, `bus.emit`) inline. Adding recovery logic only inside `record_result`, as the design doc's own wording implies, would make this entire slice a silent no-op on the scheduler-driven path — the primary automated trigger the module's own header docstring describes ("This module is invoked from the scheduler cycle"). Task 1 fixes this by making `run_due` delegate to `record_result` instead of duplicating it, which also makes the existing docstring's claim true for the first time and deletes the duplicated block. No test in this repo asserts on the duplicated block's slightly different `bus.emit` summary text or hardcoded `actor="scheduler"` (verified by grep), so this refactor is safe.

**Architecture**, in dependency order:

1. **`control_tests.py`'s recovery path** (Task 1): capture `test.last_status` into `previous_status` before it is reassigned; when `previous_status in ("fail", "warn")` and the new `status == "pass"`, call a new `_resolve_on_recovery` helper. It resolves the `Task` found by the exact `dedupe_key` `_alert_on_failure` uses (`f"ctltest-fix:{test.id}"`) — but only if that Task's `status` is still `"open"`, the value auto-creation left it, so a human who has since moved it to any other status is left alone. It surfaces the `POAM` found by the exact `source_ref` `_upsert_poam` uses (`f"control_test:{test.id}"`), scoped by `system_id` and `source` the same way `_upsert_poam` already scopes its own lookup, and still open per `_OPEN_POAM` — appending a dated note to `remediation_plan` (never touching `title`/`weakness`/`severity`/`status`, so a human's edits to those survive) and calling `bus.notify` with a fresh `dedupe_key`. The whole thing runs inside `session.begin_nested()`, wrapped in `try`/`except Exception`, logging a warning on failure — `AsyncSession.rollback()` is not savepoint-scoped and would otherwise unwind the caller's already-flushed, authoritative `ControlTestResult` write. `run_due` is refactored to call `record_result` instead of duplicating its body, so the scheduler path gets the same recovery behavior as the manual/API path for free.
2. **`conmon.py`'s symmetric path** (Task 2): the same shape, triggered when `assess_health` returns `"healthy"` for a control implementation that currently just `continue`s (`conmon.py:125-126`) with no resolve/close logic at all. `_resolve_on_recovery` looks up the Task by `f"conmon:impl:{impl_id}"` and the POA&M by `source_ref == f"conmon:impl:{impl_id}"`, with the identical open-status guard, note-append, and `bus.notify` shape as Task 1 — same savepoint/except/log discipline. Unlike `control_tests.py`, conmon has no persisted "previous health status" field to read before reassignment (health is recomputed fresh every scan, never stored on `ControlImplementation`), so there is no analogous ordering hazard here; the existence-based dedupe lookup is itself sufficient, since a Task/POAM only exists if a prior scan actually went at-risk/overdue. One documented interaction, not a bug: conmon's own `assess_health` treats any *open* `high`/`critical`-severity POA&M as an at-risk signal (`crit = [p for p in open_poams if p.severity in ("high", "critical")]`) — and the POA&M `_upsert_poam` opens for an `overdue` control is stamped `severity="high"`. Since this slice never closes that POA&M, a control that ever went `overdue` cannot itself report `healthy` again on a later scan until a human closes the surfaced POA&M through the gate, even after the original overdue cause (stale evidence, overdue assessment) is fixed — the Task still resolves and the POA&M still gets its observation note, but `assess_health`'s own crit check re-escalates to `at_risk` on the next cycle. This is a correct, deliberate consequence of "never auto-close," not a bug this slice should paper over, and it is called out explicitly in code and docs so a future reader does not "fix" it by weakening the gate. The `at_risk` path (severity `"moderate"`, not in the crit set) reaches `healthy` cleanly and is what Task 2's end-to-end `scan()` test exercises; the direct-call tests exercise `_resolve_on_recovery` itself, which has no branching on the original severity and so needs no duplicate coverage for the overdue case.
3. **Documentation** (Task 3): `docs/ARCHITECTURE.md` gets a new bullet, in the same prose style and immediately after the existing "Closure & remediation loop" bullet (which already documents the assessment-engine's own asymmetric-with-`scanners.py` decision), stating the recovery behavior, the asymmetry, and that pre-existing open items are not retrofitted. `CHANGELOG.md` records the hardening.

**No migration.** No new table, column, or POA&M status value is added — `Task.status`/`closed_at` and `POAM.remediation_plan`/`status` already carry everything this slice needs. Current alembic head is `0060_engine_rls_coverage`; this slice does not touch it.

**Tech Stack:** Python 3.12, SQLAlchemy 2.0 async, Postgres 16, FastAPI, pytest.

**Spec:** [docs/superpowers/specs/2026-08-12-recovery-closure-design.md](../specs/2026-08-12-recovery-closure-design.md)
**Depends on:** the branch state at `185770c` on `feat/evidence-prep-spine`.

## Global Constraints

- **Python** 3.12, `line-length = 100`. **Ruff** selects `["E","F","W","I","UP","B","SIM","N","PL","RUF"]`; `BLE`/`SLF` are **not** selected, so a `# noqa: BLE001` or `# noqa: SLF001` trips `RUF100` (unused noqa) — the `except Exception:` blocks in this slice carry no such noqa comment, since none is needed. `PLC0415` means imports go at module top level, never inside a function body. `RUF059` means an unused unpacked variable gets a leading underscore. Known baseline: **exactly 25 pre-existing `PLR0917`**; this slice adds no new function with more than five positional parameters (both new helpers are keyword-only after `session`/`test`/`impl_id`), so it should add nothing to that count.
- **Types:** `mypy src` is `strict = true`.
- **Logging:** `from ..logging import get_logger` (both `control_tests.py` and `conmon.py` are two levels below `src/ccf/logging.py`, so the relative import is `..logging`); never `import structlog` directly; never `extra={...}` — it collides with reserved `LogRecord` attributes and raises `KeyError`. Pass plain kwargs, matching the existing style at `governance/scheduler.py:86-91` (`log.warning("scheduler.per_tenant_step_failed", org_id=org_id, step="collection", error=str(e)[:200])`). `conmon.py` has no `log`/`get_logger` import today — Task 2 adds it.
- **Tests:** real Postgres on port **5434**, container `ccf-test-db`. `asyncio_mode = "auto"` in `pytest.ini` — new test functions in this plan are written **without** `@pytest.mark.asyncio` (some pre-existing files in this repo still carry the decorator; it is redundant under `asyncio_mode = "auto"` and this plan's new files omit it, matching `tests/test_rls_engine_tables.py`'s convention). DB-touching test modules open with `pytestmark = pytest.mark.usefixtures("fresh_engine")` plus a module-scoped `_migrate` fixture that runs `alembic upgrade head`, matching `tests/test_grc_integration.py`/`tests/test_conmon_poam.py`. **Never run two pytest sessions concurrently.** **Always run pytest in the foreground** — a past implementer backgrounded a long test run, it stalled, and the branch was left uncommitted; do not background it. Venv binaries only: `.venv/bin/pytest`, `.venv/bin/ruff`, `.venv/bin/mypy` — never bare `python3` (system Python is 3.9). **Baseline: 1009 passed, 1 skipped.**
- **Session:** `autoflush=False` (`src/ccf/db.py:88`) — a `SELECT` issued while a pending `add()` is unflushed sees nothing. Both new `_resolve_on_recovery` helpers only ever `SELECT` against rows a *prior*, already-flushed session wrote (the Task/POAM `_alert_on_failure`/`_upsert_task`/`_upsert_poam` created in an earlier call), so no extra flush is needed before their lookups — but `record_result`'s own `await session.flush()` (already present, right after `test.last_status = status`) must keep running **before** the recovery branch, since `_resolve_on_recovery` needs `res.id` (the just-added `ControlTestResult`'s id) for the observation note.
- **Savepoints:** `AsyncSession.rollback()` is **not** savepoint-scoped — it unwinds the whole transaction, not just the failing derived write. Both `_resolve_on_recovery` helpers wrap their entire body in `async with session.begin_nested():`, precedented by `governance/scheduler.py:83-113` (wraps `conmon.scan`/`control_tests.run_due` themselves) and `assessment/engine/service.py:437-444` (`_ensure_poam_for_other_than_satisfied`, "the acceptance→POA&M bridge" — the same "derived write must never cost the authoritative one" shape this plan reuses almost verbatim).
- **Best-effort ≠ silent.** A bare `except Exception: pass` makes "correctly skipped" and "raised and was swallowed" observably identical. Every test in this plan that asserts "nothing happened" also asserts nothing was logged at warning (via `monkeypatch.setattr(<module>.log, "warning", <capture>)`, the exact pattern `tests/test_assessment_dissent_evaluate.py:246-279` and `tests/test_governance_ai.py:372,388` already use), and the one failure-isolation test per task asserts a warning **was** logged with the exact event name.
- **Only auto-created, untouched items act.** Both resolve helpers identify their target exclusively by the `dedupe_key`/`source_ref` the opening code already uses, and only mutate it while it is still in the state auto-creation left it (`Task.status == "open"`; `POAM.status` still in `_OPEN_POAM`). Neither helper ever writes `Task.title`/`description`/`priority` or `POAM.title`/`weakness`/`severity` — only `Task.status`/`closed_at` and `POAM.remediation_plan`, so a human's edit to any other field is never clobbered. This is the same reasoning the acceptance→POA&M bridge (`assessment/engine/service.py:417-488`, `tests/test_assessment_poam_bridge.py:139-187`) established: "found and left alone" there means never overwritten, not never acted on, and the test for it is the same shape here — edit a field, recover, assert the edit survives — never a count-only assertion, which passes against code that overwrites.
- **Asymmetric fixtures.** Wherever two values could be swapped undetected — two orgs' control identifiers, an edited field's before/after value, a POA&M's default vs. human-set severity — the fixture uses two distinct, distinguishable values, never the same value or a same-shaped placeholder twice.
- **Assert against the specific row, not a table.** "Only matching items act" tests query by the specific `dedupe_key`/`source_ref`/org id involved, never a bare count over `Task`/`POAM`, which may be empty or nonzero for unrelated reasons.
- **Mutation discipline.** Every guard in this plan is verified by mutation: delete it, re-run the specific test, confirm it fails for the expected reason, then revert. Each task's final step states this explicitly and instructs reporting plainly if a mutation produces no failure, rather than adjusting the test until it looks right.
- **No retrofit.** Tasks and POA&Ms already open when this ships are untouched by this code — only transitions observed after it ships are acted on. This falls out of the design naturally (nothing here runs against historical data on deploy) and needs no special-casing.
- **No change to the ISSM-08/09 closure gate** (`api/routes/poams.py:216`, `_require_closure_gate`) and no new POA&M status value.
- **Licensing:** independent implementation; no code from the BUSL-licensed ato-bot project.

## File structure

| File | Responsibility |
|---|---|
| `src/ccf/governance/control_tests.py` | `_resolve_on_recovery` (Task resolve + POA&M surface on fail/warn→pass); `record_result` captures `previous_status` before reassignment; `run_due` delegates to `record_result` instead of duplicating it |
| `tests/test_control_test_recovery.py` | New: transition fires, POA&M surfaced not closed, no-op cases + nothing logged, human-edit survival, cross-org scoping, failure isolation, `run_due` delegation |
| `src/ccf/governance/conmon.py` | `_resolve_on_recovery` (same shape, keyed on `conmon:impl:{impl_id}`); `scan()` calls it instead of a bare `continue` on `"healthy"`; new `tasks_resolved`/`poams_recovered` counters in `run.summary` and the returned dict |
| `tests/test_conmon_recovery.py` | New: mirrors the control-test file for the at-risk→healthy transition, plus the documented crit-severity interaction |
| `docs/ARCHITECTURE.md`, `CHANGELOG.md` | Recovery behavior, the asymmetry with `scanners.py`, the crit-severity interaction, no-retrofit statement |

---

### Task 1: `control_tests.py` recovery path — resolve the Task, surface the POA&M, fix `run_due`'s duplication

**Files:**
- Modify: `src/ccf/governance/control_tests.py`
- Create: `tests/test_control_test_recovery.py`

**Interfaces:**
- Produces: `control_tests._resolve_on_recovery(session, test, *, result_id) -> None` (module-private, called only from `record_result`).
- Modifies: `control_tests.record_result` (captures `previous_status` before `test.last_status` reassignment; calls `_resolve_on_recovery` on a fail/warn→pass transition). `control_tests.run_due` (delegates to `record_result` instead of duplicating its write sequence).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_control_test_recovery.py`:

```python
"""Recovery path for control tests (2026-08-12 recovery-closure design):
fail/warn -> pass resolves the remediation Task _alert_on_failure opened and
surfaces (never auto-closes) the POA&M it opened.

A Task is an internal work item with a free status vocabulary and no formal
gate -- auto-resolving one when its triggering condition clears is
uncontroversial. A POA&M has the ISSM-08/09 closure gate
(api/routes/poams.py:216): all milestones complete, or dated closure
evidence, plus a separation-of-duties Approval when auth is enabled --
because closing a POA&M is an assertion, in an authorization package, that a
weakness is remediated. A single passing control test is not that assertion,
so the POA&M instead gains a dated, result-id-stamped observation note (the
same append pattern ingest/scanners.py:410-412 already uses for its own
closure note) and a notification -- surfaced for a human to close through the
gate, never closed here. This is deliberately asymmetric with
ingest/scanners.py:397's scan-absence auto-close: a vulnerability missing
from a scan is direct evidence the weakness is gone; a control test passing
once is weaker evidence that may cover only part of what the POA&M describes.

Both halves act only on the Task/POA&M this machinery itself created,
identified by the exact dedupe_key/source_ref _alert_on_failure/_upsert_poam
use, and only while untouched (Task.status == "open"; POA&M still in
_OPEN_POAM) -- a human's edit to any other field must survive, proven by
changing a field and asserting the change survives, not by a count alone.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance import control_tests
from ccf.models import POAM, Notification, Organization, System, Task
from ccf.models_grc import ConnectorConfig, ControlTest, ControlTestResult

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _make_org_system(session, name: str) -> tuple[int, int]:
    org = Organization(name=name)
    session.add(org)
    await session.flush()
    sysm = System(organization_id=org.id, name=f"{name} system")
    session.add(sysm)
    await session.flush()
    return org.id, sysm.id


async def _make_test(session, org_id: int, sys_id: int, control_id: str) -> ControlTest:
    test = ControlTest(
        organization_id=org_id,
        system_id=sys_id,
        control_id=control_id,
        name=f"Recovery test {control_id}",
        method="manual",
    )
    session.add(test)
    await session.flush()
    return test


async def _reload_test(session, test_id: int) -> ControlTest:
    return (
        await session.execute(select(ControlTest).where(ControlTest.id == test_id))
    ).scalar_one()


async def test_fail_then_pass_resolves_the_task() -> None:
    """The ordering-hazard guard: record_result must capture test.last_status
    into previous_status BEFORE reassigning it (control_tests.py:289), or this
    fails -- if the capture reads the just-reassigned value instead, the
    transition condition (previous_status in ("fail","warn") and
    status == "pass") can never be true and the Task never resolves.
    """
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Recovery TaskResolve Org")
        test = await _make_test(s, org_id, sys_id, "AC-RECOVER-1")
        test_id = test.id

    async with session_scope() as s:
        await control_tests.record_result(
            await _reload_test(s, test_id), status="fail", detail="no evidence"
        )

    async with session_scope() as s:
        await control_tests.record_result(
            await _reload_test(s, test_id), status="pass", detail="fixed"
        )

    async with session_scope() as s:
        dedupe = f"ctltest-fix:{test_id}"
        task = (await s.execute(select(Task).where(Task.dedupe_key == dedupe))).scalar_one()
        assert task.status == "done", "the Task must resolve when the test recovers to pass"
        assert task.closed_at is not None


async def test_recovery_surfaces_the_poam_without_closing_it() -> None:
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Recovery PoamSurface Org")
        test = await _make_test(s, org_id, sys_id, "AC-RECOVER-2")
        test_id = test.id

    async with session_scope() as s:
        await control_tests.record_result(
            await _reload_test(s, test_id), status="fail", detail="no evidence"
        )

    async with session_scope() as s:
        test = await _reload_test(s, test_id)
        res = await control_tests.record_result(test, status="pass", detail="fixed")
        result_id = res.id

    async with session_scope() as s:
        source_ref = f"control_test:{test_id}"
        poam = (
            await s.execute(select(POAM).where(POAM.source_ref == source_ref))
        ).scalar_one()
        assert poam.status == "open", "recovery must never close the POA&M"
        assert poam.remediation_plan is not None
        assert f"result #{result_id}" in poam.remediation_plan
        assert "now passes" in poam.remediation_plan
        notes = (
            await s.execute(
                select(Notification).where(Notification.dedupe_key == f"poam-recovery:{poam.id}")
            )
        ).scalars().all()
        assert len(notes) == 1, "the POA&M must be surfaced via the same notify() mechanism " \
            "_alert_on_failure/conmon.scan already use for 'needs a human's attention'"


@pytest.mark.parametrize("status", ["fail", "warn"])
async def test_no_transition_when_status_repeats(
    status: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """fail->fail and warn->warn must never resolve the Task, and must log
    nothing at warning -- a clean skip must be distinguishable from a
    swallowed exception.
    """
    warn_calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        control_tests.log, "warning", lambda event, **kw: warn_calls.append((event, kw))
    )
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, f"Recovery NoOp {status} Org")
        test = await _make_test(s, org_id, sys_id, f"AC-NOOP-{status.upper()}")
        test_id = test.id

    async with session_scope() as s:
        await control_tests.record_result(
            await _reload_test(s, test_id), status=status, detail="first"
        )
    async with session_scope() as s:
        await control_tests.record_result(
            await _reload_test(s, test_id), status=status, detail="second"
        )

    async with session_scope() as s:
        task = (
            await s.execute(select(Task).where(Task.dedupe_key == f"ctltest-fix:{test_id}"))
        ).scalar_one()
        assert task.status == "open"  # the test never reached "pass" -- no recovery to fire
    assert warn_calls == []


async def test_pass_to_pass_is_a_no_op_and_logs_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    warn_calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        control_tests.log, "warning", lambda event, **kw: warn_calls.append((event, kw))
    )
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Recovery PassPass Org")
        test = await _make_test(s, org_id, sys_id, "AC-PASSPASS-1")
        test_id = test.id

    async with session_scope() as s:
        await control_tests.record_result(
            await _reload_test(s, test_id), status="pass", detail="already fine"
        )
    async with session_scope() as s:
        await control_tests.record_result(
            await _reload_test(s, test_id), status="pass", detail="still fine"
        )

    async with session_scope() as s:
        # No Task/POA&M was ever opened -- there was nothing to resolve.
        assert (
            await s.execute(select(Task).where(Task.dedupe_key == f"ctltest-fix:{test_id}"))
        ).scalar_one_or_none() is None
    assert warn_calls == []


async def test_human_edited_task_and_poam_fields_survive_recovery() -> None:
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Recovery Edited Org")
        test = await _make_test(s, org_id, sys_id, "AC-RECOVER-EDIT")
        test_id = test.id

    async with session_scope() as s:
        await control_tests.record_result(
            await _reload_test(s, test_id), status="fail", detail="no evidence"
        )

    dedupe = f"ctltest-fix:{test_id}"
    source_ref = f"control_test:{test_id}"
    async with session_scope() as s:
        task = (await s.execute(select(Task).where(Task.dedupe_key == dedupe))).scalar_one()
        task.description = "Human note: already investigating, do not touch"
        poam = (await s.execute(select(POAM).where(POAM.source_ref == source_ref))).scalar_one()
        poam.severity = "critical"  # asymmetric -- auto-created default is "high"

    async with session_scope() as s:
        await control_tests.record_result(
            await _reload_test(s, test_id), status="pass", detail="fixed"
        )

    async with session_scope() as s:
        task = (await s.execute(select(Task).where(Task.dedupe_key == dedupe))).scalar_one()
        assert task.description == "Human note: already investigating, do not touch"
        assert task.status == "done"  # still resolves -- only status/closed_at are written
        poam = (await s.execute(select(POAM).where(POAM.source_ref == source_ref))).scalar_one()
        assert poam.severity == "critical"  # the human's edit, not clobbered
        assert poam.status == "open"
        assert "now passes" in (poam.remediation_plan or "")


async def test_only_the_matching_test_is_resolved() -> None:
    async with session_scope() as s:
        org_a, sys_a = await _make_org_system(s, "Recovery Scope Org A")
        org_b, sys_b = await _make_org_system(s, "Recovery Scope Org B")
        test_a = await _make_test(s, org_a, sys_a, "AC-SCOPE-A")
        test_b = await _make_test(s, org_b, sys_b, "AC-SCOPE-B")
        test_a_id, test_b_id = test_a.id, test_b.id

    async with session_scope() as s:
        await control_tests.record_result(
            await _reload_test(s, test_a_id), status="fail", detail="A failing"
        )
        await control_tests.record_result(
            await _reload_test(s, test_b_id), status="fail", detail="B failing"
        )

    async with session_scope() as s:
        # Only test A recovers; test B stays failing.
        await control_tests.record_result(
            await _reload_test(s, test_a_id), status="pass", detail="A fixed"
        )

    async with session_scope() as s:
        task_a = (
            await s.execute(select(Task).where(Task.dedupe_key == f"ctltest-fix:{test_a_id}"))
        ).scalar_one()
        task_b = (
            await s.execute(select(Task).where(Task.dedupe_key == f"ctltest-fix:{test_b_id}"))
        ).scalar_one()
        assert task_a.status == "done", "org A's recovered test must resolve its own task"
        assert task_b.status == "open", "org B's still-failing test's task must be untouched"

        poam_a = (
            await s.execute(select(POAM).where(POAM.source_ref == f"control_test:{test_a_id}"))
        ).scalar_one()
        poam_b = (
            await s.execute(select(POAM).where(POAM.source_ref == f"control_test:{test_b_id}"))
        ).scalar_one()
        assert "now passes" in (poam_a.remediation_plan or "")
        assert poam_b.remediation_plan is None


async def test_recovery_failure_is_isolated_and_logged(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the POA&M-surfacing half to raise. The authoritative
    ControlTestResult write and test.last_status must still persist, the
    savepoint must roll the whole derived update back together (the Task
    must NOT resolve either, since it shares control_tests.py's single
    begin_nested() block with the POA&M write that raised), and a warning
    must be logged -- confirming this test fails if the recovery work is
    moved outside its savepoint (see the mutation check below).
    """
    warn_calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        control_tests.log, "warning", lambda event, **kw: warn_calls.append((event, kw))
    )
    original_notify = control_tests.bus.notify

    async def _maybe_raise(*args, **kwargs):
        if str(kwargs.get("dedupe_key", "")).startswith("poam-recovery:"):
            raise RuntimeError("simulated recovery failure")
        return await original_notify(*args, **kwargs)

    monkeypatch.setattr(control_tests.bus, "notify", _maybe_raise)

    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Recovery Failure Org")
        test = await _make_test(s, org_id, sys_id, "AC-RECOVER-FAIL")
        test_id = test.id

    async with session_scope() as s:
        await control_tests.record_result(
            await _reload_test(s, test_id), status="fail", detail="no evidence"
        )

    async with session_scope() as s:
        # Must not raise -- the ControlTestResult write is authoritative.
        test = await _reload_test(s, test_id)
        await control_tests.record_result(test, status="pass", detail="fixed")
        assert test.last_status == "pass"

    async with session_scope() as s:
        test = await _reload_test(s, test_id)
        assert test.last_status == "pass"
        results = (
            await s.execute(
                select(ControlTestResult).where(ControlTestResult.control_test_id == test_id)
            )
        ).scalars().all()
        assert {r.status for r in results} == {"fail", "pass"}
        task = (
            await s.execute(select(Task).where(Task.dedupe_key == f"ctltest-fix:{test_id}"))
        ).scalar_one()
        assert task.status == "open"  # rolled back with the rest of the savepoint
    assert any(event == "control_tests.recovery_failed" for event, _ in warn_calls)


async def test_run_due_also_resolves_a_recovered_task() -> None:
    """run_due (the scheduler's own due-test evaluator) must get the same
    recovery behaviour as record_result. Before this task it duplicated
    record_result's write sequence inline instead of calling it, which would
    have made this whole slice a no-op on the scheduler-driven path -- this
    test fails if that delegation regresses back to a duplicated inline write.
    """
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Recovery RunDue Org")
        conn = ConnectorConfig(
            organization_id=org_id,
            name="Prod AWS GovCloud",
            connector_type="aws_govcloud",
            status="configured",
            last_sync=datetime.now(UTC),
            objects_discovered=0,  # 0 objects -> evaluate_test returns "fail"
        )
        s.add(conn)
        test = ControlTest(
            organization_id=org_id,
            system_id=sys_id,
            control_id="AC-RUNDUE-RECOVER",
            name="Run-due recovery test",
            method="connector",
            connector_type="aws_govcloud",
            frequency="daily",
            active=True,
        )
        s.add(test)
        await s.flush()
        test_id, conn_id = test.id, conn.id

    async with session_scope() as s:
        await control_tests.run_due(s, today=datetime.now(UTC).date())
    async with session_scope() as s:
        test = await _reload_test(s, test_id)
        assert test.last_status == "fail"  # 0 objects -> fail, opens the task/poam

    async with session_scope() as s:
        conn = (
            await s.execute(select(ConnectorConfig).where(ConnectorConfig.id == conn_id))
        ).scalar_one()
        conn.objects_discovered = 12
        conn.last_sync = datetime.now(UTC)
        test = await _reload_test(s, test_id)
        test.last_tested_at = datetime.now(UTC) - timedelta(days=2)  # due again

    async with session_scope() as s:
        await control_tests.run_due(s, today=datetime.now(UTC).date())

    async with session_scope() as s:
        test = await _reload_test(s, test_id)
        assert test.last_status == "pass"
        task = (
            await s.execute(select(Task).where(Task.dedupe_key == f"ctltest-fix:{test_id}"))
        ).scalar_one()
        assert task.status == "done", "run_due must delegate to record_result for recovery too"
```

- [ ] **Step 2: Run the tests to verify failure**

Run: `.venv/bin/pytest tests/test_control_test_recovery.py -v`
Expected: FAIL — every test that expects `task.status == "done"` fails on `AssertionError` (Task stays `"open"`, since nothing resolves it today); `test_recovery_surfaces_the_poam_without_closing_it` fails on the `Notification` lookup (`scalar_one()` raises `NoResultFound`, since nothing calls `bus.notify` for a recovery); `test_run_due_also_resolves_a_recovered_task` fails the same way. The no-op tests (`test_no_transition_when_status_repeats`, `test_pass_to_pass_is_a_no_op_and_logs_nothing`) already pass today (there is genuinely nothing to do), which is expected and fine.

- [ ] **Step 3: Implement the recovery path in `control_tests.py`**

In `src/ccf/governance/control_tests.py`, add `_resolve_on_recovery` immediately after `_upsert_poam` (before `record_result`):

```python
async def _resolve_on_recovery(
    session: AsyncSession, test: ControlTest, *, result_id: int
) -> None:
    """Best-effort recovery bookkeeping when a test transitions fail/warn -> pass.

    Resolves the remediation Task _alert_on_failure opened -- an internal
    work item with a free status vocabulary and no formal gate, so
    auto-resolving it once its triggering condition clears is
    uncontroversial. The POA&M is deliberately NOT auto-closed: closing a
    POA&M is an assertion, in an authorization package, that a weakness is
    remediated, and a single passing control test is one observation --
    possibly of a narrow assertion, possibly transient -- not that
    assertion. This is deliberately asymmetric with
    ingest/scanners.py:397's scan-absence auto-close: a vulnerability
    missing from a scan is direct evidence the weakness is gone, where a
    control test passing once is weaker evidence that may cover only part
    of what the POA&M describes. Instead the POA&M gains a dated,
    result-id-stamped observation note (the same append pattern
    ingest/scanners.py:410-412 already uses for its own closure note) and a
    notification, so a human sees it and can close it through
    api/routes/poams.py's ISSM-08/09 gate with the evidence that gate
    demands.

    Runs in its own SAVEPOINT (AsyncSession.rollback() is NOT
    savepoint-scoped -- it would unwind the caller's authoritative
    ControlTestResult write) and swallows+logs any failure rather than
    propagating it: losing the resolution is recoverable; discarding a
    recorded test result because a derived update failed is not.

    Only acts on the Task/POA&M this machinery itself created, identified
    by the exact dedupe_key/source_ref _alert_on_failure/_upsert_poam use
    for this test -- and only while they are still in the state
    auto-creation left them (Task.status == "open"; POA&M still in
    _OPEN_POAM) -- and only ever writes Task.status/closed_at and
    POAM.remediation_plan, never title/description/priority/weakness/
    severity, so a human's edit to any of those survives untouched.
    """
    try:
        async with session.begin_nested():
            task_dedupe = f"ctltest-fix:{test.id}"
            task = (
                await session.execute(select(Task).where(Task.dedupe_key == task_dedupe))
            ).scalar_one_or_none()
            if task is not None and task.status == "open":
                task.status = "done"
                task.closed_at = datetime.now(UTC)

            if test.system_id is None:
                return  # org-wide test never had a POA&M to surface (see _upsert_poam)
            source_ref = f"control_test:{test.id}"
            poam = (
                await session.execute(
                    select(POAM).where(
                        POAM.system_id == test.system_id,
                        POAM.source == "control_test",
                        POAM.source_ref == source_ref,
                        POAM.status.in_(_OPEN_POAM),
                    )
                )
            ).scalar_one_or_none()
            if poam is None:
                return
            note = (
                f"Control test '{test.name}' now passes as of "
                f"{datetime.now(UTC).isoformat()} (result #{result_id}) -- review for closure."
            )
            poam.remediation_plan = (
                f"{poam.remediation_plan}\n{note}" if poam.remediation_plan else note
            )
            await bus.notify(
                session,
                category="conmon",
                title=f"Control test recovered: {test.name} ({test.control_id})",
                body=note,
                org_id=test.organization_id,
                severity="info",
                entity_type="poam",
                entity_id=poam.id,
                dedupe_key=f"poam-recovery:{poam.id}",
            )
    except Exception as exc:
        log.warning(
            "control_tests.recovery_failed",
            control_test_id=test.id,
            error=str(exc)[:200],
        )
```

Update `record_result` to capture `previous_status` before reassignment and call the new helper on recovery:

```python
async def record_result(
    session: AsyncSession,
    test: ControlTest,
    *,
    status: str,
    detail: str | None = None,
    evidence_ref: str | None = None,
    actor: str = "user",
) -> ControlTestResult:
    """Persist one test result, update the test, and alert on fail/warn.

    Shared by the manual UI run action and the scheduler auto-run (run_due
    delegates here) so the alert + remediation-task + recovery behaviour is
    identical regardless of trigger.
    """
    if status not in ("pass", "warn", "fail"):
        raise ValueError("status must be pass|warn|fail")
    # Must be captured before the reassignment two lines below -- if this
    # instead read test.last_status after the assignment, it would always
    # equal `status` and the fail/warn -> pass transition would be
    # permanently undetectable.
    previous_status = test.last_status
    res = ControlTestResult(
        control_test_id=test.id, status=status, detail=detail, evidence_ref=evidence_ref
    )
    session.add(res)
    test.last_status = status
    test.last_tested_at = datetime.now(UTC)
    await session.flush()
    if status in ("fail", "warn"):
        await _alert_on_failure(session, test, status, detail or "")
    elif status == "pass" and previous_status in ("fail", "warn"):
        await _resolve_on_recovery(session, test, result_id=res.id)
    await bus.emit(
        session,
        verb="tested",
        entity_type="control_test",
        entity_id=test.id,
        summary=f"Control test {status}: {test.control_id}",
        org_id=test.organization_id,
        actor=actor,
    )
    return res
```

Replace `run_due`'s duplicated write sequence with a delegation to `record_result`:

```python
async def run_due(
    session: AsyncSession, *, today: date | None = None, org_id: int | None = None
) -> dict[str, Any]:
    """Auto-run every due connector-backed test. Returns per-status counts.

    With ``org_id`` set (the scheduler's per-tenant loop), scoped to that one
    organization's tests only — paired with ``set_session_tenant`` by the
    caller so RLS backstops this filter. ``org_id=None`` runs across every
    organization's tests (used by direct/manual invocations).
    """
    today = today or datetime.now(UTC).date()
    stmt = select(ControlTest).where(
        ControlTest.active.is_(True), ControlTest.method == "connector"
    )
    if org_id is not None:
        stmt = stmt.where(ControlTest.organization_id == org_id)
    tests = (await session.execute(stmt)).scalars().all()
    counts = {"evaluated": 0, "pass": 0, "warn": 0, "fail": 0}
    for test in tests:
        if not _is_due(test, today):
            continue
        status, detail, evidence_ref = await evaluate_test(session, test, today)
        await record_result(
            session, test, status=status, detail=detail, evidence_ref=evidence_ref,
            actor="scheduler",
        )
        counts["evaluated"] += 1
        counts[status] += 1
    if counts["evaluated"]:
        log.info("control_tests.auto_run", **counts)
    return counts
```

This deletes the duplicated `ControlTestResult` creation, `last_status`/`last_tested_at` assignment, `_alert_on_failure` call, and `bus.emit` call that `run_due` previously ran inline — `record_result` now does all of it, including the new recovery branch. `bus.emit`'s summary text for the scheduler path changes from `"Auto-run control test {status}: ..."` to `"Control test {status}: ..."`; grep confirms no test in this repo asserts on that string.

- [ ] **Step 4: Run tests, verify gates, commit**

```bash
.venv/bin/pytest tests/test_control_test_recovery.py -v          # 9 collected tests pass (7 functions + 2 parametrized cases)
.venv/bin/pytest tests/test_grc_integration.py tests/test_conmon_poam.py tests/test_control_test_assertions.py -v   # no regression from the run_due refactor
.venv/bin/pytest -q          # run alone, foreground; confirm no regression from the 1009 passed, 1 skipped baseline plus the 9 new tests; cite the actual count in the commit if it differs
.venv/bin/ruff check . && .venv/bin/mypy src
```

**Mutation check (all four required):**

1. *The ordering hazard.* Move `previous_status = test.last_status` to immediately after `test.last_status = status` (so it reads the just-assigned value). Re-run `tests/test_control_test_recovery.py::test_fail_then_pass_resolves_the_task` — confirm it now fails (`task.status` stays `"open"`, since `previous_status` now always equals `status` and the transition condition can never be true). Revert.
2. *The savepoint.* In `_resolve_on_recovery`, replace `async with session.begin_nested():` with a plain `if True:` (dedent the body, no savepoint). Re-run `tests/test_control_test_recovery.py::test_recovery_failure_is_isolated_and_logged` — confirm it now fails, since without a savepoint the failed `bus.notify` call leaves the session's transaction in an inconsistent state rather than cleanly rolling back only the recovery work (the outer `except Exception` still catches the Python exception, but the DB-level state the assertions check is no longer what the test expects). Revert.
3. *The best-effort swallow.* In `_resolve_on_recovery`, remove the `try`/`except` (let the `RuntimeError` from the mocked `bus.notify` propagate). Re-run `tests/test_control_test_recovery.py::test_recovery_failure_is_isolated_and_logged` — confirm `record_result` now raises instead of returning normally (the authoritative `ControlTestResult` write would no longer be protected). Revert.
4. *The untouched-only guard.* In `_resolve_on_recovery`, remove the `and task.status == "open"` condition (resolve unconditionally whenever the Task exists). Re-run `tests/test_control_test_recovery.py::test_human_edited_task_and_poam_fields_survive_recovery` — this specific test doesn't touch `Task.status`, so it will still pass; instead add a temporary local assertion (or run interactively) confirming a Task a human has moved to a *different* status (e.g. `"in_progress"`) now gets silently flipped to `"done"` too — report this plainly rather than leaving the guard removed. Revert.

```bash
git add src/ccf/governance/control_tests.py tests/test_control_test_recovery.py
git commit -m "feat(governance): resolve the remediation Task and surface the POA&M when a control test recovers"
```

---

### Task 2: `conmon.py` — the same symmetry for at-risk/overdue → healthy

**Files:**
- Modify: `src/ccf/governance/conmon.py`
- Create: `tests/test_conmon_recovery.py`

**Interfaces:**
- Produces: `conmon._resolve_on_recovery(session, *, org_id, impl_id, system_id) -> tuple[bool, bool]` (module-private, called only from `scan()`; returns `(task_resolved, poam_recovered)` for the new counters).
- Modifies: `conmon.scan()` (calls the new helper instead of a bare `continue` on `"healthy"`; adds `tasks_resolved`/`poams_recovered` to `run.summary` and the returned dict).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_conmon_recovery.py`:

```python
"""Recovery path for ConMon (2026-08-12 recovery-closure design): a control
implementation returning to "healthy" resolves the remediation Task
_upsert_task opened and surfaces (never auto-closes) the POA&M _upsert_poam
opened -- the same shape as tests/test_control_test_recovery.py, keyed on
conmon's own conmon:impl:{impl_id} dedupe_key/source_ref convention.

Unlike control_tests.py, conmon has no persisted "previous health status" on
ControlImplementation -- assess_health recomputes health fresh every scan --
so there is no ordering hazard to guard here; the existence-based dedupe
lookup is sufficient on its own, since a Task/POA&M only exists if a prior
scan actually went at-risk/overdue.

One documented, deliberate interaction: assess_health treats any OPEN
high/critical-severity POA&M as its own at-risk signal, and the POA&M
_upsert_poam opens for an "overdue" control is severity="high" -- so a
control that ever went overdue cannot report "healthy" again until a human
closes that POA&M, even after the original overdue cause is fixed. The Task
still resolves and the POA&M still gets its observation note; assess_health's
crit check simply re-escalates on the next scan. _resolve_on_recovery has no
branching on the original severity, so the at_risk path (severity="moderate",
outside the crit set) is what exercises the full scan()-level transition
below; the overdue interaction is documented, not separately re-tested, since
the resolve function's own behavior does not differ by cause.
"""

from __future__ import annotations

from datetime import date, timedelta

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance import conmon
from ccf.models import POAM, Control, ControlImplementation, Notification, Organization, System, Task

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _make_org_system(session, name: str) -> tuple[int, int]:
    org = Organization(name=name)
    session.add(org)
    await session.flush()
    sysm = System(organization_id=org.id, name=f"{name} system")
    session.add(sysm)
    await session.flush()
    return org.id, sysm.id


async def _at_risk_impl(session, sys_id: int, identifier: str) -> ControlImplementation:
    """not_implemented with no evidence/assessment-due signal -> at_risk with
    a moderate-severity POA&M (outside assess_health's crit check), so it can
    cleanly reach "healthy" once fixed -- see the module docstring's note on
    the overdue/crit-severity interaction this deliberately avoids.
    """
    ctrl = Control(identifier=identifier, control_name="Test control")
    session.add(ctrl)
    await session.flush()
    impl = ControlImplementation(system_id=sys_id, control_id=ctrl.id, status="not_implemented")
    session.add(impl)
    await session.flush()
    return impl


async def _reload_impl(session, impl_id: int) -> ControlImplementation:
    return (
        await session.execute(
            select(ControlImplementation).where(ControlImplementation.id == impl_id)
        )
    ).scalar_one()


async def test_healthy_transition_resolves_the_task() -> None:
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Conmon Recovery TaskResolve Org")
        impl = await _at_risk_impl(s, sys_id, "AC-CONMON-RECOVER-1")
        impl_id = impl.id

    async with session_scope() as s:
        result = await conmon.scan(s, today=date.today(), org_id=org_id)
        assert result["findings"] >= 1  # opens the Task/POA&M

    async with session_scope() as s:
        impl = await _reload_impl(s, impl_id)
        impl.status = "implemented"  # fixes the at_risk trigger

    async with session_scope() as s:
        result = await conmon.scan(s, today=date.today() + timedelta(days=1), org_id=org_id)
        assert result["findings"] == 0
        assert result["by_status"]["healthy"] == 1
        assert result["tasks_resolved"] == 1

    async with session_scope() as s:
        task = (
            await s.execute(select(Task).where(Task.dedupe_key == f"conmon:impl:{impl_id}"))
        ).scalar_one()
        assert task.status == "done"
        assert task.closed_at is not None


async def test_healthy_transition_surfaces_poam_without_closing() -> None:
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Conmon Recovery PoamSurface Org")
        impl = await _at_risk_impl(s, sys_id, "AC-CONMON-RECOVER-2")
        impl_id = impl.id

    async with session_scope() as s:
        await conmon.scan(s, today=date.today(), org_id=org_id)

    async with session_scope() as s:
        impl = await _reload_impl(s, impl_id)
        impl.status = "implemented"

    async with session_scope() as s:
        result = await conmon.scan(s, today=date.today() + timedelta(days=1), org_id=org_id)
        assert result["poams_recovered"] == 1

    async with session_scope() as s:
        source_ref = f"conmon:impl:{impl_id}"
        poam = (
            await s.execute(select(POAM).where(POAM.source_ref == source_ref))
        ).scalar_one()
        assert poam.status == "open"
        assert poam.remediation_plan is not None
        assert "returned to healthy" in poam.remediation_plan
        notes = (
            await s.execute(
                select(Notification).where(Notification.dedupe_key == f"poam-recovery:{poam.id}")
            )
        ).scalars().all()
        assert len(notes) == 1


async def test_still_unhealthy_does_not_resolve() -> None:
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Conmon Recovery StillAtRisk Org")
        impl = await _at_risk_impl(s, sys_id, "AC-CONMON-RECOVER-3")
        impl_id = impl.id

    async with session_scope() as s:
        await conmon.scan(s, today=date.today(), org_id=org_id)
    async with session_scope() as s:
        # Nothing fixed -- still at_risk on the second scan.
        result = await conmon.scan(s, today=date.today() + timedelta(days=1), org_id=org_id)
        assert result["tasks_resolved"] == 0
        assert result["poams_recovered"] == 0

    async with session_scope() as s:
        task = (
            await s.execute(select(Task).where(Task.dedupe_key == f"conmon:impl:{impl_id}"))
        ).scalar_one()
        assert task.status == "open"


async def test_never_unhealthy_is_a_no_op_and_logs_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    warn_calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        conmon.log, "warning", lambda event, **kw: warn_calls.append((event, kw))
    )
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Conmon Recovery NeverUnhealthy Org")
        ctrl = Control(identifier="AC-CONMON-HEALTHY-1", control_name="Test control")
        s.add(ctrl)
        await s.flush()
        impl = ControlImplementation(system_id=sys_id, control_id=ctrl.id, status="implemented")
        s.add(impl)
        await s.flush()

    async with session_scope() as s:
        result = await conmon.scan(s, today=date.today(), org_id=org_id)
        assert result["findings"] == 0
        assert result["tasks_resolved"] == 0
        assert result["poams_recovered"] == 0
    assert warn_calls == []


async def test_human_edited_task_and_poam_fields_survive_recovery() -> None:
    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Conmon Recovery Edited Org")
        impl = await _at_risk_impl(s, sys_id, "AC-CONMON-RECOVER-EDIT")
        impl_id = impl.id

    async with session_scope() as s:
        await conmon.scan(s, today=date.today(), org_id=org_id)

    dedupe = f"conmon:impl:{impl_id}"
    source_ref = f"conmon:impl:{impl_id}"
    async with session_scope() as s:
        task = (await s.execute(select(Task).where(Task.dedupe_key == dedupe))).scalar_one()
        task.description = "Human note: already investigating, do not touch"
        poam = (await s.execute(select(POAM).where(POAM.source_ref == source_ref))).scalar_one()
        poam.severity = "critical"  # asymmetric -- auto-created default is "moderate" here

    async with session_scope() as s:
        impl = await _reload_impl(s, impl_id)
        impl.status = "implemented"

    async with session_scope() as s:
        await conmon.scan(s, today=date.today() + timedelta(days=1), org_id=org_id)

    async with session_scope() as s:
        task = (await s.execute(select(Task).where(Task.dedupe_key == dedupe))).scalar_one()
        assert task.description == "Human note: already investigating, do not touch"
        assert task.status == "done"
        poam = (await s.execute(select(POAM).where(POAM.source_ref == source_ref))).scalar_one()
        assert poam.severity == "critical"
        assert poam.status == "open"
        assert "returned to healthy" in (poam.remediation_plan or "")


async def test_only_the_matching_implementation_is_resolved() -> None:
    async with session_scope() as s:
        org_a, sys_a = await _make_org_system(s, "Conmon Recovery Scope Org A")
        org_b, sys_b = await _make_org_system(s, "Conmon Recovery Scope Org B")
        impl_a = await _at_risk_impl(s, sys_a, "AC-CONMON-SCOPE-A")
        impl_b = await _at_risk_impl(s, sys_b, "AC-CONMON-SCOPE-B")
        impl_a_id, impl_b_id = impl_a.id, impl_b.id

    async with session_scope() as s:
        await conmon.scan(s, today=date.today(), org_id=None)  # global scan, both orgs

    async with session_scope() as s:
        impl_a = await _reload_impl(s, impl_a_id)
        impl_a.status = "implemented"  # only org A's implementation is fixed

    async with session_scope() as s:
        await conmon.scan(s, today=date.today() + timedelta(days=1), org_id=None)

    async with session_scope() as s:
        task_a = (
            await s.execute(select(Task).where(Task.dedupe_key == f"conmon:impl:{impl_a_id}"))
        ).scalar_one()
        task_b = (
            await s.execute(select(Task).where(Task.dedupe_key == f"conmon:impl:{impl_b_id}"))
        ).scalar_one()
        assert task_a.status == "done"
        assert task_b.status == "open"

        poam_a = (
            await s.execute(
                select(POAM).where(POAM.source_ref == f"conmon:impl:{impl_a_id}")
            )
        ).scalar_one()
        poam_b = (
            await s.execute(
                select(POAM).where(POAM.source_ref == f"conmon:impl:{impl_b_id}")
            )
        ).scalar_one()
        assert "returned to healthy" in (poam_a.remediation_plan or "")
        assert poam_b.remediation_plan is None


async def test_recovery_failure_is_isolated_and_logged(monkeypatch: pytest.MonkeyPatch) -> None:
    warn_calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        conmon.log, "warning", lambda event, **kw: warn_calls.append((event, kw))
    )
    original_notify = conmon.bus.notify

    async def _maybe_raise(*args, **kwargs):
        if str(kwargs.get("dedupe_key", "")).startswith("poam-recovery:"):
            raise RuntimeError("simulated recovery failure")
        return await original_notify(*args, **kwargs)

    monkeypatch.setattr(conmon.bus, "notify", _maybe_raise)

    async with session_scope() as s:
        org_id, sys_id = await _make_org_system(s, "Conmon Recovery Failure Org")
        impl = await _at_risk_impl(s, sys_id, "AC-CONMON-RECOVER-FAIL")
        impl_id = impl.id

    async with session_scope() as s:
        await conmon.scan(s, today=date.today(), org_id=org_id)

    async with session_scope() as s:
        impl = await _reload_impl(s, impl_id)
        impl.status = "implemented"

    async with session_scope() as s:
        # Must not raise -- scan() must complete for every other implementation.
        result = await conmon.scan(s, today=date.today() + timedelta(days=1), org_id=org_id)
        assert result["poams_recovered"] == 0  # the forced failure prevented it

    async with session_scope() as s:
        task = (
            await s.execute(select(Task).where(Task.dedupe_key == f"conmon:impl:{impl_id}"))
        ).scalar_one()
        assert task.status == "open"  # rolled back with the rest of the savepoint
    assert any(event == "conmon.recovery_failed" for event, _ in warn_calls)
```

- [ ] **Step 2: Run the tests to verify failure**

Run: `.venv/bin/pytest tests/test_conmon_recovery.py -v`
Expected: FAIL — every test expecting `task.status == "done"`, `result["tasks_resolved"]`/`result["poams_recovered"]`, or a recovery `Notification` fails (`scan()` today just `continue`s on `"healthy"`, returns no such keys, and `conmon` has no `log` attribute yet for the monkeypatch tests to target — those two collect an `AttributeError` at monkeypatch time, also a failure). `test_still_unhealthy_does_not_resolve` and `test_never_unhealthy_is_a_no_op_and_logs_nothing` fail only on the missing `result["tasks_resolved"]`/`result["poams_recovered"]` keys (`KeyError`), not on behavior — expected, since those keys don't exist yet.

- [ ] **Step 3: Implement the recovery path in `conmon.py`**

Add the `get_logger` import and add `UTC`/`datetime` to the existing `date`/`timedelta` import:

```python
from datetime import UTC, date, datetime, timedelta
```

```python
from ..logging import get_logger
```
placed with the other imports, and:
```python
log = get_logger(__name__)
```
placed after the existing `from . import bus` line.

Add `_resolve_on_recovery` immediately after `_upsert_poam` (before `health_summary`):

```python
async def _resolve_on_recovery(
    session: AsyncSession, *, org_id: int | None, impl_id: int, system_id: int | None
) -> tuple[bool, bool]:
    """Best-effort recovery bookkeeping when a control implementation returns
    to healthy. Returns (task_resolved, poam_recovered).

    Mirrors control_tests._resolve_on_recovery: resolves the Task
    _upsert_task opened (free status vocabulary, no gate, safe to
    auto-resolve); surfaces -- never auto-closes -- the POA&M _upsert_poam
    opened, with a dated observation note and a notification. See that
    function's docstring and the 2026-08-12 recovery-closure design doc for
    the full reasoning (the asymmetry with ingest/scanners.py's
    scan-absence auto-close applies identically here).

    One deliberate interaction: assess_health treats any open
    high/critical-severity POA&M as its own at-risk signal, and the POA&M
    opened for an "overdue" control is severity="high" -- so a control that
    ever went overdue cannot report healthy again until a human closes that
    POA&M through the ISSM-08/09 gate, even once the original overdue cause
    is fixed. That is a correct consequence of never auto-closing, not a bug.

    Runs in its own SAVEPOINT and swallows+logs any failure so it can never
    cost the caller's scan (AsyncSession.rollback() is NOT savepoint-scoped
    and would otherwise unwind the whole scan's already-flushed work).

    Only acts on the Task/POA&M this machinery itself created, identified by
    the exact dedupe_key/source_ref _upsert_task/_upsert_poam use for this
    implementation, and only while untouched (Task.status == "open"; POA&M
    still in _OPEN_POAM) -- and only ever writes Task.status/closed_at and
    POAM.remediation_plan, so a human's edit to any other field survives.
    """
    task_resolved = poam_recovered = False
    try:
        async with session.begin_nested():
            task_dedupe = f"conmon:impl:{impl_id}"
            task = (
                await session.execute(select(Task).where(Task.dedupe_key == task_dedupe))
            ).scalar_one_or_none()
            if task is not None and task.status == "open":
                task.status = "done"
                task.closed_at = datetime.now(UTC)
                task_resolved = True

            source_ref = f"conmon:impl:{impl_id}"
            poam = (
                await session.execute(
                    select(POAM).where(
                        POAM.system_id == system_id,
                        POAM.source_ref == source_ref,
                        POAM.status.in_(_OPEN_POAM),
                    )
                )
            ).scalar_one_or_none()
            if poam is not None:
                note = (
                    f"Control implementation {impl_id} returned to healthy as of "
                    f"{datetime.now(UTC).isoformat()} -- review for closure."
                )
                poam.remediation_plan = (
                    f"{poam.remediation_plan}\n{note}" if poam.remediation_plan else note
                )
                await bus.notify(
                    session,
                    category="conmon",
                    title=f"Control {impl_id} recovered: POA&M ready for review",
                    body=note,
                    org_id=org_id,
                    severity="info",
                    entity_type="poam",
                    entity_id=poam.id,
                    dedupe_key=f"poam-recovery:{poam.id}",
                )
                poam_recovered = True
    except Exception as exc:
        log.warning(
            "conmon.recovery_failed",
            implementation_id=impl_id,
            error=str(exc)[:200],
        )
    return task_resolved, poam_recovered
```

Update `scan()`: initialize the two new counters alongside the existing ones, call the helper on `"healthy"`, and add both counters to `run.summary` and the returned dict.

```python
    checked = findings = tasks_created = notes_created = poams_created = 0
    tasks_resolved = poams_recovered = 0
    by_status: dict[str, int] = {"healthy": 0, "due_soon": 0, "at_risk": 0, "overdue": 0}

    for impl in impls:
        checked += 1
        impl_poams = [
            p for p in poams if p.system_id == impl.system_id and p.control_id == impl.control_id
        ]
        status, reasons = assess_health(impl, ev_by_impl.get(impl.id, []), impl_poams, today)
        by_status[status] += 1
        if status == "healthy":
            resolved, recovered = await _resolve_on_recovery(
                session, org_id=org_id, impl_id=impl.id, system_id=impl.system_id
            )
            if resolved:
                tasks_resolved += 1
            if recovered:
                poams_recovered += 1
            continue
        findings += 1
```

```python
    run.controls_checked = checked
    run.findings = findings
    run.tasks_created = tasks_created
    run.notifications_created = notes_created
    run.summary = {
        "by_status": by_status,
        "poams_created": poams_created,
        "tasks_resolved": tasks_resolved,
        "poams_recovered": poams_recovered,
    }
    await session.flush()
    await bus.emit(
        session,
        verb="scanned",
        entity_type="monitoring_run",
        entity_id=run.id,
        summary=f"ConMon scan: {findings} findings across {checked} controls",
        org_id=org_id,
        payload={"by_status": by_status, "tasks": tasks_created},
    )
    return {
        "run_id": run.id,
        "controls_checked": checked,
        "findings": findings,
        "tasks_created": tasks_created,
        "notifications_created": notes_created,
        "poams_created": poams_created,
        "tasks_resolved": tasks_resolved,
        "poams_recovered": poams_recovered,
        "by_status": by_status,
    }
```

- [ ] **Step 4: Run tests, verify gates, commit**

```bash
.venv/bin/pytest tests/test_conmon_recovery.py -v          # 7 tests pass
.venv/bin/pytest tests/test_conmon_poam.py tests/test_governance.py -v   # no regression to the existing conmon suite
.venv/bin/pytest -q          # run alone, foreground; confirm no regression from the Task 1 count plus these 7 new tests; cite the actual count in the commit if it differs
.venv/bin/ruff check . && .venv/bin/mypy src
```

**Mutation check (all three required):**

1. *The untouched-only guard.* In `_resolve_on_recovery`, remove `and task.status == "open"`. Re-run `tests/test_conmon_recovery.py::test_human_edited_task_and_poam_fields_survive_recovery` — this test doesn't move `Task.status`, so add a temporary local check (or run interactively) confirming a Task a human moved to some other status now gets silently flipped to `"done"` anyway. Report this plainly. Revert.
2. *The savepoint.* Replace `async with session.begin_nested():` with `if True:` (dedented body). Re-run `tests/test_conmon_recovery.py::test_recovery_failure_is_isolated_and_logged` — confirm it now fails (the DB-level state after the forced failure no longer matches "cleanly rolled back"). Revert.
3. *The best-effort swallow.* Remove the `try`/`except` around the savepoint. Re-run `tests/test_conmon_recovery.py::test_recovery_failure_is_isolated_and_logged` — confirm `scan()` itself now raises (a single unhealthy-to-healthy control's recovery failure would abort the whole scan, including every other control implementation the scheduler needs checked that cycle). Revert.

```bash
git add src/ccf/governance/conmon.py tests/test_conmon_recovery.py
git commit -m "feat(governance): resolve conmon's remediation Task and surface its POA&M on recovery to healthy"
```

---

### Task 3: Documentation

**Files:**
- Modify: `docs/ARCHITECTURE.md`
- Modify: `CHANGELOG.md`

**Interfaces:** None — documentation only.

- [ ] **Step 1: `docs/ARCHITECTURE.md`**

Insert a new bullet immediately after the "Closure & remediation loop" bullet block and before "AI dissent path" (i.e., after the paragraph ending `...without the IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') guard migration 0054 establishes as the repo standard for exactly this GRANT.`, before `- **AI dissent path** (...)`):

```markdown
- **Recovery closure** (`ccf.governance.control_tests`, `.conmon`,
  2026-08-12 recovery-closure design): a control test recovering from
  `fail`/`warn` to `pass` (`record_result`, delegated to by both the manual
  UI/API run action and the scheduler's `run_due`) resolves the remediation
  `Task` `_alert_on_failure` opened, and conmon's own scan resolves the Task
  its `_upsert_task` opened when a control implementation returns to
  `healthy`. Neither path auto-closes the POA&M it opened. A `Task` is an
  internal work item with a free status vocabulary and no gate; a `POAM` has
  the ISSM-08/09 closure gate (`api/routes/poams.py:216`: all milestones
  complete, or dated closure evidence, plus a separation-of-duties
  `Approval` when auth is enabled) — closing one asserts, in an
  authorization package, that a weakness is remediated, and a single
  passing control test or a single healthy scan is not that assertion. This
  is deliberately asymmetric with `ccf.ingest.scanners.reconcile_findings`
  (`src/ccf/ingest/scanners.py:397`), which *does* auto-close a POA&M
  absent from the latest scan, for the same reason the assessment engine's
  closure loop above already documents: a vulnerability missing from a scan
  is direct evidence the weakness is gone, where a control test passing
  once, or a scan reporting a control healthy once, is weaker evidence that
  may cover only part of what the POA&M describes. Instead the POA&M gains
  a dated, id-stamped observation note (`remediation_plan`, the same append
  pattern `scanners.py:410-412` uses for its own closure note) and a
  `Notification` via `governance.bus.notify` — the same mechanism
  `_alert_on_failure` and `conmon.scan` already use for "needs a human's
  attention," queryable and markable-read through the existing
  `/api/notifications` endpoint. Both paths act only on the Task/POA&M they
  themselves created, identified by the same `dedupe_key`/`source_ref` the
  opening code uses, and only while still in the state auto-creation left
  them — a human's edit to any other field survives untouched. One
  interaction worth naming: conmon's own `assess_health` treats an open
  `high`/`critical`-severity POA&M as its own at-risk signal, and the
  POA&M opened for an `overdue` control is `severity="high"` — so a
  control that ever went overdue cannot report `healthy` again until a
  human closes that POA&M, even once the original overdue cause is fixed.
  That is a correct consequence of never auto-closing, not a bug. Not
  retrofitted: Tasks and POA&Ms already open when this shipped are
  untouched; only transitions observed afterward are acted on.
```

- [ ] **Step 2: `CHANGELOG.md`**

Add a new `### Added — Recovery closure for control tests and ConMon` section as the first entry under `## [Unreleased]`, above the existing `### Fixed — AI-drafted SSP narrative always carries the draft marker` section:

```markdown
### Added — Recovery closure for control tests and ConMon
- **A control test recovering from `fail`/`warn` to `pass`, or a control
  implementation returning to `healthy` in ConMon, now resolves the
  remediation `Task` that was opened for it** — both `record_result`
  (called by the manual UI/API run action and, now, the scheduler's
  `run_due` as well) and `conmon.scan` gained a symmetric resolve path.
  Previously nothing happened on recovery at all: the remediation backlog
  filled with Tasks and POA&Ms that looked like live findings and were not.
- **The POA&M is surfaced, never auto-closed.** Closing a POA&M is an
  assertion, in an authorization package, that a weakness is remediated;
  a single passing control test or healthy scan is not that assertion.
  This is deliberately asymmetric with `ingest/scanners.py`'s
  scan-absence auto-close (a missing vulnerability is direct evidence;
  a passing test is weaker, possibly-partial evidence). The POA&M instead
  gains a dated, id-stamped observation note and a notification, so a
  human can close it through the existing ISSM-08/09 gate
  (`api/routes/poams.py:216`, unchanged by this slice) with the evidence
  that gate demands.
- **`run_due` (the scheduler's due-test evaluator) no longer duplicates
  `record_result`'s write sequence** — it now delegates to it, so the
  recovery behavior above applies on the scheduler-driven path, not only
  the manual one.
- **Only auto-created, untouched items are acted on**, identified by the
  same `dedupe_key`/`source_ref` the opening code already uses, and only
  while still in the state auto-creation left them — a human's edit to
  any other field is never overwritten.
- **No retrofit**: Tasks and POA&Ms already open when this shipped are
  unaffected; only transitions observed afterward are acted on. **No
  migration**: no new table, column, or POA&M status value.
```

- [ ] **Step 3: Verify and commit**

```bash
.venv/bin/pytest -q          # run alone, foreground; confirm the final count and cite it in the commit
git add docs/ARCHITECTURE.md CHANGELOG.md
git commit -m "docs(governance): document the recovery-closure path and its asymmetry with scanner auto-close"
```

---

## Deferred, deliberately

- **No auto-closing of POA&Ms**, on either path — this is the load-bearing decision of the whole slice, not an oversight to revisit later.
- **No change to the ISSM-08/09 closure gate** (`api/routes/poams.py:216`).
- **No new tables, columns, jobs, queues, or POA&M status values.** `Task.status`/`closed_at` and `POAM.remediation_plan`/`status` already carried everything this slice needed.
- **No change to conmon's health derivation** (`assess_health`) — including the crit-severity/overdue interaction Task 2 documents rather than "fixes." Weakening that check to let a control report healthy while a high-severity POA&M sits open would be a much larger, separate decision about what "healthy" means, not a bug this slice introduced.
- **No retrofit.** Tasks and POA&Ms already open when this ships stay exactly as they are; only transitions observed afterwards are acted on.
- **No fix to the two unreconciled legacy POA&M-from-findings paths** (`api/routes/assessments.py:205`'s `poams-from-findings` and `ui.py`'s inline duplicate) — out of scope, already on the standing debt list `docs/ARCHITECTURE.md` tracks.
