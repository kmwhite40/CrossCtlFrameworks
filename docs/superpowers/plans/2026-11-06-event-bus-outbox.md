# Event Bus (Transactional Outbox) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Derived views and webhooks react to committed events within about a minute, through a Postgres outbox drained by an `event-worker`. Today webhooks are posted inside the request transaction, and derived views wait for the 24-hour scheduler.

**Architecture:**
- `bus.emit` keeps its signature. It writes the `Event` row and, in the same transaction, one `outbox_jobs` row per matching consumer.
- A worker claims jobs with `FOR UPDATE SKIP LOCKED`, through `ccf.queue`.
- When it claims a job, it marks the other pending jobs for the same `(consumer, scope_key)` as merged.
- It runs the consumer under the scope's tenant. A consumer is a full recompute of its scope from current records.

**Tech Stack:** Python 3.12, FastAPI, async SQLAlchemy, Postgres (RLS), Alembic, Typer, httpx, pytest. The test database is on port 5434 and is reached through the scratchpad's `t.sh` runner.

**Spec:** `docs/superpowers/specs/2026-11-06-event-bus-outbox-design.md` (approved 2026-11-06).

## Global Constraints

**Timing and retries:**
- **Settle delay:** 15 s for derived-view jobs, 0 s for webhook jobs.
- **Freshness target:** p95 under 60 s from the event to the end of the job.
- **Retries:** webhooks get 8 attempts over about 6 hours, with exponential backoff. Derived views get 5 attempts. The rest comes from `ccf.queue`: dead-lettering at the cap, `DEAD_LETTER_REASON` and the `last_error` truncation.

**Webhooks:**
- Sent only after commit, at least once.
- Each delivery carries the header `X-CCF-Event-Id: <event id>`.
- The body is unchanged except for two added fields, `event_id` and `occurred_at`.
- HMAC `X-CCF-Signature`, the SSRF-pinned target, and `follow_redirects=False` all stay exactly as in `bus._dispatch_webhooks`.

**What emits and what runs:**
- `emit(dispatch=False)` queues no webhook job. Internal consumers still match.
- A job runs under the tenant of its scope entity: `system:N` under the system's org, `org:N` under org N. Only platform-only webhook jobs, which have a NULL org, may run unscoped.
- Events emitted while a consumer runs are `dispatch=False`, never match the consumer that emitted them, and carry `payload["_depth"]`. Depth 3 queues nothing.

**What consumers may do:**
- Never close, accept or approve anything, or write a status that a human gate owns.
- Never read the event payload as current state. It may say what changed; the consumer re-reads the records.

**Configuration:**
- New settings `CCF_EVENT_WORKER_ENABLED` (default false) and `CCF_EVENT_DRAIN_INLINE` (default true; forced off when the worker is enabled).
- Both are set on the `api` and `event-worker` compose services.

**Staying the same:**
- The scheduler keeps every existing step. It is the backstop.
- `ccf.queue.claim_jobs` keeps its current behaviour for prep and the assessment engine.

## Review Focus

These are failure modes no single task's main tests exercise:

- **A writer that emits nothing.** A record changes in a module with no `emit`, so its derived view stays stale until the scheduler runs. Task 6 adds an `emit` wherever a dependency has none, and its test lists every consumer's trigger set against the emit sites.
- **A consumer that raises on every job,** such as a system deleted after the event. It must dead-letter after its cap, not loop. A deleted scope entity must finish the job as `done` with `result={"skipped": "scope gone"}` (Task 4).
- **A webhook receiver that returns 500 or times out.** The job is retried with backoff. `result.attempts_log` records each status code and the error, and the request that emitted the event is never slowed (Task 5).
- **A burst arriving during a running rebuild.** That leaves exactly one pending job after the run, not one per event (Task 4).
- **A worker killed mid-job.** `reap_stale_jobs` requeues the job and does not duplicate a webhook beyond at-least-once (Task 4).

---

### Task 1: `outbox_jobs` table, model, and queue eligibility

**Files:**
- Create: `migrations/versions/0115_outbox_jobs.py`
- Create: `src/ccf/models_outbox.py`
- Modify: `src/ccf/queue.py`, `claim_jobs`
- Modify: `tests/test_rls_coverage.py`, which counts the new table
- Test: `tests/test_outbox_schema.py`

**Interfaces:**
- **Produces** `OutboxJob`, with these columns:

  | Group | Columns |
  |---|---|
  | Identity | `id` (bigint pk), `organization_id` (int, nullable, FK organizations ON DELETE CASCADE) |
  | Routing | `consumer` (str 48), `scope_key` (str 96), `trigger_event_id` (bigint, FK events), `absorbed` (int, default 0) |
  | State | `status` (str 16: `pending` / `claimed` / `done` / `merged` / `failed`), `attempts` (int), `max_attempts` (int) |
  | Timing | `claimed_at`, `claimed_by`, `next_attempt_at` (timestamptz, not null, default now()), `created_at`, `finished_at` |
  | Outcome | `last_error` (text), `merged_into` (bigint, nullable), `result` (jsonb, default {}) |

  Indexes: `(status, next_attempt_at)`, plus `(consumer, scope_key, status)`.
- **Produces** `claim_jobs(session, model, *, worker, limit, eligible: ColumnElement[bool] | None = None, order_by: Any | None = None) -> list[J]`. The extra predicate is ANDed in, and `order_by` defaults to `model.created_at`.

- [ ] **Step 1: Write the failing tests.** `test_outbox_jobs_is_tenant_isolated` (RLS policy present, FORCE ROW LEVEL SECURITY on) and `test_claim_jobs_honours_an_eligibility_predicate`. The second inserts two pending jobs, one with `next_attempt_at` in the future. With `eligible=OutboxJob.next_attempt_at <= func.now()` it claims only the other. With no predicate, prep's call still claims oldest-first.
- [ ] **Step 2: Run them.** `t.sh tests/test_outbox_schema.py -v` should fail on the missing table.
- [ ] **Step 3: Write the migration.** Follow 0111's pattern: GRANT SELECT/INSERT/UPDATE to ccf_app (jobs are updated), REVOKE DELETE, an RLS policy with the standard predicate, and FORCE. Then write the model and the `claim_jobs` parameters.
- [ ] **Step 4: Verify.** The new tests, `tests/test_rls_coverage.py`, `tests/test_prep_jobs*.py` and `tests/test_assessment_engine_jobs*.py` all pass.
- [ ] **Step 5: Commit** with `feat(events): outbox_jobs table and queue eligibility (0115)`.

### Task 2: Consumer registry

**Files:**
- Create: `src/ccf/events/__init__.py`
- Create: `src/ccf/events/consumers.py`
- Test: `tests/test_event_consumers.py`

**Interfaces:**
- **Produces** a frozen dataclass:

  ```python
  @dataclass(frozen=True)
  class Consumer:
      name: str
      matches: Callable[[str, str], bool]     # (entity_type, verb)
      scope: Callable[[Event], str | None]    # "system:N" | "org:N" | None
      run: Callable[[AsyncSession, str, OutboxJob], Awaitable[dict[str, Any]]]
      settle_seconds: int = 15
      max_attempts: int = 5
  ```

- **Produces** `REGISTRY: dict[str, Consumer]` and `register(c: Consumer) -> Consumer`.
- **Produces** `async def scope_org(session, scope_key: str) -> int | None | Literal["gone"]`. It returns the org of `system:N` or `org:N`, or `"gone"` when the entity is deleted or missing. A deleted system (`deleted_at` set) counts as gone.

- [ ] **Step 1: Write the failing tests.**
  - `test_scope_org_resolves_systems_and_orgs` returns the system's org, and N for `org:N`.
  - `test_scope_org_reports_a_deleted_system_as_gone`.
  - `test_register_refuses_a_duplicate_name`.
- [ ] **Step 2: Run them** and expect an ImportError.
- [ ] **Step 3: Implement it.** The registry starts empty; consumers register in Tasks 5–6 by importing their modules from `ccf/events/__init__.py`.
- [ ] **Step 4: Verify** that the tests pass.
- [ ] **Step 5: Commit.**

### Task 3: `emit` enqueues instead of dispatching

**Files:**
- Modify: `src/ccf/governance/bus.py`. It replaces `_dispatch_webhooks` on the request path with `outbox.enqueue(session, ev, dispatch=...)`.
- Create: `src/ccf/events/outbox.py`
- Test: `tests/test_event_outbox_enqueue.py`

**Interfaces:**
- **Consumes:** `REGISTRY` and `scope_org` from Task 2, and `OutboxJob` from Task 1.
- **Produces** `async def enqueue(session, ev: Event, *, dispatch: bool) -> list[OutboxJob]`. It inserts one job per matching consumer, plus one `webhook` job per subscribed active webhook when `dispatch` is set and the event is not consumer-originated. Webhook selection copies today's org-or-global rule and subscription filter. The webhook job gets `scope_key=f"event:{ev.id}"`, `settle_seconds=0` and `max_attempts=8`.
- **Produces** the contextvar `CURRENT_CONSUMER: ContextVar[str | None]` and `CURRENT_DEPTH: ContextVar[int]`, set by the worker in Task 4. When `CURRENT_CONSUMER` is set, `emit` forces `dispatch=False`, adds `_depth` to the payload, skips the emitting consumer, and queues nothing at depth 3 or more.
- **Organization:** a job's `organization_id` is `ev.organization_id` when set. Otherwise it comes from `scope_org` (or `None` for a platform-only webhook job).

- [ ] **Step 1: Write the failing tests.**
  - `test_a_rolled_back_transaction_queues_and_sends_nothing`: `emit` with a webhook subscribed, then roll back. No job exists, and the patched `httpx.AsyncClient.post` was never called.
  - `test_emit_no_longer_posts_during_the_request`: the patched `post` is not called before commit.
  - `test_dispatch_false_queues_no_webhook_job`.
  - `test_an_orgless_event_takes_its_scopes_org`.
  - `test_a_consumers_own_event_does_not_retrigger_it_or_reach_webhooks`.
  - `test_depth_three_queues_nothing`.
- [ ] **Step 2: Run them** and confirm they fail.
- [ ] **Step 3: Implement** `enqueue` and the `emit` change. `_dispatch_webhooks` moves to Task 5's module and is not called from `emit`.
- [ ] **Step 4: Verify.** The new tests pass, along with every existing test that patches `bus._dispatch_webhooks` or asserts webhook delivery during the request. Find them with `grep -rln "_dispatch_webhooks\|X-CCF-Signature" tests`. Update them to drain the outbox through Task 4's helper, and say so in the commit.
- [ ] **Step 5: Commit.**

### Task 4: The worker: claim, merge, run, retry, dead-letter

**Files:**
- Create: `src/ccf/events/worker.py`
- Test: `tests/test_event_worker.py`

**Interfaces:**
- **Consumes:** the `claim_jobs` eligibility parameter from Task 1, plus `REGISTRY`, `scope_org`, `CURRENT_CONSUMER` and `CURRENT_DEPTH`.
- **Produces** `async def drain_once(*, worker: str, limit: int = 10, now: datetime | None = None) -> dict[str, int]`. It returns counts for `done`, `merged`, `retried`, `failed` and `skipped`. Each job runs in its own session and transaction.
- **Claim and merge:**
  - Eligible means `status='pending' AND next_attempt_at <= now` and no `claimed` job for the same `(consumer, scope_key)`. Express that as `~exists(...)`.
  - Order by `next_attempt_at`.
  - After claiming, set every other pending job for that pair to `merged`, with `merged_into=<id>`, in the same transaction. Add their count to `absorbed`.
- **Run:**
  - `scope_org` decides the tenant: `set_session_tenant(session, org)`, or none for a NULL-org webhook job. `"gone"` means status `done` and `result={"skipped": "scope gone"}`.
  - Set `CURRENT_CONSUMER` and `CURRENT_DEPTH` (from the trigger event's `_depth` plus 1) around `consumer.run`.
- **Outcome:**
  - **Success:** `done`, with `finished_at` set.
  - **Exception below the cap:** back to `pending`, with `next_attempt_at = now + base * 2**(attempts-1)` (base 60 s for derived views, 90 s for webhooks) and a truncated `last_error`.
  - **At the cap:** `failed`, with `last_error` kept.
- **Produces** `async def reap(*, older_than: timedelta = timedelta(minutes=15)) -> int`, wrapping `reap_stale_jobs`.

- [ ] **Step 1: Write the failing tests.**
  - `test_a_thousand_events_make_one_graph_rebuild`: register a counting test consumer, enqueue 1,000 events for `org:N`, drain. The consumer ran once, and `absorbed == 999`.
  - `test_a_change_during_a_run_is_picked_up_once`: the consumer enqueues 3 events for its own scope while it runs. Afterwards exactly one pending job exists, and a second drain runs it.
  - `test_a_job_waits_out_its_settle_delay`.
  - `test_a_failing_job_backs_off_then_dead_letters_at_its_cap`, with the attempt times asserted.
  - `test_the_consumer_runs_under_the_scopes_tenant`: on an **unscoped** session it asserts that `ccf.current_tenant()` inside `run` equals the system's org (RLS masks this otherwise).
  - `test_a_deleted_system_finishes_as_skipped`.
  - `test_a_killed_worker_is_reaped_and_rerun`.
- [ ] **Step 2: Run them** and confirm they fail.
- [ ] **Step 3: Implement it.**
- [ ] **Step 4: Verify.** The tests pass. Mutation-check the merge, the running-scope exclusion, the tenant set and the cap, and record the results in the commit.
- [ ] **Step 5: Commit.**

### Task 5: Webhook consumer

**Files:**
- Create: `src/ccf/events/webhooks.py`, which takes over `_dispatch_webhooks`' send logic.
- Modify: `src/ccf/governance/bus.py`, removing `_dispatch_webhooks`.
- Test: `tests/test_event_webhooks.py`

**Interfaces:**
- **Consumes:** `Consumer` and `register`; the job's `trigger_event_id`, and a `result["webhook_id"]` written by Task 3's `enqueue`.
- **Produces** the registered consumer `webhook`. `run` loads the event and the webhook (the webhook may have been deleted or deactivated, which counts as a skip). It posts as today, plus the `X-CCF-Event-Id` header and the `event_id` / `occurred_at` body fields. A non-2xx response or a transport error raises, so the worker retries. It appends `{"at", "status", "ms", "error"}` to `result["attempts_log"]`.

- [ ] **Step 1: Write the failing tests.**
  - `test_delivery_carries_the_event_id_and_signature` checks the HMAC over the exact body.
  - `test_a_500_is_retried_and_logged`.
  - `test_a_redirect_is_not_followed`.
  - `test_a_url_that_now_resolves_inward_is_refused_and_not_retried`. A refused target is final: `done` with `result.refused`.
  - `test_a_deactivated_webhook_is_skipped`.
- [ ] **Step 2: Run them** and confirm they fail.
- [ ] **Step 3: Implement it.**
- [ ] **Step 4: Verify.** The tests pass, as do the existing webhook SSRF tests (`grep -rln webhook_url tests`).
- [ ] **Step 5: Commit.**

### Task 6: Derived-view consumers

**Files:**
- Create: `src/ccf/events/derived.py`
- Modify: `src/ccf/fedramp20x/monitoring.py`, adding `scan_system(session, *, system_id: int) -> dict[str, Any]` (the per-system body of `scan`, which then loops over it).
- Modify: whichever writers of a trigger entity emit nothing today. Find them with Step 1's test.
- Test: `tests/test_event_derived_consumers.py`

**Interfaces:**
- **Consumes:** `register`, `scope_org`, `assurance.builder.rebuild_org(session, org_id)`, `capability.derive.derive_for_system(session, *, system_id)`, `monitoring.scan_system`, and `cr26.ver.seed_vdr` / `seed_avi` / `seed_ver_history`.
- **Produces** the consumers `assurance_graph` (scope `org:N`), `capability_derive`, `fedramp20x` and `cr26_documents` (all `system:N`).
  - **Triggers:** each consumer's `matches` set is a module-level frozenset of `(entity_type, verb)` taken from the emit sites. The test pins each set.
  - **`fedramp20x`:** a no-op for a system with no 20x class.
  - **`cr26_documents`:** re-seeds `ver_history`, and re-seeds VDR / AVI **only when a stored document already exists**, using that document's own `reportPeriod`. It never touches SCN, incident, OCR, SDR or CPO.
- **Deviation from the spec, recorded:** the spec's `practice_reaction` consumer is **not** built. `scoring.py`'s response returns the reaction's result, so spec 6.4 (a response that depends on the result stays inline) keeps it in the route. The other writers of `ScoringStatus` belong to sub-project 2.

- [ ] **Step 1: Write the failing tests.**
  - `test_every_trigger_has_an_emitting_writer` walks `src/ccf` for `bus.emit(` calls' `entity_type` / `verb` literals and asserts that every pair in each consumer's trigger set appears. It is the guard for the first Review Focus item.
  - `test_a_poam_change_rebuilds_the_graph_within_one_drain`.
  - `test_a_poam_change_regenerates_the_existing_vdr_with_its_period`.
  - `test_no_vdr_is_created_where_none_existed`.
  - `test_an_ocr_is_never_filed_by_a_consumer`: drain after POA&M changes, and the snapshot filings count is unchanged.
  - `test_a_derived_consumer_never_changes_a_gated_status`: snapshot the POA&M / risk / approval statuses before and after a drain, and assert they are equal.
- [ ] **Step 2: Run them** and confirm they fail.
- [ ] **Step 3: Implement it.** Add the missing `emit`s that Step 1 reports, each with `verb` and `entity_type` matching the trigger sets.
- [ ] **Step 4: Verify.** The tests pass, along with `tests/test_fedramp20x*.py`, `tests/test_assurance*.py` and `tests/test_vdr*.py`.
- [ ] **Step 5: Commit.**

### Task 7: Running it: CLI worker, compose, settings, dev loop

**Files:**
- Modify: `src/ccf/cli.py`, adding the `event-worker` command with `--once/--loop`, the same shape as `assessment-worker`. It reaps on the same cadence as `_assessment_drain_loop`.
- Modify: `src/ccf/config.py`, adding `event_worker_enabled: bool = False`, `event_drain_inline: bool = True` and `event_drain_interval_seconds: float = 3.0`.
- Modify: `src/ccf/api/main.py`. On startup, when `event_drain_inline and not event_worker_enabled`, it starts an asyncio loop that calls `drain_once(worker="api-inline", limit=1)` every interval, each call bounded by `asyncio.wait_for(..., 120)`. It is cancelled on shutdown.
- Modify: `docker-compose.yml`, adding an `event-worker` service under profile `events`, with `CCF_EVENT_WORKER_ENABLED=true` set on **both** `api` and `event-worker`. The healthcheck is disabled, as for prep-worker.
- Test: `tests/test_event_worker_cli.py`

**Interfaces:**
- **Consumes:** `drain_once` and `reap` from Task 4.

- [ ] **Step 1: Write the failing tests.**
  - `test_event_worker_once_drains_and_exits`.
  - `test_the_inline_loop_is_off_when_the_worker_is_enabled`.
  - `test_the_inline_loop_drains_a_pending_job`.
  - `test_compose_sets_the_worker_flag_on_api_and_worker`: parse the YAML and assert it.
- [ ] **Step 2: Run them** and confirm they fail.
- [ ] **Step 3: Implement it.**
- [ ] **Step 4: Verify** that the tests pass.
- [ ] **Step 5: Commit.**

### Task 8: Operator visibility: reliability check, requeue, retention, freshness

**Files:**
- Modify: `src/ccf/reliability/checks.py`, adding the check `event_outbox`.
- Modify: the admin reliability route and template, adding a "Requeue" form per failed consumer: a POST to `/admin/reliability/outbox/{consumer}/requeue` that requires admin.
- Modify: `src/ccf/governance/scheduler.py`, adding a global step `outbox_retention`. It deletes `done` and `merged` derived-view jobs older than 1 day, and `done` webhook jobs older than 30 days. It never deletes `failed` jobs.
- Test: `tests/test_event_outbox_ops.py`

**Interfaces:**
- **Produces** `async def _check_event_outbox(session) -> Check`:

  | Result | When | Message |
  |---|---|---|
  | FAIL | any `failed` job | names each consumer, its count and its oldest `last_error` |
  | WARN | the oldest pending eligible job is older than 5 min | the worker is down or behind |
  | WARN | p95 of `finished_at - events.created_at` over the last 24 h exceeds 60 s | the freshness target is missed |
  | PASS | otherwise | states the p95 |

- [ ] **Step 1: Write the failing tests.**
  - `test_a_dead_letter_fails_the_check_by_name`.
  - `test_a_stalled_queue_warns`.
  - `test_freshness_over_target_warns`.
  - `test_requeue_needs_admin_and_resets_attempts`: a control_owner gets 403. An admin's requeue sets `pending`, `attempts=0` and `next_attempt_at=now`.
  - `test_retention_keeps_failed_jobs`.
- [ ] **Step 2: Run them** and confirm they fail.
- [ ] **Step 3: Implement it.** Register the new POST in `tests/test_viewer_is_read_only.py`'s registry if that guard requires it.
- [ ] **Step 4: Verify.** The tests pass, then the full suite runs in the background with no edits until it finishes. The only accepted failure is the known `test_framework_posture_names_the_failing_requirements`.
- [ ] **Step 5: Commit**, then update the spec's status line to "built", with the deviation (no `practice_reaction`) noted.
