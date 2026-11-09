# Event bus: committed events drive webhooks and derived views

Status: built on branch `design/event-bus` (2026-11-06), approved by the owner
2026-11-06, with the owner's three decisions recorded (section 8). Where the build
differs from this design, see section 9. Sub-project 1 of the two structural
fixes from the 2026-10-20 seam audit. Sub-project 2, one record per (system,
control), gets its own design afterwards and will publish its changes through this
bus.

## 1. Why

`ccf.governance.bus.emit` is called 56 times from 28 modules. It does two things
inside the caller's transaction:

1. It appends an `Event` row. That part is right: the event commits or rolls back
   with the change it describes.
2. It posts every subscribed webhook **before the transaction commits**:
   synchronously, with a 10-second timeout per hook, one hook after another.

Doing the second step there causes three defects:

- **A webhook can announce a change that never happened.** If the request fails
  after `emit`, the transaction rolls back, but the external system has already
  been told.
- **A slow or dead receiver stalls the request** while it holds row locks: up to
  10 s for each subscribed hook. Delivery is attempted once, with no retry and no
  record of the outcome.
- **Nothing reacts to committed events.** Derived views (the assurance graph,
  capability rollups, KSI / 20x monitoring results, CR26 deliverables, SSP sync)
  are refreshed by the scheduler, whose default interval is **24 hours**, or by a
  person clicking. The three `reactions.*` functions run only because three
  routes call them directly; every other writer of the same records skips them.

The goal: after a change commits, the things that depend on it update within
seconds, without the writer having to know they exist.

## 2. Goals

- **Webhooks:**
  - Delivered only for committed events.
  - Retried with backoff, and dead-lettered visibly.
  - Never sent on the request path.
- **Derived views:**
  - Refreshed within about a minute of the change that affects them, with no
    route calling them.
- **One mechanism:**
  - A consumer subscribes once and is invoked for every writer's events,
    including background jobs and the CLI.
- **Every consumer runs tenant-scoped:**
  - Under `set_session_tenant(org)` for the event's organization. This is the
    standing RLS rule; workers running unscoped is a known open defect.
- **Reuse `ccf.queue`:**
  - Its claim / reap / dead-letter primitives, rather than a second queue.

## 3. Non-goals

- **No external broker** (Kafka, Redis, SQS). Postgres is already the queue for
  prep and the assessment engine.
- **No event sourcing.** Events are triggers and an audit trail. They are not the
  source of truth, and no state is rebuilt by replaying them.
- **No exactly-once webhook delivery.** Delivery is at-least-once, with an
  idempotency key.
- **The 56 `emit` call sites keep their signature.** No caller has to change in
  this sub-project.
- **The scheduler stays**, as the backstop full refresh (section 6.5).

## 4. Anti-goals

These are failures even if everything else works.

- **A consumer that makes a gated decision.**
  - A consumer may recompute derived data. It may also propose: notes, notifications,
    a suggested closure.
  - It must never close a POA&M, accept a risk, approve anything, or write a
    status a human gate owns.
  - The same rule already governs `reactions.py` and `control_tests`.
- **A refresh storm.**
  - A scan that updates 2,000 findings must not queue 2,000 rebuilds of one
    organization's graph.
- **A second source of truth.**
  - A consumer reading the event payload instead of the current records would act
    on stale data.
- **Silent loss.**
  - A consumer that fails or keeps failing must show up where an operator looks,
    on the reliability page, and never be swallowed.

## 5. Shape

A transactional outbox with coalescing work items.

```
request txn:   change rows  ─┐
               emit()  ──────┼─► events row
                             └─► outbox_jobs rows (one per matching consumer,
                                 coalesced on (consumer, scope_key) while pending)
               COMMIT  ← nothing leaves the database before this

event worker:  claim outbox_jobs  (FOR UPDATE SKIP LOCKED, ccf.queue)
               set_session_tenant(job.organization_id)
               run consumer(scope)   ← reads CURRENT records, not the payload
               mark done / requeue with backoff / dead-letter at the cap
```

### 5.1 Consumers

A consumer is registered in code with three things:

- **`name`**: stable, stored on jobs.
- **`matches`**: a predicate over `(entity_type, verb)`.
- **`scope(event)`**: returns the `scope_key` the work is about, such as
  `org:12` or `system:40`, or `None` to ignore the event.

**First consumers:**

| Consumer | Triggered by | Scope | Does |
|---|---|---|---|
| `webhook` | every event emitted with `dispatch=True` | one job per (event, webhook) | delivers as today: HMAC, SSRF-pinned target, no redirects |
| `assurance_graph` | changes to systems, controls, implementations, POA&Ms, risks, evidence, KSI results | `org:N` | `assurance.builder.rebuild_org` |
| `capability_derive` | changes to implementations, capabilities, control tests | `system:N` | `capability.derive.derive_for_system` |
| `fedramp20x` | changes to KSI evidence, control tests, POA&Ms on a 20x system | `system:N` | that system's slice of `monitoring.scan` |
| `cr26_documents` | changes to POA&Ms and VDR evaluations | `system:N` | regenerates **only the VER-derived deliverables** (VDR, AVI, VER history) through `seed_vdr` / `seed_avi` / `seed_ver_history` and `store.put_document`, so validation still applies |
| `practice_reaction` | `scoring_status` `status_changed` | `system:N` | today's `reactions.on_scoring_status_changed`; proposes, never closes |

The exact verb and entity lists come from the existing emit sites. Reading those
lists off the code is the builder's job. When a writer of a dependency emits
nothing today, that is a gap to add an `emit` for. It must not be worked around
inside the consumer.

### 5.2 Coalescing (the storm guard), at claim time

`emit` inserts one plain `outbox_jobs` row per matching consumer. There is no
unique index and no `ON CONFLICT`.

*My call. An insert-time unique index makes concurrent writers to one
organization wait on each other's uncommitted pending row. A 2,000-finding scan
would then stall every other writer in that organization, which is the request-path
stall this design exists to remove.*

The worker merges instead:

- **Claim the scope.** It claims the oldest eligible job for a
  `(consumer, scope_key)`. In the same transaction it marks every other pending job
  for that pair as `merged`, recording the claimed job's id, and the claimed job
  records how many it absorbed.
- **One run per scope at a time.** While a `(consumer, scope_key)` has a `running`
  job, its pending jobs are not claimable.
- **Run.** Exactly one rebuild runs per scope at a time, covering everything
  queued before the claim.
- **Changes during a run.** A change during a run leaves a pending job, which is
  claimed after the run finishes. It is never lost.
- **Webhook jobs never merge.** Each event is its own delivery, so their
  `scope_key` is the event id.

### 5.3 Settle delay

A job is eligible `settle_seconds` after it is created (15 s for derived views, 0 for webhooks; section 8).
This lets a burst finish before the expensive rebuild runs.

### 5.4 Ordering and idempotency

- **No ordering guarantee between jobs.** Consumers are full recomputes of their
  scope from current records, so order does not matter and running twice is
  harmless. This is why consumers must not read the payload (section 4).
- **Webhooks:**
  - The `X-CCF-Event-Id` header carries the event id, so receivers can drop
    duplicates.
  - The body adds `event_id` and `occurred_at`. That is additive; existing fields
    are unchanged.

### 5.5 Retries and dead letters

- **Retries:** the attempt cap and `last_error` truncation come from `ccf.queue`,
  and backoff is exponential, `next_attempt_at`. Defaults: webhooks 8 attempts
  over about 6 hours, derived views 5 attempts.
- **Dead-lettered jobs:**
  - They stay `failed`, with `last_error` kept.
  - The reliability page shows the count per consumer and the oldest failure.
  - An admin can requeue from that page.
- **Webhook delivery attempts** are recorded on the job: status code, duration
  and error. A subscriber can then answer "did they get it?".

## 6. Constraints and decisions

### 6.1 Where it runs

- **A worker process:** `ccf event-worker --loop`, a compose service under a
  profile, the same shape as `prep-worker` and `assessment-worker`.
- **In-API fallback:** when no worker runs (single-operator / dev), the API process
  runs a periodic in-process loop, through the same claim path.
  - *My call:* every 3 s, one job at a time, each under a time bound. A drain
    "after each request" would find nothing eligible during the settle delay, and
    the work would then wait for a later request.
- **Settings:**
  - `CCF_EVENT_WORKER_ENABLED`, and the API's `CCF_EVENT_DRAIN_INLINE`, both
    default to on for dev.
  - Set them on **both** the api and worker services. A worker-only flag left the
    prep and engine routers unregistered once.

### 6.2 `emit(dispatch=False)`

Keeps its meaning: no `webhook` job. Internal consumers still match. Today's six
`dispatch=False` sites are internal bookkeeping that must not reach subscribers,
and that stays true.

### 6.3 Which tenant a job runs under

*My call:* the tenant of the **scope entity**, not of whoever wrote the event.

- **Scoped jobs:** a `system:N` job runs under that system's organization, and an
  `org:N` job under organization N. When the event carries no organization (about
  11 of the 56 emit sites pass none), `emit` resolves it from the scope.
- **Platform-only jobs:** only jobs with no tenant at all run unscoped. Today that
  is a global webhook for an organization-less event. Unscoped means `RESET ROLE`,
  which bypasses RLS, so no `system:` or `org:` job may ever run that way.
- **Webhooks:** the selection rule for organization webhooks plus global webhooks
  is unchanged.
- **The column:** `outbox_jobs.organization_id` is nullable only for those
  platform-only jobs.

### 6.3a Chained events

Consumers' own writes may emit events, and chains such as KSI results feeding the
graph are intended. Those events:

- **are emitted with `dispatch=False`**, so derived recomputes produce no webhook
  noise;
- **never match the consumer that emitted them**;
- **carry a depth counter**, and an event at depth 3 queues nothing.

### 6.3b `ccf.queue`

*My call:* `claim_jobs` gains an optional eligibility predicate, for
`next_attempt_at` and the settle delay, defaulting to today's behaviour. Prep and
the assessment engine are unchanged.

### 6.4 Reactions that stay inline

Anything the caller's response depends on stays a direct call in the request. The
gates, `consume`, and validation are examples. Only refreshes and proposals move to
consumers.

`reactions.propagate_implementation` returns suggestions in the response, so it
stays inline. `on_scoring_status_changed` becomes the `practice_reaction`
consumer, and the route stops calling it.

### 6.5 Scheduler as backstop

The scheduler keeps its full per-organization refresh steps. A lost or
dead-lettered job therefore costs at most one cycle of staleness. It never costs
permanent drift.

Once the bus has run in production for a while, the scheduler interval can come
down from 24 h. That is not part of this sub-project.

### 6.6 Schema

There are two migrations.

- **`outbox_jobs`:**
  - Columns:
    - `id`, `organization_id`, `consumer`, `scope_key`
    - `trigger_event_id`, `absorbed`
    - `status`, `attempts`, `claimed_at`, `next_attempt_at`, `last_error`
    - `result` (jsonb, for webhook delivery records)
    - `created_at`, `finished_at`
  - It gets RLS like every tenant table, and is added to `test_rls_coverage`.
- **`events`:** gains no columns.
- **Old rows:** existing events are not replayed.

## 7. What is left to the builder

- **The consumer table above:** the exact predicate lists, taken from the emit
  sites.
- **Per-system scoping** inside `monitoring.scan` and the CR26 seeders, where they
  are org-wide or global today.
- **Retention:** how long `done` jobs are kept. Webhook delivery records are useful
  for about 30 days. Derived-view jobs can be deleted on success, but keep a
  counter.
- **The reliability-page section and the admin requeue action.**
- **Tests that prove each claim fails when its guard is removed:**
  - a rolled-back transaction delivers nothing;
  - 1,000 events produce one graph rebuild;
  - a change during a running rebuild is picked up;
  - a dead-lettered job is visible;
  - a consumer runs under the event's tenant (pin the org check on an unscoped
    session, because RLS masks it);
  - `dispatch=False` reaches no webhook.

## 8. Owner decisions (2026-11-06)

- **Freshness:** derived views catch up **within about a minute** of a change.
  - The settle delay is 15 s for derived views, which lets a burst merge into one
    rebuild, and 0 s for webhooks.
  - The target is p95 under 60 s, measured from the event to the end of the job.
    The reliability page reports it.
- **Worker:** production runs a **separate `event-worker` container**, the same
  shape as `prep-worker`. The in-API loop (section 6.1) exists for dev and
  single-operator mode only, and is off when the worker is enabled.
- **Webhooks:**
  - **Change them.** They are sent after commit, delivered at least once and
    retried for about 6 hours.
  - Each message gains an `X-CCF-Event-Id` header plus `event_id` and
    `occurred_at` body fields.
  - The release notes tell receivers to drop duplicates by event id.

## 9. Deviations from this design (as built)

- **`practice_reaction` was not built.** Section 5.1 and 6.4 say
  `reactions.on_scoring_status_changed` becomes a `practice_reaction` consumer
  (triggered by `scoring_status` `status_changed`, scope `system:N`, proposing and
  never closing), and that the route stops calling it. The route
  (`ccf.api.routes.scoring`) still calls it inline. This remains open.
- **Job states.** Section 5.2's `running` is named `claimed` (the `ccf.queue`
  vocabulary the worker reuses); a job absorbed by a claim is `merged`, with
  `merged_into` naming the claimed job. The table also has `claimed_by` and a
  per-row `max_attempts` (webhooks 8, derived views 5), beyond section 6.6's list.
- **One migration, not two.** Section 6.6 says two; `events` gains no columns, so
  only `0115_outbox_jobs` exists.
- **Settings defaults.** Section 6.1 says `CCF_EVENT_WORKER_ENABLED` and
  `CCF_EVENT_DRAIN_INLINE` both default on. As built, `CCF_EVENT_WORKER_ENABLED`
  defaults **off** and `CCF_EVENT_DRAIN_INLINE` defaults on, so with no settings the
  API drains in-process (the dev / single-operator mode of section 8). Compose sets
  `CCF_EVENT_WORKER_ENABLED=true` on both `api` and `event-worker`, which turns the
  inline loop off. `ccf event-worker` refuses to run without the flag.
- **The `event-worker` compose service runs by default**, not under a profile
  (section 6.1), so production gets the separate container section 8 asks for.
- **Webhook backoff** is `170 s * 2**(n-1)`, so 8 attempts span about 6 h.
- **Claim fencing.** Not in the design: a job's outcome is written only while its
  claim (`claimed_by`, `attempts`) still holds. A run that outlived its claim
  (reaped, then re-claimed) reports `lost` and writes nothing.
- **Requeue** is on the reliability page only; there is no CLI requeue command.
- **Slack/Teams notification posts** (follow-up, not in the design). `bus.notify`
  posted inside the caller's transaction. It now renders the message under the
  same policy (`delivery.render`: configured URL, `notify_min_severity`) and queues
  a `notify_delivery` job keyed `notification:N` (migration
  `0116_outbox_trigger_nullable`: such a job has no trigger event). The job never
  merges, retries on the webhook schedule (8 attempts, 170 s base), runs under the
  notification's organization (org-less: platform-only, the `event:N` rule), and
  refuses a notification whose organization disagrees with the job's. A non-2xx is
  now a retried failure (it used to count as sent). An escalation that re-surfaces
  a notification is posted; a same-or-lower-severity refresh is not.
- **Trigger sets grew with the writers that were silent** (follow-up). Writers of
  view inputs that emitted nothing now emit, and the pairs they emit joined the
  trigger sets: the graph gained `control_test`/`connector_config`/`evidence_object`
  `created`, `connector_config`/`evidence_object`/`ai_agent`/`vendor` `updated`,
  `system_component deleted` and the five `authorization_package` decisions that
  move a system's `ato_status`; `capability_derive` gained `system_component
  deleted`; `fedramp20x` gained `evidence deleted`, `waiver approved`/`revoked` and
  `capture_snapshot created`. `test_every_view_input_constructor_emits_or_is_covered`
  extends the POA&M constructor guard to every model a view reads.
- **A promoted rationale records its provenance** (follow-up to section 9.1's C1
  promotion, which stays). `poams.acceptance_rationale_provenance` (migration
  `0117_poam_rationale_provenance`) names the stored document the rationale came
  from, who last saved it and when (read before the seed overwrites it), and who
  ran the promotion (`event:cr26_documents`, or the person who seeded, passed as
  the seeders' new `actor`, distinct from `updated_by` so the row stays
  seeder-written). The POA&M API shows it beside the rationale, and a `poam
  rationale_promoted` event (in no trigger set) puts it on the timeline. Writing a
  different rationale on the POA&M, or leaving `risk_accepted`, clears it.
