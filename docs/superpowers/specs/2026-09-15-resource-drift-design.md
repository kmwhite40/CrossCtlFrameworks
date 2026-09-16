# Resource drift and retention (P2c / CC&E #2)

**Status:** design, awaiting implementation plan
**Extends:** the posture spine (0068), `api/routes/posture.py`
**Satisfies:** programme item P2c (snapshots/retention) and CC&E capability #2
(drift detection at resource level). One sub-project, because they are the same
data read forwards and pruned backwards.

## 1. A bug found while designing this, which defines the shape

`GET /api/posture/failing-resources` documents itself as returning "every
resource **currently** failing a control test". It does not. It selects every
`ControlTestResourceResult` row with `verdict == "fail"` across **all** results
for a test, newest first, with nothing restricting it to the most recent scan.

Verified empirically: record a failing resource, record a passing result for
the same resource, call the endpoint — it still reports the resource as
failing, with the stale `observed` text from the earlier scan.

The cause is the thing this sub-project exists to address. `0068` made the
resource table **append-only history**, which was right, but nothing since has
given the platform a notion of *latest*. Read as current state, an append-only
table answers a different question than the one asked — and an operator acting
on that endpoint chases a resource that was fixed weeks ago.

So the work is: define "latest" once, use it everywhere current state is meant,
and then read the same history deliberately, as history.

## 2. Latest state, defined once

```python
def latest_result_ids() -> Select   # control_test_id -> the most recent result id
```

`MAX(ControlTestResult.id)` grouped by `control_test_id`. Deliberately the id
and not `run_at`: two scans in the same second tie on `run_at`, and a tie makes
"latest" ambiguous. Ids are monotonic per insert, so they cannot tie.

Every caller that means *current* state joins this. `/failing-resources` is
corrected to do so; drift uses it to find the newer side of a comparison.

`ControlTest.last_status` already denormalizes the test-level verdict, and this
does **not** replace it — that field is what recovery detection reads, and
duplicating it here would create a second answer to the same question.

## 3. Drift as a pure comparison

```python
@dataclass(frozen=True)
class ResourceTransition:
    resource_id: str
    kind: str              # regressed | recovered | appeared | disappeared | changed
    before: str | None     # verdict, or None when the resource is new
    after: str | None      # verdict, or None when the resource is gone
    observed: str | None   # the newer observation, for context

def diff_resources(before: Sequence[ResourceFinding], after: Sequence[ResourceFinding]) -> list[ResourceTransition]
```

Five kinds, and the two that do not exist today are the point:

- **regressed** — was `pass`, now needs cover (`fail`, `warn`,
  `manual_review_required`). The alert-worthy transition.
- **recovered** — needed cover, now `pass`.
- **appeared** — absent before, present now. A new resource entering scope
  already failing is materially different from one that regressed, and
  conflating them misattributes when the weakness began.
- **disappeared** — present before, absent now. **Nothing in the platform
  notices this today.** A resource that vanishes was deleted, moved out of
  scope, or the collection silently truncated — the last of which is a failure
  that currently looks like an improvement, because the failing row simply
  stops being returned.
- **changed** — same verdict, different `observed`. Quiet drift: a resource
  failing for a new reason is still news.

Unchanged resources produce no transition. `not_applicable` and `not_tested`
participate: a resource moving from `fail` to `not_applicable` is not a
recovery and must not be reported as one, so the classification keys on the
`REQUIRES_COVER` set already defined in `governance/waivers.py` rather than a
second list.

Pure, table-driven, no database — the same discipline as
`posture/declared.py` and `governance/waivers.py`.

## 4. The timeline

```python
async def resource_timeline(session, *, test_id: int, resource_id: str, limit: int = 50)
```

One resource's verdicts for one check, newest first, each entry carrying the
result id, `run_at`, verdict, observed text, and `waiver_id`. This is the
"when did this start failing, and what has it been doing since" question, and
it is the read the configuration-timeline ask in the CC&E directive needs for
*observed* state (desired state is `packs/diff.py`, built in P2b).

## 5. Retention: keep the series, window the detail

A daily scan of 10,000 users writes 3.65M resource rows a year, per check.
Unbounded growth is not a hypothetical.

The rule: **the aggregate is kept forever; the per-resource detail is
windowed.** `ControlTestResult` rows — with `evaluated`, `failing`, `waived`,
`status` and `expected` — are never pruned, so the time series an
authorization package draws on stays complete. `ControlTestResourceResult`
rows older than the window are deleted.

Two exemptions, both load-bearing:

1. **The latest result per test is never pruned**, regardless of age. A check
   that last ran eighteen months ago must still be able to say *which*
   resources were failing, or pruning silently converts "3 of 47 failing" into
   an unexplainable number.
2. **A row with a `waiver_id` is never pruned.** It is the record of which
   specific resource an acceptance covered. Deleting it leaves a waiver whose
   justification cannot be checked, which is precisely the audit question a
   waiver exists to answer.

Window from settings (`posture_resource_retention_days`, default 400 — over a
year, so an annual assessment window is always covered). Pruning is explicit:
a CLI command and a function, **not** wired into the scheduler by this
sub-project. Automatic deletion of assessment detail should be a decision an
operator makes knowingly, and a first release that deletes on a timer before
anyone has seen the volume is the wrong default.

## 6. What this does NOT do

- No new tables. Everything reads `0068`'s existing rows.
- No change to `record_result`, `_alert_on_failure`, or recovery.
- No alerting on drift. A transition is a read-side observation here;
  alerting on `disappeared` in particular needs a policy decision about
  collection failures that belongs with the enforcement work.
- No change to `ControlTest.last_status`.
- Pruning is never automatic (§5).

## 7. Testing strategy

- `diff_resources` is pure: table-driven over all five kinds, plus the cases
  that must *not* be a recovery (`fail` → `not_applicable`) and must not be a
  regression (`not_applicable` → `fail` is an appearance of a real finding, but
  from an excluded state — classified `regressed`, and tested either way so the
  choice is explicit rather than incidental).
- The bug in §1 gets a regression test asserting a fixed resource is **absent**
  from `/failing-resources`, and a companion asserting a still-failing one is
  **present** — without the second, the fix could be "return nothing".
- Retention: rows inside the window survive; older ones go; the latest result's
  rows survive at any age; a waived row survives; and the `ControlTestResult`
  count is unchanged by a prune.
- Mutation testing on every guard, with the harness invariants from the
  mutation-testing memory — including keying backups by full path, since this
  adds `posture/retention.py` alongside existing modules.
