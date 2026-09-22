# Live capture is proved by the artifact, not by a status column — design

**Status:** design 2026-09-22. Closes a live defect that reopens
`fix/connector-backed-claim` (merged at `e92ee64`) through a different path.

---

## 1. The defect

`fix/connector-backed-claim` made an SSP's "this is evidenced" claim depend on
whether *this tenant* has a working connector, rather than on whether Concord
ships one for the declared platform. The ladder it introduced
(`governance/control_tests.connector_backing_state`) reads four columns of
`ConnectorConfig`:

```
status == "configured"  ·  last_sync is not NULL  ·  not stale  ·  objects_discovered > 0
```

**Those are self-reported status columns. Any code path that writes them
manufactures the proof.** One such path exists today.

Measured, `POST /connector-configs/{id}/sync` (`api/routes/grc.py`) is a
**mock** — its own docstring says *"Mock sync path — records discovery + sets
status until live auth is wired"* — and it sets exactly those four fields:

```python
c.objects_discovered = _MOCK_DISCOVERY.get(c.connector_type, 100)   # gcp -> 200
c.status = "configured"
c.last_sync = _now()
c.error_message = None
```

Its sibling `POST /connector-configs` creates the row with **no credential**.
Both are gated on `get_principal` only — any authenticated user, any role.

So **two API calls and no credentials** make `organization_capture_is_live`
return `True`, which omits the manual-evidence caveat and retains a
platform-sourced `Implemented` in a document filed with a federal regulator.
It works for any `connector_type` the caller names, including `aws_govcloud`
and `m365`.

The mock is honest about itself — it emits `payload={"mock": True}` to the
audit bus. Nothing downstream reads that flag.

### 1.1 The lesson, one level deeper than last time

This morning's fix stopped trusting a **static table** and asked the tenant
instead. It then trusted a **status field** the application sets. The same
shape, one layer down: a value that asserts something the platform has not
established.

The honest question — *did this tenant actually capture anything* — already has
an artifact that answers it. `CaptureSnapshot` is what a real capture produces
(`governance/collection.py:66`), keyed `(organization_id, connector, odp_key)`
with `connector = conn.key`, the same value space as
`ConnectorConfig.connector_type`.

**Proof becomes the artifact, not the claim.**

---

## 2. The rule

`organization_capture_is_live(session, organization_id, connector_type)`
returns `True` only when **all three** hold:

1. **The connector is currently usable** — the existing
   `connector_backing_state` ladder returns `current`. A revoked or
   unconfigured connector cannot evidence anything, however much it captured
   last month.
2. **At least one `CaptureSnapshot` exists** for this `(organization_id,
   connector)` whose `captured_at` is within the staleness window. This is the
   rung the mock cannot fabricate: it writes no snapshots.
3. **The credential is the tenant's own**, not the host's (§3).

Any of the three failing means not live, and the caveat is added. The
conservative direction is unchanged and is restated in the code: over-flagging
costs a reviewer an edit; under-flagging ships a claim nothing verified.

### 2.1 Staleness comes from the artifact

Rung 2 measures `CaptureSnapshot.captured_at`, not `ConnectorConfig.last_sync`.
`last_sync` says the connector *ran*; `captured_at` says it *produced
something*. Where they disagree, the artifact is the honest one.

### 2.2 The mock is gated to development

`is_dev_env` (`config.py:368`) already exists. The mock sync path is refused
outside development. This is defence in depth, not the fix: rung 2 already
means a mock sync evidences nothing. **Both are applied** — a future write path
to those columns must not reopen this, and a mock that silently does nothing in
production is worse than one that says so.

### 2.3 What this deliberately does NOT change

`connector_backing_state` keeps its current definition, and
`governance/control_tests._evaluate` keeps using it unchanged. Control tests
therefore still trust the status columns.

That is a narrower instance of the same weakness and it is **recorded, not
silently fixed here**: a control test is an internal check, while the SSP claim
is a federal assertion, and widening this change into the control-test
scheduler would alter what a tenant's tests report in the same branch that
fixes a document claim. It needs its own measurement of what currently passes.

---

## 3. A host profile is not a tenant credential

Every provider authenticates with a tenant-supplied API credential except AWS,
which also accepts `profile` — a named profile resolved from the **host's**
`~/.aws/credentials` (`connectors/aws.py:79`). That is one shared identity for
the deployment, not this organization's.

The capture path keeps working — existing deployments are not broken. But a
profile-backed connector **never counts as live tenant capture**, because the
SSP sentence it would license ("this organization's own automated capture
evidences this control") is not true of a host identity.

`aws.py:64` distinguishes the two cases already:
`(access_key_id and secret_access_key) or profile`. Rung 3 reads the resolved
credential and returns `False` when the only identity available is a host
profile. Keep the test specific and named rather than inventing a general
"is this credential tenant-scoped" abstraction for a single case.

---

## 4. Testing requirements

1. **The two-call reproduction, pinned failing first.** Create a
   `ConnectorConfig` with no credential, call the mock sync, then generate
   statements: the manual-evidence caveat **must still be present** and a
   platform-sourced `Implemented` must still be downgraded. **Write this first
   and confirm it FAILS on unmodified code**; report what it printed. This is
   the whole change in one test.
2. **Each rung independently**, by seeding real rows: config current but no
   snapshot → not live; snapshot present but connector unconfigured → not live;
   snapshot present but stale → not live; all three → live.
3. **A real capture still evidences.** Seed a configured connector *and*
   `CaptureSnapshot` rows and assert the caveat is absent — a fix that makes
   nothing ever count is not a fix.
4. **The mock is refused outside development**, and still works in it.
5. **A profile-backed AWS credential does not count as live**, while an access
   key pair for the same org does — asserted separately so §3 cannot collapse.
6. **Control tests are unchanged** — assert `connector_backing_state`'s
   behaviour is identical for the same inputs, so §2.3 is a recorded decision
   rather than an accident.

Mutation-verify each rung: remove it, confirm a test fails. A rung whose
removal leaves the suite green is not protecting anything.

---

## 5. Out of scope

- **Changing what control tests trust** (§2.3). Recorded for its own change.
- **Removing the mock endpoint.** Gating it is enough once rung 2 exists, and
  deleting it would remove a credential-free demo path that may be in use.
- **A general "tenant-scoped credential" abstraction** (§3). One case does not
  justify one.
- **Backfilling a judgement about past claims.** A document generated before
  this change cannot be distinguished from one generated after; as with the
  platform default, the fix stops new occurrences.
