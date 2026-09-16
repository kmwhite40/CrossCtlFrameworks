# Config-change impact, and drift telemetry (CC&E #6 and #11)

**Status:** design, awaiting implementation plan
**Extends:** `packs/diff.py` (P2b), `capability/service.py` (P1),
`posture/scan.py`, `api/metrics.py`
**Two capabilities, one spec.** They are small, they share a purpose — making
the drift signal actionable rather than merely present — and separating them
would mean two rounds of ceremony for a day's work. They are built as separate
tasks with separate tests.

---

# Part A — Change impact for a configuration change (#6)

## A1. The pattern already exists; the subject is new

`catalog/impact.py` answers "what would adopting this catalog revision do to
*this* deployment": which systems' baselines move, which authored entries are
orphaned, which mappings dangle. That is exactly the shape #6 needs, applied to
a different change: a **desired-state** change — a pack version that adds,
removes, or re-parameterizes a posture rule.

So this reuses the shape and the ingredients, and adds no new machinery:
`packs/diff.py:diff_posture_rules` supplies the change,
`posture/resolve.py` supplies what the rules mean, `capability/service.py`
supplies the graph, and `models_grc` / `models_waivers` supply what already
exists here.

## A2. What an operator needs to know before adopting

For each rule added, removed, or changed:

- **Controls affected** — the rule's `control_ids` (Form B) or the platform
  evaluator's (Form A, which inherits them). "This change touches AC-2 and
  AC-6" is the first question.
- **Capabilities affected** — via `capabilities_for_control`, so the answer
  reaches the authored narrative: a rule change that touches a capability means
  SSP prose derived from it may need review (P4a made that prose
  capability-derived).
- **Existing checks that would be retired** — a removed rule leaves a
  generated `ControlTest`. `posture/scan.py`'s docstring already states the
  rule: such a test must be **DEACTIVATED, never deleted**, because validation
  history is the product. Impact analysis is where that consequence becomes
  visible before it happens, and it reports the test's current
  `last_status` — "retiring a check that is currently failing on 3 resources"
  is a materially different decision from retiring a passing one.
- **Waivers that would be orphaned** — this is the non-obvious one. A waiver
  keyed on `check_key` survives the removal of the check it accepts, leaving a
  formal acceptance of a finding that can no longer be produced. Nobody would
  look for that, and it is exactly the kind of stale governance artefact an
  assessor finds instead.

## A3. Shape

```python
@dataclass
class ConfigChangeImpact:
    controls_affected: list[dict]      # control_id, why (added/removed/changed), rule keys
    capabilities_affected: list[dict]  # capability key/title, the controls reached
    checks_retired: list[dict]         # test id, check_key, last_status, system_id
    waivers_orphaned: list[dict]       # waiver id, check_key, status, expires_on
    def is_empty(self) -> bool
    def to_dict(self) -> dict

async def build_config_change_impact(session, *, org_id, diff: PostureRuleDiff) -> ConfigChangeImpact
```

Read-only and side-effect free, as `AdoptionImpact` is: computed for a human to
review, never applied.

An **unknown baseline** (`diff.baseline == UNKNOWN_BASELINE`, from a pack
version installed before manifests were retained) produces an empty impact with
that reason recorded — not a speculative one. Guessing at what changed from
missing history is the failure mode `packs/diff.py` already refuses.

Exposed as `GET /api/packs/{pack_key}/impact?from_version=&to_version=`.

---

# Part B — Telemetry for drift and suppression (#11)

## B1. What to count, and the constraint that shapes it

`api/metrics.py` already carries the precedent — `KSI_DRIFT_EVENTS` counts KSI
regressions, `FEDRAMP20X_READINESS` gauges readiness per system — and the
middleware's own comment records the governing constraint: **bound the
cardinality.** A label per check key is defensible (checks are content, in the
tens); a label per *resource* is not, and a fleet of 10,000 users would put
10,000 series into Prometheus from one check.

So: **no `resource_id` label anywhere, and no `check_key` label.** Verdict and
transition kind are small closed vocabularies; `system_id` follows the existing
readiness gauge's precedent.

| Metric | Type | Labels | Incremented where |
|---|---|---|---|
| `ccf_posture_check_results_total` | Counter | `verdict` | `scan_for_system`, per outcome recorded |
| `ccf_posture_drift_transitions_total` | Counter | `kind` | `scan_for_system`, per transition observed |
| `ccf_posture_waiver_suppressions_total` | Counter | — | `record_result`, when a waiver suppressed the consequence |
| `ccf_posture_resource_detail_pruned_total` | Counter | — | `prune_resource_detail` |
| `ccf_posture_failing_resources` | Gauge | `system_id` | `scan_for_system`, after a scan |

## B2. Counted at write time, not read time

Drift transitions are counted **during a scan**, not in the drift endpoint. A
counter incremented by a read double-counts every refresh of a dashboard and
reports activity that did not happen. This costs one extra query per check per
scan, which is the correct trade.

The waiver suppression counter is the one an assessor will ask about: how often
is this platform declining to act on a finding? Counting it at the moment of
suppression makes that answerable.

## B3. Instrumentation must never break the thing it measures

Every increment is wrapped so a metrics failure cannot fail a scan or lose a
recorded result — the same discipline `fedramp20x/monitoring.py` and
`readiness.py` already apply with their local imports and guarded calls. A
posture scan that dies because Prometheus is unhappy is a worse outcome than
missing telemetry.

---

## Testing strategy

- Impact: table-driven over added / removed / changed rules; a removed rule with
  an existing `ControlTest` reports it as retiring with its current status; a
  removed rule with a waiver reports the waiver as orphaned; an unknown
  baseline reports empty **with a reason**; another tenant's checks and waivers
  never appear.
- Telemetry: assert counter values move by the expected amount across a scan,
  using `prometheus_client`'s registry to read samples. Assert **no metric
  carries a resource or check label** — a structural test on the metric
  definitions, so the cardinality rule cannot be broken by a later addition.
- A test that a raising metrics call does not fail a scan.
- Mutation testing on every guard, with the harness invariants from the
  mutation-testing memory.
