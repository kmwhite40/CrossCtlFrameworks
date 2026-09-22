# Baseline delta — what moving to a higher baseline would require

**Status:** design 2026-09-22. First implementation of a capability the
platform has never had: comparing a system against a target it has **not**
adopted.

---

## 1. Nothing does this today

Measured across `src/ccf`: there is no model, service, endpoint, CLI command,
template or test containing the concept *target profile*, *desired state*, or
*delta to reach X*. `ssp/seed.py` and `ssp/nist80053.py` seed from **the
system's own** `System.baseline` and raise without one. `catalog/diff.py` diffs
two OSCAL catalog **revisions**, not two baselines. `packs/service.py`
`coverage` compares a system against a control set, but only one the tenant has
already **installed**.

So the question a customer asks before an uplift — *"we are Moderate; what
would High require?"* — has no answer in the product.

---

## 2. It must not become the tenth notion of "gap"

**Nine distinct gap concepts already exist** and none share a vocabulary or a
data structure: profile-derivation gaps, `automation.coverage`, the `/coverage`
catalog heatmap, `ssp.completeness`'s `control_gaps`, pack coverage,
`insights.data_quality`, FedRAMP 20x KSI gaps, LLM-authored assessment gaps,
and catalog-integrity gaps.

This spec adds a tenth *question*, so it must not add a tenth *vocabulary*.
What it reuses, explicitly:

| Concern | Reused from | Never re-derived |
|---|---|---|
| Identifier normalisation | `catalog.canonical.canonicalize` | no second normaliser |
| "does this system satisfy a control" | `{implemented, inherited}` — the set `packs/service.py` and `capability/rollup.SATISFIED` both already use | no third definition |
| Baseline membership | `framework_mappings` rows | no new membership table |

What it deliberately does **not** reuse: `automation.coverage`, which is scoped
to the ~110 CMMC practices of `profile.derivation` and answers a different
question over a different universe. Joining the two would give one number two
meanings.

---

## 3. The unit is a canonical control, not a catalog row

**This is the finding that decides the whole design.** The `controls` table
holds assessment objectives and ODP placeholders, not only controls. Measured:

```
FedRAMP Low       rows=1525   distinct canonical controls=157
FedRAMP Moderate  rows=2312   distinct canonical controls=323
FedRAMP High      rows=2673   distinct canonical controls=409
```

Raw rows in the High-minus-Moderate difference include `AU-06(07)#row906` (a
literal row marker), `SA-11(02)_ODP[03]` (a parameter placeholder) and
`PS-03b.[01]` (an objective decomposition). Counting them would report a
**387-row** uplift where the truthful answer is **87 controls**.

So membership is resolved through `canonicalize` on both sides, exactly as
`capability/derive.py:72-91` does and as pack coverage was just fixed to do
(`2a40109`). A raw string compare here would not merely miss — it would
produce a confidently wrong number in front of a customer planning an uplift.

Baseline membership lives in `framework_mappings` with
`column_key ∈ {"FedRAMP Low", "FedRAMP Moderate", "FedRAMP High"}` and
`value = "X"`. The value is a membership marker; nothing else is encoded in it.

---

## 4. The target does not superset the current baseline

The obvious model — *High contains Moderate, so a delta is "what to add"* — is
false. Measured at the canonical level, one control is in Moderate and **not**
in High: **`CM-2(2)`**.

Whether that is a workbook defect or a real FedRAMP quirk, **the design must
not assume supersetting.** Reporting only additions would silently imply that
a control the system currently owes is being dropped.

So the result has **two** lists:

- **`added`** — in the target, not in the current baseline. The uplift.
- **`removed`** — in the current, not in the target. Expected to be small or
  empty, and **not silently hidden when it is not**.

A `removed` entry is reported as an observation, never as permission to stop
implementing something. The platform states the catalog's answer; it does not
advise dropping a control.

---

## 5. What makes it a gap assessment rather than a catalog diff

For each control in `added`, join the system's existing
`ControlImplementation`. A system moving Moderate → High has usually already
implemented some of the 87.

```python
@dataclass(frozen=True)
class BaselineDelta:
    system_id: int
    current: str            # "moderate"
    target: str             # "high"
    added: list[str]        # canonical ids in target, not in current
    removed: list[str]      # canonical ids in current, not in target (§4)
    already_satisfied: list[str]   # of `added`, those already implemented|inherited
    outstanding: list[str]         # of `added`, the rest
    unmapped: list[str]            # target rows that did not canonicalize (§6)
```

`already_satisfied + outstanding == added`, asserted — the invariant that stops
the two lists drifting, in the same spirit as `poam_aging`'s documented
`on_track + overdue + no_due_date == open_total`.

---

## 6. What cannot be resolved is named, never dropped

A target row whose identifier does not canonicalize goes in `unmapped`. It is
not an addition and not a satisfaction — it is a row the platform could not
place, and an operator planning an uplift needs to know the count rather than
receive a number quietly short by that many.

This is the rule pack coverage was just given for unparseable pack ids
(`2a40109`): identity is the only honest fallback, and what was matched that
way is reported.

---

## 7. A system with no baseline

Measured on the dev database: of 14 systems, **8 have `baseline = NULL`**,
5 moderate, 1 high. A delta from an unknown baseline is not computable.

**Refuse it, and say why.** Do not default to Low — that would invent a
current state and report an uplift the customer does not owe. This is the same
rule as `ssp/seed.py`, which raises `"system has no baseline or FIPS-199
categorization"` rather than guessing.

---

## 8. Deliberately out of scope

- **The per-objective 800-53B columns.** `framework_mappings` also carries
  `Confidentiality|Integrity|Availability NIST SP 800-53B Non-NSS
  Low|Moderate|High` — nine columns that map onto `System.fips199_*` and would
  give a more precise delta than a single baseline. Real, and a second change:
  it needs a decision about which of the two sources is authoritative when they
  disagree, which is exactly the kind of question that should not be answered
  inside a first implementation.
- **Cross-framework deltas** ("we hold CMMC; what would FedRAMP add"). The
  crosswalk resolves to free-text strings, not control rows, so there is
  nothing to join status onto. It needs a mapping-to-rows resolution layer
  first.
- **Advising an uplift.** The platform reports what a baseline contains and
  what the system has. It does not recommend, schedule, or open POA&Ms.
- **A UI.** Service and API first; where it renders is a separate decision.

---

## 9. Testing requirements

1. **The measured numbers are pinned**: Low 157, Moderate 323, High 409
   distinct canonical controls, and an 87-control Moderate → High uplift,
   asserted against the real shipped catalog — not a fixture. If the workbook
   changes, this must fail and be re-measured, not silently drift.
2. **`CM-2(2)` appears in `removed`** for Moderate → High. The anomaly is
   pinned so it cannot vanish unnoticed, in either direction.
3. **Row-level counting is caught**: a test that would pass on raw rows
   (387) and fails on canonical controls (87). This is the defect the design
   exists to avoid, so it gets a dedicated test.
4. **`already_satisfied + outstanding == added`**, over a seeded system with a
   mix of implemented, inherited, planned and absent controls.
5. **A system with `baseline = NULL` is refused**, with the reason, not
   defaulted to Low.
6. **Same baseline in and out** yields empty `added` and `removed` — a
   degenerate case that must not error.
7. **Tenant isolation**: the implementation join sees only this organization's
   rows. Note that `get_session` binds the RLS tenant, so an HTTP-only test
   cannot distinguish an explicit predicate from RLS; if one is used, pin it on
   an unscoped session.

Mutation-verify: remove the canonicalization and confirm the row-count test
fails; remove `removed` and confirm `CM-2(2)`'s test fails.
