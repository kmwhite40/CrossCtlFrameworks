# The CR26 vocabulary (P9a-i)

**Status:** design, awaiting implementation plan
**Extends:** `models.py` (`System`), `patching/sla.py`, `fedramp20x/`
**Closes:** the vocabulary half of G15
**Defers:** CPO and SDR deliverables (their own spec), the Ongoing Certification
Report (`CCM-OCR-AVL`), and `certification_status` — see §5

## 1. Why this is smaller than it looked

P9a was written as four things: Certification Classes, Accepted Weaknesses, the
Ongoing Certification vocabulary, and the CPO + SDR deliverables. Reading the
primary source shrank it twice.

**The Class mapping does not exist.** fedramp.gov/2026/agencies/use/classes/:

> "Agencies should not treat Certification Classes as one-for-one replacements
> for Low, Moderate, or High impact levels."
> "FedRAMP Certification Classes are not aligned to how secure a cloud service
> offering is!"

A Class describes the depth, frequency and quality of assurance data a provider
commits to supplying — not the sensitivity of the information a system holds.
The definitions are deliberately overlapping adequacy ranges (B: most Low and
*some* Moderate or High; C: most Low or Moderate and *some* High; D: most
systems regardless). So the schema change P9a was blocked on should never be
made. See the gap analysis §G15, closed 2026-09-16.

**Accepted Weaknesses are not a new concept.** CR26 eliminates the
provider-side POA&M outright and replaces it with a list of Accepted Weaknesses.
This platform is provider-side and already models the weakness; what changes is
the name and the threshold, not the record.

What remains is a vocabulary, not a subsystem.

## 2. Accepted Weakness: declared or elapsed

The rule (Vulnerability Evaluation and Reporting):

> "Providers MUST categorize any vulnerability that is not **or will not be**
> fully mitigated or remediated within 192 days of evaluation as an accepted
> vulnerability."

**Both halves of that sentence matter.** "Will not" is a forward-looking
provider decision — a weakness can be accepted on day 3 — and no elapsed-time
arithmetic can represent a decision that has not been made yet. A projection
keyed only to age would report an accepted weakness as an open remediation item
for up to 191 days.

The declared half already has a home. `POAM.status` carries `risk_accepted`,
and `constants.py` already draws the distinction CR26 needs:

- `POAM_ACTIVE_STATUSES` — the remediation backlog, **excludes** `risk_accepted`
- `POAM_UNRESOLVED_STATUSES` — not yet remediated, **includes** `risk_accepted`

So:

> **Accepted Weakness = `status == "risk_accepted"` (declared, any age)
> ∪ (`status in POAM_ACTIVE_STATUSES` ∧ elapsed > 192 days) (elapsed)**

The elapsed half is scoped to `POAM_ACTIVE_STATUSES` — the remediation backlog,
which *excludes* `risk_accepted` — so the two halves are **disjoint** and a row
is counted once. Scoping it to `POAM_UNRESOLVED_STATUSES` instead would overlap,
because that set includes `risk_accepted` by design.

**No table, no migration, no second writer.** `POAM` stays the single record of
a provider-side weakness; an Accepted Weakness is a classification of that row.
The Rev5 lane keeps rendering POA&Ms from the same rows and the CR26 lane
renders the projection, so the two cannot drift — there is only one fact.

### 2.1 An assumption stated rather than hidden

**The 192 days run from *evaluation*; `POAM` records `identified_on`.** These
may not be the same act — evaluation is VER-defined. The projection keys to
`identified_on` as the closest existing field, and that substitution is an
explicit assumption to confirm against the VER ruleset, not a silent
equivalence. If they differ, only the key changes; the shape does not.

### 2.2 Reuse `sla.py`'s boundary semantics exactly

`patching/sla.py` already classifies a weakness against a timeframe and its
boundary rules were reviewed and confirmed correct:

- inclusive at the limit — 192 days means 192, not 191
- `unknown` for a missing `identified_on`, and for `closed_on` before it
- **status consulted before any closure date**, so a reopened weakness carrying
  a stale `closed_on` cannot read as resolved

That last rule is not incidental. Shipping it the other way round was a
Critical in the flaw-remediation work: a reopened POA&M classified
`closed_on_time` and counted toward compliance. Do not write a second date
comparison; extend the one that already exists.

### 2.3 A correctness fix this forces

`risk_accepted` currently classifies as `breached` in SI-2 and appears in
`breaching_ids`, with no bucket of its own — which contradicts
`posture.poam_aging`. Under CR26 semantics that is plainly wrong: an accepted
weakness is not an SLA breach, it is the outcome the rule defines. Give it its
own bucket, and assert the buckets sum to the total.

## 3. Class and Path

Two columns on `System`, siblings of `baseline`, neither derived from anything:

```
certification_class   A | B | C | D        nullable
certification_path    program | agency     nullable
```

Nullable is load-bearing, not convenience. Through 2026–27 an offering can hold
a Rev5 ATO and pursue a CR26 Certification at once, so no row may be forced to
claim a Class it does not have. Null means "not CR26-certified", which is
correct for every existing row and for the whole Rev5 lane.

`baseline`, `ato_status` and the FIPS-199 triple are untouched.

**The rule to encode in the column comment:** nothing may derive
`certification_class` from `baseline`, or `baseline` from
`certification_class`. FedRAMP says so explicitly, and the overlapping adequacy
ranges make any such derivation wrong in both directions — a Class B offering
may serve a High system, and a High system may be served by B, C or D.

## 4. Testing

- **A scenario table for the projection**, in the shape `sla.py`'s tests
  already use: `risk_accepted` before 192 days (accepted, declared);
  unresolved past 192 (accepted, elapsed); reopened with a stale `closed_on`
  (not accepted, not resolved); missing `identified_on` (`unknown`); `closed_on`
  before `identified_on` (`unknown`).
- **The SI-2 buckets sum to the total** once `risk_accepted` has its own
  bucket. A version where they silently did not was shipped once.
- **A guard that nothing derives Class from baseline or vice versa** — grep-
  shaped, like `test_role_names_are_real.py`, because this is the kind of thing
  a future edit reintroduces innocently and no amount of exercising the routes
  would catch a derivation added in a helper.
- **Migration** chains off the current head, carries the `pg_roles` GRANT
  guard, and leaves exactly one head. Three migrations in this programme forked
  by chaining off a renamed or duplicate revision; verify with the full
  `alembic heads` output, never piped through `tail`.
- Every new test must be able to fail. This programme produced at least seven
  that could not — a loop over an empty registry, an assertion on a field set
  before the branch under test, a guard asserting strings that never existed.

## 5. What this does NOT do

- **`certification_status` is not modelled.** The enumerated Ongoing
  Certification vocabulary is not published in any source reachable from here.
  The certification ruleset covers Classes, Paths, and downgrade/cancellation
  notice (120 days), but never lists status values. Inventing them is precisely
  what the gap analysis refused to do for Classes, and was right to. Recorded
  as an open question with its reason.
- **No CPO or SDR.** Their own spec. Note SDR is largely a *rendering* of ODP
  assignments the platform already holds (`ssp/odp.py`, `odp_values`), and CPO
  replaces the SSP for Rev5 — a second deliverable profile over content the SSP
  generator already produces, which is the "two lanes, one platform" shape the
  gap analysis proposed.
- **No Ongoing Certification Report.** `CCM-OCR-AVL`; frequency undefined in
  reachable sources.
- **No agency-side POA&M change.** CR26 keeps agency POA&Ms for agency-owned
  actions and states they are explicitly not automatic from provider
  vulnerability data. This platform is provider-side, so the projection is
  correct here — but any future agency-facing surface must not reuse it.

## 6. Deadline

VDR and VER become mandatory for all offerings obtaining or maintaining FedRAMP
Certification on **7 December 2026** — earlier than the 2027-01-01 CR26 date the
gap analysis cites. §2 is the VER-driven half and is the reason this spec leads
with Accepted Weakness rather than with Class.
