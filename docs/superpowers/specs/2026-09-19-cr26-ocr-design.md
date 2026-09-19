# CR26 Ongoing Certification Report — design

**Status:** design 2026-09-19. P9a-ii part 5. Sixth of eleven CR26 deliverables.

**Schema:** `fedramp-ongoing-certification-report-schema-2026-06-24.json`,
`$schemaVersion` 0.2.0, titled *FedRAMP Ongoing Certification Report
(CCM-OCR-AVL)* — "Quarterly Ongoing Certification Report (OCR) per
CCM-OCR-AVL, covering the entire period since the previous report."

---

## 1. This deliverable inverts the ones before it

The SDR is mostly a rendering of platform data. The VER family is partly. The
**OCR is almost entirely authored**: of its nine required fields, one can be
honestly derived and eight are human statements about the business — what
changed, what is planned, which agencies use the product, what incidents
occurred.

That inversion is the whole design. A seeder built on the habits of the last
three deliverables would produce a valid document that lies nine times.

### 1.1 Measured: an all-empty OCR validates

```
{certificationPackageOverviewUri, reportPeriod, certificationDataChanges: [],
 plannedCertificationDataChanges: {planningHorizonThrough, changes: []},
 acceptedVulnerabilities: "", transformativeChanges: [],
 updatedRecommendations: [], activeAgencies: [],
 reportableIncidents: {incidents: []}}
-> ok=True, errors=[]
```

Every required field accepts an empty value. Nothing in the schema stops a
generator filing a document that says nothing while appearing complete.

### 1.2 One of those empties is an explicit attestation

`reportableIncidents.incidents`, from the schema's own description:

> Provide an empty array to attest that **no FedRAMP Reportable Incidents
> occurred** during this period.

An empty array here is not an absence of data. It is a **positive statement to
a federal regulator that nothing happened**, and it is the favourable answer.
The platform cannot know it. Emitting `[]` because nobody authored anything
would be the most serious instance of this programme's signature defect yet —
every earlier one misstated a control or a vulnerability; this one would file
a false incident attestation.

The same reasoning applies with less force to `certificationDataChanges`,
`transformativeChanges` and `activeAgencies`: an empty array reads as "none",
not as "unknown".

---

## 2. The rule: seed the structure, omit what nobody authored

**A required field with no authored content is OMITTED, and the document is
invalid until a human supplies it.**

This is not a new doctrine. `seed_sdr` already does exactly this with
`certificationPackageOverviewUri`, and its docstring states why: *"a seeded SDR
is invalid until someone publishes the CPO and supplies its URI. That is
correct rather than unfortunate — something is genuinely still owed."*

The OCR simply has eight such fields instead of one. The seeded document is a
**scaffold with a to-do list**, not a filing. It becomes valid when it becomes
true.

**Rejected alternative:** emitting empty values and reporting the gaps only in
the seed result. A document that validates is a document someone can file, and
the result object does not travel with it. The invalidity *is* the guard.

---

## 3. Field map

### 3.1 Carried forward

| Field | Source |
|---|---|
| `certificationPackageOverviewUri` | the stored document, if authored; **never invented** |

### 3.2 Caller-supplied

| Field | Source |
|---|---|
| `reportPeriod` | `period_from` / `period_to`, as for the VDR and AVI |

**`reportPeriodDate` is NOT `reportPeriodDateTime`.** The OCR uses a different
`$def` from the VER family: `{from, to}` with `format: date`, not `date-time`.
**And `date` IS enforced in this environment** while `date-time` is not —
measured, `enforced_formats()` lists `date` and omits `date-time`. So:

```
reportPeriod.from = "2026-07-01T00:00:00Z"
  -> ok=False  ["reportPeriod/from: '2026-07-01T00:00:00Z' is not a 'date'"]
```

Reusing the VER family's `_instant` here fails loudly rather than silently,
which is the one place this deliverable is *safer* than its predecessors. Emit
`date.isoformat()`. Do not import `_instant`.

### 3.3 Derived — exactly one

| Field | Source |
|---|---|
| `acceptedVulnerabilities` | a summary sentence over the system's accepted weaknesses |

It is a **string**, not an array — "Summary of accepted vulnerabilities. Full
records are reported per VER-RPT-AVI." The platform knows this: reuse
`ccf.patching.sla.accepted_weakness_state` over the system's POA&M rows, the
same scanner-derived-flaw, same-period partition the AVI's own walk scopes
to.

**Correction (review round 2): the count and the AVI's array CAN disagree, and
an earlier version of this spec wrongly claimed they cannot.** Measured, one
system, one period, three `risk_accepted` in-period `scan` rows:

```
AVI acceptedVulnerabilities: 1
AVI omitted_poam_ids: [(47, "no acceptance rationale"), (48, "no description")]
OCR acceptedVulnerabilities: "3 accepted vulnerabilities for this reporting
  period. Full records are reported per VER-RPT-AVI."
OCR accepted_count: 3
```

The count is the honest number: it is the **whole population** of accepted
weaknesses in period, exactly what `accepted_weakness_state` says about each
row. The AVI's own `acceptedVulnerabilities` array is narrower by two further
filters the count does not apply — `render_vulnerability` can refuse a row
(no description, no detection source), and `merge_accepted` omits any
accepted row with no acceptance rationale, which is the *default* state of an
elapsed accepted weakness nobody has declared or documented. Narrowing the
OCR's count to match the AVI's array would hide accepted vulnerabilities from
the summary *because* they are undocumented — the favourable answer, and the
wrong direction under a rule obliging disclosure. The count must stay the
whole population; the gap must be made visible instead (see `avi_gap` below).

The sentence states a count and points at the AVI, and says nothing it cannot
support — the cross-reference is the schema's own required wording, and
stays. What changes is that the platform stops asserting the two numbers
agree.

**If the count is zero, say zero — do not omit.** A derived zero is measured,
not assumed, and differs from the eight fields below precisely because the
platform can see the whole population.

### 3.4 Authored — omitted until supplied, and named

| Field | Why the platform cannot supply it |
|---|---|
| `certificationDataChanges` | what changed in the certification data since the last report, as a human summary |
| `plannedCertificationDataChanges` | a forward-looking commitment, including `planningHorizonThrough` (`format: date`, "at least 3 months from report end") |
| `transformativeChanges` | a judgment about which changes were transformative |
| `updatedRecommendations` | guidance to customers |
| `activeAgencies` | which agencies use the product — commercial knowledge the platform does not hold |
| `reportableIncidents` | **an attestation** (§1.2) |

Each is preserved verbatim when authored, and omitted when not. Each omission
is named in the result.

**"Authored" means the key is PRESENT, not that its value is non-empty.** The
seeder itself never writes any of these six keys when nothing was authored —
so if a key is there at all, it can only have come from a human's own `PUT`.
An authored `[]` is that human's attestation that nothing happened this
period, and it must be preserved exactly like a non-empty one: an empty array
in this context still reads as "none", not "unknown" (§1.2) — but that is the
reason the *seeder* must never fabricate one on nobody's behalf, not a reason
to discard one a human actually supplied. Refusing an authored empty makes
the OCR's single most common case — a quiet quarter in which genuinely
nothing happened — unfileable: an operator who honestly authors `[]` for
`certificationDataChanges`, `transformativeChanges`, `updatedRecommendations`,
and `activeAgencies` must see the document become valid, not stay invalid for
saying so. `reportableIncidents`'s empty `incidents` array is the sharpest
instance of this rule, not an exception to it: every one of these six fields
is governed by the same presence test.

`plannedCertificationDataChanges` and `reportableIncidents` are objects with
their own `required` keys, so a partially-authored one is **invalid**, not
merely incomplete. Treat an object missing its required keys as unauthored:
omit it and name it, rather than filing half an attestation. An object with
*all* of its required keys present — including one whose value is an empty
array, such as `plannedCertificationDataChanges.changes` — is fully authored
and carried forward, by the same presence rule.

---

## 4. The result

```python
@dataclass(frozen=True)
class OcrSeedResult:
    document: Cr26Document
    missing_fields: list[tuple[str, str]]   # field name, why it is still owed
    accepted_count: int                     # what the derived summary counted
    avi_gap: list[tuple[int | str, str]]    # (poam id, reason) the AVI cannot report
```

`missing_fields` is the to-do list. It names every required field omitted for
want of an author, with a reason written for the person who has to fix it. The
reason distinguishes a field nobody touched from one a human authored but left
unusable (malformed shape) — collapsing those two into one message destroys
the authored content with no record of what was actually wrong.

`accepted_count` is reported separately so an operator can reconcile the OCR's
prose summary against the AVI's records without parsing the sentence.

`avi_gap` is the honest accounting §3.3 requires: which of the rows
`accepted_count` counted the AVI will not be able to report right now, and
why, computed by running `ccf.cr26.ver.render_all` and
`ccf.cr26.ver.merge_accepted` read-only — the same pipeline `seed_avi` uses,
never a second hand-maintained copy of "why AVI omits a row". A non-empty
`avi_gap` beside a document that otherwise validates is the operator's signal
that they owe acceptance rationales, not silence.

---

## 5. Testing requirements

1. **A freshly seeded OCR with nothing authored is INVALID**, and its errors
   name every omitted required field. Assert the error list by exact equality —
   this document's whole design is that it fails until it is true.
2. **An authored value survives a re-seed** for each of the six authored
   fields, and the derived summary refreshes.
3. **`reportableIncidents` is never emitted empty by the seeder.** A test must
   fail if it ever is. This is the attestation guard and it is the most
   important test in the file.
4. **The period renders as `date`, not `date-time`** — exact string, plus a
   test that a date-time value is rejected by the validator, pinning the
   difference from the VER family.
5. **A partially-authored `plannedCertificationDataChanges` or
   `reportableIncidents` is treated as unauthored**, not filed half-complete.
6. **The derived summary agrees with `accepted_count`**, and `accepted_count`
   agrees with what `accepted_weakness_state` says about the same rows.
   Separately: seed BOTH the AVI and the OCR for the same system and period,
   and assert `accepted_count >= len(avi["acceptedVulnerabilities"])` with
   every difference accounted for in the AVI's own `omitted_poam_ids` — the
   OCR and the AVI are not asserted to agree (§3.3), but the size and cause of
   their disagreement must be provable, not assumed.
7. **A row with no `identified_on` never enters `accepted_count`.** Mutating
   that guard away must be caught by a dedicated test — an undated row cannot
   be placed in any period, and this is the one guard in the module a mutation
   sweep found unpinned (review round 2).

---

## 6. Out of scope

- **Quarterly scheduling.** The schema calls this a quarterly report covering
  "the entire period since the previous report", but nothing in the platform
  records when the previous one was filed, and `cr26_documents` keeps one row
  per kind. The caller supplies the period, exactly as for the VDR and AVI
  (VER-family spec §6.1). Chaining is an operator obligation until a
  scheduling decision is made.
- **An authoring UI.** The document is authored through
  `PUT /cr26-documents/ocr`, as the other deliverables are.
- **No migration.** The store is unchanged.
