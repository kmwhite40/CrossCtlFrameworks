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
same partition the AVI uses, so the OCR's summary and the AVI's records cannot
disagree.

The sentence states a count and points at the AVI, and says nothing it cannot
support. It is regenerated on every seed; it is not authored and is not
preserved.

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

`plannedCertificationDataChanges` and `reportableIncidents` are objects with
their own `required` keys, so a partially-authored one is **invalid**, not
merely incomplete. Treat an object missing its required keys as unauthored:
omit it and name it, rather than filing half an attestation.

---

## 4. The result

```python
@dataclass(frozen=True)
class OcrSeedResult:
    document: Cr26Document
    missing_fields: list[tuple[str, str]]   # field name, why it is still owed
    accepted_count: int                     # what the derived summary counted
```

`missing_fields` is the to-do list. It names every required field omitted for
want of an author, with a reason written for the person who has to fix it.

`accepted_count` is reported separately so an operator can reconcile the OCR's
prose summary against the AVI's records without parsing the sentence.

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
6. **The derived summary agrees with `accepted_count`**, and both agree with
   what `accepted_weakness_state` says about the same rows — so the OCR and the
   AVI cannot contradict each other.

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
