# CR26 VER Family — Vulnerability Detail Report, Accepted Vulnerability Info, Historical VER Activity

**Status:** design approved 2026-09-18. P9a-ii part 4.

**Deadline:** VDR and VER become mandatory for all offerings obtaining or
maintaining FedRAMP Certification on **2026-12-07** — the programme's earliest
deadline, ahead of CPO/SDR maintenance (2027-01-01 for 20x, 2027-08-01 for
Rev5).

---

## 1. Scope: one renderer, three envelopes

The three deliverables are not three features. Measured against the vendored
schemas:

| Kind | Root `required` | Array contents |
|---|---|---|
| `vdr` | `certificationPackageOverviewUri`, `reportPeriod`, `vulnerabilities` | `vulnerabilityDetail` |
| `avi` | `certificationPackageOverviewUri`, `reportPeriod`, `acceptedVulnerabilities` | `acceptedVulnerabilityInfo` |
| `ver_history` | `certificationPackageOverviewUri`, `generatedAt`, `activeVulnerabilities`, `acceptedVulnerabilities` | both of the above |

`acceptedVulnerabilityInfo` is `{vulnerabilityDetail, acceptanceRationale}`,
both required. So the whole family is **one** `POAM → vulnerabilityDetail`
renderer, **one** accepted/not-accepted partition, and three envelopes.
`ver_history` is VDR's array plus AVI's array with no period filter.

Building VDR alone would build ninety per cent of the other two, so they ship
together.

### 1.1 The renderer is the unit of risk

Everything hard about this work is in `render_vulnerability(poam)`. The
envelopes are trivial. Design and review attention belongs on the renderer and
on the partition, not on the three seeders.

---

## 2. The partition has three outcomes, not two

`ccf.patching.sla.accepted_weakness_state(poam, today=...)` returns
`accepted | not_accepted | unknown` (`ACCEPTED_WEAKNESS_STATES`). It returns
three states deliberately — see its docstring, and the P9a-i note that a
boolean here reports poor record-keeping as the favourable answer.

| state | destination |
|---|---|
| `accepted` | AVI's `acceptedVulnerabilities`; `ver_history.acceptedVulnerabilities` |
| `not_accepted` | VDR's `vulnerabilities`; `ver_history.activeVulnerabilities` |
| `unknown` | **neither** — omitted, and named in the seed result |

**`unknown` must not fall into VDR.** VDR's own schema description is "Covers
non-accepted vulnerabilities only", so placing an unmeasurable row there
asserts it is *not* accepted. Under a rule obliging providers to report their
accepted weaknesses, that is the favourable answer, and it is the exact
inversion `accepted_weakness_state` exists to refuse. Omitting and reporting
is the honest alternative and matches `omitted_ksi_ids`.

Do not re-derive the partition. Call `accepted_weakness_state`.

---

## 3. Field map

### 3.1 Required, and sourced

`vulnerabilityDetail.required` is exactly
`['providerTrackingId', 'detection', 'vulnerabilityDescription']`; `detection`
itself requires `['detectedAt', 'detectionSource']`.

| Field | Source | Note |
|---|---|---|
| `providerTrackingId` | `POAM.id` | **`type: string`** — measured. `42` fails with `"vulnerabilities/0/providerTrackingId: 42 is not of type 'string'"`. Render `str(poam.id)`. |
| `detection.detectedAt` | `identified_on` | `DATE`, **nullable**. Rendered at midnight UTC — a *declared convention*, §3.3. |
| `detection.detectionSource` | `scanner` else `source` | Both `VARCHAR`, **both nullable**. |
| `vulnerabilityDescription` | `weakness` else `title` | `title` is `NOT NULL`, so one is always present. |

"else" means **first non-blank after stripping**, not first non-`NULL`. A
column holding `""` or `"   "` is as absent as one holding `NULL`, and the SDR
shipped a whitespace description twice by testing only for `None`. `title`
being `NOT NULL` guarantees the column exists, not that it has content — if
both `weakness` and `title` strip to nothing, the row is omitted under §7.

### 3.2 Optional, and sourced

`overdueStatus` — `{isOverdue: bool}` required, `explanation` optional.

Source is `ccf.patching.sla.classify`, which returns
`on_track | overdue | no_due_date`. Map `overdue → true`, `on_track → false`,
and **omit the whole `overdueStatus` object for `no_due_date`**. A row with no
due date cannot be shown to be overdue, and `isOverdue: false` is the
favourable answer — the same three-state rule as §2, one level down. This is
the single most likely place to reintroduce this programme's signature defect.

### 3.3 The midnight-UTC convention, stated once

`identified_on` is a `DATE`; `detectedAt` is a `date-time`. Widening the date
to `T00:00:00Z` asserts a precision the source does not have. It is rendered
anyway, because the alternative is omitting every vulnerability (§7), and it
is recorded here as a **declared convention** so that no reader mistakes it for
a measured fact.

Consequence to state in the implementation, not to hide: a vulnerability
identified on the first day of a report period renders at that day's midnight,
so it falls **inside** a period whose `from` is that same midnight. Period
boundaries are inclusive at the lower edge as a result of this convention, not
by separate design.

### 3.4 Omitted, and why

Every one of these is optional in the schema, so omission validates. Each is
omitted because emitting it would assert something the platform cannot defend
— the §1.3 rule carried forward from the SDR spec.

| Field | Why omitted |
|---|---|
| `currentRating` | `nRating` is `type: integer, enum: [1,2,3,4,5]`. `POAM.severity` is `low\|moderate\|high\|critical` — **four** values on a different scale. Mapping four onto five invents a scale. This is `controlImplementationStatus` (SDR §1.2.1) in a new field. |
| `painReductionEvents[]` | Each event requires `rating`, an `nRating`. No source, same reason. |
| `projectedNextReduction` | Requires `targetRating`, an `nRating`. `scheduled_completion` could supply `estimatedAt`, but a required sub-field has no source, so the whole object goes. |
| `isInternetReachable` | Boolean with no third state and no source. `false` is the favourable answer. |
| `isLikelyExploitable` | As above. |
| `finalDisposition` | `enum: [Fully Mitigated, Partially Mitigated, Remediated, False Positive]`. `POAM.status` is `open\|in_progress\|completed\|risk_accepted\|closed`, which cannot distinguish `Remediated` from `False Positive`. Asserting `Remediated` for a row closed as a false positive is the harsher-claim error in reverse. |
| `potentialAgencyImpact` | No source. |
| `evaluationCompletedAt` | No source. |
| `supplementaryRiskInformation` | No source. `remediation_plan` is a plan, not risk information. |

**Do not add a mapping for any of these without a new source.** If a future
session adds an N-rating column, `currentRating` becomes renderable; until
then it is absent, and that absence is correct rather than incomplete.

---

## 4. The validator is not a backstop for dates

Measured in this environment:

```
jsonschema FormatChecker registered checkers:
  date, email, idn-email, idn-hostname, ipv4, ipv6, regex, time, uuid

date       enforced      <- stdlib
date-time  NOT enforced  <- rfc3339_validator not installed
uri        NOT enforced  <- rfc3987 not installed
```

```
detectedAt "2026-09-01"          -> ok=True   (a date, silently accepted as date-time)
detectedAt "2026-09-01T00:00:00" -> ok=True   (naive, no zone)
providerTrackingId 42            -> FAILS     (type IS checked)
```

`ccf.cr26.validation.enforced_formats()` already reports this and its docstring
explains why it is environmental. **Use it; do not restate the list.**

Two consequences the implementation must respect:

1. **Every `date-time` in this family is unvalidated** — `detectedAt`,
   `reportPeriod.from`, `reportPeriod.to`, `generatedAt`. A malformed value
   reaches the deliverable with `ok: True, errors: []`.
2. **Tests must assert the exact rendered string**, never merely that the
   document validates. `assert ok` is worthless for these fields.

This inverts the SDR's situation, where `format: date` *was* enforced and
caught a datetime. Do not carry the SDR's intuition across: there the validator
was a real guard, here it is not.

---

## 5. `acceptanceRationale`

Required on every `acceptedVulnerabilityInfo`, and no `POAM` column holds one.

It is **authored into the stored document and preserved across re-seeds**,
exactly as `ksiImplementation` is in the SDR. No migration.

`merge_accepted(authored, derived) -> (merged, omitted)` mirrors
`ccf.cr26.sdr.merge_indicators`:

- key on `vulnerabilityDetail.providerTrackingId`
- preserve `acceptanceRationale`
- refresh the whole `vulnerabilityDetail` from source
- **omit any entry with no rationale, and name it** — an accepted vulnerability
  with no rationale cannot validate, so emitting `""` would be the CPO's
  empty-description defect again
- keep unrecognised entries rather than silently dropping provider content

Read `merge_indicators` before writing this. It has been through five review
rounds and its aliasing, self-healing and ordering behaviour are settled; do
not rediscover them.

---

## 6. Seeders, store and routes

### 6.1 Signatures

```python
async def seed_vdr(session, *, system_id: int, period_from: datetime,
                   period_to: datetime) -> VerSeedResult
async def seed_avi(session, *, system_id: int, period_from: datetime,
                   period_to: datetime) -> VerSeedResult
async def seed_ver_history(session, *, system_id: int) -> VerSeedResult
```

The caller supplies the report period. Nothing in the platform records what a
previous report covered, and `VER-RPT-PER` ("must cover all activity since the
previous report") is a policy obligation on the operator, not a fact the
seeder can derive. `ver_history` takes no period — its schema has none, and
carries `generatedAt` instead.

`VerSeedResult` reports:

- `document` — the stored `Cr26Document`
- `omitted_poam_ids: list[tuple[int, str]]` — **one tuple per (id, reason)
  pair**, not per row, so a POA&M tripping two rules appears twice. §7 requires
  reporting every reason that applies; collapsing to one tuple per row would
  force a choice about which reason to keep and hide the rest. The reason is
  what makes this actionable — `omitted_ksi_ids` carries bare ids because there
  was one possible reason, and here there are five (§7).
- `counts: dict[str, int]` — rows partitioned to each destination

### 6.2 Store

Unchanged. `cr26_documents` stays `UNIQUE(system_id, kind)`; the three new
kinds are already in `CR26_KINDS`. Each document records the period it covered
inside its own body, so a re-seed overwrites a report with a report, and the
period is never inferred.

No migration. `alembic heads` must remain `0079_cr26_documents`.

### 6.3 Routes

Three handlers in the existing `src/ccf/api/routes/cr26.py`, mirroring
`seed_sdr_document`:

```
POST /systems/{system_id}/cr26-documents/vdr/seed          body: {from, to}
POST /systems/{system_id}/cr26-documents/avi/seed          body: {from, to}
POST /systems/{system_id}/cr26-documents/ver_history/seed  no body
```

`ver_history` keeps its underscore. It is the only kind in `CR26_KINDS`
containing one, and the generic `GET`/`PUT`
`/cr26-documents/{kind}` routes take the kind verbatim — so a hyphenated seed
path would disagree with the read path for the same document. Match the kind,
not URL fashion.

Admin only — `require_role(*AUTHOR_ROLES)`, where `AUTHOR_ROLES = ("admin",)`.
`_owned_system` runs before anything touches the seeder, returning 404 rather
than 403 for another tenant. Every field of `VerSeedResult` is surfaced in the
response body, and **each is asserted at the HTTP layer**: on the SDR, deleting
two result fields from the route left the whole suite green, and those fields
were the only operator-facing signal.

`from` must be strictly before `to`; reject with 422 otherwise. An inverted
period would produce a report whose own stated window is impossible.

---

## 7. Omission rules, consolidated

A POA&M is omitted, with its id and reason, when:

1. `identified_on` is `NULL` — `detection.detectedAt` is required and has no
   other honest source. `updated_at` is when the row last changed, not when the
   vulnerability was detected.
2. `scanner` and `source` both strip to nothing — `detection.detectionSource`
   is required.
3. `weakness` and `title` both strip to nothing — `vulnerabilityDescription`
   is required. `title` is `NOT NULL`, which guarantees the column exists and
   says nothing about its content (§3.1).
4. `accepted_weakness_state` returns `unknown` (§2).
5. For AVI and `ver_history.acceptedVulnerabilities` only: no authored
   `acceptanceRationale` (§5).

Rules 1–4 are evaluated for every document; rule 5 only for the accepted half.
A row may trip more than one; report all reasons that apply, not the first —
see `omitted_poam_ids`' shape in §6.1.

Every one of these five is a **blank-or-missing** test, never a `None` test.
That is one rule applied five times, and it belongs in one helper rather than
five call sites: the SDR needed four review rounds on a loop that asked the
same question in two different forms.

An empty result is valid — no array in any of the three schemas carries
`minItems`, measured. `vulnerabilities: []` validates.

---

## 8. Invalid by design

All three documents are invalid until a CPO exists, for exactly one reason.
Measured for each kind:

```
vdr         -> ["<root>: 'certificationPackageOverviewUri' is a required property"]
avi         -> ["<root>: 'certificationPackageOverviewUri' is a required property"]
ver_history -> ["<root>: 'certificationPackageOverviewUri' is a required property"]
```

With a URI supplied, a populated document of each kind returns `ok=True,
errors=[]` — measured, with one real vulnerability and one real accepted
vulnerability respectively.

`certificationPackageOverviewUri` is carried forward from the stored document
when present and **never invented**, as in the SDR.

---

## 9. Testing requirements

These are requirements, not suggestions. Each names a defect this programme has
actually shipped.

1. **Assert `validation_errors` by exact equality on a POPULATED document.**
   The SDR pinned its "invalid for exactly one reason" claim only on documents
   with empty arrays, so the entire derived half never reached the validator.
   Each of the three kinds needs one assertion against a document containing a
   real entry.
2. **Assert rendered date strings exactly.** §4 — the validator will not catch
   a malformed `date-time`. A test asserting only `ok=True` cannot fail for
   these fields.
3. **Pin the three-state partition and the three-state overdue rule.** For
   each, a fixture in every state, asserting that `unknown` / `no_due_date`
   produces omission rather than the favourable answer.
4. **Pin every omission reason.** One test per rule in §7, asserting both that
   the row is absent from the document and that its id and reason appear in
   `omitted_poam_ids`.
5. **Assert every `VerSeedResult` field in the route response.** §6.3.
6. **A rule that is deliberately *not* applied needs a test too.** On the SDR,
   "a blank part is not a dropped part" was documented twice and tested
   nowhere, and inverting it left the suite green. Any comment saying "we
   deliberately do not do X" must have an assertion behind it.
7. **Use `tests/conftest.py`'s `isolate_ksi_rows` / `isolate_source_rows` if
   any test creates global-catalog rows.** POA&M rows are system-scoped, so
   this family probably needs neither — but check by counting, not by
   assuming.

---

## 10. Out of scope

- **`fedRampRequirements` sourcing.** There is no machine-readable CR26
  ruleset; the ~246 rule ids exist only as prose in FedRAMP's README. This
  affects the CPO and SDR, not this family — none of these three schemas has
  such a field.
- **A `nRating` column.** §3.4. Adding one is a product decision about whether
  Concord adopts FedRAMP's 1–5 scale alongside its own four-value severity.
- **Widening `is_draft_or_placeholder`** to catch a bare `"[DRAFT]"`. Carried
  from the SDR branch; it changes customer-visible SSP completeness scores and
  belongs to its own decision.
- **Scheduling.** Nothing here runs on a timer. Who calls these seeders, and
  how the report period chains from one call to the next, is an operator
  concern until a scheduling decision is made.
