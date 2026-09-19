# CR26 Incident Report — design

**Status:** design 2026-09-19. P9a-ii part 6. Seventh of eleven CR26 deliverables.

**Schema:** `fedramp-incident-report-schema-2026-06-24.json`, `$schemaVersion`
0.2.0, titled *FedRAMP Incident Report (IEC-CSO-IIR / IEC-CSO-OIR /
IEC-CSO-FIR)* — "Unified schema for the three incident report types in the
IEC-CSO lifecycle: Initial (IEC-CSO-IIR), Ongoing (IEC-CSO-OIR), and Final
(IEC-CSO-FIR)."

**Depends on** migration `0081` (`document_key`), merged at `633a377`. This is
the deliverable that store change was made for.

---

## 1. One incident, three filings, one tracking id

`providerTrackingId` is required, and its description is the whole design
constraint:

> Provider's internally assigned identifier for this incident. **Must be
> consistent across IIR, OIR, and FIR reports** for the same incident.

So a single incident produces up to three filed reports that deliberately
share an identifier, and a system has many incidents over time.

### 1.1 The key must carry the report type, or filing an Ongoing destroys the Initial

`cr26_documents` is unique on `(system_id, kind, document_key)`. Keying on
`providerTrackingId` alone would put all three reports of one incident in the
same row, so advancing an incident from Initial to Ongoing **overwrites a filed
federal report** — exactly the loss migration `0081` was added to prevent,
reintroduced one layer up.

**`document_key` is `"{providerTrackingId}/{reportType}"`.** Every filed report
survives, and the three reports of one incident are adjacent and sortable.

The separator is `/` because a `providerTrackingId` is provider-assigned free
text and may contain almost anything; `/` is rejected in the tracking id
(§3.1) so the key cannot be ambiguous. A key that two different incidents could
produce would silently merge two incidents' reports.

---

## 2. Nothing here is derived

Concord holds no incident data. Every field — the description, the timeline,
the impact, the indicators of compromise, the root cause — is a human
statement. The platform's contribution is **identity, continuity, validation
and a to-do list**, not content.

That makes this the OCR's shape, not the SDR's: seed the scaffold, carry what
was authored, omit what was not, and let the document stay invalid until it is
true (OCR spec §2). A document that validates is a document someone can file.

### 2.1 What the seeder is actually for: continuity

The one genuine service is **carrying an incident forward across its own
lifecycle**. Seeding an `Ongoing` report for an incident that already has an
`Initial` copies the still-true facts forward — the tracking id, the incident
description, the timeline, the coordinator, the affected agencies — so an
operator does not retype them into three documents and cannot accidentally
file three reports that disagree about the same incident.

Carry-forward reads the **most recent prior report for the same tracking id**,
in lifecycle order `Initial → Ongoing → Final`. Fields authored on *this*
report always win; carry-forward only fills what this report does not have.

**Never carry `reportType` or `resolvedAt` forward.** `reportType` is the
identity of the report being written. `resolvedAt` asserts the incident is
over, and copying it from a prior report onto a new one would assert a
resolution that was not restated.

---

## 3. Field rules

### 3.1 Required and caller-supplied

| Field | Source |
|---|---|
| `reportType` | caller; must be `Initial`, `Ongoing` or `Final` |
| `providerTrackingId` | caller; non-blank after stripping, and must not contain `/` (§1.1) |
| `certificationPackageOverviewUri` | carried from this report, else the prior one; **never invented** |

A blank tracking id, or one containing `/`, is refused at the seeder with a
`ValueError` and at the route with 422. This is not an omit-and-name case: a
report that cannot be identified cannot be filed, and a malformed key would
corrupt the store's own addressing.

### 3.2 The one conditional the schema enforces

```
if reportType == "Final" then required: resolvedAt
```

Measured: a `Final` report without `resolvedAt` fails with
`"<root>: 'resolvedAt' is a required property"`. This is the only conditional
in the document and the validator does enforce it — unlike the prose-only
rules elsewhere in CR26.

**The seeder never supplies `resolvedAt`.** It asserts an incident is over and
recovery complete; only a human knows that. A seeded `Final` with no authored
`resolvedAt` is invalid, and that is correct — something is genuinely still
owed.

### 3.3 Authored, carried, and named

Everything else is optional in the schema and authored in practice:
`federalIncidentCoordinator`, `incidentDescription`, `timeline`,
`potentialImpact`, `functionalImpact`, `recoveryPlan`, `affectedAgencies`,
`observedActivity`, `indicatorsOfCompromise`, `relatedCveIds`, `rootCause`,
`responseAndRecoveryActivities`.

Each is preserved when authored on this report, carried forward from the prior
report when not (§2.1), and simply absent when neither has it. Because they are
optional, absence does not invalidate the document — so the result reports them
as *advisory*, distinctly from the fields that do.

**`timeline` and `potentialImpact` have no required sub-keys**, measured — a
half-filled one validates. Carry them forward whole or not at all; merging them
field-by-field would build a timeline no human ever wrote.

### 3.4 `date-time` is NOT enforced here

`timeline.startedAt`, `detectedAt`, `evaluationCompletedAt` and `resolvedAt` are
`format: date-time`, and this environment does not enforce it — the VER family's
situation, not the OCR's, where `date` *is* enforced. The seeder writes no
date-time of its own, so there is nothing to get wrong; but any test asserting
one must compare the exact string rather than trusting the validator.

### 3.4.1 An unparseable `resolvedAt` satisfies the conditional and means nothing

Measured:

```
{reportType: "Final", providerTrackingId: "INC-1", resolvedAt: "whenever"}
  -> ok=True, errors=[]
```

The conditional in §3.2 only requires the key to be *present*. Because
`date-time` is unenforced (§3.4), `"whenever"` satisfies "this incident was
resolved at" with a value that is not a time — a document that validates while
asserting something untrue, in the field that closes an incident.

The seeder never writes `resolvedAt`, so it cannot cause this. But it must
**name it**: when a `Final` report carries a `resolvedAt` that does not parse
as an ISO-8601 instant, report it in `missing_required` — it is not missing,
but it fails the same obligation, and nothing else in the stack will say so.
Do not rewrite or drop the operator's value; report it and leave it.

### 3.5 `potentialImpact.currentRating` — do not map

It references the same 1–5 `nRating` the VER family refused to synthesise from
Concord's four-value severity scale. Carry it if authored; never derive it.

---

## 4. The result

```python
@dataclass(frozen=True)
class IncidentSeedResult:
    document: Cr26Document
    document_key: str                      # "{trackingId}/{reportType}"
    carried_from: str | None               # the prior report's key, or None
    carried_fields: list[str]              # what continuity supplied
    missing_required: list[tuple[str, str]]  # blocks validity
    missing_advisory: list[str]            # optional, absent, worth knowing
```

`carried_from` and `carried_fields` exist so an operator can see what the
platform asserted on their behalf. Continuity is a convenience that puts words
into a federal filing; it must be visible, not silent.

`missing_required` and `missing_advisory` are deliberately separate lists.
Collapsing them would tell an operator that a missing `rootCause` blocks
filing when it does not, and that a missing `resolvedAt` on a Final is merely
advisory when it is the one thing that makes the document invalid.

---

## 5. Testing requirements

1. **Filing an Ongoing does not destroy the Initial.** Seed Initial, then
   Ongoing, then Final for one tracking id; assert three rows survive with
   distinct keys and the Initial's body unchanged. This is the defect the whole
   store change exists to prevent.
2. **A `Final` with no authored `resolvedAt` is invalid**, and its
   `validation_errors` are exactly `["<root>: 'resolvedAt' is a required
   property"]` when everything else is present — asserted by equality.
3. **`reportType` and `resolvedAt` are never carried forward.** Seed a Final
   with `resolvedAt`, then a new Ongoing for the same incident; the Ongoing must
   have neither the Final's `reportType` nor its `resolvedAt`.
4. **Authored beats carried**, per field.
5. **A blank or `/`-containing tracking id is refused** at the seeder and 422 at
   the route.
6. **Two incidents on one system do not collide**, and neither do their reports.
7. **Every `IncidentSeedResult` field crosses the HTTP boundary** — on this
   module, deleting result fields from a route left the whole suite green.

---

## 6. Out of scope

- **Deriving anything from platform data.** Concord has no incident source.
- **The 1-hour US-CERT reporting clock.** A timing obligation, not a document
  field, and nothing in the platform tracks it.
- **Amending a filed report.** A re-seed of the same key updates that report;
  the audit event is the record it changed, as for every other deliverable.
- **No migration.** `0081` already did the work.
