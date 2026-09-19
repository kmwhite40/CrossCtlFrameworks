# CR26 Significant Change Notification — design

**Status:** design 2026-09-19. P9a-ii part 7. Eighth of eleven CR26 deliverables.

**Schema:** `fedramp-significant-change-notifications-schema-2026-06-24.json`,
`$schemaVersion` 0.1.2, *FedRAMP Significant Change Notification (SCN-CSO-INF)*.

**Depends on** migration `0081` (`document_key`), merged at `633a377`.

---

## 1. The document has no identity, so the caller supplies one

Root `required` is `certificationPackageOverviewUri`, `changeType`,
`changeDescription`. There is **no tracking id, no change id, no date** —
nothing in the document distinguishes one significant change from another.
That is deliberate; the schema's own description says "structure of the
information may vary depending on how the provider tracks this internally."

But a provider files one SCN per significant change and has many over time, so
the store needs a key. Unlike the Incident Report — where `providerTrackingId`
is mandated and the key is derived from it — **the SCN's `document_key` is
supplied by the caller** as `change_ref`, the provider's own reference for the
change.

`change_ref` is validated the same way the incident tracking id is
(§3.1): non-blank after stripping, bounded by
`ccf.models_cr26.DOCUMENT_KEY_MAX_LENGTH`. It is used verbatim as the key —
there is no second component to compose, so no separator and no `/` rule.

**Reuse `DOCUMENT_KEY_MAX_LENGTH`**; do not restate 128. Two copies of that
number drifting apart is a defect this programme has already shipped.

---

## 2. Nothing is derived, and one thing is checked

Concord holds no record of a provider's significant changes. Every field is
authored, so this takes the OCR/Incident shape: seed the scaffold, carry what
was authored, omit what was not, stay invalid until true.

### 2.1 `impactedControls` is the first field the platform can check

> KSI or control identifiers that will be verified, assessed, or validated as
> part of this change.

Concord holds both — `Control.identifier` and `KSI.identifier` — and
`ccf.catalog.canonical.canonicalize` already normalises control ids
(`IA-02` → `IA-2`). So for the first time in this programme, the platform can
tell an operator that something they typed does not exist.

Measured, nothing checks it today:

```
impactedControls: ['AC-999', 'not-an-id', '']  ->  ok=True, errors=[]
```

**Check, name, and never refuse.** Each entry is resolved against the control
catalog (after `canonicalize`) and the KSI catalog. Unrecognised entries are
reported in the result as advisory; the document keeps them verbatim.

Refusing would be wrong, and this is the important half of the rule: FedRAMP's
own identifiers, a framework Concord has not ingested, or a provider's internal
reference may all be legitimate here and unknown to us. An unrecognised
identifier is **a thing worth telling an operator about, not a thing worth
blocking a federal filing over**. `canonicalize`'s own limits make the point —
it matches a two-letter family, so `EIA-02` yields nothing, and treating that
as an error would refuse a valid identifier from a framework we do not hold.

Blank entries are a different matter: an empty string in `impactedControls`
identifies nothing at all and is reported as such.

---

## 3. Field rules

### 3.1 Required

| Field | Source |
|---|---|
| `changeType` | caller; `Adaptive` or `Transformative`, enforced by the schema's enum (measured: `"adaptive"` fails) |
| `changeDescription` | authored |
| `certificationPackageOverviewUri` | carried from the stored document; **never invented** |

### 3.2 A blank `changeDescription` validates and says nothing

Measured:

```
{changeType: "Adaptive", changeDescription: ""}  ->  ok=True, errors=[]
```

`changeDescription` is required and has no `minLength`, so an SCN can satisfy
"short description of the change" with nothing at all — the blank-required-string
trap this programme has now met in the CPO, the SDR and the OCR.

The seeder **never writes `changeDescription`**. When the stored document has
none, or has one that is blank after stripping, the field is **omitted** so the
document is invalid and the gap is named. An operator is told the change has no
description rather than filing one that appears complete.

### 3.3 Authored, carried and named

`assessorName`, `relatedVulnerability`, `changeTypeExplanation`, `reason`,
`customerImpact`, `planAndTimeline`, `impactedControls`, `impactAnalysis` are
all optional and authored. Preserve what is there; omit what is not; report
absences as advisory, distinctly from the two that block validity.

`planAndTimeline` is an object — carry it whole or not at all, as the incident
report does with `timeline`, so the platform never assembles a plan no human
wrote.

**`changeTypeExplanation` is advisory but worth naming specifically.** It
explains why a change was categorised `Adaptive` rather than `Transformative`,
and that categorisation determines what FedRAMP requires next. An SCN with a
`changeType` and no explanation is valid and thin; say so.

---

## 4. The result

```python
@dataclass(frozen=True)
class ScnSeedResult:
    document: Cr26Document
    document_key: str
    missing_required: list[tuple[str, str]]
    missing_advisory: list[str]
    unrecognised_controls: list[tuple[str, str]]   # entry, why it was not recognised
```

`unrecognised_controls` is separate from `missing_advisory` because it is the
one list describing something the operator *did* write rather than something
they did not. Collapsing them would tell an operator a field is missing when
its content is merely unfamiliar to us.

---

## 5. Testing requirements

1. **Two SCNs on one system do not collide** — distinct `change_ref`s, two
   rows, neither overwriting the other.
2. **A blank or absent `changeDescription` is omitted and named**, and the
   document is invalid with exactly that error alongside any other genuinely
   missing required field — asserted by equality.
3. **An unrecognised `impactedControls` entry is named and kept**, never
   dropped and never a refusal. Include a real control id, a real KSI id, an
   unknown id, and a blank — and assert the document still holds all four
   verbatim.
4. **A canonicalisable control id is recognised** — `IA-02` must resolve where
   `IA-2` exists, proving `canonicalize` is actually applied.
5. **A blank or overlong `change_ref` is refused** — `ValueError` at the
   seeder, 422 at the route — and the bound comes from
   `DOCUMENT_KEY_MAX_LENGTH`, asserted to be the same object.
6. **Every `ScnSeedResult` field crosses the HTTP boundary.**

---

## 6. Out of scope

- **Deciding whether a change is significant, or which type it is.** That is
  the provider's judgment; `SCN-CSO-EVA` governs it and the schema notes that
  routine recurring changes need no notification at all.
- **Cross-checking `impactedControls` against the system's own SSP.** Tempting
  — we could ask whether the named controls are in this system's baseline —
  but a significant change may touch a control not yet in the SSP, and saying
  "that control is not in your baseline" would be advice, not a fact.
- **No migration.** `0081` already did the work.
