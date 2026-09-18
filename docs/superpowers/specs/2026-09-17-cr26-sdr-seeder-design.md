# The CR26 SDR seeder (P9a-ii, part 3)

Status: approved 2026-09-17. Third and last unit of P9a-ii, after the schema
spine (`2026-09-17-cr26-schema-spine-design.md`) and the document store
(`2026-09-17-cr26-document-store-design.md`).

## 1. The SDR really is mostly rendering — with one gap

The gap analysis predicted the CR26 deliverables would be "a second deliverable
profile over content the SSP generator already produces". That proved **false
for the CPO**, which is mostly facts about the business living nowhere in the
platform. It is **true for the SDR**, measured field by field:

| SDR field | Source | Real? |
|---|---|---|
| `securityControls[].controlId` | `SSPControlEntry.control_id` | yes |
| `securityControls[].parameterValues` | `SSPControlEntry.odp_values` | yes |
| `securityControls[].controlImplementationStatus` | `SSPControlEntry.implementation_status` | yes |
| `securityControls[].controlImplementationDescription` | `SSPControlEntry.part_narratives` | yes |
| `keySecurityIndicators[].ksiId` | `KSI.identifier` | yes |
| `keySecurityIndicators[].ksiImplementationStatus` | `ksi_states.status` | yes |
| `keySecurityIndicators[].ksiValidation` | `ksi_validation_results` (status, `validated_at`, `source`) | yes |
| `keySecurityIndicators[].ksiAssessment` | `ksi_assessor_reviews` (finding, status, assessor) | yes |
| `keySecurityIndicators[].ksiTests` | `KSI.validation_method`, `KSI.rule` | yes |
| `keySecurityIndicators[].ksiEvidence` | `ksi_validation_results.evidence_refs` | yes |
| **`keySecurityIndicators[].ksiImplementation`** | **nothing** | **the gap** |

`ksiImplementation` is the provider's narrative of *how the offering meets*
each indicator. `KSI.description` is the catalog's org-agnostic description of
the **requirement**, so rendering it there would describe the obligation while
claiming to describe the implementation — the same "validates and is wrong"
failure the CPO seeder refuses.

### 1.2 Three of the four control fields need a shape conversion, not a copy

The table above is honest about the *source* and glosses the *shape*. The SDR
wants strings where the platform holds JSONB, and leaving that unspecified is
where an implementer invents something:

| SDR field | Column | Column shape | Conversion |
|---|---|---|---|
| `controlId` | `control_id` | `VARCHAR(32)` | direct |
| `controlImplementationStatus` | `implementation_status` | JSONB `list[str]` | **see §1.2.1** — enum-constrained; the `", ".join(...)` this row once prescribed can never validate |
| `controlImplementationDescription` | `part_narratives` | JSONB `list[{"text": ...}]` | `" ".join(p["text"])` over the **written** parts only — **see §1.2.2**; `[DRAFT]` and ODP-placeholder parts are dropped, and the key is omitted if nothing survives |
| `parameterValues` | `odp_values` | JSONB `{odp_key: value}` | `[{"parameterId": k, "parameterValue": str(v)}]` |

**Follow `ssp/nist80053_docx.py`'s joins rather than inventing new ones** —
lines 170 and 173 already render exactly these two fields for the Word SSP, and
the SDR is meant to be a second profile over the same content, not a second
opinion about how to flatten it.

> **This paragraph and the table above it are corrected by §1.2.1 and §1.2.2,
> forty and eighty lines below.** Read them before implementing either field.
> The docx renderer writes into a Word table cell, where any string is fine
> and a reviewer sees the `[DRAFT]` marker with their own eyes; the SDR is a
> machine-read federal deliverable with an enum on one field and no reader on
> the other. Following it produced two defects, one Critical. The *narrative
> join itself* — a space between parts — is still the docx renderer's, and
> that much of this paragraph stands.

**`parameterValues` must omit unfilled parameters.** `ssp/nist80053.py:71`
scaffolds `odp_values` as `{param.id: None}` for every parameter in the
control, so an unanswered ODP is present with a `None` value. `parameterValue`
is `type: string` and both it and `parameterId` are required, so
`str(None)` would emit `"None"` — a document that validates while asserting the
provider chose the literal string "None" as a control parameter. **Drop any
entry whose value is `None`.** This is the same failure class as inventing the
CPO's seven fields, wearing different clothes.

### 1.1 The trap is subtler here than in the CPO

All six required `keySecurityIndicators` item fields are arrays of free text —
`implementationStatement`, `validationStatement` and `assessmentStatement` are
each nothing more than `type: string`, and `ksiTests` is an array of strings.
**So `ksiImplementation: []` satisfies the schema.** A seeder could emit a
structurally valid, complete-looking KSI entry that says nothing whatsoever
about how the offering meets that indicator.

The CPO's gap is visible because the document fails validation. The SDR's would
be invisible. That asymmetry is why §2 omits rather than empties.

### 1.2.1 CORRECTION — `controlImplementationStatus` is enum-constrained too

§1.2 told the implementer to follow `ssp/nist80053_docx.py`'s joins. That was
right about the *narrative* and wrong about the *status*, and the difference
is the whole lesson: the docx renderer writes into a Word table cell, where
any string is fine. **The SDR has an enum.**

`securityControls.items.properties.controlImplementationStatus` is
`enum: ["Implemented", "Not Implemented", "Partially Implemented"]`, and every
field of `securityControls.items` is **optional**. Measured against the real
validator:

```
implementation_status ['implemented']        -> 'implemented'        invalid
implementation_status ['planned','partial']  -> 'planned, partial'   invalid
```

A `", ".join(...)` of two values can **never** be an enum member. This is the
fourth appearance of the claim-versus-rendering error in this one spec, and the
first inside code that had already passed review.

The platform's vocabulary is
`ssp.constants.IMPLEMENTATION_STATUS_OPTIONS = ("Implemented", "Partially
Implemented", "Planned", "Alternative Implementation", "Not Applicable")` —
whose first two members are **exact** matches for the schema's, so genuine
single-valued data was always fine. The lowercase `"implemented"` in the test
fixture disguised that.

**Decision, applying §1.3's principle rather than re-asking it:** emit
`controlImplementationStatus` only when the entry carries **exactly one**
status and that status is a member of the schema's enum. Otherwise **omit the
key** — it is optional, so omission validates. `Planned`, `Alternative
Implementation` and `Not Applicable` are therefore omitted rather than
translated: "Not Implemented" is a harsher claim to a regulator than "Planned"
is, and inventing the harsher one is the same defect in the other direction.

The narrative join has no enum to violate, so §1.2.1 left it alone. That was
wrong for a different reason, and **§1.2.2 below supersedes this paragraph**:
free text can still make a false claim. Do not read this section without it.

### 1.2.2 CORRECTION — the description ships `[DRAFT]` scaffolding

§1.2.1 fixed the status and did not look at the line beside it. Measured
end to end against the real validator, on an entry as `ssp/nist80053.py`
scaffolds it:

```
RENDERED: [{'controlId': 'AC-2',
            'controlImplementationDescription': '[DRAFT] AC control AC-2 is the
              responsibility of System Owner. Describe the implementation.',
            'parameterValues': []}]
VALID: True   ERRORS: []   STATUS KEY PRESENT: False
```

`ssp/nist80053.py:83-91` writes that exact text, with `"draft": True`, into
**every** control entry of **every** new 800-53 project, alongside
`implementation_status: [Planned]`. §1.2.1 correctly omits `Planned` — so the
one field that would have signalled incompleteness is silent, and the
description carries the placeholder instead. A scaffolded-but-unwritten SSP is
the state of every new project, and the state an operator is most likely to
press "seed" in. The document validates, and tells FedRAMP that the provider's
implementation description is an instruction to write one.

Second source, same field: `ssp/statements.py:65` and `ssp/platforms.py:145-161`
emit `[ORGANIZATION-DEFINED: …]`, and `ssp/odp.py` leaves `[Assignment: …]` /
`[Selection …]`, into narrative text with no `draft` flag at all.

This is the **fifth** claim-versus-rendering defect on this spec, and the first
found on a line immediately beside one already corrected.

**Decisions:**

- **Drop any narrative part flagged `draft`, or whose text trips
  `ssp/completeness.py`'s placeholder predicate.** The platform already owns
  this judgement — that module calls the same text *"draft narrative — needs
  review"* — so the predicate is **promoted to `is_draft_or_placeholder` and
  imported**, never restated. A second copy of a rule is how this spec's
  status enum went wrong twice.
- **Omit `controlImplementationDescription` entirely when nothing survives.**
  `required` is absent from `securityControls.items`, so every property there
  is optional. The seeder previously emitted `""`, and a test pinned that as
  intended on the grounds that "every key must be present so a caller never
  handles KeyError" — but `""` asserts the provider's description *is blank*,
  which is the same defect this spec refuses for `ksiImplementationStatus`.
  Convenience for our callers is not worth a false statement in a federal
  deliverable.
- **`parameterValues: []` is unaffected.** An empty list of *answered*
  parameters is a true statement about a control nobody has filled in. An
  empty description is not. The distinction is the whole rule.
- **Report the affected control ids in the seed result**, beside
  `omitted_ksi_ids`. Nothing in the document says a control is unwritten — the
  scaffolded `Planned` is omitted as untranslatable — so without this the
  control gap reaches no operator at all. **Two lists, deliberately
  overlapping**, because they answer different questions and an operator
  reading either must get a complete answer to it:
  - `controls_missing_description` — no `controlImplementationDescription` at
    all, because nothing was written or everything was scaffolding.
  - `controls_with_dropped_parts` — at least one part **that had content**
    was dropped, *whether or not anything survived*. This is the case most
    easily missed: `ssp/statements.py:88-90` appends
    `" Frequency: {frequency}."` — carrying `_resolved_frequency`'s
    placeholder when unset — to the END of otherwise-complete composed
    paragraphs, so three sentences of real provider content can be dropped
    whole for one trailing token, leaving a control that still has a
    description and a status and reads complete.

    A **blank** part is deliberately NOT reported here. Nothing was lost, and
    naming a never-written control as having lost content is a false statement
    in the one channel this section exists to make truthful. The distinction
    matters enough to be tested: the rule cannot be deleted green, but it can
    be *inverted* green, which no delete-the-guard mutation would catch.

  `rendered_control_count` travels with them, because `ssp_project_id: None`
  cannot distinguish "no SSP" from "an empty SSP project that happened to be
  the most recently updated one".

- **Dropping is its own failure mode, and the answer is reporting, not
  keeping.** Omitting the whole description whenever any part drops was
  considered and rejected: it discards defensible content to avoid a partial
  claim the operator can already see and fix. The SDR is invalid by design and
  is a seed a human completes, so the result object *is* the remediation
  channel — exactly as `omitted_ksi_ids` already works.

- **Blank parts are stripped and skipped before the join.** `" ".join(["", ""])`
  is `" "` — truthy, and the `""` this section eliminates wearing one character
  of disguise. `ssp/seed.py:60-79` writes one part per objective part
  (multi-part is the CMMC norm) and `api/routes/ui.py:1341-1345` re-saves each
  with `str(...)` and no strip, so a cleared textarea persists as `""`.
  `merge_indicators`' `_has_narrative` already applies exactly this rule to KSI
  narratives one level down, and `ssp/completeness.py` strips too.

- **The placeholder predicate is given the RAW text, never the stripped copy.**
  `constants.DRAFT_PREFIX` is `"[DRAFT] "` — with the trailing space — and
  `is_draft_or_placeholder` tests it as a plain substring, so stripping first
  destroys the token whenever the marker ends the string. `"[DRAFT] "` would
  then ship as `"[DRAFT]"`, keep its status, and appear in **neither** gap
  list: strictly worse than the original defect, which at least reached
  `controls_missing_description`. Reachability is human editing rather than
  scaffolding — `api/routes/ui.py`'s `ssp_save_entry` rebuilds every part as
  `{"label", "text"}` and drops the `draft` key on every save, so for any
  control ever touched in that editor the flag gate is inert and the predicate
  is the only gate left, which is the design `ssp/statements.py:47` documents.

- **The composed description is checked once more, after the join.** The join
  can manufacture the very token the per-part check rejected: `DRAFT_PREFIX` is
  `"[DRAFT] "` with a trailing space, so a bare `"[DRAFT]"` part slips the
  per-part predicate and then the `" "` separator supplies the missing space —
  putting a literal `"[DRAFT] "` into the *shipped* description, reading as
  complete, keeping its status, and appearing in neither gap list. Measured:

  ```
  [{'text':'[DRAFT]'}, {'text':'Kept.'}]  ->  desc='[DRAFT] Kept.'  gaps=([], [])
  is_draft_or_placeholder('[DRAFT] Kept.') -> True
  ```

  The existing predicate already returns `True` on the composed string, so
  re-running it once after the join closes this **inside this branch** — no
  change to `is_draft_or_placeholder`, no decision about SSP completeness
  scoring. A control that trips the composed check is treated exactly like one
  whose parts were all scaffolding: description omitted, named in both lists.

  **Still open, and still follow-up work elsewhere:** a bare `"[DRAFT]"` that
  never gains a space — a lone part with nothing after it — is not matched by
  the predicate at all, and that hole lives inside `is_draft_or_placeholder`,
  reachable from its four call sites. Widening it would make `completeness.py`
  flag more narratives as needing review, which is a user-visible scoring
  decision rather than a CR26 cleanup. `tests/test_cr26_sdr_controls.py`'s
  `test_a_bare_draft_token_that_never_gains_a_space_is_still_shipped` records
  the gap so it stays visible rather than being assumed closed. See the
  evaluation in the task report.

### 1.3 Two of the five derived fields are claims, not renderings

§1.2 caught that the control fields need a shape conversion rather than a copy.
The same lens was never applied to the KSI fields, and two of them fail it —
not on shape, but on **meaning**.

| SDR field | What the platform stores | What the schema wants |
|---|---|---|
| `ksiImplementationStatus` | `pass \| warn \| fail \| not_tested \| manual_review_required \| not_applicable` (`fedramp20x.VALIDATION_STATUSES`; `ksi_states.status` is assigned straight from a verdict at `fedramp20x/validation.py:382`) | `Implemented \| Not Implemented \| Partially Implemented` |
| `ksiEvidence[]` | `evidence_refs`: bare strings such as `"AC-2:implemented"` | objects whose `evidenceType` ∈ `Log, Report, Screenshot, Configuration, Policy, Procedure, Audit Record` |

**A validation verdict is not an implementation status.** "This automated check
passed" and "the provider has implemented this indicator" are different
assertions, and `not_tested` is emphatically not "Not Implemented". Mapping the
full vocabulary would have the platform tell FedRAMP "Not Implemented" about
something nobody has yet examined. That is a compliance claim the platform
cannot support, and it is the §1.1 failure — a document that validates and is
wrong — wearing its third disguise in this one spec.

**Decisions taken 2026-09-18:**

- **Map only the two unambiguous verdicts.** `pass` → `Implemented`,
  `fail` → `Not Implemented`. For `warn`, `not_tested`,
  `manual_review_required` and `not_applicable`, **omit the field**. It is
  optional in the schema, so omission validates, and it leaves the genuinely
  ambiguous cases to the human who is already authoring `ksiImplementation`.
- **Emit evidence without a type.** One object per ref carrying
  `evidenceDescription` (the ref) and `lastUpdated` (`validated_at`), with
  `evidenceType` omitted. Every `evidence` property is optional — measured:
  an object of only those two fields validates `ok: True` — so the platform can
  state what it knows and stay silent about a classification it does not hold.
  Inferring the type from a ref's shape would present our guess to a regulator
  as the provider's assertion.

**A warning for whoever writes the derived producer:** the test fixture in
`tests/test_cr26_sdr_indicators.py` uses `ksiImplementationStatus:
"implemented"` (lowercase) and `evidenceType: "scan"`, **neither of which is a
valid enum member**. It is harmless in a pure-function test and the merge does
not own the producer — but do not read that fixture as the shape to produce.
Read the vendored schema.

## 2. Omit, do not empty

**A KSI with no authored `ksiImplementation` is left out of the document
entirely, and named in the seed result.**

A shorter, truthful SDR beats a complete-looking one full of empty arrays. An
omitted KSI is a visible gap an operator can act on; an emptied one is a
well-formed lie that FedRAMP would accept as structurally valid.

The seed result therefore reports the omitted `ksiId`s. That list is the
deliverable's own to-do list, and it is worth more to an operator than the
document it accompanies.

## 3. The document is its own authoring surface

There is **no migration**. `ksiImplementation` is authored into the stored SDR
document through the `PUT /api/systems/{id}/cr26-documents/sdr` endpoint that
already exists, exactly as the CPO's seven unsourced fields are.

So `seed_sdr` **merges**, keyed by `ksiId`:

- the five derived fields — `ksiImplementationStatus`, `ksiValidation`,
  `ksiAssessment`, `ksiTests`, `ksiEvidence` — are **refreshed on every seed**,
  because they are facts about the system that change as scans and reviews run;
- `ksiImplementation` is **preserved** from what was authored, because it is
  the one field the platform cannot derive.

`securityControls` is regenerated wholesale: every field of it is derived, so
there is nothing to preserve.

### 3.1 The merge is the riskiest thing here

This is the first place in the programme that reconciles two sources *inside an
array*, and array merges are where silent data loss lives. A merge keyed on
`ksiId` that drops an unmatched entry would destroy authored narrative with no
error.

A test must therefore author a narrative for one KSI, seed **twice**, and prove
both halves: that the narrative survives, and that the derived fields actually
changed in between. Proving only the first would pass against a seeder that
ignores the database entirely.

## 4. Two fields deliberately left unfilled

- **`fedRampRequirements: []`.** The key is required; the array has no
  `minItems`, so empty validates. FedRAMP publishes no machine-readable
  ruleset — the rule ids exist only in README prose — so there is nothing to
  populate it from. Unchanged from the spine's spec, which refused to invent
  one.
- **`certificationPackageOverviewUri` is omitted unless authored.** It is
  required at the root, so a seeded SDR is **invalid until someone publishes
  the CPO and supplies its URI**. That is correct rather than unfortunate: the
  SDR's purpose is to reference a real, published CPO, and this platform does
  not publish anything. The seeder preserves an authored value and never
  invents one.

A seeded SDR is therefore invalid on first seed, like a seeded CPO, and for the
same reason: something is genuinely still owed.

## 5. Which SSP project

`SSPProject.system_id` is nullable with no unique constraint, so a system may
have several projects. **Two existing precedents disagree**: `api/routes/oscal.py`
orders by `SSPProject.id.desc()`, `api/routes/reports.py` by
`SSPProject.updated_at.desc()`.

This follows `reports.py` — most recently updated — because it is the closer
analogue, rendering a document rather than assembling a package, and because
"most recently worked on" is the better answer to "which SSP describes this
system today".

**The chosen project's id is returned in the seed result.** The ambiguity is
real and cannot be resolved by picking well; what it can be is *visible*, so an
operator never has to guess which SSP their SDR was rendered from.

## 6. What this deliberately does NOT do

- **No migration, no new column.** §3.
- **No `ksiImplementation` invention**, including from `KSI.description` or
  `ksi_states.notes` — `notes` is per-system free text not designed as an
  implementation statement, and a provider who used it for a reminder would
  file that reminder to FedRAMP.
- **No export or submission.** Still absent for every deliverable.
- **No OCR, VDR, SCN or incident report.** Their own units; the store already
  holds their kinds.

## 7. Testing

- The merge, per §3.1: author, seed twice, assert the narrative survives **and**
  the derived fields changed.
- A KSI with no narrative is absent from `keySecurityIndicators` and present in
  the omitted list.
- `securityControls` renders from the real `SSPControlEntry` rows, asserting a
  value that differs from the column default — not `[]`, which is what an
  inert seeder produces.
- A seeded SDR is invalid, and the errors name `certificationPackageOverviewUri`.
- The project chosen is the most recently updated when several exist, and its
  id is reported.
- Every new test must be able to fail. This programme has shipped at least
  seven that could not, six of them in the two preceding CR26 units, every one
  because the asserted value equalled what the code produces doing nothing.
  Before trusting an assertion, ask what it would be if the code under test
  were deleted.
