# Concord pipeline stage — design

**Status:** design 2026-09-21. Resolves the `certification_status` open question
recorded in `2026-09-16-cr26-vocabulary-design.md` §5.

**Supersedes** the refusal recorded in four places — that spec §5, the
originating plan (lines 806, 836), `docs/architecture/forge-capability-inventory.md:996`,
and `docs/concord-build-level-report-2026-09.html:746`. Each must be amended to
point here, not silently left contradicting this.

---

## 1. What FedRAMP has actually published, checked at source

The open question said the vocabulary "is not published in any source reachable
from here." That was right in 2026-09 and is **still right today**, which is the
whole reason this spec exists in the shape it does.

Checked 2026-09-21, primary sources only:

| Source | What it gives |
|---|---|
| [Marketplace designations](https://www.fedramp.gov/brand/fedramp-marketplace/marketplace-designations/) | Two labels only: *FedRAMP Certified (Rev5)*, *FedRAMP Validated (20x)* |
| [2026 consolidated ruleset](https://www.fedramp.gov/2026/reference/20x/a/fedramp-certification/) | **No status enumeration at all.** Defines how a provider pursues certification |
| [RFC-0020](https://www.fedramp.gov/rfcs/0020/) | The five-per-regime status lists — **and nothing else does** |
| The eleven vendored schemas | No status enum anywhere; the OCR schema (`CCM-OCR-AVL`), structurally *about* ongoing certification, has zero enums |

**RFC-0020 is a proposal.** Its effective date reads "March 18, 2026
(tentatively)" and the page carries no adoption banner. The two designations it
names are corroborated by the non-RFC brand page; **the five-member status lists
are not corroborated anywhere outside the RFC.**

The two designations are already modelled: the vendored CPO schema's
`certificationType: ["20x", "Rev5"]`. Nothing to add there.

### 1.1 So this is not FedRAMP's vocabulary, and must never claim to be

G15 (`docs/superpowers/assessments/2026-09-14-grc-capability-gap-analysis.md:560`)
settled the standard: where FedRAMP has not published, Concord does not invent,
and secondary sources that contradict each other are the reason the primary
source is the only acceptable authority.

This spec does not overturn that. It does something different: it models
**Concord's own operational tracking** of where a system sits in its pipeline,
and borrows RFC-0020's words so the values are recognisable to an operator.
The distinction is not cosmetic — it decides the field's name, its type, and
the one test that matters most (§4).

**Two different questions, deliberately not conflated:**

- *"What does the FedRAMP Marketplace say about this system?"* — a fact about a
  register Concord does not ingest. **Out of scope** (§6).
- *"Where does Concord understand this system to be?"* — an operator's own note
  to themselves. **This field.**

A single field answering both is the claim-versus-rendering defect in its
purest form: an operator sets an internal note, and a reader takes it for a
federal fact.

---

## 2. The name carries the claim

The column is **`pipeline_stage`**, not `certification_status`.

`certification_status` reads as a status FedRAMP conferred. `pipeline_stage`
reads as a position in a process, which is what it is. The open question named
it `certification_status` because that is what FedRAMP's unpublished vocabulary
would have been called; now that the field is Concord's own, the name has to say
so. The old name is not kept as an alias — an alias is how the two questions in
§1.1 get conflated again.

---

## 3. The value carries its regime, so an impossible state cannot be stored

RFC-0020 gives **two** five-member lists, not one:

```
Rev5: Preparation, Agency Authorization In Process, Assessment by FedRAMP,
      Continuous Monitoring, Remediation
20x:  Preparation, Prioritized, Assessment by FedRAMP,
      Persistent Validation, Remediation
```

They overlap on three (`Preparation`, `Assessment by FedRAMP`, `Remediation`)
and differ on two each. *Continuous Monitoring* is Rev5-only; *Persistent
Validation* and *Prioritized* are 20x-only.

**A flat seven-member union would make "Rev5 + Persistent Validation"
representable.** That state cannot exist, and this programme's recurring defect
is a value that validates while asserting something untrue.

The obvious fix — a second `certification_type` column and a check constraint —
is **rejected**. `certificationType` is deliberately absent from the CPO seeder
(`src/ccf/cr26/cpo.py`): *"a declaration the provider makes, not a fact the
platform can compute."* Adding a column for it here would smuggle that
declaration into the platform through a side door, and give two columns that can
disagree.

**Instead the regime is part of the value.** Ten members, each self-describing:

```python
PIPELINE_STAGES: tuple[str, ...] = (
    "rev5:preparation",
    "rev5:agency-authorization-in-process",
    "rev5:assessment-by-fedramp",
    "rev5:continuous-monitoring",
    "rev5:remediation",
    "20x:preparation",
    "20x:prioritized",
    "20x:assessment-by-fedramp",
    "20x:persistent-validation",
    "20x:remediation",
)
```

A mismatched pair is **unrepresentable**, not merely undocumented — no
constraint to write, no second column to disagree with, nothing to keep in sync.
And it is honest about the three shared words: preparing for Rev5 and preparing
for 20x are different states that happen to share a label.

Storage follows the `certification_class` / `certification_path` pattern exactly
(`migrations/versions/0078_cr26_certification.py:25`): a constants tuple, a
SQLAlchemy `Enum`, and a real Postgres enum type, `nullable=True`, defaulting to
NULL. NULL means "nobody has said" — the honest default, and the only one on a
field no platform signal can populate.

### 3.1 Independent of Class, Path and baseline

Nothing derives a stage from `certification_class`, `certification_path` or
`System.baseline`, or any of those from a stage. `tests/test_certification_class_is_independent.py`
already enforces the Class/baseline half by AST walk; extend the same guard
rather than writing a second one.

---

## 4. It never reaches a filed document, and a test says so

No CR26 schema has a status property (§1), so there is nowhere to render this
and no renderer that currently could. **That is a fact about today's eleven
schemas, not a property of the field** — a future vendored schema could add
one, and the seeder written against it would reach for the nearest
status-shaped column.

So the guard is a test, not a comment: **no CR26 deliverable's document body
may contain any `PIPELINE_STAGES` member.** Seed every stage onto a system,
seed every deliverable kind in `DELIVERABLE_KINDS`, and assert no member
appears anywhere in the stored JSON.

This is the single most important test in the change. It is what makes an
internal note safe to keep beside federal filings.

Mutation check: render a stage into any seeder and the test must fail.

---

## 5. Testing requirements

1. **Every member round-trips through a real INSERT** — the migration hardcodes
   its members independently of `constants.py` and nothing else cross-checks a
   typo between the two. This is why `tests/test_cr26_certification_columns.py`
   exists for Class and Path; same reason, same test.
2. **The members are exactly RFC-0020's two lists, regime-prefixed** — asserted
   against a literal, so a silent edit to the tuple fails.
3. **No stage reaches any CR26 document** (§4), mutation-verified.
4. **The column defaults to NULL** and a system with no stage is valid.
5. **Independence from Class, Path and baseline**, both directions (§3.1).
6. **A cross-regime value is rejected** — `"rev5:persistent-validation"` must
   fail at both the Python enum and the Postgres enum, asserted separately, so
   the belt-and-suspenders claim is actually tested rather than assumed.

---

## 6. Out of scope

- **Ingesting the FedRAMP Marketplace.** Concord does not read the register, so
  it cannot report what the register says (§1.1). If that is wanted later it is
  a *different field* with a different truth condition — a fact sourced from
  FedRAMP, not an operator's note — and conflating the two is the defect this
  spec is shaped to prevent.
- **Deriving a stage from anything.** No platform signal establishes it. It is
  authored or it is NULL.
- **Driving behaviour from it.** Nothing gates, schedules, warns or escalates on
  the stage in this change. It is a label an operator sets and reads.
- **Tracking RFC-0020's adoption.** If FedRAMP adopts it, the members may need
  revisiting; that is a scheduled re-check, not code. Record the check date.
