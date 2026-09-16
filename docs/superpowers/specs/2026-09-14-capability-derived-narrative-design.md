# P4a — Capability-Derived SSP Narrative (design)

**Date:** 2026-09-14
**Status:** Design approved in brainstorming; awaiting spec review
**Depends on:** `docs/superpowers/specs/2026-09-14-capability-ontology-design.md` (P1)
**Programme context:** `docs/superpowers/assessments/2026-09-14-grc-capability-gap-analysis.md` (G6, corrected)
**Sub-project:** P4a — the first of eight pieces G6 decomposed into

## 0. Scope correction that shrank this sub-project

G6 originally called the SSP generator "a per-control editor, not an engine"
and listed "no inheritance / shared responsibility in statements". Both
understated what exists, and the correction makes this change materially
smaller and safer.

`ssp/statements.compose` is a real composer. It tailors a statement from
responsibility (`not_applicable` / `inherited` / `shared` / `customer`),
inheritance source, environment, services, ODP values, live connector
captures, responsible role, review frequency, policy reference, and CRM
reference; it offers three style variants; it returns a `needs_review` flag;
and `_inherited_evidence_clause` **refuses to claim evidence is retained
without a real CRM reference** (FR-11), reporting `needs_review` instead.
`governance/automation.py:545` feeds that reference from
`vendor.authorization` and `policy_ref` from a real `Policy` matched by
control id.

**The actual gap is one sentence:** `compose` derives narrative from a
control's derivation *inputs*, not from a capability's authored *text*. One
MFA decision is still re-derived for every dependent control rather than
written once and reused.

So this is **additive to a composer that works**, not a replacement for one.

## 1. Problem

P1 gave Concord a `Capability` — authored once per organization, mapped to
many controls across many frameworks. Nothing reads its `statement`.

The duplication P1 was built to end therefore persists in the SSP: the
mechanism clause in a customer-responsible statement is
`"by configuring {services}"`, where `services` is a generic environment
string. Every control that depends on MFA says the same vague thing, and
changing how MFA is actually implemented changes nothing anywhere.

## 2. Goals and non-goals

**Goals.**

1. A capability's authored `statement` supplies the *mechanism* clause for
   every control it covers.
2. Editing one capability re-renders every control that maps to it.
3. A control with no capability composes **byte-identically** to today.

**Non-goals.**

- **No change to the `needs_review` / `DRAFT_PREFIX` posture** (§4.3).
- **No involvement of the AI path.** `ai.draft_narrative` in
  `governance/automation.py` is untouched.
- **`statements.py` stays pure.** No database access is added to it; its
  docstring asserts side-effect freedom and that stays true.
- **No new storage.** Attribution is already answerable from the capability
  edges.
- **None of P4b–h**: evidence and posture citation, OSCAL SSP import,
  narrative redline, CRM *document* generation, the CR26 profile,
  policy/procedure generation, FedRAMP template conformance.

## 3. Where the capability text goes

Each responsibility branch of `compose` produces a **body sentence** and then
`_finish` appends the tails (ODP params, role, frequency, evidence, policy,
draft prefix). Only the body's *mechanism* clause changes.

| Responsibility | Today's mechanism | With capabilities |
|---|---|---|
| `customer` | "…on {env} by configuring **{services}** to {obj}." | "…on {env} by **{capability statements}**." |
| `shared` | "…the organization configures **{services}** to {obj}." | "…the organization **{capability statements}**." |
| `inherited` | the provider implements it; the customer line covers residual action | capability text describes the **residual** action inside that customer line |
| `not_applicable` | "Control X is not applicable…" | **ignored** — nothing is implemented, so there is nothing to describe |

Everything `_finish` appends is unchanged in every branch. The tails are
control-specific and already correct; the capability supplies only the part
that duplicates.

### 3.1 Multiple capabilities

P1's edges are many-to-many, so several capabilities may cover one control.
The parameter is a sequence, joined with "; " into one clause, **sorted by
capability key**.

Deterministic ordering is not cosmetic: regenerating an SSP must produce
identical prose, which matters for reproducibility now and is a precondition
for P4d's redline later.

### 3.2 Three exclusions

- **Empty or whitespace-only `statement`** — there is nothing to weave, and an
  empty clause would render "…by ." .
- **`status == "not_applicable"`** — the capability does not describe this
  system's implementation, so its text must not claim to.
- **A project with no `system_id`** — that column is nullable
  (`models.py:1049`), so an unbound project composes exactly as it does today.

## 4. Components

### 4.1 `compose` — the pure change

```python
def compose(
    *,
    control_id: str,
    ...,                                   # every existing parameter unchanged
    capability_statements: Sequence[str] = (),
) -> tuple[str, bool]
```

The default empty tuple is what guarantees the additive property: every
existing call site and every existing test is unaffected, and a golden test
asserts byte-identical output when it is empty (§6).

A private `_mechanism_clause(capability_statements, services)` returns the
capability text when present and `f"configuring {services}"` otherwise, so the
branches read the same as they do now.

### 4.2 Resolution — in `capability/service.py`

```python
async def capability_statements_by_control(
    session: AsyncSession, *, system_id: int
) -> dict[str, list[str]]
```

Returns **canonical** control id -> statements, for capabilities bound to that
system through `capability_components -> SystemComponent.system_id`.

The map has exactly one key space: canonical ids (`AC-2`). Reconciling the two
id forms an `SSPControlEntry` may carry is the *caller's* job (§4.4), so this
function has one obvious contract rather than a dictionary holding two kinds
of key.

**One query, loaded before the loop.** `automation.py` iterates one entry per
control — 400+ for an 800-53 High project — so a per-control query would be
400 round trips. It already pre-loads `policy_by_control`, `vendors_by_name`,
and `caps_by_nist` before its loop; this follows that established pattern.

Lives beside P1's `capabilities_for_control` rather than in `ssp/`, so
`statements.py` stays pure.

### 4.3 The review posture, deliberately unchanged

`shared` and `customer` return `needs_review=True` today, which drives
`DRAFT_PREFIX`. A capability statement is **human-authored**, so there is a
real argument it carries stronger provenance than machine-composed prose and
should not be marked draft.

**That is not changed here.** Relaxing a review requirement is a
compliance-posture decision, and getting it wrong puts unreviewed text into an
authorization package. `needs_review` behaves identically whether or not a
capability contributed. Capability-sourced narrative is a candidate for
relaxing it later, as its own decision with its own approval.

### 4.4 Wiring in `automation.py`

Before the entry loop, load the map once. Inside the loop, look a control up
by **both** id spaces and pass the result to `compose`:

```python
def _cap_key(entry: SSPControlEntry) -> str | None:
    """The canonical id this entry's capabilities would be filed under.

    ``control_id`` may be a CMMC practice (``AC.L2-3.1.1``), which does not
    canonicalize, while ``nist_id`` carries the 800-53 form. Both are tried so
    a CMMC project is not silently left without capability narrative --
    ``automation.py`` already bridges the same two id spaces for captures via
    ``caps_by_nist.get(e.nist_id)``.
    """
    for candidate in (entry.control_id, entry.nist_id):
        c = canonicalize(candidate or "")
        if c is not None:
            return c.value
    return None


key = _cap_key(e)
cap_statements = caps_by_control.get(key, []) if key else []
```

Canonicalizing both candidates keeps the map single-keyed while still matching
either id form — the reconciliation lives in one small named function rather
than in two `or`-chained lookups whose key spaces disagree.

## 5. Data model

**No schema change.** P1's `capabilities` and `capability_controls` already
hold everything this reads, `SSPControlEntry.part_narratives` already stores
the rendered text, and attribution is answerable from the edges. No migration.

## 6. Testing strategy

- **The additive guarantee** — a golden test: for each responsibility branch
  and each style, `compose(...)` with no `capability_statements` returns text
  **byte-identical** to `compose(...)` called without the parameter at all.
  This is the test that makes the change safe.
- **Each branch with capability text** — `customer` and `shared` weave it into
  the mechanism clause; `inherited` puts it in the residual customer line;
  `not_applicable` ignores it entirely.
- **Multiple capabilities** — joined, and ordering is deterministic across
  repeated calls with the inputs shuffled.
- **Exclusions** — empty and whitespace-only statements dropped;
  `not_applicable` capabilities dropped; a project with no `system_id`
  composes as today.
- **`needs_review` unchanged** — identical with and without capability text,
  in every branch.
- **Resolution** — scoped to the requesting system (a capability bound to
  another system's component does not leak); matches through canonical ids and
  through `nist_id`; returns `{}` for a system with no capabilities.
- **Edit-once-propagate, end to end** — two controls mapped to one capability;
  render; edit the capability's `statement`; re-render; **both** narratives
  change. This is the point of the sub-project and deserves its own test.
- **Tails preserved** — with capability text present, the ODP parameters,
  role, frequency, evidence, CRM, and policy clauses all still appear.

Every guard is mutation-tested: delete it, confirm a test fails, restore.
Tests must not assume an empty database (`session_scope` commits, the schema
migrates once per session) and must use unique values for unique columns.

## 7. Risks

| Risk | Mitigation |
|---|---|
| A capability rewrites a statement that was correct | Only the mechanism clause changes; every tail `_finish` appends is untouched, and a golden test pins the no-capability path |
| Narrative becomes non-reproducible | Statements are sorted by capability key, with a shuffled-input test |
| An empty statement renders "…by ." | Excluded before joining (§3.2) |
| 400 controls become 400 queries | One pre-loaded map, following `automation.py`'s existing pattern (§4.2) |
| A CMMC project silently gets no capability narrative | Lookup tries the canonical id *and* `nist_id`, with a test for each |
| Review requirements quietly relax | `needs_review` is explicitly unchanged and tested to be identical either way (§4.3) |
| `statements.py` gains a database dependency | Resolution lives in `capability/service.py`; the purity is asserted by the module docstring and by tests calling `compose` with no session |

## 8. Open items

1. **Relaxing `DRAFT_PREFIX` for capability-sourced narrative.** Deliberately
   deferred (§4.3) — a compliance-posture decision needing its own approval.
2. **Naming contributing capabilities inside the prose.** Rejected for now:
   it reads poorly, and `capabilities_for_control` already answers "why does
   my SSP say this". Revisit only if an assessor asks for it inline.
