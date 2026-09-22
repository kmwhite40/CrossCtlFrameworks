# Trust Center corroboration — what the platform can back

**Status:** design 2026-09-22. Makes the Trust Center state which of its claims
the platform can support, without preventing the operator from making them.

---

## 1. Measured, and it decides the design

Every field on `/trust` is operator-typed JSONB on one row. Nothing derives
from control, evidence, POA&M or assessment data. `framework_badges` is an
arbitrary `{framework, status}` pair with no vocabulary, no expiry, and no link
to an authorization record.

Measured on the dev database:

```
systems: ato_status='none' x14     (every system)
existing badge: [{"framework": "CMMC L2", "status": "In progress"}]
```

**So the obvious design — replace typed badges with derived ones — produces an
empty page.** There is no authorization on record anywhere to derive from. A
Trust Center showing nothing would be honest and useless, and an operator would
route around it.

The operator's claim may well be true: an organization can hold a CMMC
assessment the platform has never been told about. **The platform's job is not
to know, it is to say what it can and cannot back.**

---

## 2. The rule: corroborate, never refuse

For each typed badge the platform attempts corroboration and reports one of
three states. It **never** blocks a badge, edits it, or hides it.

| State | Meaning |
|---|---|
| `corroborated` | platform data supports this claim |
| `unsupported` | the platform holds nothing either way |
| `contradicted` | platform data says something different |

This is the SCN rule already settled in this programme
(`2026-09-19-cr26-scn-design.md` §2.1): *"check, name, and never refuse."* An
observation worth telling an operator about is not a thing worth blocking over.
Refusing a badge would make a real certification unrecordable on evidence that
does not support the conclusion.

### 2.1 `unsupported` is the common case and must not read as doubt

With every system at `ato_status='none'`, nearly every badge will be
`unsupported`. That is a statement about **Concord's knowledge**, not about the
organization's compliance. The wording must say so — "the platform holds no
authorization record for this framework", never "unverified" or "unconfirmed",
which read as suspicion of the claim.

This is the same asymmetry the guided onboarding path draws between `unknown`
and `not_started`: absence of evidence rendered as evidence of absence is the
defect, and in a page about an organization's security posture it is a
defamatory one.

### 2.2 `contradicted` is the one that earns the feature

A badge saying **Authorized** while no system carries `ato_status='authorized'`
is the case worth catching, and it is the only one an operator must act on —
either by recording the authorization or by correcting the badge.

---

## 3. What counts as corroboration

Per badge, matched on the framework name, using only signals that already
exist. **No new derivation, no new table.**

| Badge claims | Corroborated by |
|---|---|
| authorized / certified | a system in this org with `ato_status='authorized'` and `ato_expires_on` in the future |
| in progress | a system with `ato_status='in_progress'`, **or** an `AuthorizationPackage` for a system in this org |
| expired | `ato_status='expired'`, or `ato_expires_on` in the past |

Framework matching is **deliberately loose and reported as such**: badge
frameworks are free text ("CMMC L2") and nothing in the platform stores a
framework per system in that vocabulary. The match is on the org's systems as a
whole, not per framework — and the rendered text says so, rather than implying
a precision the data does not have.

**Correction (implementation, 2026-09-22): two readings of this section were
too literal and were narrowed.** Both were found by building it, and both are
the §2.1 defect aimed at the strongest possible claim.

1. **A NULL `ato_expires_on` is not a lapse.** Read literally, a system
   Concord records as `ato_status='authorized'` with no expiry on file would
   make an "Authorized" badge `contradicted` — Concord reporting *its own
   authorization record* as disagreeing with the badge that record supports.
   `contradicted` must never do that. The rule is
   `ato_status='authorized' AND (ato_expires_on IS NULL OR ato_expires_on >= today)`.
2. **An organization with no systems at all is `unsupported`, never
   `contradicted`.** §2.2 as written has no qualification, but applied to an
   empty table it prints "does not match platform records" at a tenant that
   has told Concord nothing. `contradicted` requires system rows whose own
   `ato_status` asserts non-authorization — the measured `none` × 14 case.

**An expired authorization is surfaced even when no badge claims it.** A
badge reading "Authorized" over a system whose `ato_expires_on` has passed is
`contradicted`, and a page with no badge at all still reports the expiry,
because an expired ATO is the single fact a trust page most needs to not omit.

---

## 4. The `published` flag is inert and stays that way

`TrustProfile.published` is settable through the API and **read by no code**.
This change does not begin to honour it: `/trust` is not in
`_PUBLIC_PREFIXES`, publishing is a decision that has not been taken, and a
flag that silently starts gating something is worse than one that does nothing.

**Make its inertness explicit** — a comment on the column and on the API field
saying it is recorded and not yet honoured, so the next reader does not assume
it works.

---

## 5. What this does not do

- **No public page.** `/trust` stays session-gated; `tests/test_auth_gate_prefixes.py` pins that set deliberately.
- **No new posture derivation.** Only `ato_status`, `ato_expires_on` and `AuthorizationPackage` existence — all already computed.
- **No badge vocabulary.** Constraining free text to an enum would refuse real claims the platform has no standing to judge.
- **No blocking, editing or hiding** of any operator claim (§2).
- **No change to the export**, beyond carrying the corroboration state so the downloaded artifact cannot say more than the page.

---

## 6. Testing requirements

1. **A badge claiming "Authorized" with no authorized system is `contradicted`** — the case the feature exists for.
2. **`unsupported` renders as absence of platform knowledge, not doubt** — assert the rendered text contains no word implying the claim is questionable, and pin the specific phrasing.
3. **A corroborated badge** over a system with `ato_status='authorized'` and a future expiry.
4. **An expired ATO is reported even with no badge present** (§3).
5. **No badge is ever dropped, edited or reordered** — the stored JSONB is byte-identical before and after rendering.
6. **The export carries the same states as the page**, so the artifact cannot claim more than the screen. Assert by comparing both.
7. **Tenant isolation**: another organization's systems never corroborate this one's badges. Note that `get_session` binds the RLS tenant, so pin this on an unscoped session and first assert the other tenant's rows are visible without the predicate.

Mutation-verify each state rule. A rule whose removal leaves the suite green is not protecting anything.
