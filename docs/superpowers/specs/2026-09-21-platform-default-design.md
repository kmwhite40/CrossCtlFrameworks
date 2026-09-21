# "No cloud platform" is an answer, not a missing value — design

**Status:** design 2026-09-21. Fixes the most severe instance of this
programme's signature defect found so far.

---

## 1. What happens today

The intake questionnaire asks *"Primary cloud platform?"* and offers four
answers (`governance/automation.py` `QUESTIONNAIRE`):

```
['m365_gcc_high', 'azure_gov', 'aws_govcloud', 'none']
```

Measured, end to end:

```
declared 'm365_gcc_high' -> ssp 'm365'         -> 'Microsoft 365 (Entra ID / Purview / Intune)'
declared 'azure_gov'     -> ssp 'azure'        -> 'Microsoft Azure (Gov)'
declared 'aws_govcloud'  -> ssp 'aws_govcloud' -> 'AWS GovCloud (US)'
declared 'none'          -> ssp 'm365'         -> 'Microsoft 365 (Entra ID / Purview / Intune)'
declared ''              -> ssp 'm365'         -> 'Microsoft 365 (Entra ID / Purview / Intune)'
```

**A customer who answers "none" gets an SSP describing Microsoft 365**, with
Entra ID, Purview and Intune drafted as their implemented controls. So does a
customer on GCP, Oracle Cloud or on-premises equipment, because every
unrecognized value lands in the same place.

This is not an edge case. `none` is **one of the four answers the product
itself offers.**

### 1.1 Why it is worse than the defects before it

Every earlier instance misstated a control, a vulnerability count, or whether
evidence existed. This one **misdescribes the customer's entire technology
stack** in a document filed with a federal regulator — naming products they do
not run as the mechanisms implementing their controls.

### 1.2 Three layers, all defaulting the same way

1. `governance/automation.py:399` — `PLATFORM_TO_SSP.get(profile.cloud_platform or "", "m365")` in `generate_ssp`.
2. `ssp/platforms.py:212` — `normalize_platform` returns `DEFAULT_PLATFORM` (`"m365"`) for anything not in `PLATFORMS`.
3. `SSPProject.platform` — `VARCHAR(32) NOT NULL`, Python-side default `'m365'`.

Each is individually defensible as "pick something sensible". Together they
make "we do not know" indistinguishable from "Microsoft 365", in both
directions and at every layer.

---

## 2. The fix: make "no platform" representable

**`none` becomes a real platform**, with an honest label and an empty service
catalog — not a missing value for a default to fill.

That is what removes the need for a default at all: today `normalize_platform`
must return *something*, and the only somethings available are real product
names. Give it a truthful one and the pressure disappears.

- `PLATFORMS` gains `"none"`, labelled so no reader could mistake it for a
  product — e.g. *"No cloud platform declared"*.
- Its service catalog is **empty**, so nothing platform-specific can be drafted
  for it. A statement generator asking "what services implement AC here" gets
  nothing and must say so, rather than borrowing another platform's answer.
- `PLATFORM_TO_SSP` gains `"none": "none"`, so the questionnaire's fourth
  answer survives the translation instead of falling into the default.
- `SSPProject.platform`'s Python-side default becomes `"none"`. **No migration**
  — it is a client-side default, and the column stays `NOT NULL` because
  `"none"` is now a value rather than an absence.

### 2.1 Unrecognized is not the same as none, and must not become it

`none` means *the customer told us they have no cloud platform*. An
unrecognized string — `gcp`, `oracle`, a typo, a value from a future
questionnaire — means *we do not know what they have*. Collapsing the second
into the first would repeat this defect one layer over: silence presented as an
answer.

**`normalize_platform` returns `str | None`** and gives `None` for anything not
in `PLATFORMS`. Every caller must then decide, and the type checker makes that
unavoidable — the same reasoning as `coverage`'s keyword-only
`connector_backed`: a forgotten caller should be an error, not a silent false
claim.

Callers divide cleanly:

- **Write paths** (`api/routes/ssp.py:252`, `:643`, `:684`, `api/routes/ui.py:1217`, `:1247`)
  currently coerce user input before storing it, so a project row can end up
  claiming a platform nobody chose. These must **refuse** an unrecognized value
  (422) rather than coerce. The UI offers a fixed choice list, so a value
  outside it is a bug or a hand-crafted request — neither deserves a guess.
- **Read paths** (`platform_label`, `services_for`, `connector_key_for_platform`,
  `ssp/seed.py:113`, `:144`) must render the unknown case honestly: say what was
  declared, never substitute a product name, and draft no platform-specific
  content.

### 2.2 `generate_ssp` stops defaulting

`automation.py:399` uses the mapping with no fallback. A profile whose
`cloud_platform` is absent or unrecognized yields a project with platform
`"none"` **and the fact is reported**, exactly as the guided onboarding path
already reports it at step 2 (`onboarding.py` says *"Concord does not recognize
the declared platform …"* rather than defaulting). One behaviour, two surfaces.

---

## 3. Rows already written cannot be silently repaired

Every SSP project coerced to `m365` is now indistinguishable from one
legitimately on M365. **Rewriting them would be a second guess on top of the
first**, and would destroy the record of what was actually stored.

But the mismatch **is** detectable: `SystemProfile.cloud_platform` keeps the
declared answer while `SSPProject.platform` holds the coerced one. A project
whose platform does not correspond to its system's declared answer is a
candidate.

**Add a reliability check** (`ccf/reliability/checks.py`, beside the others)
that counts projects whose platform disagrees with their system's declared
`cloud_platform`, and names the remediation as a human decision — not an
automatic rewrite. `WARN`, never `FAIL`: a legitimate mismatch is possible if
someone deliberately changed a project's platform after intake.

This is the honest half. The defect shipped; the fix stops new occurrences and
makes the old ones findable, and says plainly that it cannot tell which past
rows were wrong.

---

## 4. Testing requirements

1. **The headline case, pinned**: a profile declaring `none` produces a project
   whose platform is `"none"`, whose label names no product, and whose generated
   statements contain no Microsoft/AWS service name. **Write this first and
   confirm it FAILS against current code**; report what it printed.
2. **An unrecognized platform is distinct from `none`** in state and in what the
   customer is told — asserted separately, so the §2.1 collapse cannot happen.
3. **Write paths refuse** an unrecognized platform with 422 rather than storing
   a coerced value. Assert on the stored row, not only the status code.
4. **No platform-specific content is drafted for `none`**: generate statements
   for a `none` project and assert no service name from any other platform's
   catalog appears — iterate the real catalogs rather than listing strings, so a
   newly added service is covered automatically.
5. **`normalize_platform` returns `None`**, and every call site handles it —
   enforced by `mypy` being clean, plus a test for each read helper's unknown
   branch.
6. **The reliability check counts a coerced project and not a consistent one**
   (§3), and is `WARN`, never `FAIL`.
7. **The three questionnaire answers still map as before** — a regression guard,
   asserted against the literal table, since this change touches the mapping
   they travel through.

Mutation-verify each: restore a default, confirm a test fails.

---

## 5. Out of scope

- **Rewriting existing rows** (§3). Detection only.
- **Adding GCP, Oracle or on-prem as platforms.** Supporting a platform means a
  service catalog and a responsibility model; `none` is what an unsupported
  platform honestly maps to until then.
- **A migration.** The column default is client-side and `"none"` is a value,
  not an absence.
- **Changing the questionnaire's four options.** They are correct; only the
  translation of the fourth was wrong.
