# The CR26 schema spine (P9a-ii, part 1)

Status: approved 2026-09-17. Successor to
`docs/superpowers/specs/2026-09-16-cr26-vocabulary-design.md`, which deferred
the CPO and SDR deliverables to "their own spec". This is the half of that
which everything else depends on; the generators follow separately.

## 1. Why the spine comes before the generators

FedRAMP publishes the CR26 deliverables as **JSON schemas at stable URLs**, in
`FedRAMP/schemas`. Eleven of them, 45,495 bytes in total. That single fact
decides the shape of all the CR26 deliverable work:

> **Concord validates against the published schema. It never invents the shape
> of a FedRAMP deliverable.**

The programme has already paid once for taking a FedRAMP structure from a
secondary source — two blog summaries gave opposite Class-to-impact-level
orderings, and only the primary source settled it. A generator written against
a schema we transcribed by hand would repeat that at greater cost, because the
error would be in emitted artefacts rather than in a column.

So the first unit of work pins the schemas as authority-published reference
data and makes offline validation against them work. It ships nothing an
operator sees, and that is the point: every later CR26 deliverable is a
projection validated by this module.

## 2. What gets pinned

All eleven, not the three with a near-term consumer. The marginal cost is one
`DEFAULT_SOURCES` row and one vendored file each, they share a single
drift-detection path, and the deadline that actually binds first is VDR/VER on
**2026-12-07** — earlier than CPO/SDR maintenance on 2027-01-01. Pinning the
whole set now is the cheap half of that deadline-bound work; pinning three
guarantees a second spine job before December.

| Schema file (`fedramp-…-schema-2026-06-24.json`) | Title / rule id | `$schemaVersion` | Bytes |
|---|---|---|---|
| `certification-package-overview` | Certification Package Overview (**FRC-CSO-PKG**) | 0.1.4 | 10,461 |
| `security-decision-record` | Security Decision Record (SDR-CSO-FRR) | 1.1.1 | 8,146 |
| `common-definitions` | Common Definitions | 0.3.0 | 5,909 |
| `incident-report` | Incident Report (IEC-CSO-IIR / OIR / …) | 0.2.0 | 4,868 |
| `ongoing-certification-report` | Ongoing Certification Report (CCM-OCR-AVL) | 0.2.0 | 3,817 |
| `significant-change-notifications` | Significant Change Notification (SCN-CSO-INF) | 0.1.2 | 3,516 |
| `assessor-information` | Assessor Information (MKT-IAS-WEB) | 1.0.1 | 2,563 |
| `advisor-information` | Advisor Information (MKT-CAS-WEB) | 1.0.1 | 2,283 |
| `historical-ver-activity` | Historical VER Activity | 0.1.1 | 1,442 |
| `accepted-vulnerability-info` | Accepted Vulnerability Info (VER-RPT-AVI) | 0.1.1 | 1,271 |
| `vulnerability-detail-report` | Vulnerability Detail Report (VER-RPT-VDT) | 0.1.1 | 1,219 |

Two naming facts worth recording, because both contradict a source someone
will reach for later:

- The CPO schema's own title is **`FRC-CSO-PKG`**, while
  `fedramp.gov/2026/reference/20x/c/certification-package-overview/` calls the
  rule `CPO-CSO-OVR`. **The schema wins** — it is the artefact being validated.
- `certificationType` in the CPO schema enumerates **`20x` and `Rev5`**, not
  Classes. See §5.

### 2.1 Two-level versioning, and why the manifest carries both

FedRAMP versions each schema **independently** by `$schemaVersion` (semver:
patch = documentation, minor = backward-compatible additions, major =
breaking), while the `2026-06-24` in every filename is the **ruleset**
revision and moves only when FedRAMP publishes a new ruleset. The spread is
already live — `certification-package-overview` is at 0.1.4 while
`assessor-information` is at 1.0.1 — so a single version field cannot describe
this set. The manifest records the ruleset date once and the `$schemaVersion`
per file.

## 3. Vendored and watched, both

This mirrors `src/ccf/oscal/schemas/` exactly, which is the established
precedent for a specification we validate against rather than ingest.

- **`src/ccf/cr26/schemas/`** — the eleven files on disk plus `MANIFEST.json`
  in the shape of `oscal/schemas/MANIFEST.json` (`source_url`, `retrieved_at`,
  `files` → sha256), extended with `ruleset_version` and a per-file
  `$schemaVersion` per §2.1. Vendoring is what makes validation work with no
  network and no configuration.
- **Eleven `CatalogSource` rows** (`models.py:1152`) seeded through
  `DEFAULT_SOURCES`: `kind="generic"`, `authority="FedRAMP"`,
  `framework_code="FEDRAMP"` (the code already exists in
  `etl/frameworks.py`), `auto_ingest=False`. Each row is seeded with
  `last_sha256` already set to the digest `MANIFEST.json` pins, so the first
  poll compares upstream against **what we actually vendored**. Left NULL it
  would compare against nothing — eleven "changed" events on day one — and
  thereafter only upstream against upstream, silently adopting a schema that
  moved between the vendoring and the first poll.

`kind="generic"` is content-hash-only, and that is the correct call for the
same reason `etl/sources.py` already records for baseline profiles: *a profile
is not a catalog*. A schema is not a catalog either. Nothing here parses a
schema into tables; the existing ETag-conditional poller detects that upstream
changed and surfaces it for a human, exactly as `auto_ingest=False` intends.
**Drift must never be adopted silently** — a schema that changed under us is
precisely the event a person needs to see.

No migration is expected: `catalog_sources`, the `generic` kind, `CatalogCheck`
and `seed_sources`' upsert-by-key all exist. The implementation plan
confirms this rather than assuming it.

## 4. Offline validation, and the one absolute `$ref`

`src/ccf/cr26/validation.py` mirrors `oscal/validation.py`: vendored copy by
default, dialect resolved through `jsonschema.validators.validator_for` rather
than hardcoded, and graceful degradation when `jsonschema` is unavailable.
`jsonschema>=4.20,<5` is already a dependency.

**The load-bearing detail.** The CPO and SDR schemas reference the shared
definitions by *absolute URL*:

```
"$ref": "https://fedramp.gov/schemas/fedramp-common-definitions-schema-2026-06-24.json#/$defs/certificationPackageOverviewUri"
```

Under `jsonschema` 4.x that resolves through `referencing`. **Measured by
counting socket constructions, which is the only method that answers this
correctly** — see the warning below about why:

| validator | sockets attempted | outcome |
|---|---|---|
| no registry | **1** | fetches the reference over the network |
| vendored registry | **0** | resolves locally and validates |

**With no registry, `jsonschema` fetches the schema over the network.** With a
registry, it never falls back to the network: anything absent from the registry
raises `Unresolvable` with zero sockets attempted. So `registry=` is not a
convenience — it is the entire network barrier.

> **This claim was got wrong twice while writing this spec, and the reason is
> instructive.** Blocking sockets and observing `Unresolvable` looks like proof
> that the library fails closed. It is not: the block *causes* the retrieval to
> fail, and `referencing` converts that failure into `Unresolvable`. The
> exception is the consequence of the block, not evidence that no fetch was
> attempted. Only counting socket constructions distinguishes the two. Anyone
> revisiting this must measure the same way.

An earlier draft of the table above also claimed `jsonschema` *warns* that
"automatically retrieving remote references can be a security vulnerability".
Do not lean on that. The warning lives in `_warn_for_remote_retrieve`
(`jsonschema/validators.py`), which issues it as a `DeprecationWarning` only
*after* the retrieval succeeds — and `DeprecationWarning` is suppressed by
default anyway. Warnings captured during the socket count showed none on this
path in 4.26.0. **The socket count is the claim that carries the argument.**

Left alone, this fails two ways and the second is the dangerous one: it fails
closed wherever there is no network — including CI — and where there *is*
network it silently validates against whatever upstream serves that day,
defeating the pin entirely and leaking the fact that validation is happening.

**The second trap is that resolution is lazy.** A `$ref` resolves only when
validation actually descends into the property carrying it. A document that
fails an earlier `required` check never gets there. Measured on the CPO schema:
an empty document returns **3** ordinary validation errors
(`serviceIdentification`, `serviceProperties`, `contactInformation`) and never
raises — earlier drafts of this spec said 12, which was wrong; the surrounding
argument is unaffected. CPO's only absolute `$ref` sits at
`serviceIdentification.properties.logo`,
several levels below a `required` check an empty document already fails. So a
test fixture built as "a minimal invalid document" — the natural thing to write
first — **passes with or without a registry**, and the failure appears only for
documents complete and valid enough to descend. That is precisely inverted: the
spine would look correct in tests and break on the first real deliverable.

So the module builds a `referencing.Registry` mapping each vendored schema's
`$id` to its on-disk copy, and validation resolves only through it. Three
requirements follow, and none is optional:

1. **Every test asserting reference resolution must use a document complete
   enough to descend into the `$ref` it claims to exercise** — and "complete
   enough" is per-schema, because the refs sit at different depths. A test that
   only exercises invalid documents proves nothing.
2. **A test must assert validation succeeds with no network access** — sockets
   blocked, not merely "it worked on my machine".
3. **Coverage must extend past the one schema that is easiest to test.** Eight
   of the eleven carry absolute `$ref`s besides CPO and SDR; a suite that
   exercises resolution for one kind leaves the rest unproven.

Surveying the set, **ten of the eleven schemas carry absolute `$ref`s**, one to
three each, and every one targets the same file (common-definitions). Only
`common-definitions` itself has none. So the registry is small — one resource
satisfies every reference — but it is needed by almost every schema, not just
CPO and SDR.

Two smaller findings from the same survey, recorded so they are not
rediscovered:

- The eleven schemas contain **four** regex patterns
  (`^CVE-[0-9]{4}-[0-9]{4,}$`, `^\d{6}$`, `^[0-9]{3}-[0-9]{3}-[0-9]{4}$`, and an
  image-extension pattern), all plain and Python-`re`-compatible. **The
  `_translate_ecma_pattern` machinery in `oscal/validation.py` has no
  counterpart here and must not be copied over.** It exists because OSCAL uses
  ECMA constructs Python's `re` rejects; CR26 does not.
- The only `format` values are `date`, `date-time`, `email` and `uri`, and
  **format checking is a trap here that must be handled explicitly.**
  `jsonschema` ignores `format` unless a checker is passed, and even then it
  registers a checker for a given format only when that format's optional
  validator library is installed. Measured against this environment
  (`jsonschema` 4.26.0):

  | format | checker registered | rejects a malformed value |
  |---|---|---|
  | `date` | yes | yes |
  | `email` | yes | yes |
  | `date-time` | **no** (`rfc3339-validator` absent) | **no — silently passes** |
  | `uri` | **no** (`rfc3986-validator` absent) | **no — silently passes** |

  **Decision: pass a `FormatChecker`, add no dependency, and pin the live set
  in a test.** Enforcement is therefore real for `date` and `email` and absent
  for `date-time` and `uri`. A test asserts *which formats are actually
  enforced*, so the gap is a recorded fact rather than an assumption — without
  it, a future test written to prove a malformed `date-time` is caught could
  never pass, and one written to prove a document validates would pass
  vacuously. That is the defect class this programme has shipped at least
  seven times.

  Adding `rfc3339-validator` and `rfc3986-validator` is the known remedy and is
  deliberately deferred: this unit ships no generator, so nothing emits a
  `date-time` or `uri` yet, and the two dependencies buy nothing until one
  does. The generator sub-project revisits it — at which point malformed dates
  in a submitted package become a real risk worth two small pure-Python
  dependencies.

## 5. What this deliberately does NOT do

- **No generators.** CPO and SDR emission is the next sub-project. This one
  ends at "a document can be validated".
- **No CR26 rule table.** The SDR requires `fedRampRequirements` (`frrID`,
  `frrImplementation`, …), but **FedRAMP publishes no machine-readable
  ruleset** — `FedRAMP/schemas` carries the eleven schemas and documents rule
  ids in README prose only. Inventing a rule table from prose is exactly what
  §9.7 of the gap analysis refused to do for Certification Classes. Recorded
  as an open question with its reason; the generator sub-project must solve
  sourcing before it can fill that array.
- **No change to `certification_class` / `certification_path`.** The columns
  shipped in `0078_cr26_certification` are confirmed correct *and* correctly
  placed: the CR26 ruleset uses "Class: Class A | Class B | Class C | Class D"
  and "Path: Program | Agency" as **rule-applicability dimensions**, and
  neither appears anywhere in the eleven deliverable schemas, which carry
  `certificationType: 20x | Rev5` instead. Class and Path scope *which rules
  apply* — which is what a column on `System` is for — not what a generator
  emits.
- **No Class B/C historical metrics.** The SDR reference requires 30-day and
  annual historical metrics for Class B and C, and daily data for Class C.
  `CaptureSnapshot` carries `UniqueConstraint(org, connector, odp_key)` and so
  keeps **last value only**, making drift unprovable today. That is real,
  deadline-relevant retention work, and it is a separate sub-project — naming
  it here so it is not mistaken for something this spine delivers.

## 6. Deadlines

CPO and SDR adoption opened **2026-07-04** and is already available today.
Maintenance becomes mandatory **2027-01-01** for 20x and **2027-08-01** for
Rev5, with CPO updates required bi-weekly. VDR and VER become mandatory
**2026-12-07**, which is why §2 pins all eleven schemas rather than three.
