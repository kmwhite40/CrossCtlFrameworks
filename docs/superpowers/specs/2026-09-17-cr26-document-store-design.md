# The CR26 document store (P9a-ii, part 2)

Status: approved 2026-09-17. Successor to
`docs/superpowers/specs/2026-09-17-cr26-schema-spine-design.md`, which pinned
FedRAMP's eleven CR26 JSON schemas and made offline validation against them
work but deliberately shipped no generators. This is the first consumer of
that validator.

## 1. What this is, and what it is not

FedRAMP's CR26 revision replaces the Word/Excel deliverables with JSON
documents. The first of them is the **Certification Package Overview** (`CPO`,
whose schema titles itself `FRC-CSO-PKG`) — "a simple overview document
replacing the historical System Security Plan for FedRAMP Rev5", required in
both human-readable and JSON form, with maintenance mandatory from
**2027-01-01** and bi-weekly updates thereafter.

**It is not a generator, and calling it one would mislead.** Measured against
the schema, the CPO has ten required fields and this platform can supply
**three**:

| CPO required field | Source |
|---|---|
| `providerName` | `Organization.name` |
| `serviceName` | `System.name` |
| `serviceDescription` | `System.description` |
| `serviceAcronym` | **nowhere** |
| `fedRampPackageId` | **nowhere** |
| `website` | **nowhere** |
| `logo` | **nowhere** |
| `certificationType` | **nowhere** (and deliberately not derived — §4) |
| `serviceType` (SaaS/PaaS/IaaS) | **nowhere** |
| `deploymentModel` | **nowhere** |
| `contactInformation` | **nowhere** — `Vendor` is third-party supply chain, and there is no party or contact table at all |

The gap analysis predicted the CR26 deliverables would be "a second deliverable
profile over content the SSP generator already produces". That is true of the
SDR, whose substantive arrays render from the KSI subsystem and
`SSPControlEntry`. **It is false of the CPO**, which is mostly facts about the
business that live nowhere in the platform. So what ships is a seeded skeleton,
authoring, and — the actual value — **validation against the published
schema**.

## 2. One table for all eleven kinds

`cr26_documents`, keyed by a `kind` column drawn from the `CR26_KINDS`
vocabulary the spine already vendors.

This is not speculative generalisation. The set of kinds is **closed and
published**: eleven schemas, already on disk, already pinned by sha256, and
`cr26.validation.validate_document` already dispatches by exactly that key. The
alternative is eleven near-identical tables as the SDR, Ongoing Certification
Report, Vulnerability Detail Report and Significant Change Notification arrive —
and VDR/VER are mandatory from **2026-12-07**, sooner than the CPO's own
maintenance date.

| Column | Purpose |
|---|---|
| `organization_id` | tenant scope; direct RLS shape |
| `system_id` | the offering this document describes |
| `kind` | one of `CR26_KINDS` |
| `document` | the JSON document itself (JSONB) |
| `ruleset_version` | the CR26 ruleset revision it was judged against (`2026-06-24`) |
| `schema_version` | that schema's own `$schemaVersion` at validation time |
| `is_valid` | whether it validated |
| `validation_errors` | what failed, so a caller need not re-derive it |

Recording **both** versions is not redundancy: FedRAMP versions the ruleset (the
date in every filename) and each schema (semver) independently, and the spread
is already live — the CPO schema is at 0.1.4 while `assessor-information` is at
1.0.1. A document validated a year ago must be able to say what it was judged
against.

**Uniqueness:** one current document per `(system_id, kind)`. The documents are
self-versioning — the CPO's own `CPO-CSO-MTD` metadata block carries version,
last-updated and update-source — so a second history mechanism here would be a
second record of one fact. Change history is `AuditLog`'s job, and it already
carries a `prev_hash`/`row_hash` chain (**never construct `AuditLog` directly —
use `ccf.api.audit.record_event`, or the chain silently breaks**).

## 3. Validate on write; refuse at submit, not at save

Every write runs the document through `ccf.cr26.validation.validate_document`
and persists `is_valid`, `validation_errors`, `ruleset_version` and
`schema_version` alongside it.

**Writes are never refused for being invalid.** A draft in progress is
necessarily incomplete — a CPO cannot have its assessor before an assessor
exists — so refusing invalid writes makes authoring impossible. Refusal belongs
at export or submit, which this unit does not ship. What it does ship is the
guarantee that **no document is ever stored without a recorded verdict**: there
is no path that writes `document` and leaves `is_valid` null or stale.

This also gives the spine its first production consumer. The schema-spine
branch's final review noted that `validate_document` had no caller outside its
own tests, and the CR26 vocabulary branch's review said the same of
`accepted_weakness_state`. A validator nothing calls is a validator nobody has
checked the ergonomics of.

## 4. `certificationType` is authored, never derived

The CPO's `certificationType` enumerates exactly `20x` and `Rev5`. It is
tempting to infer it — a system with a `certification_class` set is presumably
on the 20x lane — and that inference must not be made.

It is the same class of mistake as deriving Certification Class from
`System.baseline`, which FedRAMP explicitly disclaims and which migration
`0078` and `tests/test_certification_class_is_independent.py` exist to prevent.
Through 2026–27 an offering may hold a Rev5 ATO and pursue a CR26 Certification
at once, so the presence of a Class says nothing definitive about which
deliverable profile a given package is being filed under. The field is a
declaration the provider makes, not a fact the platform can compute.

The seeder therefore leaves it unset, and the resulting document is invalid
until a human supplies it — which is the correct and visible outcome.

## 5. Multi-tenancy

`cr26_documents` carries its own `organization_id` and takes the **direct** RLS
shape (`organization_id = ccf.current_tenant()`), not the parent-chain shape
used by `control_test_results` and `poam_milestones`.

Two guards must be updated together, and they are opposites:

- `EXPECTED_TENANT_ISOLATION_TABLES` in `tests/test_rls_coverage.py` is a
  positive-control snapshot with a **hardcoded count** — currently
  `len(found) == len(EXPECTED_TENANT_ISOLATION_TABLES) == 137` at line 185.
  Both the frozenset entry and the count must change, to **138**.
- `GLOBAL_TABLES` in `tests/test_rls_registry_no_gap.py` is for
  authority-published reference data and **must not** gain this table.

**`organization_id` is `NOT NULL`, and is taken from the system rather than
from the principal.** There is a folk rule in this programme that new tenant
tables should copy `vendors`' nullable `organization_id`, because an unscoped
principal writes a null-org row that the RLS predicate then hides from scoped
tenants. Checked rather than assumed, that rule does not generalise:
`Vendor.organization_id` is indeed nullable, but `System.organization_id` is
`NOT NULL`. (A second part of the same folk rule — that `people` is a sibling
example — is simply wrong: **there is no `people` table**.)

The nullable trick exists for tables written straight from a principal, where
auth-disabled tests leave `org_id is None`. It is unnecessary here, because
every `cr26_documents` row already has a `system_id`, and `System` carries a
non-null `organization_id`. Deriving the tenant from the system is both
stricter and simpler than admitting null-org rows, and it removes the failure
mode where a row is written with no tenant and silently becomes invisible to
everyone.

## 6. What this deliberately does NOT do

- **No SDR.** Its own unit. Its substantive arrays do render from existing
  content, and note that `fedRampRequirements` has **no `minItems`**, so an
  empty array validates — the missing machine-readable ruleset blocks semantic
  completeness, not schema validity.
- **No export, no submission, no UI.** Refusal-at-submit is named in §3 as the
  right home for strictness, and is not built here.
- **No CR26 rule table.** FedRAMP publishes no machine-readable ruleset; the
  rule ids exist only in README prose. Unchanged from the spine's spec.
- **No history table.** See §2.
- **No promoted columns.** Nothing in the platform queries `serviceAcronym` or
  `deploymentModel` today. If a query need appears, the cheap move is a column
  generated *from* the document, not a second hand-maintained copy of it —
  going the other way, after authoring has started, means migrating real
  customer data.

## 7. Testing

- A round-trip through the database that reads values **back from Postgres**,
  not from the dict that was written.
- A document that validates and one that does not, asserting `is_valid`,
  `validation_errors` and both version fields are recorded in each case —
  including that an invalid document is still **stored**.
- The seeder supplies exactly the three fields §1 lists, and leaves
  `certificationType` unset. A test asserts the seeded document is **invalid**,
  which is the honest expectation and prevents a future change quietly
  inventing values for the missing seven.
- A guard that nothing derives `certificationType` from `certification_class`
  or `baseline`, in the shape of
  `tests/test_certification_class_is_independent.py`.
- RLS coverage per §5, with the count bumped.
- Migration chains from `0078_cr26_certification`, carries the `pg_roles` GRANT
  guard used since `0054`, and leaves **exactly one head** — verified with the
  FULL `alembic heads` output, never piped through `tail`, which hid a second
  head once and errored 1,992 tests.
- Every new test must be able to fail. This programme has shipped at least
  seven that could not, and the schema-spine branch spent three fix rounds on
  exactly that.
- The suite is hermetic as of `5aa64c3`: a conftest guard fails any test that
  opens a connection to :80/:443. Nothing here should need the network.

## 8. Deadlines

CPO adoption opened **2026-07-04**. Maintenance becomes mandatory
**2027-01-01** for 20x and **2027-08-01** for Rev5, with CPO updates required
bi-weekly. VDR and VER become mandatory **2026-12-07** — sooner than either,
which is why §2 builds a table that already fits them.
