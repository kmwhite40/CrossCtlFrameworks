# Concord GRC Capability Gap Analysis & Build Program

**Date:** 2026-09-14
**Status:** Analysis complete — build program awaiting approval
**Audience:** Concord platform owner + engineers who will implement the program

## 1. Scope & method

Requested: a full review of Concord against comparable GRC platforms, then
build every gap — specifically live environment posture scanning, OSCAL
catalogs (FedRAMP/NIST/CMMC) sourced live and diffable against an adopted
baseline, CCIs, an SSP generator uplift, a local-LLM API, and Paramify's
architecture (the Stack -> Risk -> Solution -> Capability ontology plus the four
product pillars: Automate SSPs, Manage POA&Ms, Trust Center, Gap Assessment).

Method: read the source tree directly (~42k LOC, 28 modules, 57 API route
modules), the data model, the OSCAL layer, the connector contract, the
assessment engine, and the scan-ingest path; compared against Paramify's
published architecture and the federal/commercial GRC field (Xacta, eMASS,
RegScale, Vanta, Drata, Hyperproof). Every gap cites the file establishing
current state.

Licensing constraint honored: ATO Bot (BUSL 1.1) informed problem decomposition
only. No ATO Bot source is copied, quoted, or transcribed.

Note on naming: the supplied comparison table used "Carbon" for the target
platform. This analysis maps the ontology onto **Concord (`ccf`)** — this
repository — against modules verified in source.

## 2. The central architectural decision

Everything else in this document is downstream of one choice.

Concord today is control-first. `SSPControlEntry` is keyed
`(project_id, control_id)` with narrative authored per control
(`models.py:1033-1058`), and `ssp/nist80053.py` seeds one draft entry per
baseline control. Evidence attaches to controls. `ControlTest` is keyed to a
control plus an ODP key. Compliance state is computed by reading control rows.

```
Control -> question -> answer -> evidence attachment
```

The consequence is duplication proportional to framework breadth. One MFA
decision must be written into IA-2, IA-2(1), IA-2(2), AC-7, MA-4 and every
other dependent control — then rewritten per project and per framework. At
800-53 High (400+ controls) across FedRAMP, CMMC, and 800-171 simultaneously,
that is the dominant cost of the product.

The ontology inverts it:

```
Stack -> Risk -> Solution -> Capability -> { Controls, Evidence, Validation }
                                                     |
                                              Compliance State
                                                     |
                                    { SSP, POA&M/Issues, Reports/Trust Center }
```

A **Capability** is authored once ("Entra ID Conditional Access enforces MFA"),
mapped to many controls across many frameworks, validated by a deterministic
check, and cited by every document that depends on it. Control status becomes
*derived* from capability coverage rather than authored per control. Editing the
capability propagates everywhere.

This is not an SSP feature. It re-parents SSP narrative, evidence, validation,
gap assessment, and trust reporting simultaneously — which is why it must land
before the posture spine and the SSP uplift, not after. A posture check keyed
only to a control id would have to be re-keyed to capabilities later.

### Ontology mapped onto Concord's actual objects

| Ontology layer | Concord today | Verdict |
|---|---|---|
| **Stack** (people / process / tech / inventory / data flows) | `SystemComponent` (`boundary/`, diagram-oriented inventory); `governance/personnel.py`; policies in `governance/` | **Partial** — inventory exists; no stack abstraction uniting people + process + tech + data flows |
| **Risk** | `Risk` (`models.py:862`) — system-scoped, likelihood/impact, `source_ref` traceable to originating finding | **Exists**, but terminal — no edge to Solution or Capability |
| **Solution** | — | **Absent** |
| **Capability** | — | **Absent** |
| Capability -> Controls (multi-framework) | `framework_mappings` — crosswalks control **to control** | **Wrong axis** — no capability-to-control edge |
| Capability -> Evidence | `Evidence` attaches to controls | **Wrong parent** |
| Capability -> Validation | `ControlTest`/`ControlTestResult` keyed to control + ODP key; KSI rules (`fedramp20x/validation.py`) | **Wrong parent**, right mechanism |
| Compliance State | `scoring/`, `analytics/`, `ssp/completeness.py`, `fedramp20x/readiness.py` | **Exists**, computed from control rows |
| SSP | `ssp/` per-control entries | **Needs re-parenting** |
| POA&M / Issues | `POAM`, milestones, scan reconciliation (`ingest/scanners.py`) | **Strong** |
| Reports / Trust Center | `portal/` (scoped, expiring, audited) | **Partial** — no live public trust page |

**The gap is the middle two rows.** Solution and Capability do not exist, so
`Risk` has nowhere to connect downward and controls have nothing to derive
from. Adding those two objects plus their control-mapping edge is the
highest-leverage change in this document.

### Where Concord is already ahead

Paramify's stated position is that an LLM must not generate compliance
evidence — evidence paths stay deterministic and AI may only summarize
validated results. Concord already implements this more rigorously than the
comparison implies:

- `queries/` — deterministic, parameterized, reproducible assurance queries, no AI.
- `fedramp20x/validation.py` — deterministic KSI rule evaluation, pure core.
- `ingest/scanners.py` — deterministic, idempotent POA&M reconciliation.
- `ai_actions/provenance.py` — model, prompt version, input/output SHA-256, citations.
- AI-drafted SSP narrative always carries `DRAFT_PREFIX` until a human clears it.
- The assessment engine's dissent challenger: a credible disagreement degrades
  the verdict to `insufficient_evidence` rather than averaging or voting.

One divergence to govern deliberately: the assessment engine *does* use a model
to reach verdicts over retrieved evidence (`assessment/engine/evaluate.py`),
mitigated by bounded prompts, candidate-validated citations, human acceptance,
and full provenance. That is defensible — but once deterministic posture checks
exist, the design principle must be explicit:

> **When a deterministic check exists for an objective, its result takes
> precedence over a model verdict. The model covers what no check can reach.**

## 3. Regulatory driver: Consolidated Rules for 2026

Verified against fedramp.gov (not the secondary summary that raised it — that
summary's dates were directionally right but incomplete, and its citations
carried `utm_source=chatgpt.com`, so every claim below was checked at source).

**Timeline.** CR26 took effect **2026-07-04**. FedRAMP 20x became widely
available **2026-06-25** as a Certification path. Class B and C pipelines opened
**2026-08-31**. **Full enforcement begins 2027-01-01** — roughly 3.5 months from
today. New Rev5 certification applications stop **2027-06-11**; existing Rev5
certifications expire no earlier than **2028-12-31**.

**What CR26 changes for a platform like Concord.**

| Old | New under CR26 | Concord exposure |
|---|---|---|
| FedRAMP authorization | FedRAMP **Certification** | Vocabulary throughout |
| Impact Levels Low/Mod/High | **Certification Classes A/B/C/D** | `System.fedramp_baseline` enum (`models.py:355`); `_BASELINE_FILES` keyed low/moderate/high (`catalog/oscal.py`); ~83 impact-level references in source |
| SSP + appendices | **Certification Package Overview + Security Decision Record** (CPO + SDR) | `ssp/` renders `.docx`; CR26 wants JSON |
| **POA&Ms** | **Eliminated — replaced by "Accepted Weaknesses" lists** | Entire POA&M subsystem: models, milestones, reconciliation, aging analytics, OSCAL POA&M export |
| Continuous Monitoring | **Ongoing Certification** | `fedramp20x/monitoring.py` |
| Word/Excel templates | **Simplified JSON documents**; OSCAL optional in some cases | Both docx generators; OSCAL-centric package assumption |
| Monthly scanning | Meaningful detection/response of **all** potential weaknesses | `ingest/scanners.py` scope |

Two corrections this forces on the rest of this document:

1. **OSCAL is no longer the assumed primary format for the FedRAMP path.** CR26
   moves to simplified JSON with OSCAL optional. OSCAL remains right for Rev5,
   CMMC, DoD, and interoperability — but P4 must not be designed as
   OSCAL-only.
2. **POA&M elimination applies to the 20x/Certification path only.** Rev5 runs
   to at least 2028-12-31, and CMMC/DoD/FISMA are unaffected. The POA&M
   subsystem is not dead — it becomes the Rev5/CMMC lane. This is a both/and,
   not a migration.

**Prior work to credit.** `docs/superpowers/assessments/2026-07-21-fedramp-2026-terminology-review.md`
already identified the Certification-Class shift (flagging the A/B/C/D ↔ impact
mapping as needing primary-source validation) and the Accepted-Weaknesses
framing, registered as **FR-14** and deferred as "non-breaking, pre-2027-01-01."
That deferral was sound in July. With enforcement 3.5 months out and an
Accepted-Weaknesses deliverable now in scope, FR-14 should be un-deferred and
absorbed into this program rather than tracked separately.

## 4. The continuous-assurance reframe — and why it converges on the ontology

A proposal was raised to build continuous assurance (KSI validation, persistent
validation, VDR, SCN, Trust Center, machine-readable packages) as a distinct
module. Two things about it need saying plainly, one corrective and one
affirming.

**Corrective: the premise understates this codebase.** That proposal positions
Concord as the "regulatory intelligence layer / control knowledge graph" with
evidence and validation belonging to a separate engine. This repository is not
a mappings library. It already contains deterministic KSI validation
(`fedramp20x/validation.py`), 20x readiness scoring (`fedramp20x/readiness.py`),
a machine-readable 20x package foundation (`fedramp20x/package.py`), 20x
monitoring (`fedramp20x/monitoring.py`), an assurance graph (`assurance/`),
evidence confidence scoring with reproducible digests (`evidence/`), evidence
freshness analytics (`analytics/`, surfaced at `/api/posture/evidence-freshness`),
a validation-pack runtime (`packs/`), scan ingestion with idempotent
reconciliation (`ingest/scanners.py`), package provenance with diff and replay
(`packages/`), and an external portal (`portal/`). Roughly two-thirds of the
proposed module already exists here. Building it alongside rather than into
these modules would duplicate them — the exact outcome the governing constraint
in section 5 forbids.

**Affirming, and the key synthesis: FedRAMP designed KSIs as capability-oriented
requirements** — automatically validated toward measurable outcomes rather than
satisfied by control narrative. That is independent, authoritative confirmation
of this document's root finding.

> **A KSI is a Capability.**

So continuous assurance is not a parallel stack. It is **the first and most
valuable consumer of the P1 capability ontology** — and CR26's 2027-01-01
enforcement date is the business reason to build P1 now rather than later. The
capability object serves the 20x/Certification lane and the Rev5/CMMC lane from
one definition.

The resulting shape is shared services with **two deliverable profiles**, not
two applications:

```
                     shared platform services
   catalog/CCI · capability ontology · connectors · evidence fabric
   validation engine · risk · identity · audit · scheduler · MCP
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
      Rev5 / CMMC / DoD profile        CR26 / 20x profile
      impact levels L/M/H              Certification Classes A-D
      SSP (.docx) + OSCAL              CPO + SDR (JSON)
      POA&M + milestones               Accepted Weaknesses
      SAR                              KSI validation + VDR + SCN
      OSCAL package                    machine-readable package + Trust Center
```

Both profiles read the same capabilities, the same evidence, and the same
validation results. Only the deliverable vocabulary differs.

## 5. Governing constraint: integrate, do not duplicate

Every sub-project below **extends existing Concord objects**. None creates a
parallel subsystem beside one that already works. This is the same instruction
that governed the ATO Bot integration, where it caused three planned slices to
be cancelled rather than built — and the cancellations surfaced more real
defects than the slices would have added features.

Two duplication risks are specific and worth naming now, because both are easy
to get wrong and expensive to undo:

**Capability -> framework mapping.** A capability must map to the **canonical
800-53 control item only**, then reach every other framework by traversing the
existing `framework_mappings` crosswalk. Mapping each capability directly to
FedRAMP *and* CMMC *and* 800-171 *and* SOC 2 would duplicate the crosswalk
Concord already maintains — and guarantee the two drift apart.

**Posture results.** Posture checks must produce results in the existing
`ControlTest`/`ControlTestResult` vocabulary and route failures through the
existing `reconcile_findings` POA&M path. A second findings table with a second
verdict vocabulary and a second POA&M writer is the most likely way this
program damages the platform.

### Reuse ledger

| Sub-project | Extends / reuses | Must not create |
|---|---|---|
| **P0** source spine | `catalog/oscal.py` loader, `MANIFEST.json` sha256 verification, `ingestion_runs` provenance, `governance/scheduler.py` for fetch cadence | A second catalog loader or a parallel provenance table |
| **P1** ontology | `Risk` (`models.py:862`), `SystemComponent` (`boundary/`), `framework_mappings` for cross-framework reach, `packs/` for shippable capability libraries | A new inventory table beside `SystemComponent`; direct capability->per-framework mappings |
| **P2** validation/posture | `ControlTest`/`ControlTestResult`, `fedramp20x/validation.py` verdict vocabulary (`pass`/`warn`/`fail`/`not_tested`/`manual_review_required`/`not_applicable`) and its pure `evaluate_rule` core, `reconcile_findings` for POA&M, `governance/bus.py` alerts, `governance/scheduler.py` | A second findings model, verdict vocabulary, POA&M writer, or scheduler |
| **P3** connectors | `ConfigConnector` contract + registry, `connectors/credentials.py` per-org credential resolution (never global/env), existing `capture()` path kept intact alongside new `scan()` | A parallel connector interface; a global credential fallback |
| **P4** SSP engine | `ssp/generator.py` table/shading helpers, `ssp/odp.py` parsing, `ssp/completeness.py`, `oscal/validation.py` schema validation, `packages/` diff machinery for narrative redline, `DRAFT_PREFIX` discipline | A third docx renderer; a separate differ; a new OSCAL validator |
| **P5** STIG/SCAP | `ingest/scanners.py` — `ScanFinding`, `detect_format`, `parse_scan`, `reconcile_findings`; add parsers only | A separate scan-ingest pipeline |
| **P6** gap + trust | `scoring/`, `ssp/completeness.py`, `fedramp20x/readiness.py`, `catalog/reconcile.py`, `analytics/`, `portal/` token model | A new scoring engine; a second external-access mechanism |
| **P7** MCP | `queries/registry.py` as the tool source of truth, `auth.py` principals + RLS, `ai_actions`/`approvals` for writes, audit hash-chain | Hand-written parallel tool endpoints; a bypass of the approval gate |
| **P8** interop | `governance/bus.py` event bus, `Task`, `POAM.source_ref` idempotency pattern, `identity/` | Per-integration bespoke plumbing outside the bus |

Cross-cutting, for every sub-project: new tenant-owned tables get **RLS**; all
mutations go through the **audit hash-chain**; any AI touchpoint records through
`ai_actions/provenance.py`; all periodic work runs on `governance/scheduler.py`.

## 6. Gap register

### G1 — The Solution/Capability layer is absent (root gap)

Covered in section 2. `Risk` exists but is terminal; no Solution, no Capability,
no capability-to-control mapping edge, and evidence plus validation hang off
controls instead of capabilities. Every gap below is either caused by this or
made cheaper by fixing it first.

### G2 — Live security posture scanning

**Current state.** `connectors/base.py` defines
`ConfigConnector.capture() -> list[CapturedParameter]`, where
`CapturedParameter` is `(odp_key, value, nist_id, source, confidence)`. This is
*ODP value capture* — filling a blank in an SSP sentence — not posture
assessment.

Measured coverage: **12 parameters across 2 providers.** `msgraph` advertises 6
(`connectors/msgraph.py:38-45`), `aws_govcloud` 6 (`connectors/aws.py:37-44`),
of which only two are real reads (EC2 default EBS encryption, CloudWatch Logs
retention). That is the entire live surface today.

**Gaps.**

1. **Wrong output shape.** A posture check yields per-resource verdicts
   ("47 storage accounts evaluated, 3 allow public access") with expected vs
   observed and resource identity. `CapturedParameter` holds one scalar string.
   No resource-level finding object exists anywhere.
2. **No time series.** `CaptureSnapshot` carries
   `UniqueConstraint(organization_id, connector, odp_key)` (`models.py:1468`)
   and keeps only the latest value. Its docstring calls it "the config-drift
   baseline," but one row per key cannot express drift. Trend and "this control
   held across the authorization period" are unprovable.
3. **No system/boundary scoping.** Captures are org-scoped, so findings cannot
   be placed inside an authorization boundary or reconciled against `boundary/`
   inventory.
4. **Missing providers.** Azure: none. GCP: none. M365: partial Graph. AWS: two reads.
5. **No gov-cloud endpoint handling.** Azure Government, M365 GCC High / DoD
   Graph endpoints, GCP Assured Workloads, and the AWS GovCloud partition each
   need distinct endpoints, auth, and service-availability caveats.
6. **Name collision.** `api/routes/posture.py` is *compliance* posture
   (rollups over POA&Ms/evidence). Security posture needs its own namespace.

### G3 — OSCAL sources are unversioned and unadoptable (corrected)

**Corrected 2026-09-14.** This gap was first written as "no fetcher; refresh is
manual." That was wrong, and the correction narrows the gap substantially.

**What actually exists.** `ccf.etl.sources` is a working catalog-currency
subsystem: `CatalogSource` (`models.py:1098`) is a DB-backed registry of
upstream authorities seeded by `ccf sources-seed`; `check_source()` fetches with
`If-None-Match` ETag conditional requests *and* compares body sha256 so an
ETag-ignoring server produces no false drift; `parse_oscal_catalog()` indexes
each control by a title+prose hash and `_diff_index()` yields a real
added/modified/removed changelog; `CatalogCheck` is an append-only poll log; and
scheduler, alert digest, API (`api/routes/catalog.py`), and CLI
(`ccf sources-seed`, `ccf sources-check`) are wired. `auto_ingest` defaults off
because "drift is recorded for a human to review and re-ingest through a gated
PR" — the human-gated principle is already established design.

**The real gap is a disconnect.** Two subsystems exist and do not talk:
`etl/sources.py` polls URLs and records that content drifted; `catalog/oscal.py`
loads sha256-pinned files from disk, and everything that matters — SSP seeding,
reconciliation, scoring, reliability — reads *that*. Detected drift therefore
goes nowhere. Specifically missing:

1. **No adoption path** from detected drift into the pinned catalog. This is the
   "update against my baseline" gap.
2. **No revision retention.** `CatalogSource` holds `last_sha256` and
   `content_index` for the latest poll only — no revisions to diff between
   arbitrary points or roll back to. The same last-value-only shape as
   `CaptureSnapshot` in G2.2; worth noting as a recurring pattern.
3. **No commit pinning.** Sources poll `.../oscal-content/main/...`, a moving
   branch ref, so a recorded drift cannot be reproduced.
4. **No impact analysis.** The existing diff is catalog-level, not "what
   adoption does to my systems' baselines and my authored SSP content."
5. **No offline import**, so air-gapped environments cannot adopt at all.
6. **Manifest is hand-maintained** rather than generated at adoption.

**Catalog coverage gaps** (unchanged by the correction): only the HIGH baseline
is a registered source, though `_BASELINE_FILES` needs all three; CSF 2.0 is
bundled on disk but unregistered; **FedRAMP Rev 5 OSCAL baselines** absent
(`FEDRAMP` is a classified framework name at `etl/frameworks.py:30` with no
catalog behind it); **800-171 r2/r3** named (`etl/frameworks.py:25-26`), no
catalog; **CMMC** named (`etl/frameworks.py:32`), no catalog, and since DoD
publishes no official OSCAL it must be *derived* and labeled derived;
**DISA CCI list** absent (G4). Note 800-53A r5 *is* already a registered source
but is not parsed into the loaded catalog.

**Integrity tension to preserve.** Adoption must not weaken the hash-pin
property. Pin the upstream commit SHA, generate the manifest, and require
explicit human adoption of a reviewed diff — never silently promote content a
catalog authorization decisions rest on.

### G4 — CCIs entirely absent

Zero occurrences of CCI in `src/ccf`. Needs the DISA CCI list ingested, CCI as
a first-class identifier, and a CCI -> 800-53 **control-item** mapping (AC-2 a.1
granularity — finer than the control-level canonical ids `catalog/canonical.py`
produces).

CCI is the DoD join key: STIG and SCAP results reference CCIs, CCIs map to
800-53. Without it there is no path from technical scan output to control
status, and no alignment with eMASS, which assesses at CCI granularity.

**Source material reviewed 2026-09-14, and one finding changes the design.**
Two sources were supplied: the DISA CCI list in flattened CSV form, and
`commoncriteria.github.io/pp/references/nistvscci.html`.

- **The CCI list tops out at 800-53 rev 4. There is no rev 5.** The CSV carries
  repeating `(revision, control)` pairs for revisions **4, 3, and 1**, and the
  second source is explicitly "NIST SP 800-53 **Revision 4** and the DISA FSO
  CCI List". Concord's catalog is **rev 5**, so CCI cannot be joined to the
  adopted catalog directly — it needs a rev4 → rev5 bridge, which NIST
  publishes separately. Mapping CCI straight onto rev 5 would silently
  mis-attribute controls, which is the failure mode this programme exists to
  avoid.
- **References are at control-*item* granularity** — `AC-1 b 1`,
  `AC-2 (7) (a)`, `AC-19 (4) (b) (4)`. A CCI maps to a sentence of a control,
  not a control, and that is finer than `catalog/canonical.py` parses today.
- **The mapping is sparse per revision.** Rows with empty rev-4 columns
  (`CCI-000062`) have no rev-4 home at all, so a parser must treat an empty
  pair as absent rather than as a blank control.
- **`type` is `policy` or `technical`**, and the distinction is load-bearing:
  *technical* CCIs are what a STIG or SCAP result can satisfy, *policy* CCIs
  are documentation obligations. That maps directly onto the
  deterministic-check-wins principle — a technical CCI is a candidate for a
  posture check, a policy CCI is not.
- The second source is **HTML only** and is a coordination page rather than an
  authority; DISA's `U_CCI_List.xml` remains the artifact to pin. Useful for
  cross-checking a parser, not as a system of record.
- The supplied CSV arrived **truncated** by message size, so it is a sample
  (roughly the AC family) of a ~2,000-entry list — fixture-grade material, not
  the full source.

### G5 — STIG/SCAP ingestion missing

`ingest/scanners.py` parses Nessus/Tenable XML, AWS Inspector JSON, and
generic/Qualys CSV into `ScanFinding`, reconciling into POA&Ms deterministically
and idempotently — good framework, wrong format family. No STIG checklist
(`.ckl`) parser and no XCCDF/SCAP ARF parser. These carry the CCI references,
so G5 is what makes G4 pay off.

### G6 — SSP narrative is derived per control, not authored once

**Corrected 2026-09-14.** The original framing ("a per-control editor")
understated what exists. `ssp/statements.compose` is a real composer: it
tailors a statement from responsibility, inheritance source, environment,
services, ODP values, live captures, responsible role, review frequency,
policy reference, and CRM reference, in three style variants, returning a
`needs_review` flag and marking drafts with `DRAFT_PREFIX`.

The actual gap is narrower and sharper: **`compose` derives narrative from a
control's derivation inputs, not from a capability's authored text.** So one
MFA decision is still *re-derived* for every dependent control rather than
*written once and reused* — edit-once-propagate does not exist. That is P4's
core, and it is additive to a composer that works rather than a replacement
for one.

Beyond the re-parenting in G1:

1. **OSCAL SSP is export-only.** No import/round-trip, so a CSP's OSCAL SSP or
   a prior authorization package cannot be ingested. (Paramify sells this as a
   service — "SSP ingestion and digitalization.")
2. **Inheritance in statements — CORRECTED 2026-09-14.** This previously said
   inheritance and shared responsibility were absent from SSP narrative. They
   are not. `ssp/statements.compose` handles `not_applicable`, `inherited`,
   `shared`, and `customer` responsibility; `_inherited_evidence_clause`
   names the provider and a CRM reference and **deliberately refuses to claim
   evidence is retained without one** (FR-11), returning `needs_review`
   instead. `governance/automation.py:545` feeds `crm_ref` from
   `vendor.authorization` and `policy_ref` from a real `Policy` matched by
   control id. Statements also carry the responsible role, review frequency,
   ODP values, and live connector captures.
   **What is genuinely missing is CRM *document* generation** — `crm_ref` is a
   reference string, not a produced Customer Responsibility Matrix.
3. **No evidence or posture citation in statements.**
4. **No narrative diff/redline between SSP revisions.** `packages/` has diff;
   SSP prose does not.
5. **No FedRAMP template conformance validation.** The docx is
   "FedRAMP-style," not validated against the required template and appendices.
6. **Static platform statements.** `ssp/platforms.py` holds canned per-platform
   prose rather than text derived from the tenant's real configuration.
7. **No policy/procedure generation.** Paramify generates policies and
   procedures from the same model; Concord has policy records but no generator.

### G7 — No local-LLM API surface

Full REST API (57 route modules) with OpenAPI, `ai/gateway` for *outbound*
model calls, and `ai_actions` (typed, citation-first, human-approved). Nothing
lets an external or local model call *into* Concord. Zero MCP presence.

The foundation already exists: `queries/` is a registry of typed, parameterized,
tenant-scoped, reproducible queries with no AI — exactly the shape a tool
surface wants. RLS, RBAC/SoD, and the audit hash-chain supply the safety
envelope. Needs: tool definitions generated from the query registry plus
selected read endpoints, principal/tenant binding for a local model, writes
routed through the existing approval gate, and every tool call audited.

Paramify already advertises MCP, so this is table stakes.

### G8 — POA&M automation lacks risk-factor SLAs and VDR/VER

`ingest/scanners.py:35` sets remediation SLAs from a flat
`SEVERITY_SLA_DAYS` map by normalized severity. Absent: FedRAMP 20x-style
calculation from exploitability, internet reachability, and data impact —
and no VDR/VER support (LEV/IRV/PAIN) anywhere in `fedramp20x/`.

**Corrected 2026-09-14:** this section previously called the closure loop an
open defect. It is implemented and tested -- `_resolve_on_recovery`
(`control_tests.py:270`) resolves the Task on fail->pass and deliberately
leaves the POA&M open with a dated observation note for the ISSM-08/09 gate,
covered by `tests/test_control_test_recovery.py`. See
`docs/architecture/forge-capability-inventory.md` §2.6, which supersedes this
document wherever they disagree.

### G9 — "True sources of value": provenance is partial

Authoritative-source traceability exists for the workbook (`ingestion_runs`
with source sha256), bundled OSCAL (`MANIFEST.json`), and packages
(provenance/replay). It is **absent** for FedRAMP/CMMC/CCI (which do not exist
yet), for posture checks (which do not exist yet), and for upstream revision
tracking generally (G3). Every control, baseline, CCI, KSI, capability, and
check should resolve to a verifiable upstream artifact plus revision.

### G10 — Product-surface and interop gaps

Against Paramify's four pillars:

| Pillar | Concord today | Gap |
|---|---|---|
| **Automate SSPs** | Per-control docx generators, completeness, ODP | Capability model (G1), OSCAL import, inheritance/CRM, policy generation (G6) |
| **Manage POA&Ms** | POA&Ms, milestones, scan reconciliation, alerts, auto-tasks | Jira/ServiceNow sync; risk-factor SLAs and VDR/VER (G8); closure defect |
| **Trust Center** | `portal/` — scoped, expiring, audited assessor/customer access | No live public trust page with current control + evidence + KSI state |
| **Gap Assessment** | `ssp/completeness.py`, `scoring/`, `fedramp20x/readiness.py`, `catalog/reconcile.py` | Components exist but no single "pick a framework, see gaps, get a living roadmap" surface; no CMMC SPRS score tracking |

Additional field gaps: **eMASS interop** (no import/export — table stakes for
DoD) and **ticketing integrations** (no Jira or ServiceNow adapter, though
`ConnectorConfig.connector_type` already enumerates both).

**Corrected 2026-09-14:** this row previously claimed SSO/SCIM and Slack
notifications were missing. Both exist — `identity/` and
`api/routes/identity.py` implement **OIDC SSO and SCIM v2**, and
`governance/delivery.py` posts severity-gated alerts to a Slack/Teams webhook.
See `docs/architecture/forge-capability-inventory.md`, which supersedes this
document wherever they disagree.

### G11 — Significant Change Notification engine absent

Nothing in Concord detects environment change, classifies its security-boundary
impact, or produces an SCN. This was missed in the first pass of this analysis
and is one of the higher-value gaps in the program.

The building blocks exist: `boundary/` holds the authorization boundary and
inventory, `assurance/` does impact analysis over the authorization graph, and
`governance/bus.py` is an event bus. What is missing is change *ingestion*
(config/event streams, IaC apply events, deployment pipelines), a change
classifier (boundary impact? security impact? SCN required?), and an SCN object
with review/approve/generate workflow.

This matters beyond FedRAMP: the same engine answers "what did this change
break in my authorization" for CMMC and RMF.

### G12 — No immutable snapshots, no point-in-time reconstruction

Concord keeps reproducible evidence digests (`evidence/`), package replay
(`packages/`), and `CalibrationSnapshot` — but no general snapshot model across
evidence, validation results, and configuration. Combined with the
`CaptureSnapshot` last-value-only constraint (G2.2), the platform cannot answer:

> What was the security state of this system at 14:03 UTC on 16 June?

That question is the difference between an evidence repository and a defensible
continuous-assurance record, and it is what an assessor reviewing an ongoing
certification will ask. Requires append-only evidence/validation/config
snapshots with collection timestamps, hashes, and expiry — never overwriting a
prior observation.

### G13 — KSI validation rules are not validation-as-code

`fedramp20x/validation.py` evaluates a JSON `rule` field per KSI through a pure
`evaluate_rule` core — a good deterministic engine with a thin, non-portable
rule language. Missing: declarative, versioned validation definitions carrying
provider, evidence sources, named tests, and evaluation frequency, shippable as
content rather than code.

`packs/` (the local-first framework/control/evidence/rule pack runtime) is the
natural home — validation packs per framework × provider ("CR26 AWS",
"CMMC M365", "CJIS Azure") rather than rules embedded per deployment.

### G14 — No composite assurance score or automation-share metric

`scoring/` and `analytics/` produce compliance percentages. Absent: a composite
assurance score across validation coverage, evidence freshness, vulnerability
performance, configuration integrity, identity assurance, change governance,
and logging coverage — and more importantly the **validation-source split**
(automated / semi-automated / manual). That split is the metric that makes
"drive manual validation toward zero" measurable, and it is the number that
distinguishes this platform from a questionnaire tool.

Evidence freshness exists (`analytics/evidence_freshness`) but as an isolated
endpoint rather than a first-class scoring dimension.

### G15 — CR26 Certification profile absent

Per section 3: Certification Classes A-D, the CPO + SDR JSON deliverables,
Accepted Weaknesses in place of POA&Ms, and Ongoing Certification vocabulary all
have no representation. `System.fedramp_baseline` is a low/moderate/high enum
(`models.py:355`) with ~83 impact-level references across source.

**RESOLVED 2026-09-16 at FedRAMP source — and the answer is that there is no
mapping to build.** fedramp.gov/2026/agencies/use/classes/ states plainly:

> "Agencies should not treat Certification Classes as one-for-one replacements
> for Low, Moderate, or High impact levels."

and, more bluntly:

> "FedRAMP Certification Classes are not aligned to how secure a cloud service
> offering is!"

A Class describes the **depth, frequency and quality of assurance data a
provider commits to supplying**, not the sensitivity of the information a system
holds. The published definitions are adequacy *ranges*, deliberately
overlapping, never equivalences:

| Class | FedRAMP's own wording |
|---|---|
| A | adequate for pilots, configuration and testing, or extremely low / negligible risk |
| B | adequate for most **Low**, and some **Moderate or High**, impact systems |
| C | adequate for most **Low or Moderate**, and some **High**, impact systems |
| D | adequate for most systems **regardless of impact level** |

**Design consequence:** Certification Class is an independent axis alongside
impact level, never derived from it. A `Class -> baseline` column, lookup or
enum would encode a relationship FedRAMP explicitly disclaims, and would be
wrong in both directions — a Class B offering may serve a High system, and a
High system may be served by Class B, C or D.

Note secondary sources actively contradict each other on this (one FedRAMP blog
summary renders it "Class B (Low), Class C (Moderate)" while another says Class
B *replaces* Moderate). That disagreement is itself the reason the primary
source is the only acceptable authority here, and why `System.fedramp_baseline`
must stay as it is.

Also folded in from the VDR work (G8): findings need CVE/CVSS/**EPSS**/**CISA
KEV** enrichment and asset-owner attribution, none of which exist today.

## 7. Build program

Ten sub-projects. Each gets its own spec, plan, and implementation cycle, and
each is independently shippable. "Fully, not partially" is satisfied per
sub-project — one spec covering all ten would guarantee the opposite.

**P0 — Authoritative source spine (live OSCAL + CCI).** Fetch/verify/version/
diff/adopt upstream sources with commit-SHA pinning and per-revision
provenance; catalogs for FedRAMP r5 baselines, 800-171 r2/r3, 800-53A, CMMC
(derived, labeled), and the DISA CCI list; CCI -> control-item mapping.
Closes G3, G4, G9.

**P1 — Capability ontology.** Stack, Solution, and Capability as first-class
objects; `Risk` connected downward; capability -> canonical-control mapping
reaching other frameworks via the existing crosswalk; evidence and validation
re-parented onto capabilities; control status derived from capability coverage.
**KSIs modeled as capabilities**, per section 4. Closes G1.

**P2 — Validation & posture spine.** Append-only, resource-level,
expected-vs-observed, system-scoped, time-series check results; `scan()`
alongside the existing `capture()`; immutable evidence/validation/config
snapshots with point-in-time reconstruction; validation-as-code definitions
shipped through `packs/`; the deterministic-check-wins principle; POA&M closure
defect fixed here. Closes G2.1-G2.3, G2.6, G12, G13.

**P3 — Provider connectors / evidence fetchers.** Azure (ARM/Policy/Defender),
GCP (Cloud Asset Inventory/SCC), AWS expansion (Config, CloudTrail, Security
Hub, GuardDuty, Inspector, IAM, Access Analyzer, KMS, SSM, ECR, VPC flow logs),
M365 expansion (Purview, Defender, Intune, Secure Score) — each with gov-cloud
endpoints and service-availability caveats. Normalize into one evidence schema
so validation logic never learns provider origin. Closes G2.4-G2.5.

**P4 — Document engine, dual-profile.** Capability-derived narrative with
edit-once-propagate-everywhere; Rev5/CMMC profile (.docx + OSCAL) and CR26
profile (CPO + SDR JSON) from one model; OSCAL SSP import/round-trip;
inheritance, shared responsibility, and CRM generation; evidence and posture
citation; narrative diff/redline; policy/procedure generation. Closes G6.

**P5 — STIG/SCAP ingestion via CCI.** CKL and XCCDF/ARF parsers into
`ingest/scanners.py`; findings -> CCI -> control; reuse POA&M reconciliation.
Closes G5.

**P6 — Gap Assessment, Assurance Score, Trust Center.** Framework requirements
versus implemented capabilities as one surface with a living roadmap; CMMC SPRS
tracking; composite assurance score with the automated/semi-automated/manual
validation-source split; live public trust page over `portal/`. Closes G10's
Gap Assessment and Trust Center rows, plus G14.

**P7 — Local-LLM tool API (MCP).** MCP server over the deterministic query
registry plus selected read endpoints; tenant/principal binding; writes via the
existing approval gate; per-call audit. Closes G7.

**P8 — VDR & interop.** EPSS/KEV/CVSS enrichment, asset-owner attribution,
risk-factor remediation SLAs (exploitability × internet reachability × data
impact) replacing flat `SEVERITY_SLA_DAYS`; eMASS import/export;
Jira/ServiceNow/Slack via `governance/bus.py`; OIDC/SAML SSO + SCIM. Closes G8
and G10's remaining rows.

**P9 — CR26 Certification profile & SCN.** Certification Classes A-D (after
the mapping is validated at source), Accepted Weaknesses, Ongoing Certification
vocabulary, absorbing the deferred FR-14 register item; plus the Significant
Change Notification engine — change ingestion, boundary-impact classification,
affected-capability/control resolution, SCN review/approve/generate. Closes
G11, G15. SCN is the larger half and depends on P3.

## 8. Recommended sequencing

The foundation-first decision stands, with one deadline-driven adjustment that
needs confirmation.

**CR26 enforcement on 2027-01-01 is ~3.5 months out**, and it changes the
relative urgency inside P0. P0's FedRAMP Rev5 OSCAL baselines and CCI work
serve the Rev5/CMMC/DoD lane, which runs to at least 2028 — valuable, not
urgent. P0's *fetch/version/diff/adopt machinery* is urgent, because CR26 rules
and KSI definitions will keep moving and the platform needs to track upstream
revisions deliberately.

So: **narrow P0's first pass** to the source machinery plus the catalogs the
ontology and CR26 actually need, and defer FedRAMP Rev5 baselines + CCI into a
second pass alongside P5.

```
P0' source machinery  ->  P1 ontology  ->  P2 validation spine  ->  P9a CR26 profile
                                                                ->  P3 connectors  ->  P9b SCN
                                                                ->  P4 documents   ->  P6 gap/score/trust
then: P0'' (FedRAMP r5 baselines + CCI) + P5, P7, P8
```

Rationale: P1 is now doubly justified — it is the root architectural gap *and*
KSIs are capability-oriented by design, so the CR26 lane needs it. P9a (CR26
vocabulary and deliverable profile) is cheap and deadline-bound, so it lands
early once capabilities and validation exist. P9b (SCN) waits for connectors
because it needs change telemetry.

If an early demo outweighs foundation order, the alternative remains a thin
vertical slice — one provider, one stack, ~10 capabilities, ~10 live checks, end
to end — trading known rework for a visible result in roughly a fifth of the time.

## 9. Open decisions

1. **Sequencing vs. demo.** Foundation-first (P0->P1->P2->P4) or the thin
   vertical slice?
2. **CMMC catalog provenance.** No official DoD OSCAL exists. Confirm it should
   be derived from 800-171 + the CMMC model and labeled derived.
3. **Upstream adoption policy.** Recommendation: a new upstream catalog revision
   always requires reviewed human adoption. Auto-adopt would let an upstream
   change silently move an authorization boundary.
4. **Ontology migration path.** Existing `SSPControlEntry` narrative must either
   migrate into capabilities or coexist. Recommendation: coexist behind a
   derived/authored flag, so no authored content is lost and capability coverage
   can grow incrementally.
5. **Local-LLM write scope.** Read-only tools first, or writes behind the
   existing approval gate from the start?
6. **Sequencing adjustment (needs confirmation).** Narrow P0's first pass to
   source machinery and defer FedRAMP Rev5 baselines + CCI, per section 8?
7. ~~**Certification Class mapping.**~~ **CLOSED 2026-09-16.** Validated at
   FedRAMP source: there is no A/B/C/D-to-impact-level mapping, and FedRAMP
   explicitly warns against treating one as a replacement for the other. Class
   becomes an independent axis; `System.fedramp_baseline` is unchanged. See G15.
   This unblocks P9a without the schema change it was waiting on.
8. **Two lanes, one platform.** Confirm the section 4 shape — shared services
   with two deliverable profiles — rather than a separately built continuous-
   assurance application.
