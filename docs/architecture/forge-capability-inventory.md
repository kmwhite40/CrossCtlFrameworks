# Forge Capability Inventory — Architecture Discovery (Phase 1)

**Date:** 2026-09-14
**Repository:** `CrossCtlFrameworks` — the `ccf` package, product name **Concord**
**Purpose:** Phase 1 gate. Classify every requested capability as
**EXISTS / EXTEND / WIRE / NEW** against what the repository actually contains,
so nothing already built gets rebuilt.
**Audience:** platform owner + the engineers implementing the programme

## 0. Method and one structural correction

Every classification below was read out of source, not inferred. Where a prior
document of mine disagrees, this file wins and the correction is stated inline.

**Naming.** The target architecture names Forge / Concord / Fabric / Carbon /
Anchor / Forge AI as modules, with Concord as "regulatory intelligence and
mappings." **This repository is Concord**, and it already contains most of what
that diagram assigns to Carbon, Fabric, and Anchor. Splitting the tree along
those lines would itself be the duplication the brief prohibits, so the five
names are treated as **logical layers over the existing package**:

| Logical layer | Physical location today |
|---|---|
| Concord (regulatory intelligence) | `ccf/catalog`, `ccf/etl`, `ccf/oscal`, `ccf/packs` |
| Fabric (evidence) | `ccf/evidence`, `ccf/connectors`, `ccf/ingest`, `ccf/prep` |
| Carbon (assessment & assurance) | `ccf/assessment`, `ccf/governance`, `ccf/fedramp20x`, `ccf/scoring`, `ccf/analytics`, `ccf/assurance` |
| Anchor (identity & boundary) | `ccf/auth.py`, `ccf/identity`, `ccf/boundary` |
| Forge AI | `ccf/ai`, `ccf/ai_actions`, `ccf/ai_governance` |

No directories are created for these. The architecture is logical.

## 1. Platform inventory

~42k LOC of Python across 28 packages, 57 API route modules, 63 Jinja
templates, 66 Alembic migrations, 1527 passing tests.

### Services and engines

| Area | Location | Notes |
|---|---|---|
| Cross-framework catalog + mappings | `etl/frameworks.py`, `catalog/` | ~25 frameworks classified; `framework_mappings` crosswalks control→control |
| OSCAL catalog loader (sha256-pinned) | `catalog/oscal.py` | 800-53r5 + L/M/H baselines + CSF 2.0 |
| Catalog revisions (fetch/diff/adopt) | `catalog/revisions.py`, `catalog/diff.py`, `catalog/impact.py` | **Added 2026-09-14** (P0'), migration 0066 |
| Catalog currency poller | `etl/sources.py` | ETag + sha256 drift detection, `CatalogCheck` log |
| Catalog reconciliation (advisory) | `catalog/reconcile.py` | Identity, baseline, drift, dangling endpoints |
| OSCAL schema validation | `oscal/validation.py`, `oscal/schemas/` | Official NIST v1.1.2 schemas |
| Authorization package export | `packages/` | SSP+SAR+POA&M+component-definition, provenance, diff, replay |
| SSP authoring & generation | `ssp/` (2,170 LOC) | CMMC L2/800-171 docx, 800-53r5 docx, ODP parsing, completeness |
| Assessment engine | `assessment/engine/` | Objectives → retrieval → LLM verdict → dissent → human accept → SAR → POA&M |
| Evidence prep & retrieval | `prep/`, `evidence/` | Parsers, chunking, confidence scoring, reproducible digests |
| FedRAMP 20x | `fedramp20x/` (1,561 LOC) | KSI catalog, deterministic rule validation, readiness, dependencies, package |
| Continuous control monitoring | `governance/conmon.py`, `governance/control_tests.py` | `ControlTest`/`ControlTestResult`, scheduler-driven |
| Scan ingestion → POA&M | `ingest/scanners.py` | Nessus/Tenable, AWS Inspector, CSV/Qualys; idempotent reconciliation |
| Inheritance / shared responsibility | `governance/automation.py` | Profile-driven: applicable + inherited (platform **and** vendor) controls, SPRS, coverage, auto-POA&M |
| Risk register | `models.py:862`, `governance/risk.py` | System-scoped, likelihood/impact, `source_ref` traceable |
| TPRM | `governance/tprm.py`, `models_tprm.py` | Weighted CAIQ-lite questionnaire scoring, vendor register |
| AI governance | `ai_governance/` | Agent inventory, risk scoring, approval, monitoring, kill-switch |
| AI action layer | `ai_actions/` | Typed, citation-first, human-approved; full provenance |
| Assurance graph | `assurance/` | Authorization digital twin + impact analysis |
| Compliance packs runtime | `packs/` | Validated JSON manifests, per-tenant install, coverage, tests |
| Deterministic query layer | `queries/` | Typed, parameterized, reproducible; **no AI** |
| Analytics | `analytics/` | Org rollups, systems scorecard, POA&M aging, evidence freshness |
| Reporting | `reporting/` | xlsx + docx report builder |
| Self-assurance | `self_assurance/` | Concord continuously assessing itself |
| Reliability self-check | `reliability/` | DB, migrations, core services, 20x layer |
| External portal | `portal/` | Scoped, expiring, token-auth, audited access |

### Cross-cutting platform services

| Service | Location | State |
|---|---|---|
| Event bus + webhooks + notifications | `governance/bus.py` | Append-only `Event`, webhook fan-out, de-duplicated `Notification` |
| Outbound delivery | `governance/delivery.py` | Slack/Teams webhook, severity-gated, never raises |
| Alert digest | `governance/digest.py` | Portfolio sweep: ATO expiry, catalog drift, POA&M load, reviews due |
| Scheduler | `governance/scheduler.py` | In-app asyncio loop: drift poll, ConMon, digest, connector collection |
| Notification hub API | `api/routes/notifications.py` | Unified inbox across modules |
| Authentication | `auth.py` | Session cookie + bearer token; `session_version` revocation |
| Enterprise identity | `identity/`, `api/routes/identity.py` | **OIDC SSO + SCIM v2 provisioning** |
| RBAC / SoD | `auth.py`, `api/auth_deps.py` | `require_role(...)`, separation-of-duties on writes |
| Row-level security | migrations 0010/0020/0044/0064 | RLS on every tenant-owned table; `GLOBAL_TABLES` allowlist test |
| Audit hash-chain | `api/audit.py`, `models.py:1160` | `prev_hash`/`row_hash`; `record_event` is the only safe writer |
| Approvals | `governance/approvals.py` | Approval workflow |
| Tasks | `Task` model, `api/routes/tasks.py` | Internal remediation tasks |
| UI | 63 Jinja templates + `api/static` | Top-nav shell; shared partials `_charts`, `_controls_table`, `_scoring_score`, `_ssp_entry` |
| Workers | `docker-compose.yml` | `migrator`, `etl`, `poller`, `prep-worker`, `assessment-worker` |

### Integrations — actual state

| Provider | State | Evidence |
|---|---|---|
| Microsoft Graph / M365 / Entra | **Partial adapter** | `connectors/msgraph.py` — 6 ODP params, MFA + Conditional Access reads |
| AWS GovCloud | **Partial adapter** | `connectors/aws.py` — 6 ODP params, 2 real reads (EBS default encryption, CW log retention) |
| Azure / Azure Gov | **Vocabulary only** | `ConnectorConfig.connector_type` enumerates it; no adapter |
| GCP | **Vocabulary only** | Same |
| GitHub / Jira / ServiceNow | **Vocabulary only** | Same; no adapter |
| Slack / Teams | **EXISTS (outbound)** | `governance/delivery.py` webhook |
| Qualys / Nessus / Tenable / Inspector | **EXISTS (file ingest)** | `ingest/scanners.py` parsers |
| Okta | **Name only** | A string in `governance/automation.py`; no integration |
| Defender / Sentinel / Intune / Purview | **Name only** | Mentioned in connector `PARAMETER_MAP` prose; no reads |
| GitLab / CrowdStrike / Kubernetes | **Absent** | No occurrences |
| MCP | **Absent** | Zero occurrences anywhere |

**The key integration finding:** `ConnectorConfig.connector_type`
(`models_grc.py:203`) already enumerates
`azure|azure_gov|m365|m365_gcc_high|aws|aws_govcloud|gcp|github|jira|servicenow`.
The configuration surface, credential storage (`connectors/credentials.py`,
per-org, no global fallback), status tracking, and UI all anticipate these
providers. **Only the adapters are missing.** This is EXTEND, not NEW.

## 2. Capability classification

### 2.1 Common control graph — **EXTEND**

**Exists:** `framework_mappings` (control→control crosswalk, ~25 frameworks),
`Control`/`Framework`/`ControlFamily`, `catalog/canonical.py` +
`catalog/reconcile.py` for id normalization, `assurance/` graph with impact
analysis, `boundary/` components, `KSI.nist_refs`.

**Gap:** the crosswalk runs control→control. There is **no
capability→control edge**, and no component→control edge at all — so one
technical control cannot yet be declared once and reused across frameworks.
`Risk` (`models.py:862`) exists but is terminal: no edge downward.

**Action:** implement the Capability object and its edges — this is programme
item **P1**, whose design is already approved in outline. Store the **canonical
control id as a string** (as `SSPControlEntry.control_id` does), not an FK,
because the workbook-derived `controls` table and the OSCAL catalog genuinely
differ — that is why `reconcile.py` exists. Cross-framework reach resolves
through `canonicalize()` → `controls.identifier` → `framework_mappings` at
query time. **Concord's crosswalk stays the authoritative mapping source; no
second mapping table.**

**Verified traversal:** canonical `AC-2` → CMMC `AC.L2-3.1.2`, FedRAMP `AC-2`,
ISO `A.5.16`. Note `controls.identifier` is zero-padded (`AC-01`); the
canonical form is `AC-1`, so canonicalization is mandatory on this path.

New APIs requested map onto: `/api/controls/{id}/relationships`,
`/api/frameworks/{id}/coverage` (extends existing `api/routes/coverage.py`),
`/api/evidence/{id}/supported-controls`, `/api/controls/{id}/evidence`,
`/api/controls/{id}/findings`.

### 2.2 Evidence fabric — **EXTEND**

**Exists:** `Evidence` model, `evidence/` confidence scoring with reproducible
digests, `models_evidence.py` + `models_evidence_conf.py`, `prep/` parsers and
chunking, an evidence repository with pluggable backend (local / S3 with
optional Object Lock WORM), and **evidence freshness already computed**
(`analytics.evidence_freshness`, served at `/api/posture/evidence-freshness`).

**Gaps against the requested evidence object:** `Evidence.implementation_id`
parents evidence to a *(system, control)* `ControlImplementation`, so evidence
cannot attach to a capability or be shared across controls without duplication.
Absent fields: provider, connector, tenant/account, resource + resource type,
collection method, source timestamp (distinct from collected-at), refresh
interval, explicit freshness **state**. Freshness is computed ad hoc rather
than stored as `LIVE | CURRENT | AGING | STALE | EXPIRED` with per-type
thresholds.

**Action:** add the provenance/resource columns; add nullable `capability_id`
(the approved coexist posture — every existing `implementation_id` row keeps
working); promote freshness to a stored, configurable state. Append-only is
**partly** true already: the evidence repository is versioned and
content-addressed, but `CaptureSnapshot` (connector captures) has
`UniqueConstraint(organization_id, connector, odp_key)` and keeps **only the
latest value** — that one must become append-only or drift is unprovable.

### 2.3 Connector abstraction — **EXTEND**

**Exists:** `connectors/base.py` defines `ConfigConnector` — a
provider-neutral ABC with a registry (`get_connector`, `list_connectors`),
per-org credential resolution that explicitly refuses a global/env fallback,
and a `PARAMETER_MAP` so the UI can show what a connector *would* pull before
credentials exist. Compliance logic is **already decoupled** from provider
SDKs: boto3 is imported behind an availability check, Graph via `httpx`.

**Gap:** the contract's output is `CapturedParameter(odp_key, value, …)` — an
*ODP value*, not normalized evidence and not a posture verdict. Two adapters
exist (12 parameters total).

**Action:** do **not** create a new connector interface. Extend the existing
one with a second method returning normalized evidence/posture objects
alongside the existing `capture()`, then add adapters for the providers the
config vocabulary already names. Keep `credentials.py` as the only credential
path.

### 2.4 Autonomous control testing — **EXTEND**

**Exists:** `ControlTest`/`ControlTestResult` with `method='connector'`,
scheduler-driven auto-run, alert + remediation task on failure
(`governance/control_tests.py`); `fedramp20x/validation.py` — a **deterministic**
rule engine with a pure, unit-testable core and the verdict vocabulary
`pass | warn | fail | not_tested | manual_review_required | not_applicable`;
and the LLM assessment engine for objectives no check can reach, with a dissent
challenger that degrades rather than averages.

**So the deterministic/AI split the brief asks for already exists**, in the
right proportion, with the right vocabulary.

**Gap:** deterministic tests read `CaptureSnapshot` (last value, one scalar per
ODP key), so there is no resource-level evaluation ("47 evaluated, 3 failing"),
no expected-vs-observed, no time series. Rules are a thin JSON dialect rather
than portable validation-as-code.

**Action:** extend `ControlTestResult` for resource-level, append-only results;
express rules as versioned validation-as-code shipped through `packs/`; adopt
the explicit principle that **a deterministic result outranks a model verdict
whenever a check exists**.

### 2.5 Regulatory change intelligence — **EXTEND**

**Exists, and more than expected:** `etl/sources.py` polls registered
authorities with ETag + sha256, parses OSCAL, diffs per-control prose, logs
every poll to `CatalogCheck`, raises digest alerts on drift, and deliberately
does **not** auto-ingest. As of 2026-09-14 the P0' work adds retained
commit-pinned revisions, a full diff (controls, prose, parameters, baseline
membership), an impact report against this deployment's own systems and
authored content, and human-gated adoption.

**Gap:** sources cover NIST only. FedRAMP (`GSA/fedramp-automation`), CMMC,
800-171 r2, and the DISA CCI list are not registered. There is no
requirement-text-level change feed for non-OSCAL sources (CR26 rules, RFCs).

**Action:** register the remaining authorities through the existing
`DEFAULT_SOURCES` + `CatalogSource` registry using the `fmt`/`kind` dispatch
already present. No new subsystem.

### 2.6 Findings & remediation workflow — **EXTEND**

**Exists:** SAR findings from the assessment engine, `POAM` + `PoamMilestone`,
`Task`, `Risk` promotion from findings with `source_ref` idempotency,
`governance/approvals.py`, alerting via the bus, and
`governance/conmon.py`/`control_tests.py` auto-opening alerts and tasks on
failure.

**Known open defect (pre-existing, documented):** auto-opened Tasks and POA&Ms
**never close** when a control test later passes, and no test covers the
fail→pass transition. Resource-level posture testing multiplies auto-opened
volume, so this must be fixed as **resolve-or-propose (never auto-close)** in
the same work, consistent with the deliberate ISSM-08/09 gate that stops the
engine retiring its own finding.

**Action:** EXTEND — close the loop, add retest/closure, and relate findings to
capabilities and evidence.

### 2.7 POA&M automation — **EXTEND**

**Exists:** `ingest/scanners.py` reconciles scan findings into POA&Ms
deterministically and idempotently (re-ingest is a no-op, improvement
auto-closes, regression reopens); `automation.py` generates POA&M placeholders
for profile-derived gaps; aging analytics.

**Gap:** SLAs come from a flat `SEVERITY_SLA_DAYS` map keyed on normalized
severity. No exploitability / internet-reachability / data-impact factors, no
EPSS, no CISA KEV, no asset-owner attribution. No VDR/VER (LEV/IRV/PAIN)
anywhere. Under CR26 the FedRAMP lane replaces POA&Ms with **Accepted
Weaknesses** — a second deliverable profile, not a migration (Rev5 runs to at
least 2028-12-31, and CMMC/DoD are unaffected).

### 2.8 MCP gateway — **NEW**

**Zero MCP presence.** But the foundation is unusually good: `queries/` is a
registry of typed, parameterized, tenant-scoped, reproducible queries with no
AI — precisely the shape a tool surface wants — and RLS + RBAC/SoD + the audit
hash-chain supply the safety envelope.

**Action:** NEW server, but **generated from `queries/registry.py`** plus
selected read endpoints rather than hand-written tools. Writes route through
the existing `ai_actions` / approvals gate; every tool call audited. Do not
build a parallel read API.

### 2.9 AI GRC agents — **EXISTS / WIRE**

**Exists:** `ai/` gateway with providers, `ai_actions/` (typed, citation-first,
human-approved, full provenance: model, prompt version, input/output SHA-256,
cited units), `ai_governance/` (non-human actor inventory, risk scoring,
approval, monitoring, incidents, kill-switch), `governance/ai.py`,
`api/routes/ai_agents.py` + `ai_settings.py`, and the assessment engine's
dissent path. AI-drafted SSP narrative always carries `DRAFT_PREFIX` until a
human clears it.

**Action:** mostly **WIRE** — expose these agents through the MCP gateway
(2.8) and give them the capability graph (2.1) to reason over. The governance
and provenance rails already exist and must be reused, not re-invented.

### 2.10 Shared responsibility & inheritance — **EXTEND**

**Exists, and this was missed in earlier analysis:** `governance/automation.py`
derives, from a `SystemProfile`, which controls are *applicable*, which are
*inherited from the cloud platform*, and which are *inherited from each linked
vendor* — plus SPRS score, coverage rollup, and POA&M placeholders for gaps.
Pure function of profile + vendor register, idempotent, snapshot is the single
source SSP and coverage read. `FedRAMPDependency` tracks authorized
dependencies for 20x.

**Gap:** inheritance is not expressed in **SSP narrative** — no
customer/provider responsibility split in statements and no CRM (Customer
Responsibility Matrix) generation. `FedRAMPDependency` is not wired into SSP
statements.

**Action:** EXTEND into the document layer (programme item P4). The derivation
engine itself is done.

### 2.11 Third-party risk management — **EXISTS**

`governance/tprm.py` (weighted CAIQ-lite scoring, pure function, gap flagging),
`models_tprm.py`, vendor register, `api/routes/vendors.py` +
`questionnaires.py`, vendor review alerts in the digest, and vendor-inherited
controls in `automation.py`.

**Action:** **EXISTS.** Only wiring: relate vendors to capabilities and
inherited responsibilities once 2.1 lands. Build nothing new.

### 2.12 AI governance — **EXISTS**

See 2.9. `ai_governance/` covers inventory, risk scoring, approval workflow,
monitoring events, incidents, and kill-switch, each audited. **Build nothing
new.**

### 2.13 Trust Center — **EXTEND**

**Exists:** `portal/` — scoped, expiring, token-authenticated, fully-audited
external access for customers, assessors, and vendors with no internal
account.

**Gap:** no *public* trust page publishing current control state, KSI results,
and evidence freshness without a token.

**Action:** EXTEND `portal/` with a public, read-only, cached projection.
Reuse the portal token model and audit path; do not build a second external
access mechanism.

### 2.14 Analytics / API access layer — **EXISTS / EXTEND**

`analytics/` (org summary, systems scorecard, POA&M aging, evidence freshness),
`api/routes/posture.py` (**note: this is *compliance* posture — internal
rollups. The name is taken; security posture needs its own namespace**),
`queries/` deterministic exportable queries with CSV export, `reporting/` xlsx
+ docx, 57 route modules with OpenAPI at `/docs`, `api/routes/diff.py` and
`events.py`.

**Action:** EXTEND with capability-graph and posture endpoints. The access
layer itself exists.

### 2.15 Continuous assurance scoring — **EXTEND**

**Exists:** `scoring/` (CMMC SPRS engine — pure functions, live per-system),
`fedramp20x/readiness.py`, `ssp/completeness.py`, `analytics/` rollups,
`evidence/` confidence scoring, `assessment/engine/calibration.py`.

**Gap:** no single composite assurance score across validation coverage,
evidence freshness, vulnerability performance, configuration integrity,
identity assurance, change governance, and logging coverage — and, more
importantly, no **validation-source split** (automated / semi-automated /
manual). That split is what makes "drive manual validation toward zero"
measurable and is the number that separates this from a questionnaire tool.

**Action:** EXTEND by composing the existing scorers. Write no new scorer.

### 2.16 Evidence freshness — **EXTEND**

Computed today (`analytics.evidence_freshness`) but not a stored, configurable
state. See 2.2.

### 2.17 FedRAMP 20x / KSI validation — **EXISTS / EXTEND**

**Exists:** `fedramp20x/` — KSI catalog seeded from
`data/fedramp_20x_ksi_catalog.json` (idempotent upsert on `identifier`),
deterministic rule validation with append-only history and per-system KSI
state, readiness scoring, authorized-dependency tracking, assessor review, and
a machine-readable package foundation. KSIs stay traceable to 800-53 through
`nist_refs`.

**Source-hierarchy constraint (must be preserved):** there is **no official
FedRAMP 20x OSCAL package**. The OSCAL Foundation's Phase One KSI catalog is
community-maintained and **must not** become the system of record. FedRAMP
provides the requirements; NIST provides OSCAL (`usnistgov/OSCAL`, distinct
from `usnistgov/oscal-content`); Concord generates its own OSCAL. The existing
code already takes this posture and its docstring disclaims official OSCAL
output — preserve it.

**Gap:** CR26 (in force 2026-07-04, **enforced 2027-01-01**) renames
authorization→Certification, replaces Impact Levels with Certification Classes
A–D, replaces the SSP with CPO + SDR in JSON, and **eliminates POA&Ms in favour
of Accepted Weaknesses**. Registered as **FR-14** in the 2026-07-21
terminology review and deferred there as "non-breaking, pre-2027-01-01"; that
deferral should now be lifted. The Class↔impact mapping remains **unvalidated
at source** and no schema change may depend on it until it is.

### 2.18 VDR — **NEW (on existing rails)**

No VDR/VER, LEV/IRV/PAIN anywhere. Scan ingestion, POA&M reconciliation,
severity SLAs, and aging analytics all exist to build on. Needs EPSS/KEV/CVSS
enrichment, asset-owner attribution, risk-factor SLAs, and the VDR surface.

### 2.19 Significant change notification — **NEW**

Nothing detects environment change, classifies boundary impact, or produces an
SCN. Building blocks exist: `boundary/` (authorization boundary + inventory),
`assurance/` (impact analysis over the authorization graph), `governance/bus.py`
(events), `governance/scheduler.py`. Missing: change ingestion (config/event
streams, IaC apply, deployment pipelines), a classifier
(boundary-impacting? security-impacting? SCN required?), and an SCN object with
review/approve/generate workflow. Valuable beyond FedRAMP — the same engine
answers "what did this change break in my authorization" for CMMC and RMF.

## 3. Summary

| Capability | Status |
|---|---|
| Common control graph | **EXTEND** |
| Evidence fabric | **EXTEND** |
| Connector abstraction | **EXTEND** |
| Autonomous control testing | **EXTEND** |
| Regulatory change intelligence | **EXTEND** |
| Findings & remediation workflow | **EXTEND** |
| POA&M automation | **EXTEND** |
| MCP gateway | **NEW** (generated from `queries/`) |
| AI GRC agents | **EXISTS / WIRE** |
| Shared responsibility & inheritance | **EXTEND** (engine exists; document layer missing) |
| Third-party risk management | **EXISTS** |
| AI governance | **EXISTS** |
| Trust Center | **EXTEND** (`portal/`) |
| Analytics / API access layer | **EXISTS / EXTEND** |
| Continuous assurance scoring | **EXTEND** (compose existing scorers) |
| Evidence freshness | **EXTEND** (exists as computation, not state) |
| FedRAMP 20x / KSI validation | **EXISTS / EXTEND** (CR26 delta) |
| VDR | **NEW** (on existing rails) |
| Significant change notification | **NEW** |

**Nothing in the requested set is wholly absent except MCP, VDR, and SCN.**
Two of those three build directly on existing rails. Everything else extends
or wires what is already here — which is why Phase 1 mattered: earlier analysis
of mine wrongly called the catalog fetcher, OIDC SSO, and SCIM missing, and all
three exist.

## 4. Corrections to prior documents

`docs/superpowers/assessments/2026-09-14-grc-capability-gap-analysis.md`
contains three errors this inventory supersedes:

1. **"No fetcher; refresh is manual."** False — `etl/sources.py` polls with
   ETag + sha256 and diffs OSCAL prose. Corrected in that document's G3.
2. **"No SSO/SCIM."** False — `identity/` and `api/routes/identity.py`
   implement OIDC SSO and SCIM v2.
3. **"A KSI is a Capability."** Imprecise. FedRAMP designed KSIs as
   capability-*shaped requirements*; they sit on the **requirement** side with
   controls. A Capability *satisfies* KSIs. The payoff is that KSIs map to
   capabilities roughly 1:1 where controls fragment one capability across many.

## 5. Phase 1 gate

Discovery is complete for the capabilities listed in the brief. Implementation
of any capability classified NEW or EXTEND should proceed only through its own
design and plan, in the sequence already agreed: **P0' (done) → P1 capability
graph → P2 validation/posture → P4 document layer**, with connectors and
STIG/SCAP parallel, then Trust Center + scoring, MCP, and the CR26/SCN work.

Phases 6 and beyond of the brief were truncated in transmission and are not
covered here.
