# FedRAMP Consolidated Rules as an authoritative source

**Status:** design, approved direction (retire + fresh start), implementing
**Extends:** `etl/sources.py`, `fedramp20x/catalog.py`, `cr26/sdr.py`, `cr26/scn.py`
**Adds:** `fedramp20x/rules.py`, `fedramp20x/rules_data/`, migration `0093`
**Replaces:** `fedramp20x/ksi_catalog.json` (51 phase-one KSIs, Concord's wording)

## 1. How this was found, and what was not taken

The request was to review <https://myctrl.tools> and integrate what Concord
can use without duplicating a mechanism it already has. The site is a CC BY
4.0 aggregator of 102 frameworks with a public read-only API
(`/api/v1/{frameworks,controls,crosswalks,guidance,search}`). Measured
2026-10-14 against `data_version 2026.10.15`:

| Offering | Taken? | Why |
|---|---|---|
| Crosswalks | **No** | 35,935 mappings into 800-53, 97% `related-via-bridge`: transitive inference through an intermediate catalog, not published by either framework. Spot checks fan out: CMMC 3.8.3 (media sanitization) → PM-5 (system inventory). `framework_mappings` carries no per-row provenance, so imported rows would be indistinguishable from the workbook's. |
| Control text | **No** | API descriptions are cut at ~200 characters and some are paraphrase (CSF PR.AA-01 is not NIST's wording). |
| Licence labels | **No** | 18 frameworks tagged `proprietary` (ISO, SOC 2, PCI, TISAX) and 3 `cc-by-nd`; the site's CC BY label cannot relicense them. The labels are also wrong in places — CIS Controls is CC BY-NC-SA, not CC BY-ND. |
| Technology guidance | **No** | Commands map to a whole technology (AWS → 15 controls), not to the control a command verifies, and derive from CIS Benchmarks, whose terms restrict commercial use. |
| `data_source` pointer for FedRAMP 20x KSI | **Yes, as a pointer** | `github.com/FedRAMP/rules`, public domain. Concord takes the dataset **from FedRAMP**, not from the aggregator: myctrl serves `2026.07.14.01`; upstream is `2026.10.13.01`. |

## 2. The defect this closes

Concord's KSI catalog is the 2025 phase-one set: 51 indicators
(`KSI-IAM-01` …), wording "summarized", 800-53/CMMC mappings "Concord's
REPRESENTATIVE interpretation". Its own header says to replace it "when
FedRAMP publishes final machine-readable KSI definitions". FedRAMP has.

The 2026 Consolidated Rules define **46** indicators with a different ID
scheme (`KSI-CED-RAT`), drop the TPR theme, add SCR, and carry FedRAMP's
own control mappings. **No phase-one ID exists in the 2026 dataset**, and
FedRAMP publishes no old→new correspondence.

Concord renders CR26 Security Decision Records — a 2026 deliverable — with
`keySecurityIndicators[].ksiId` drawn from the phase-one catalog. **Every
SDR Concord produces today cites indicators the current rules do not
define.** `cr26/sdr.py:merge_requirements` also says "there is no
machine-readable FedRAMP ruleset to check an `frrID` against". There now is:
245 FRR requirement IDs, every one Concord's code cites among them.

## 3. Decisions

1. **Upstream, pinned, verified.** `rules_data/fedramp-consolidated-rules.json`
   and its JSON Schema are vendored with a `MANIFEST.json` (sha256, upstream
   commit, retrieved date, dataset version). Load verifies the hashes and
   validates the dataset against the vendored schema, as FedRAMP's
   `AGENTS.md` instructs. Registered in `DEFAULT_SOURCES` as a watched
   `generic` source (`auto_ingest=False`), the same posture as the CR26
   schemas, so the existing poller reports upstream drift.
2. **Two authors, two files.** FedRAMP's statements, names, themes and
   control mappings come only from the dataset. Concord's machine-readable
   validation rules live in `rules_data/ksi_rules.json`, keyed by the 2026
   IDs. It starts **empty**: phase-one rules are not carried onto 2026
   indicators, so every 2026 KSI evaluates as `manual` until a rule is
   authored for it on its own statement. `cmmc_refs` is empty — FedRAMP
   publishes none.
3. **Retire, never delete.** Tenant tables reference `ccf.ksis` with
   `ON DELETE CASCADE`. `seed_ksis` sets `retired_at` on any row absent from
   the dataset (and clears it if one returns), the pattern the workbook ETL
   uses for controls. Tenant state on retired KSIs stays in the database for
   history and is excluded from every list, score, package and deliverable.
4. **One definition of "current".** `catalog.current_ksis()` and
   `catalog.current_ksi_ids()` are the only filters; every reader uses them.
   The guard is behavioural: a test seeds one retired and one current KSI
   with tenant state and asserts each consumer omits the retired one.
5. **Class variants are kept, not chosen.** Five indicators state
   `varies_by_class` (class B marked **Optional**). Concord holds no
   FedRAMP service class for a system, so the variants are stored verbatim
   in `statement_by_class` and the description labels each by class.
   Scoring does not change on class; recording the class is follow-up work.
6. **Deliverables name what the pinned ruleset does not define.** In the
   SDR, an authored `ksiId` or `frrID` absent from the pinned dataset is
   **kept and named** — `undefined_ksi_ids` on the seed result, and a note
   on `omitted_requirements` — with the dataset version. *Revised during
   implementation:* the design first said "omit", but the stored document is
   where that narrative lives, and `merge_indicators` already decided, for
   stated reasons, that a catalog revision must not destroy human work.
   Derived indicators come from current KSIs only. An SCN entry naming a
   retired KSI is flagged as such. Capability↔KSI links accept current
   identifiers only (422 otherwise).
7. **Writes to a retired KSI are refused** (409) — state, reviews,
   exceptions. Reads by identifier still resolve, flagged `retired`.

## 4. Not in scope

- Authoring validation rules for the 46 indicators (each needs its own
  reading of the statement; no phase-one rule is reused).
- A FedRAMP service-class field on the 20x profile.
- The `CTL` section: 79 controls, 14 with parameters. Not the FedRAMP Rev. 5
  parameter overlay — that gap (`GSA/fedramp-automation`) stays open.
- FRD definitions surfaced in the UI.

## 5. Class-scoped KSI applicability (follow-on)

`System.certification_class` (A–D, migration-era CR26 vocabulary) already
exists and is deliberately independent of `baseline`. The dataset says what
each class owes, so Concord derives applicability from it rather than
authoring it:

| Class | Applicable KSIs | Source in the dataset |
|---|---|---|
| A | the 7 KSI IDs in `FRC-CLA-MFR.related` ("MUST address … the following") | `FRR.FRC.data.all.CLA.FRC-CLA-MFR` |
| B, C, D | all KSIs ("MUST include all Key Security Indicators in a FedRAMP independent assessment at least once per year") | `FRR.IVV.data.20x.CSX.IVV-CSX-AIA.varies_by_class.{b,c,d}` |
| B | the 5 `varies_by_class` KSIs whose class-B statement begins `**Optional:**` are **optional** | each KSI's `varies_by_class.b` |
| D | the same 5 publish no class-D statement; they remain required (IVV-CSX-AIA), and the description says no D wording is published | — |
| none | not CR26-certified, or not recorded: every current KSI, labelled unscoped | — |

Each classification cites the rule that produced it. Tests pin the exact
upstream text this depends on (the IVV-CSX-AIA "all Key Security Indicators"
wording per class, the FRC-CLA-MFR KSI list, the `**Optional:**` prefix), so
a re-vendored dataset that changes any of them fails a test instead of
silently re-scoping every Class A system.

Readiness counts only required KSIs; optional and not-required ones are
reported beside the score, never in it. The SDR's derived indicators — and so
its to-do list — cover required and optional KSIs for the system's class.
Validation still runs every current KSI: evaluating is cheap and the history
is useful if a class changes.

`FRC-CSX-VVK` (minimum automated methods per KSI: A MAY, B ≥1 SHOULD, C ≥2
MUST, D ≥4 MUST) is reported as a class requirement against the count of
automated leaf rules Concord holds per KSI; with the rule overlay empty that
count is 0, which is the true answer.

## 6. Class *and Path*; and automated methods (follow-on)

**Path.** Independent review found §5 incomplete: every KSI rule sits in a
subset whose applicability is `types: [20x], paths: [Program]`, and Rev5
Classes B–D owe the control list in `IVV-CSF-AIA`, not KSIs. Concord records
Class and Path but not certification type. An Agency-path system is therefore
Rev5 by elimination and owes no KSI. Class A on the Agency path contradicts
FRC-CLA and is reported, not resolved. Program-path or path-less scope is
stated as conditional on the system being 20x. Every per-system consumer
(readiness, gaps, onboarding, dashboard, drift, package facts and exceptions,
SDR) uses one helper, `applicability.counted_ksi_ids` / `SystemScope`.

**Methods, not verdicts** (decision: user, 2026-10-15). A KSI carries a
curated list of Concord platform posture checks (`ksis.methods`, migration
0094). Each comes with a rationale for why its *failure* contradicts the
statement; a shared 800-53 control does not qualify a check. Failing → KSI at
most `warn`. Passing → evidence. Neither → `pass`. Only tier-0 results count.
Methods that ran on the system count toward FRC-CSX-VVK and are named in the
SDR's `ksiTests`.

## 7. Which FRR requirements a provider owes (follow-on)

The SDR's `fedRampRequirements` is entirely authored; Concord could not say
which of the 245 FRR IDs a system owes. The dataset can, with care:

- A requirement applies to a provider when its subset's `applicability`
  lists the system's Class and (if recorded) Path and the requirement's
  `affects` (or the subset's) includes `Providers`.
- **Type is not recorded**, and the 20x and Rev5 sets differ (Class C,
  Program: 154 vs 158 -- first written as 155 vs 159 from output that let
  VDR's type-specific `20x.TFR` / `rev5.TFR` buckets count for both types;
  a type-specific bucket is now that type only). So the answer is three lists, never one: owed under
  either type, owed only if 20x, owed only if Rev5. An Agency path is Rev5
  only (no 20x subset lists it), which collapses the split.
- **Class A** additionally owes what `FRC-CLA-MFR` (MUST), `FRC-CLA-RFR`
  (SHOULD) and `FRC-CLA-OFR` (MAY) name in `related`; subset applicability
  alone undercounts it.
- Force is the requirement's `force`, or its class variant's; a class with no
  variant is reported as "no force stated", never borrowed from another class.
- Processes whose `info.status` is `placeholder` or `empty` are excluded.

Each requirement carries FedRAMP's per-type effective block (`is`, `obtain`)
and `in_force` (required and past its obtain date for every type it is owed
under) -- most Rev5 requirements obtain 2027-01-01. The SDR seed reports
`frr_unaddressed`: MUST / MUST NOT requirements owed in every scenario,
**in force today**, with no authored entry. Reported beside the document,
like `omitted_ksi_ids`; nothing is written into it.
