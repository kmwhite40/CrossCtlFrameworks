# Crosswalk 20x in Concord — design

2026-11-11. Source reviewed: `Mycroft-io/crosswalk-rev5-to-20x` v1.0.0
(`f2a6ebb`, Apache-2.0, Mycroft Technologies Inc.). Decisions taken with the
product owner: integrate **both directions on one engine**, and **split
"Traced"** so a partly reported control is not shown as traced.

## What Crosswalk is

A single browser page an *agency* reviewer uses on a cloud provider's FedRAMP
20x certification package (the CR26 JSON files). It lays the Security Decision
Record against the Rev5 Class B/C/D control baseline, using the "related
controls" FedRAMP publishes for each Key Security Indicator (KSI) and rule
(FRR), and gives every baseline control one coverage state. It also merges the
vulnerability reports into one register and exports CSV, XLSX, an HTML report
and two OSCAL skeletons.

Concord is the *provider* side: it builds the SDR, CPO, VDR, AVI and history
documents (`ccf.cr26`) and shares them through the trust center. The two meet
at those files.

## What Concord takes, and what it does not

| Taken | How |
|---|---|
| The crosswalk (control → mapped KSIs and rules → coverage state) | Ported to Python in `ccf.fedramp20x.crosswalk`, pure functions. Apache-2.0 permits it; attribution in `NOTICE` and the module docstring. |
| The vulnerability register | Ported, with the merge fixed (below). |
| FedRAMP's agency control guidance (`agency_actions`, `fedramp_guidance`) | Vendored from `FedRAMP/JSONViewer@128f6cc` (CC0), pinned by SHA-256 in the rules-data manifest. |
| Formula-safe CSV export | Ported. |
| Package overview and latest ongoing report | Ported as pure extraction (`package_overview`, `ongoing_report`), rendered by Jinja with autoescape and never `|safe`. A URL becomes a link only when it is http(s) (`safe_url`); anything else (`javascript:`, `data:`) is shown as text. A list the report omits reads "not stated"; an empty one reads "none reported". |
| Per-file schema errors | The first 25 with path and message, then "and N more". The vendor upload keeps 50 errors per file, so a file at that cap reads "at least 50", not an exact count it does not have. |
| Review workbook (`review.xlsx`) | Summary, Control inheritance, Agency determinations, Vulnerability register. Written with `openpyxl` (already a dependency). Cells go through `_safe_cell` after XML-illegal characters are stripped (stripping first means `"\x01=..."` cannot become a formula); integers stay numbers; a cell over 32,000 characters is cut and says so. A "not known" completeness count reads "not known", not "None of None". |
| Printable report (`report.html`) | A standalone Jinja template (`crosswalk_report.html`), autoescaped, no external resources, a CSP in both the response and a `<meta>` so it loads nothing when opened from disk. Served as an attachment. Family by family. |
| OSCAL SSP skeleton and POA&M (`oscal-ssp.json`, `oscal-poam.json`) | Ported with the defects below removed. OSCAL 1.1.2, deterministic `uuid5` IDs seeded by the export scope (system or vendor), the package and the class. Both validate against the NIST OSCAL 1.1.2 JSON schemas Concord already vendors (`ccf/oscal/schemas`, via `ccf.oscal.validation`), in tests. |

Every export goes through one route per page (`/export/{name}`, the `EXPORTS` table) behind the same gates as the CSVs: `require_system_in_scope` for a system, the organization-filtered `_vendor` for a vendor; readable by every member including viewers. The register CSV and the POA&M are refused (409) when the package holds no vulnerability file, and the page shows them as not available and says why; the POA&M is also refused when the files list no vulnerabilities (OSCAL requires one item, and an empty plan would read as "nothing to remediate"). Every page and export carries the NOTICE.

| Not taken | Why |
|---|---|
| Crosswalk's `reference.json` | Concord already pins FedRAMP's consolidated rules (KSI and FRR control mappings, the FRC-CSF-BSL class baselines). One rules source, not two. Crosswalk's copy is a newer upstream version (2026.11.02.01 vs Concord's 2026.10.13.01); updating Concord's pin is a separate change because the KSI catalog and applicability read it too. |
| Control titles from JSONViewer | Concord ships NIST's 800-53 Rev. 5 OSCAL catalog. |
| The JS schema validators | Concord validates CR26 documents with `ccf.cr26.validation` against the same vendored schemas. |
| Crosswalk's OSCAL status and risk mappings | Replaced; see "OSCAL exports" below. |
| Crosswalk's own zip writer for XLSX | Concord already depends on `openpyxl`. |

## Defects in the upstream logic, and Concord's answer

1. **"Traced" counted partly reported controls.** Upstream marks a control
   Traced when every *reported* mapped entry is Implemented, even when other
   mapped KSIs or rules are not reported at all. On FedRAMP's own sample
   package that is 27 of 60 Traced controls in Class B, 79 of 146 in C and 96
   of 179 in D. Concord adds **Partly reported**: some mapped entries
   reported, all Implemented, some missing. **Traced** requires every mapped
   entry reported and Implemented.
2. **Register merge ignored dates.** Upstream overwrote each row with the
   later *file in processing order* (VDR, then AVI, then history), so an
   older snapshot could replace newer detail, and an acceptance was sticky
   once seen. Concord orders observations by each document's own date (the
   VDR/AVI `reportPeriod.to`, the history `generatedAt`); the newest
   observation decides the row, including whether it is accepted.
3. **Status matching.** A missing or unrecognised status is never read as
   Implemented (kept from upstream; pinned by a test).
4. **The certification type was defaulted to 20x.** Upstream reads any package
   whose overview does not say "Rev5" as 20x, so a Rev5 package uploaded
   without its CPO showed every KSI as a missing gap. Concord takes the type
   only from the package; when it is not stated, which KSIs and rules are
   owed is shown as not known. The provider preview also passes the
   system's recorded Certification Path, which narrows both.

## After the independent review (2026-11-11)

No Critical or High finding. Fixed: the type default (above); register
dates compared as text (RFC 3339 offsets and fractions now order as
instants); uploads that failed the database write with a 500 and lost every
file (NaN/Infinity, deep nesting, a NUL in a string are now refused by name);
two files of one kind in one upload (the second is refused); the upload
outcome read from the URL (now rendered by the POST itself, so a link cannot
forge it); rules not filtered by path (filtered when known, and the page says
when it is not).

## OSCAL exports: what upstream asserted, and what Concord exports instead

Concord never fabricates a compliance status or an approval. Upstream's
OSCAL exports did both in places; each is handled here and pinned by a test
and a mutation check.

1. **"Not Implemented" became `planned`.** That asserts a plan nobody stated.
   Concord maps only Implemented → `implemented` and Partially Implemented →
   `partial`. For any other or missing status, `implementation-status` (optional
   in OSCAL 1.1.2) is left out, the by-component remarks say why, and every
   provider status is kept in a `provider-status` prop (`"KSI-X: Not
   Implemented"`).
2. **A partly reported control became `implemented`.** Upstream marked the
   by-component implemented when every *reported* mapped entry was
   Implemented, however many were missing. Concord exports `implemented` only
   for a control in state Documented or Traced; a Partly reported control has
   no implementation status, and the remark names the entries not reported.
3. **"Accepted" became `deviation-approved`.** That asserts an authorizing
   official's approval the package does not contain: the AVI records the
   *provider's* acceptance. Concord exports an accepted vulnerability as risk
   status `open` (the vulnerability is still present, which the package does
   state), with `provider-status: Accepted`, and the POA&M item's remarks say
   the package does not show a deviation was requested or approved.
   `deviation-requested` was rejected too: nothing shows a request was made to
   this agency.
4. **A missing detection time became the export time.** Upstream said so in a
   remark, but the observation still carried a `collected` time nobody
   observed. `collected` is required on an observation, so Concord exports no
   observation for that vulnerability (observations are optional) and the
   POA&M item says the package gives no valid detection time and none is
   substituted. A date alone, or an impossible date, is not a valid one.
5. **The rest.** No `inherited` claim (the package does not say what an
   agency inherits). The cloud service component's status is `other`, "not
   stated", rather than `operational`. The estimated next reduction date is a
   prop, not the risk `deadline` (an estimate is not a deadline). Observation
   method is `UNKNOWN`: the package names a detection source, not a method.
   Agency fields read "AGENCY TO COMPLETE".

## Coverage states (Concord)

Exactly one per baseline control; the counts sum to the baseline size.

| State | Rule |
|---|---|
| Needs review | Any reported mapped entry, or the provider's own control entry, has a status other than Implemented (including none). |
| Documented | The provider has its own Implemented entry for the control. |
| Traced | Every mapped KSI and rule is reported, all Implemented. |
| Partly reported | Some mapped entries reported (all Implemented), some not reported. |
| Not reported | FedRAMP maps entries to the control; the package reports none. |
| No mapping | FedRAMP maps nothing to the control. The agency decides. |

A link is where to look, not evidence a control is satisfied; every page says
so, as upstream does.

## Two uses of one engine

**Provider preview** — `/fedramp20x/agency-view?system_id=N`. Reads the
system's own stored CR26 documents (`cr26_documents`, single-instance kinds)
and shows what an agency reviewer will see. The class is the system's
recorded `certification_class`; when none is recorded the page says so and
offers a class to preview *as*, labelled as an assumption. No writes.

**Agency view** — under Third-Party Risk, per vendor:
`/vendors/{id}/fedramp-package`. Upload the provider's package files; each is
detected by kind, validated against the vendored schema (an invalid file is
kept with its verdict, as `ccf.cr26.store` does), and replaced on re-upload
with an audit event. Then the same crosswalk, a determinations list and the
register, with CSV, XLSX, HTML report and OSCAL exports. The class is chosen on the page (the CPO does not
state one); nothing is computed until it is chosen.

Storage: migration `0121_vendor_cert_documents`, one tenant table with a forced
RLS policy, `unique (vendor_id, kind)`, and `ccf.assert_parent_org` on
`vendor_id` so a row cannot point at another organization's vendor. A vendor
with no organization is refused. Upload limit 10 MB per file.

Roles: read for any member of the organization; upload and delete for
`admin` and `control_owner` (the third-party write roles). Viewers stay
read-only through the existing viewer gate.

## Tests

Engine: every state on constructed inputs; the counts sum; the split rule on
FedRAMP's sample package (vendored as a CC0 fixture); register ordering by
date; formula-safe CSV and XLSX; unknown IDs reported, not dropped; overview
and ongoing report extraction, "not stated" apart from "none reported"; only
http(s) URLs linkable; both OSCAL exports valid against the official 1.1.2
schemas for Classes B, C and D (and the check shown able to fail); each
status rule on a one-control model; no `planned`, no `deviation-approved`, no
substituted detection time. Routes: every export on both pages for a viewer,
another organization's export 404, the register and POA&M refused without
vulnerability files, package text escaped in the report. Routes: isolation
on an RLS-cleared session, role gates, NULL-org vendor refused, invalid file
stored with its verdict, re-upload replaces and audits. Mutation-check each
guard.
