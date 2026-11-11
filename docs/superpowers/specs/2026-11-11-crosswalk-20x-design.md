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

| Not taken | Why |
|---|---|
| Crosswalk's `reference.json` | Concord already pins FedRAMP's consolidated rules (KSI and FRR control mappings, the FRC-CSF-BSL class baselines). One rules source, not two. Crosswalk's copy is a newer upstream version (2026.11.02.01 vs Concord's 2026.10.13.01); updating Concord's pin is a separate change because the KSI catalog and applicability read it too. |
| Control titles from JSONViewer | Concord ships NIST's 800-53 Rev. 5 OSCAL catalog. |
| The JS schema validators | Concord validates CR26 documents with `ccf.cr26.validation` against the same vendored schemas. |
| The OSCAL SSP and POA&M exports | Concord has its own OSCAL generation. Crosswalk's maps "Not Implemented" to OSCAL `planned`, which asserts a plan nobody stated. Deferred. |
| XLSX and HTML report | CSV covers the review; deferred. |

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
register, with CSV exports. The class is chosen on the page (the CPO does not
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
date; formula-safe CSV; unknown IDs reported, not dropped. Routes: isolation
on an RLS-cleared session, role gates, NULL-org vendor refused, invalid file
stored with its verdict, re-upload replaces and audits. Mutation-check each
guard.
