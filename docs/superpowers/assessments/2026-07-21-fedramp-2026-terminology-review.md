# FedRAMP 2026 (CR26) Terminology-Shift Review — Concord (ccf)

**Date:** 2026-07-21 · **Trigger:** user request to review
https://www.fedramp.gov/2026/providers/updating/changes/#terminology-shifts
**Timeline:** CR26 ("Consolidated Rules for 2026") effective **2026-07-04**;
**enforcement begins 2027-01-01**. Today (2026-07-21) it is live but not yet enforced.

## Determination

**No MUST-CHANGE items.** Nothing in the platform makes a claim that becomes
*incorrect* under CR26 in a way that breaks compliance output. The platform's core
vocabulary (POA&M, ATO, Continuous Monitoring, SSP) is largely NIST-generic /
multi-framework (CMMC, FISMA, OSCAL), not FedRAMP-exclusive branding, and FIPS 199 /
NIST 800-53 / OSCAL terms — which the platform relies on — are explicitly unchanged.
The agency **ATO** concept (`System.ato_status`) is explicitly **unchanged** by CR26.

The changes are **SHOULD-CHANGE, cosmetic/label-only, scoped to FedRAMP-20x surfaces**,
worth doing before 2027-01-01 enforcement. Renaming underlying enums/DB values is a
breaking change and is **not** recommended; prefer a display-label layer.

## Confirmed terminology shifts (old → new)

| Old | New | Codebase impact |
|---|---|---|
| "Authorized" (FedRAMP status) | "Certified" | `fedramp20x/__init__.py` READINESS/DEPENDENCY statuses; `fedramp20x.html` labels — SHOULD-CHANGE (display label only) |
| Impact Levels Low/Mod/High | Certification Classes A/B/C/D | `fedramp_baseline` enum, `impact_level` field — SHOULD-CHANGE (display mapping); **A/B/C/D↔impact mapping NEEDS PRIMARY-SOURCE VALIDATION** |
| SSP + Appendices | Certification Package Overview + Security Decision Record | `ssp/generator.py` targets **CMMC** SSP, not FedRAMP submission — NOT-APPLICABLE (cosmetic comparison text only) |
| Continuous Monitoring | Ongoing Certification | generic `governance/conmon.py` NOT-APPLICABLE (NIST CA-7 term); `fedramp20x/monitoring.py` SHOULD-CHANGE |
| POA&Ms | Accepted Weaknesses | platform-wide POAM feature NOT-APPLICABLE (NIST/OSCAL term); only `fedramp20x/package.py:319` "Open POA&Ms" narrative — needs manual validation |
| Authorization Package | Certification Package | generic `ccf.packages` NOT-APPLICABLE; `fedramp20x/package.py` docstrings SHOULD-CHANGE |
| FedRAMP Ready | retired | not referenced anywhere — NOT-APPLICABLE |

## Recommended follow-up (register: FR-14, deferred — non-breaking, pre-2027-01-01)

1. Add a display-label layer in `fedramp20x/` UI: render `authorized`→"Certified",
   `continuous_monitoring`→"Ongoing Certification" without renaming enum/DB values.
2. Surface a Certification-Class mapping wherever `fedramp_baseline`/`impact_level`
   shows — **after** confirming the A/B/C/D↔Low/Mod/High mapping against a primary
   fedramp.gov source (secondary sources only, so far).
3. Revisit the `fedramp20x/package.py` "Open POA&Ms" narrative if/when an actual
   FedRAMP Certification Package export is built (Accepted-Weaknesses framing).
4. Do **not** touch the generic FISMA baseline selector, the platform-wide POAM
   model/router, `ccf.governance.conmon`, or the OSCAL `plan-of-action-and-milestones`
   model name — all NIST-generic, unaffected by CR26.

**Epistemic note:** the fedramp.gov page described the class concept but not the
explicit A/B/C/D↔impact table; that mapping was corroborated only by secondary sources
(Secondfront, A-LIGN). Re-verify against primary FedRAMP documentation before encoding
any mapping into the product.
