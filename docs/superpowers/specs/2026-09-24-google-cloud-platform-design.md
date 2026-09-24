# Google Cloud as a declarable platform

**Status:** design 2026-09-24. Makes a Google Cloud customer's SSP correct.
Adds no connector, and says so everywhere that matters.

---

## 1. What a GCP customer gets today

`normalize_platform("gcp")` returns `None` — *Concord does not recognize this*.
That was the right answer when it was written: the alternative on offer was
`NO_PLATFORM`, and collapsing "unrecognized" into "the customer has no cloud
platform" is the defect `platforms.py` was rebuilt to prevent.

The consequence is that a Google Cloud customer's drafted SSP names no
services at all, and `catalog_absence_note` explains that Concord does not
recognize their platform. Honest, and useless to them.

Measured, `gcp` is currently the codebase's **canonical example of an
unrecognized platform** — eighteen assertions across
`test_platform_default.py` and `test_seeder_draft_marker.py` use that string
to prove unrecognized values are refused, labelled and never drafted for.
Those tests protect a real invariant that has nothing to do with Google: they
move to a value that is genuinely unsupported.

---

## 2. What this adds, and what it deliberately does not

**Adds:** a label, a government environment, a per-family service catalogue, a
FIPS module and key-custody sentence, a responsibility model, and the intake
questionnaire option.

**Does not add a connector.** `PLATFORM_CONNECTOR_KEYS` gets **no `gcp`
entry**, and that is the substantive decision, not an omission:

- `connector_backing_state` and `organization_capture_is_live` already answer
  "does this tenant capture anything" rather than "does Concord ship a
  connector". A platform with no connector flows through them correctly and
  produces the manual-evidence caveat.
- So a Google Cloud customer gets a drafted SSP that names real services **and**
  an evidence claim that correctly says nothing automated verified them. Those
  two facts are independent, and the machinery to keep them independent was
  built in `fix/connector-backed-claim` and the live-capture change.

A platform entry that implied automated capture it does not have would be the
same class of false claim those changes exist to prevent.

---

## 3. The one claim to be careful with

Every platform's `PE` line asserts what is inherited from the provider's
datacenters. Azure and AWS name a FedRAMP **level** ("FedRAMP High"); the
Microsoft 365 entry does not, saying "Microsoft's FedRAMP-authorized
datacenters" instead — because M365 spans tiers and the code never sees which
one the customer holds.

**Google Cloud follows the M365 wording, not the Azure wording.** Authorization
scope varies by service and by Assured Workloads configuration, and this module
sees only the platform code. Asserting a level Concord cannot confirm is the
defect the FIPS certificate-number placeholder already exists to avoid, one
field over.

Everything drafted stays `[DRAFT]`-marked and organization-confirmed, as every
other platform's text is.

---

## 4. Service catalogue

One entry per control family, naming services that exist and do the thing:
Cloud IAM and Organization Policy for AC, Cloud Audit Logs and Chronicle for
AU, Security Command Center for CA/RA/SI, Cloud KMS and Confidential Computing
for SC/MP, OS Config and Artifact Registry for CM/MA, and so on. Written to the
same standard as the existing three: an assessor should be able to check each
name against the customer's console.

---

## 5. Testing requirements

1. **Every existing parametrized test over `CLOUD_PLATFORMS` passes for
   `gcp`** — FIPS module named, no fabricated certificate number, key custody
   stated, `[DRAFT]` marked. These already exist and simply gain a case; that
   is the point of having parametrized them.
2. **The unrecognized-platform invariant still has a subject.** The tests that
   used `gcp` move to a value that is genuinely unsupported, and a test asserts
   that value is *not* in `PLATFORMS`, so this cannot rot into passing
   vacuously the day someone adds it.
3. **`gcp` has no connector**, asserted by name: `connector_key_for_platform`
   returns `None`, and a GCP system's coverage reports manual evidence rather
   than platform-sourced.
4. **The drafted text names Google services and no other provider's.** Assert
   no "AWS", "Azure", "Microsoft" or "Entra" appears in a `gcp` statement — the
   platform-default defect was a system being drafted with another provider's
   product names, and this is the direct check for it.
5. **The questionnaire option round-trips** to the SSP platform code.
6. **`PE` names no FedRAMP level** for `gcp` (§3).
7. **Every platform-keyed structure has a `gcp` entry**, derived from
   `CLOUD_PLATFORMS` rather than hand-listed, so a half-added platform fails
   here instead of drafting a blank family.

Mutation-verify: remove the service catalogue entry and confirm test 4 fails;
remove the FIPS entry and confirm test 1 fails.
