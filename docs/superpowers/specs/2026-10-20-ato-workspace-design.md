# ATO Workspace: design

Date: 2026-10-20. Part 1 of the m365-docs-hub port: the AWS components, ATO
Workspace and Compliance Assessment, in five parts.

## Intent

The user asked us to "copy" m365-docs-hub's ATO Workspace into Concord and then
narrowed that to: **don't duplicate. Integrate it, and make it work.**

The source has the right workflow ideas:

- a package lifecycle with ISSO → ISSM → AO sign-off
- POA&M extensions
- risk-acceptance expiry
- an action queue
- audience briefs

None of that ideal workflow is real in the source:

- Every actor is hard-coded as `'operator'`.
- Workflow state lives in browser localStorage.
- Package transitions are held in React state only and never saved.
- Readiness gives full credit when it has no data.
- Freeze blockers are computed but never enforced.

Concord has some of the pieces already: a single-use approval engine with
separation of duties (SoD), gated POA&M closure and risk acceptance,
`AuthorizationPackage` fact snapshots, `System.ato_status`, ConMon health, and
FedRAMP 20x readiness. It has no workflow over packages and no idea of who the
ISSO, ISSM or AO of a system is.

So the port adds only what is missing, on the existing models.

## What is added, and what it extends

| Capability | Extends | New |
|---|---|---|
| Who signs | `System`, `User` | `system_role_assignments`: one user per (system, role); role ∈ `system_owner, isso, issm, authorizing_official` |
| Approval authority | `governance/approvals.decide` | Authority is `admin` **or** the right holder of a system role for the entity's system. This replaces `APPROVER_ROLES`, whose `authorizing_official` could never match a `User.role`. Decisions also resolve the entity first and refuse one outside the caller's organization. |
| Package lifecycle | `AuthorizationPackage` (facts are already frozen at capture) | A `status` column, a `manifest_sha256` over the package's fact digests, and an append-only `authorization_package_events` table |
| System ATO state | `System.ato_status` / `ato_expires_on` | Driven by the package: entering review sets `in_progress`, an AO decision sets `authorized`, and the scheduler step `ato_expiry` sets `expired`. Before this, nothing ever wrote `in_progress` or `expired`. |
| POA&M extension | `POAM.due_on` / `original_due_on`, and the expiry-extension gate | `poam_extensions`: a request, then a decision by the ISSM, AO or an admin, with SoD. With auth on, a direct PATCH that moves an active POA&M's `due_on` later is refused. |
| Risk acceptance | `Risk`, `POAM` `risk_accepted`, `Waiver`, `KSIException` | No new table. A read model joins the four existing acceptance kinds with their expiries. An expired acceptance blocks authorization. |
| Workspace | The `ui_grc` page pattern, the Authorization nav group | `/ato` (portfolio) and `/ato/{system_id}` (one system). The existing `/workspace` is the customer-journey page and is left alone. |
| Briefs | The workspace aggregate | Per-audience HTML (`ao`, `issm`, `isso`, `system_owner`) rendered from the same aggregate. They contain no number the aggregate does not hold. |

## Package lifecycle

```
draft ─submit─▶ isso_review ─isso_approve─▶ issm_review ─issm_approve─▶ ao_review
                     │                           │                         │
                     └──────────return (reason)──┴─────────────────────────┤
                                  ▼                                        ├─authorize──────────────▶ authorized
                               returned ─submit─▶ isso_review              ├─authorize_conditional──▶ conditional   (reason + expiry)
                                                                           └─deny (reason)──────────▶ denied
authorized | conditional ─(newer package authorized)─▶ superseded
authorized | conditional ─(scheduler, past expiry)──▶ expired
```

- **Who may act.** With auth on, each stage belongs to the holder of that
  system role (ISSO, ISSM, AO), or to an `admin`. Submitting needs a
  write-capable member, and an ISSO, ISSM and AO all assigned. SoD: one review
  cycle's sign-offs must come from different people, none of them the
  submitter. With auth off, a single operator acts alone and SoD cannot apply.
  This is the same rule the approval engine already uses.
- **Blockers.** They are recomputed live and enforced at `authorize` and
  `authorize_conditional`:
  - a critical or high POA&M that is open or in progress. This is the rule
    `POST /systems/{id}/authorize` already enforced, moved into one shared
    function.
  - an acceptance past its expiry.
  - with auth on, a role left unassigned.
- **Readiness % is informational.** It is never a gate.
- **Direct authorize.** With auth on, `POST /api/systems/{id}/authorize`
  refuses with 409 and points to the package. Otherwise it would bypass every
  stage above. With auth off it still works as before.
- **Audit.** Each transition writes an `authorization_package_events` row and
  a `record_event` audit-chain row carrying the package's real organization.

## Calls made here (the builder's, not the user's)

- One user per (system, role). FedRAMP and RMF name one AO per system. We can
  add co-holders later if needed.
- No new values in `user_role`. The system role is a relationship, and
  `admin` stays as the platform floor.
- A POA&M approval may be granted by its system's ISSO, ISSM or AO. Accepting
  risk (POA&M `risk_accepted`, extending an acceptance's expiry, Risk
  `accepted`) needs an approval **granted by the AO** or an admin, because
  under RMF accepting risk is the AO's decision.
- **Evidence review** (supersede, refresh, attestation, and the source's
  per-type freshness windows) is **deferred**. A concurrent branch
  (`fix/tier0-gate-bypasses`) is changing evidence review independence right
  now. The workspace reads evidence state as it is: counts by status, plus
  expired and expiring within 30 days, the same as ConMon's `DUE_SOON_DAYS`.
- **Not ported from the source:**
  - the evidence "quality score", which credits approval it never checked
  - the weighted readiness composite and its 25/70/80/85/90 gates
  - the ConMon health formula (100 − 8·crit…), whose weights are unsourced
  - drift keyword routing
  Concord's own ConMon status per control and its 20x readiness are shown
  instead. When there is nothing behind a value, the page says "no data".
- **Monthly ConMon report with ISSM approval:** deferred to a later part.

## Non-goals

- Changing the AWS, Compliance Assessment, IaC or evidence-review code. Those
  are later parts.
- A second package or acceptance store.
