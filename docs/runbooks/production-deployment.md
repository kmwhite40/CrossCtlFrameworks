# Production deployment

The checklist that has to pass before Concord serves a real authorization
package. Every item here was a real finding, not a precaution.

`docker-compose.yml` in this repository is a **development stack**. It carries
dev-only secrets on purpose and must not be deployed.

## 1. Configuration the application refuses to start without

`ccf.config.enforce_secure_config` raises on start in a non-development
environment unless all of these hold:

| Variable | Requirement |
|---|---|
| `CCF_ENV` | not `dev` / `test` |
| `CCF_AUTH_ENABLED` | `true`. With auth off every caller is the system principal with no organization, and org-scoped pages refuse. |
| `CCF_AUTH_SESSION_SECRET` | not `dev-insecure-change-me`. A strong random value, 32+ bytes. |
| `CCF_API_CORS_ORIGINS` | explicit origins, never `*` |

## 2. Configuration it warns about but starts without

These do not block startup — neither lets a request act as someone it is not,
which is the bar for refusing — but both are logged at `warning` as
`config.insecure_default` on every start. Read the first lines of the log
after a deploy.

| Variable | Why it matters |
|---|---|
| `CCF_AI_CREDENTIAL_MASTER_KEY` | Wraps every stored connector, AI provider and MFA secret. **Without it the cipher fails closed and no credential can be saved at all** — which presents as "the connector page will not accept my key". With the wrong one, existing credentials are unreadable. Back it up separately from the database. |
| `CCF_AI_CREDENTIAL_KEY_PROVIDER` | Defaults to `local`, which keeps key material in the environment. Production should be `aws_kms` so the platform never holds it. |
| `CCF_CSRF_TRUSTED_ORIGINS` | Only if a separately-hosted front end posts to this API. Leave empty otherwise. |

## 2a. Configuration that decides whether the platform does anything on its own

Nothing below blocks startup, nothing warns, and every one defaults to **off**.
A deployment that follows every other section of this runbook and skips this one
comes up healthy, serves every page, and then sits still: no connector
collection, no ConMon scan, no control-test auto-runs, no assurance-graph
rebuild. Continuous monitoring that only runs when somebody clicks is not
continuous, and the platform will not tell you — an operator's first sign is a
posture page that never changes.

| Variable | Default | What stays switched off without it |
|---|---|---|
| `CCF_SCHEDULER_ENABLED` | `false` | **Every recurring job.** The in-app scheduler runs connector collection, pack sync, the ConMon scan, connector-backed control-test auto-runs, capability derivation and the assurance-graph rebuild — per organization, once per cycle. Set `true`, or drive `ccf scheduler --once` from an external cron. **Two separate passes, and the distinction matters when reading the log.** The *control-test* pass (`tests_evaluated`) runs authored connector tests that are due, and deliberately excludes scan-generated ones — its evaluator has nothing useful to say about a posture check and would bury the real verdict. The *posture scan* pass (`posture_checks_run`) runs every provider against every live system, which is what refreshes posture verdicts. Until that pass existed, nothing re-ran a posture check at all: a tenant scanned in September still showed September's verdicts, while the SSP cited them as automated evidence carrying their original observed-on dates. `tests_evaluated=0` is normal and not the number to watch; `posture_checks_run` is. |
| `CCF_SCHEDULER_INTERVAL_HOURS` | `24.0` | The cycle cadence. It also sets the staleness threshold the `assurance_graph_freshness` reliability check warns past, so shortening the interval tightens that check automatically. |
| `CCF_AWS_CAPTURE_ENABLED` | `false` | AWS configuration capture. Leave off unless an AWS connector is bound. |
| `CCF_PREP_ENABLED` | `false` | The evidence-prep pipeline and its worker. |
| `CCF_AI_ENABLED` | `false` | AI drafting. Off is a defensible production posture; on requires a configured provider and leaves AI-drafted content visibly badged. |

Verify it took, rather than assuming — see section 6.

**The bundled `docker-compose.yml` turns the scheduler on.** `config.py` still
defaults `scheduler_enabled` to `false` — that is the library default and every
sentence above is about it — but the compose stack sets
`CCF_SCHEDULER_ENABLED: "true"` on the `api` service, so a `docker compose up`
does run recurring jobs. It is set on `api` alone and deliberately not on the
`x-ccf-env` anchor: the anchor also feeds `etl`, `cli` and `poller`, and
`scheduler.start()` is idempotent per process rather than across them, so
putting it in the anchor would run one scheduler per container and fire every
tenant's cycle several times over. Any other deployment method — a Helm chart,
a systemd unit, a hand-rolled container — inherits the `false` default and must
set this itself.

The two workers are behind compose **profiles** rather than an environment
variable, so they do not start with a plain `up`:

```
docker compose --profile prep --profile assessment up -d prep-worker assessment-worker
```

Both poll in a loop and log `{"claimed": 0, ...}` against an empty queue, which
is what healthy-and-idle looks like. Neither is needed for the scheduler.

### Defaults that weaken an assurance claim rather than a feature

These are off by default too, and each one changes what the platform can honestly
say about its own output. They are listed apart from the table above because
switching them on is a compliance decision, not an operational one.

| Variable | Default | What the default costs you |
|---|---|---|
| `CCF_EVIDENCE_OBJECT_LOCK_ENABLED` | `false` | Evidence is written without WORM/object-lock. Only storage-enforceable on `evidence_backend='s3'` (Object Lock, COMPLIANCE mode); on `local` the platform logs `evidence.worm_not_storage_enforced` rather than making a false immutability claim — which is the right behaviour, and also means local evidence is mutable. An assessor asking "can this evidence have been altered after collection" gets "yes" while this is off. Pair with `CCF_EVIDENCE_OBJECT_LOCK_RETENTION_DAYS` (default 365) when no per-organization retention policy applies. |
| `CCF_AI_ALLOW_UNCITED_DRAFTS` | `false` | Leave it off. On, AI may produce draft content with no citation behind it, in a document an authorizing official reads. The default is the safe one; it is named here so nobody turns it on without meaning to. |
| `CCF_FEDRAMP20X_OSCAL_VALIDATE` | `false` | FedRAMP 20x OSCAL output is not schema-validated on export. A package that fails validation at the reviewer's end is discovered by the reviewer. |
| `CCF_OSCAL_REQUIRE_OFFICIAL_SCHEMA` | `false` | Validation falls back to a bundled schema rather than requiring the official one. |
| `CCF_READONLY` | `false` | Not a gap — a mode. Set it for a demonstration or a frozen archive instance so nothing can be written through the UI or API.

## 3. TLS and the reverse proxy

- Session cookies and PIV/CAC both assume TLS termination in front of the app.
- `ccf.identity.piv` reads the client identity a terminator established, and
  accepts it **only** from a peer address named in its trusted CIDR list. An
  empty list is closed, not open.
- Do not rewrite `Host`. `CsrfOriginMiddleware` compares the browser's
  `Origin` against the served `Host`; a proxy that replaces `Host` with an
  upstream name makes every state-changing request fail with
  `cross-origin request rejected`. If the public name legitimately differs,
  add it to `CCF_CSRF_TRUSTED_ORIGINS` rather than relaxing the check.
- Keep `Referrer-Policy` at `same-origin`. `no-referrer` makes browsers send
  `Origin: null` on every non-GET request, which the CSRF check correctly
  refuses — two defensible headers that together break every form in the
  product.

## 4. Accounts

- **No seeded or demo accounts.** Verify before opening access:

  ```sql
  SELECT id, email, role, organization_id, active FROM ccf.users ORDER BY id;
  ```

  Any account whose password was set outside your provisioning process must be
  removed, not just disabled.
- Confirm MFA policy for the deployment (`ccf.identity.mfa_service`); TOTP
  enrolment is enforced by `auth_gate_middleware` once a policy requires it.

## 5. Migrations

`api` and `migrator` are separate compose services built from the same
Dockerfile. **Building one does not build the other**, and a stale migrator
reports success while leaving the database on the previous revision.

```bash
docker compose build api migrator
docker compose up -d api
docker compose up migrator
psql -c "select version_num from ccf.alembic_version;"   # confirm the head
```

## 6. What to verify after the first deploy

| Check | Expected |
|---|---|
| `GET /healthz` | 200 |
| Any form submission | not `cross-origin request rejected` |
| `select count(*) from ccf.users` | only accounts you provisioned |
| A connector's **Test** button | the provider's own error, or connected |
| `/api/posture/summary` `systems_total` | equals live systems in that org |
| `GET /api/reliability` → `assurance_graph_freshness` | `pass`, within a day or two of deploy. A persistent `warn` that the graph is *N*d old means no scheduler is running — see section 2a. |
| The API log on start | `scheduler.started` with the interval, if `CCF_SCHEDULER_ENABLED=true`. Its absence is the only signal that nothing recurring will happen. |

## 7. Known limits to state before anyone relies on this

- **Posture check coverage is 42 checks touching 48 of the 288 controls in a
  FedRAMP Moderate baseline** — roughly 17%. Re-measure with the command below
  rather than trusting this sentence; the intersection is not asserted by a test
  (see the note following the table) and the last two figures stated from
  inference rather than measurement were both wrong. Every registered connector now
  ships checks, so binding a credential to any of them produces verdicts rather
  than an empty scan. By provider:

  | Provider | Checks | Controls evidenced |
  |---|---|---|
  | `msgraph` (Entra / Intune) | 19 | AC-2, AC-2(3), AC-2(12), AC-3, AC-6, AC-6(1), AC-7, AC-7(1), AC-8, AC-11, AC-11(1), AC-12, AC-17, AC-19(5), AC-20(2), AU-2, AU-3, AU-6, AU-12, CM-2, CM-6, IA-2, IA-2(1), IA-2(2), IA-2(11), IA-3, IR-4, MP-7, SC-28, SC-28(1), SI-2, SI-4, SI-5 |
  | `aws_govcloud` | 13 | AC-3, AC-4, AU-2, AU-9, AU-9(3), AU-12, CM-6, CM-7, IA-2, IA-2(1), IA-5, IA-5(1), RA-5, RA-5(2), SC-7, SC-7(3), SC-28, SC-28(1), SI-2, SI-2(2), SI-4 |
  | `azure_arm` | 5 | AU-4, AU-11, CM-2, CM-6, RA-5, SC-8, SC-8(1), SC-23, SC-28, SC-28(1), SI-3, SI-4 |
  | `gcp` | 3 | AU-4, AU-11, CM-2, CM-6, SC-12, SC-28, SC-28(1) |
  | `puppetdb` | 2 | CM-2, CM-6, CM-8 |

  `AC-8` was added because **no provider could reach it at all**. It reads
  `/v1.0/identityGovernance/termsOfUse/agreements`, verified against the live GCC
  High tenant — not only against Graph's published `$metadata` — and the property
  that decides it, `isViewingBeforeAcceptanceRequired`, is present there.

  An `AT-2` check shipped beside it and was **removed after being verified against
  that tenant**, which is why the sentence above now says "verified against the
  tenant" rather than "verified against the metadata". It read
  `/v1.0/security/attackSimulation/simulations`, which genuinely is in the v1.0
  model — but the model published at `graph.microsoft.com` is the **commercial**
  one, and `graph.microsoft.us` answers `400 BadRequest: Resource not found for
  the segment 'attackSimulation'` on both `/v1.0` and `/beta`, while
  `/v1.0/security` itself answers 200. That is a cloud capability gap, not a
  licensing one, which would answer 403. The check would have reported
  `manual_review_required` on every scan of every GCC High tenant for ever, and
  read as a tenant problem rather than a platform one.

  **The AT family therefore still has zero coverage**, and closing it needs either
  a Graph surface this cloud serves or per-cloud check applicability, which
  Concord does not have today: a check is either registered for a provider or it
  is not, with no notion of the sovereign clouds it can actually run in. That is
  the mechanism that would let this check return for commercial tenants without
  misreporting GCC High ones.

  Three of the distinct controls these checks evidence — `AC-2(12)`,
  `AU-9(3)` and `IA-2(11)` — are **not** in the Moderate baseline, which is why
  the intersection figure is lower than the control count. They are not wasted:
  a High-baseline system is held to them, and `GET
  /api/systems/{id}/framework-posture` reports against whichever baseline the
  system actually carries. But nobody should read 40 as Moderate coverage.

  A check declaring several controls is evidence about **all** of them when it
  does not pass, and about its first one when it does
  (`ccf.posture.evidence`). The counts above are the full declared sets, which
  is what the running product now credits; before that asymmetry was
  implemented the product credited only the first control of each check, and
  this table overstated what a scan actually reported.

  The check total and every control id in the table are asserted against the
  registry by `tests/test_runbook_states_real_coverage.py`, in both directions —
  the table may neither name a control no check evidences nor omit one that a
  check does. **The baseline intersection is not asserted**: baseline
  membership lives in `controls.fisma_mod`, which a catalog ingest loads and the
  test database therefore does not have, so a guard over it would skip forever.
  Re-measure it after adding or removing a check:

  ```
  CCF_DATABASE_URL="postgresql+asyncpg://ccf:ccf@localhost:5433/ccf" \
  python -c "
  import asyncio
  from ccf.analytics.framework_posture import baseline_controls, fold_to_control
  from ccf.connectors import connector_keys
  from ccf.posture.checks import checks_for
  from ccf.db import session_scope
  ev = {f for k in connector_keys() for c in checks_for(k) for i in c.control_ids
        if (f := fold_to_control(i))}
  async def main():
      async with session_scope() as s:
          mod = await baseline_controls(s, 'moderate')
      print(f'{len(ev & mod)} of {len(mod)}  ({len(ev)} distinct controls evidenced)')
  asyncio.run(main())"
  ```

  Concord reports what it assessed and names what it did not: a scan response
  carries `checks_expected`, `checks_run` and a reason for every skipped check,
  and `GET /api/systems/{id}/framework-posture` reports the baseline as the
  denominator rather than the checks that happened to run.

  **State this number to anyone relying on the output.** Keep this table current
  — it said "9 checks across 7 controls" for several releases after the real
  figure had more than doubled, which is the kind of stale claim this platform
  exists to catch elsewhere. It is generated by:

  ```
  python -c "from ccf.posture.checks import checks_for; from ccf.connectors import connector_keys; print({k: len(checks_for(k)) for k in connector_keys()})"
  ```

- **800-171 coverage is 20 of the 110 requirements.** The 800-53 → 800-171
  crosswalk shipped in the catalog reaches only 80 of the 110 at all, so 30
  requirements cannot be evidenced by any scan regardless of check coverage.
  `framework-posture` reports those as `unreachable`.
- **A CMMC SSP shows evidence for 29 of the 110 practices**, from the 37 of 42
  checks that declare one. This is a *different* number from the two above and
  from the per-provider table: those count controls a check evidences, while
  this counts practices a **CMMC document can actually display**.

  The distinction exists because it was the defect. A posture check declares
  NIST 800-53 ids; a CMMC project's SSP entries are practice ids seeded from
  `ccf.scoring_controls`, and the two vocabularies do not intersect. So every
  verdict — passes cited as evidence and failures owed a POA&M alike — landed on
  no entry in the document an assessor reads. On the live tenant that was four
  failing checks and `controls_with_open_findings: 0`.

  `ccf.posture.practices.CHECK_PRACTICES` states the mapping, quoting each
  practice's requirement text beside it, because the entry is a compliance
  assertion that reaches an authorization package. The catalog crosswalk cannot
  supply it: `framework_mappings` stores the 800-171 side as prose and reaches
  14 of the 32 checks, none of them the four that were failing.

  Five checks are deliberately unmapped, in `practices.UNMAPPED` with the
  argument recorded — 800-171 has no authenticator-lifetime requirement for key
  rotation; "a Defender plan is on the Standard tier" does not say which
  protection runs; Identity Protection risk detections are not a named practice;
  Conditional Access sign-in frequency is not session termination; and 800-171
  carries no system use notification requirement, so the AC-8 check raises
  800-53 coverage without raising practice coverage. Their
  findings keep appearing in `generate_statements`' `findings_unmatched_controls`
  rather than disappearing into a zero. The practice ids and the mapped/unmapped
  split are asserted by `tests/test_check_practice_mapping_is_sound.py`.

  Practices covered, by domain: **AC** 3.1.1, 3.1.5, 3.1.8, 3.1.10, 3.1.19,
  3.1.22 · **AU** 3.3.1, 3.3.2, 3.3.8 · **CM** 3.4.1, 3.4.2, 3.4.7 · **IA** 3.5.1,
  3.5.3, 3.5.4, 3.5.6, 3.5.7, 3.5.8 · **MP** 3.8.7 · **RA** 3.11.2 · **SC** 3.13.1,
  3.13.5, 3.13.6, 3.13.8, 3.13.10, 3.13.16 · **SI** 3.14.1, 3.14.3, 3.14.6.

  The two network-boundary checks added four practices (3.4.7, 3.13.1, 3.13.6,
  3.14.6) and **no** new Moderate-baseline controls: the 800-53 ids they declare
  were already covered by other checks, and the one genuinely new id, `CM-7`, is
  not in the Moderate baseline. That is why the baseline intersection above did
  not move while the practice count did -- the two numbers measure different
  things, and this is the clearest illustration of it the coverage data has
  produced.

  The `AC-8` check is the opposite case, and the reason it was chosen: the control
  was reachable by nothing. It is deliberately **unmapped** on
  the CMMC side -- 800-171 carries no system use notification requirement, and
  the closest candidate (3.1.9, CUI-specific privacy and security notices) is
  about something else -- so it raises 800-53 coverage and not practice coverage.
  The argument is recorded in `ccf.posture.practices.UNMAPPED` rather than left
  as an omission. The practice count is unchanged at 28 of 110 for that reason.
- **An SSP reports its own system's evidence, not its organization's.** Two
  systems sharing one Microsoft 365 tenant each carry their own control tests
  and their own POA&M for a tenant-level finding, which is correct — each system
  tracks its own remediation. What was not correct was one document reporting
  both: before this was scoped, the SSP for one system stated each finding twice
  and cited the sibling system's POA&M id. A project that names no system
  (7 of 21 in the live database) still falls back to organization scope, because
  nothing else can describe it.
- **The Microsoft Graph app registration needs
  `DeviceManagementConfiguration.Read.All`** on top of the permissions the
  earlier checks required. Without it the two device-compliance-policy checks
  (AC-11 session lock, SC-28 storage encryption) report
  `manual_review_required` naming that permission — never a false pass or fail,
  but no evidence either.

  The same permission now also backs the **`inactivity_period` ODP capture**
  (800-171 3.1.10), which reads the lock timeout from the device compliance
  policy. Without the grant that parameter is simply not captured, and the SSP
  renders it as organization-defined and outstanding. That is deliberate: the
  value used to be taken from the Conditional Access *sign-in frequency* — a
  different setting on a different control — which on the live tenant put
  "inactivity period = 8 hours" under the session-lock requirement while the
  session-lock check was passing at fifteen minutes. The real value is 15
  minutes. An unfilled parameter is recoverable; a wrong one in an authorization
  package is not. The device-policy read is guarded separately from the
  Conditional Access read, so a missing Intune grant cannot discard the MFA
  capture alongside it.
- **A ready connector does not mean every one of its checks runs.** Before a
  check is scanned, the shared-responsibility template is asked who owns the
  control; only `customer` and `shared` are scanned, and a domain the template
  cannot answer is recorded as `manual_scope_review` — evidence a human must
  supply, not a verdict. So `checks_run` can be far below `checks_expected` with
  nothing failing. The scheduler's cycle line carries `posture_manual_review`
  for exactly this reason; read it before concluding a scan is broken.

  This gap hid a real defect for as long as it existed. The M365 branch of
  `responsibility_for` read only a control's CMMC coverage status, and the scan
  path — which holds NIST 800-53 ids, not CMMC practices — had none to pass, so
  *every* M365 check resolved to `manual_scope_review` on every tenant. A ready
  msgraph connector with fourteen working checks scanned none of them. M365 now
  falls back to a domain-level answer derived from the scoring placemat.

  All 42 registered checks are scannable today, and
  `tests/test_every_check_can_be_scanned.py` fails if that stops being true —
  its allowlist of unscannable checks is empty on purpose.

- **Scan scope is asked separately from who owns a control**, and the
  distinction matters if you are changing either. `responsibility_for` answers
  ownership and feeds two regulator-facing consumers: SSP control origination
  (`ssp.seed`) and SPRS scoring state
  (`governance.automation._platform_state`). Both deliberately refuse to guess,
  so an unanswered domain is flagged for a human rather than defaulted.

  That refusal used to decide scan coverage too, which left **half the AWS suite
  and all of PuppetDB producing no evidence** — root MFA, password policy,
  access key rotation and S3 public-access blocks among them, because the
  hyperscaler template declines to state an SSP origination for the whole `AC`
  and `IA` domains. Those settings are changed by nobody but the customer, so
  the ownership question was never the one the scan path needed answered.

  `ssp.responsibility.SCAN_SCOPE_OVERRIDES` now answers scan scope on its own,
  and an entry can only ever upgrade an *unanswered* domain to `scan` — a domain
  the template positively calls provider-owned or not-applicable cannot be
  opened from there. **Do not fix a scan-coverage gap by editing the
  responsibility table**: that moves SSP origination and a score reported to the
  DoD. `tests/test_scan_scope_is_not_responsibility.py` pins both halves.
- **eMASS integration is unverified against a live instance** — written from
  the published specification and exercised only against a fake.
- **AWS Security Hub attestation ingest is unverified against a live account** —
  the same status as eMASS, and for the same reason: no organization in this
  deployment has an AWS credential bound, so the code has never read a real
  findings store. What *was* verified is the API contract rather than prose: the
  operations, the `ComplianceStatus` enum (`PASSED` / `WARNING` / `FAILED` /
  `NOT_AVAILABLE`), the `Compliance.SecurityControlId` /
  `RelatedRequirements` / `AssociatedStandards` members and the `NextToken`
  pagination were read out of botocore's `securityhub` service model
  (API version 2018-10-26), not inferred. Everything else is driven against a
  stubbed boto3 session.

  Two numbers nobody should state until a real account has been read: how many
  of the 288 Moderate controls AWS's mapping actually reaches, and what share of
  `RelatedRequirements` entries Concord cannot place. Both are *measured* by the
  ingest rather than assumed — `POST /api/systems/{id}/attestations` returns
  `controls_read`, `written`, `unreadable_requirements` and
  `controls_without_a_requirement` — so the way to find out is to bind a
  credential and read the report, not to estimate from AWS's documentation.

  What the design guarantees without a live account, because each is pinned by a
  test and a mutation:

  - no status becomes a `pass` by default. `NOT_AVAILABLE`, an unrecognised
    status, a non-string status and a missing `Compliance` block all resolve to
    `manual_review_required`;
  - a truncated page walk is never published. The read reports
    `available: false` and the ingest writes nothing, leaving the previous
    complete assessment in place to go stale on its own;
  - one Security Hub control relating to several requirements becomes one row
    per requirement, so a single automated check cannot mark three controls
    satisfied;
  - a failing attestation opens no POA&M and no remediation Task, because the
    same split would file three weaknesses for one misconfigured resource. The
    verdict is still recorded in full;
  - `effective_verdict` ranks platform > attested > pack, so one of Concord's
    own checks is never overridden by an attestation and an attestation is never
    overridden by a tenant pack rule that merely ran later.

  The Microsoft half of the same idea **does not work**, and this is now measured
  rather than inferred. `secureScoreControlProfile.complianceInformation` is where
  Microsoft would publish a framework mapping — Graph's v1.0 model declares it as
  `Collection(complianceInformation)` = `[{certificationName,
  certificationControls: [{name, url}]}]`, verified against the published
  `$metadata`. Read against the live GCC High tenant (`graph.microsoft.us`,
  org 2's bound credential, all pages):

  | | |
  |---|---|
  | Secure Score control profiles | **417** |
  | with a non-empty `complianceInformation` | **0** |
  | with an 800-53 certification | **0** |
  | distinct certification names seen | **0** |

  The last row is the one that settles it. `ccf.posture.attested.securescore_mapping`
  reports *every* certification name it saw, matched or rejected, precisely so a
  wrong 800-53 matcher cannot be mistaken for absent data — and it saw none at
  all. Microsoft is not publishing ISO, PCI or anything else there either; the
  field is simply unused. (An earlier note here said "200 profiles"; that was a
  single page of results, and the real figure is 417.)

  `implementationStatus` on `controlScores` is free prose rather than a verdict,
  so it is not a substitute.

  **Consequence, stated plainly:** the "one API read, many controls" mechanism has
  no Microsoft equivalent. Raising M365 800-53 coverage beyond Concord's own
  checks requires either more native checks — each one an evaluator Concord wrote
  and can defend — or hand-authoring a crosswalk from Microsoft's product
  taxonomy, which would be roughly sixty compliance assertions Concord makes
  itself, at `platform` trust rather than provider-attested. Re-run the
  measurement against any other tenant before committing to the second: the
  function takes profiles and returns the table above.
- **FedRAMP-assigned ODP values are not in the data.** Parameters carry their
  label, guidance and choices from the catalog; FedRAMP's own assigned values
  are not available to import.
