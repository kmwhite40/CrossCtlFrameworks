# Concord — handbook

Two parts, for two readers.

- **[Part I — Engineering and operations](#part-i--engineering-and-operations)**,
  for engineers joining this codebase and anyone running a deployment.
- **[Part II — Working in Concord](#part-ii--working-in-concord)**, for the
  people doing compliance work in the product.

This is the one document to read first. It covers what Concord is, how to run
it, how the code is shaped, **the invariants that will bite you**, and how work
is done here. Everything else is linked from the last section.

Measured at `main` on 2026-09-24. Where this document quotes a number, it was
counted, not remembered.

---

# Part I — Engineering and operations

## 1. What Concord is

A compliance platform for organizations pursuing FedRAMP, CMMC and NIST
authorizations. A customer defines what compliance means for them, authorizes a
system against it, operates the programme day to day, and files the resulting
documents — without leaving the product.

The output is **documents a federal regulator acts on**: system security plans,
assessment reports, plans of action and milestones, OSCAL packages. That single
fact drives nearly every convention in this handbook. A bug here is not a
crash; it is a true-looking sentence in a filing.

| | |
|---|---|
| Stack | Python 3.12, FastAPI, SQLAlchemy 2, PostgreSQL, Alembic |
| Frontend | Jinja2 + htmx + Alpine, server-rendered. **No build step, no `package.json`** |
| Surface | 322 API paths, 113 server-rendered paths, 28 CLI commands |
| Schema | 83 mapped models, 84 migrations, single Alembic head |
| Tests | 332 files, 96,403 lines against 77,063 lines of application code |

---

## 2. Running it

```bash
docker compose up -d --build       # db, migrator, api, workers
open http://localhost:8088
```

Services: `db`, `migrator`, `api`, `etl`, `cli`, `poller`, `prep-worker`,
`assessment-worker`.

**Ports, and one that is not ours.** The dev database is on **5433** and the
test database on **5434**. Port 5432 belongs to an unrelated project's
container on this machine and must be left alone — a future "fix" that frees
5432 breaks somebody else's work.

**Tests** need the test database and run one session at a time:

```bash
.venv/bin/pytest -q                # 6-10 minutes
```

That range is machine load, not variance in the code: the fastest and slowest
runs measured on the same commit differed by four minutes.

Never run two pytest sessions at once. The session fixture drops and recreates
the schema, so a concurrent run corrupts the other's results — and the way it
shows up is not obviously a concurrency problem. See §4.7.

---

## 3. The shape of the code

`src/ccf` is one package with 34 subpackages. The large ones, by line count:

| Package | What lives there |
|---|---|
| `api` | HTTP routes, templates, auth dependencies, audit middleware |
| `governance` | control tests, waivers, automation, insights, conmon |
| `cr26` | FedRAMP CR-26 deliverables (SDR, CPO, VER family, OCR) |
| `posture` | live provider checks, resource findings, drift |
| `ssp` | system security plan drafting, platform catalogues, completeness |
| `prep`, `assessment` | evidence preparation and assessment workflow |
| `connectors` | AWS, Azure ARM, Microsoft Graph, PuppetDB capture |
| `catalog`, `etl`, `cci` | the control catalog and how it is loaded |
| `identity` | OIDC, SCIM, TOTP, PIV/CAC |
| `ai`, `ai_actions`, `ai_governance` | the typed AI action path and its guardrails |

Models are split across `models.py` and `models_<domain>.py` files. Migrations
are `migrations/versions/NNNN_<name>.py`, strictly sequential.

---

## 4. The invariants that will bite you

This is the section worth reading twice. Every item cost somebody real time.

### 4.1 `ccf.controls` is not a table of controls

It holds assessment **objectives** (`AC-01a.01(a)[01]`), **ODP placeholders**
(`SA-11(02)_ODP[03]`) and **row markers** (`AU-06(07)#row906`) alongside actual
controls. Counting rows overstates controls by roughly **four times**.

FedRAMP High is 2,673 rows and **409** distinct controls. A Moderate-to-High
uplift is **87** controls, not the 387 a row count gives.

Always normalise through `catalog.canonical.canonicalize`. It is the single
identifier normaliser; catalog identifiers are zero-padded (`AC-01`), canonical
form is not (`AC-2`). Do not write a second one.

### 4.2 Row-level security hides the thing your test is checking

`api/deps.get_session` binds the PostgreSQL tenant for the request, so RLS
already blocks cross-tenant reads. **A cross-tenant test driven over HTTP
therefore cannot tell an application-layer organization predicate from the
database policy** — it passes either way.

Nineteen of thirty-eight cross-tenant tests were unable to fail for this
reason. Pin scoping assertions on an unscoped `session_scope()`, and first
assert the other tenant's rows *are* visible without the predicate, so the
negative below it means something.

### 4.3 The test environment makes every caller a global principal

`conftest.py` sets `CCF_ENV=test`, and `config._DEV_ENVS` counts `test` as
development. So the whole suite runs the permissive branch of every
`is_dev_env` gate, and `require_role(...)` resolves to `SYSTEM_PRINCIPAL`,
whose `org_id` is `None`.

Every organization predicate written `if principal.org_id is not None` is a
no-op under those conditions. If you are testing scoping, set
`CCF_AUTH_ENABLED=true` and authenticate as a real user, or your assertions
pass against the wrong behaviour. This has happened more than once.

`tests/test_production_env_gates.py` exists to drive the strict branch of
these gates deliberately.

### 4.4 Session tokens carry no audience claim

`auth.sign_session` / `read_session` mint `{uid, exp, sv}` signed with
`auth_session_secret`. **Anything signed with that secret verifies as a login
session**, whatever cookie name it is stored under.

Any new token type needs its own **derived** key:

```python
hmac.new(base_secret.encode(), b"<purpose>-v1", hashlib.sha256).hexdigest()
```

Two already do this — portal grants and the half-authenticated MFA cookie — and
both were written because the alternative was account takeover. Derivation
rather than an audience claim, because a claim check fails **open** the first
time a reader forgets it, while a derived key fails closed.

### 4.5 A default that resolves to a product name is a claim

`normalize_platform` returns `None` for a platform Concord does not recognize,
and that is deliberately **not** the same as `"none"`, which means the customer
told us they have no cloud platform. Collapsing the two once produced system
security plans describing Microsoft 365 for customers who run nothing of the
kind.

The same shape recurs: a value that validates and is wrong. Ask "is this true?"
rather than "does this validate?" — especially of an empty array, which in a
compliance deliverable usually asserts *none occurred* rather than *no data*.

### 4.6 A guard that authorizes without resolving scope

If an authentication dependency answers "may this caller in?" without answering
"to which tenant?", assume every route beneath it is unscoped until you have
read each one. SCIM's guard returned `None` and five routes each invented their
own scope; none of them had one.

### 4.7 Diagnosing a suite failure

Before debugging, run `pgrep -f pytest`. A second session against the same
database produces deadlocks **and** failures in unrelated modules — any
assertion written against an unscoped query (`== []`, `count == N`) breaks that
way. The unrelated failure is the dangerous symptom, because it looks like a
real defect.

Other stock signatures:

- **Every test ERRORs** with `Can't locate revision` → the shared test database
  is stamped from another branch. Recreate it; conftest re-migrates.
- **Every test errors on connection refused** → Docker is down, or
  `ccf-test-db` exited.

---

## 5. Configuration

100 settings in `src/ccf/config.py`, all `CCF_`-prefixed. The ones that change
behaviour most, and their fail-closed defaults:

| Setting | Default | Effect |
|---|---|---|
| `CCF_AUTH_ENABLED` | off | **An unconfigured instance is unauthenticated.** |
| `CCF_ENV` | — | `dev`/`local`/`test` take the permissive branch of every gate |
| `CCF_AI_CREDENTIAL_MASTER_KEY` | unset | Required to store any secret, including authenticator secrets |
| `CCF_SCIM_ENABLED` | off | With `CCF_SCIM_ORGANIZATION_ID` required on multi-tenant |
| `CCF_PIV_ENABLED` | off | **`CCF_PIV_TRUSTED_PROXIES` empty refuses to enable** |
| `CCF_OIDC_ORGANIZATION_ID` | unset | Required on multi-tenant, or new-user creation is refused |

The pattern throughout: **an unset restriction is the closed case, not the open
one.** Where that is not obvious, the code says why at the refusal.

---

## 6. Operating it

**Runbooks** in `docs/runbooks/` cover ingestion failure, header-contract
mismatch, catalog drift, index corruption, system-profile automation, and
Windows packaging. They were verified against the code on 2026-09-24; every
path and command they name exists.

**Rotating the credential master key** — the procedure that is easy to get
wrong, because before it existed changing the key orphaned every stored secret:

1. Set `CCF_AI_CREDENTIAL_PREVIOUS_KEYS` to a JSON array holding the **old**
   key, and `CCF_AI_CREDENTIAL_MASTER_KEY` to the new one.
2. `ccf keys-rewrap` — moves every stored secret onto the current key and
   reports anything it could not read, with the key id to restore.
3. `ccf keys-status`, then drop the old key from the environment.

Rewrapping is never lazy. A read path that re-encrypts can roll back while an
operator believes rotation finished, and it makes "is it done?" unanswerable.

**Scheduled work** runs through `ccf scheduler`, `ccf conmon-scan`,
`ccf notify-digest`, `ccf packs-sync` and the two workers.

---

## 7. How work is done here

The conventions are not ceremony; each one was adopted after the absence of it
shipped a defect.

**Measure before designing.** Query the database, read the call sites, count
the rows. Several specs in `docs/superpowers/specs/` carry a "Correction
(implementation)" block where a measurement disproved the author's premise —
that is the process working, and those blocks stay.

**Write the spec, then the failing test, then the code.** Specs live in
`docs/superpowers/specs/YYYY-MM-DD-<topic>-design.md`. 51 of them.

**Mutation-verify every guard.** Delete the check, confirm a named test fails,
put it back. A guard whose removal leaves the suite green is not protecting
anything. This routinely finds tests that could never fail — a loop over an
empty registry, a fixture drifted so an assertion compares against `None`, an
assertion on a spelling that never existed.

A mutation that survives because a *second* guard now covers the case is
redundancy, not a gap. Report it; do not weaken the test to keep it caught.

**Review the whole branch, not just the tasks.** On fourteen stacked pull
requests, every one carried a defect its own per-task review had missed, and
almost all of them lived in a seam *between* tasks. The most recent example: a
certificate login path where every piece was correct and nothing in the
application could create the link they all depended on.

**Say what you could not do.** A claim the platform cannot defend is omitted
and named, never approximated. That applies to commit messages and
documentation as much as to generated documents.

---

## 8. Where everything else is

| Document | Covers |
|---|---|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | subsystem boundaries and request flow |
| [`DATA_MODEL.md`](DATA_MODEL.md) | the schema and its relationships |
| [`DESIGN.md`](DESIGN.md) | the visual design system and its tokens |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | assets, STRIDE, accepted risks, key rotation, PIV trust boundary |
| [`PRODUCT_STRATEGY.md`](PRODUCT_STRATEGY.md) | where the product is going |
| [`portal.md`](portal.md), [`self-assurance.md`](self-assurance.md) | the external portal, and Concord assessing itself |
| `runbooks/` | operational procedures |
| `superpowers/specs/` | why each feature is shaped the way it is |
| `concord-build-level-report-2026-09.html` | the customer-facing build-level report |

**If a figure in one of these disagrees with the repository, the repository
wins and the document is stale.** Several were, and were corrected rather than
worked around.


---

# Part II — Working in Concord

**For:** compliance staff, system owners, control owners and security leads who
use Concord to get a system authorized and keep it that way. No engineering
knowledge assumed.

---

## 9. Who you are in the system

Four roles. Yours decides what you can change, not what you can see.

| Role | Can |
|---|---|
| **viewer** | Read everything in your organization. Change nothing. |
| **control_owner** | Everything a viewer can, plus write the control implementations, evidence and POA&Ms you own. |
| **assessor** | Record assessment results and findings. The role a 3PAO's people hold. |
| **admin** | All of the above, plus users, connectors, settings and external portal access. |

You only ever see your own organization's data. That is enforced twice — in the
application and in the database — so a link to another organization's record
does not resolve, it 404s.

---

## 10. The five areas, and what each is for

The left rail groups everything by where you are in the authorization
lifecycle. If you are hunting for a page, work out which of these you are doing.

| Area | You are answering |
|---|---|
| **Dashboard** | "Where does my programme stand this morning?" |
| **Compliance** | "What does compliance mean for us?" — controls, frameworks, coverage, crosswalks, packs |
| **Authorization** | "Is this system authorized?" — intake, SSP builder, assessments, scoring, FedRAMP 20x |
| **Operations** | "What is happening today?" — evidence, control tests, POA&Ms, risks, connectors, personnel, vendors, the audit workspace |
| **Insights** | "What do I tell someone else?" — reports, the executive dashboard, trust center, external portal, audit trail |

Three destinations are pinned above the groups because people need them from
anywhere: **Executive**, **FedRAMP 20x** and **AI governance**. Users, Settings
and the API docs sit at the foot of the rail.

---

## 11. Your first system, in six steps

Open a system and Concord shows you a guided path. Each step is a door: it
takes you to the page where that work actually happens.

1. **Answer the intake questionnaire.** Who owns the system, what it handles,
   which cloud platform it runs on. Everything downstream is derived from these
   answers, so this is the one step worth slowing down for.
2. **Connect your evidence sources.** A connector captures configuration from
   your cloud or identity provider automatically. If Concord ships no connector
   for your platform, this step says so rather than sitting red forever — you
   are not failing a step there is nothing to do.
3. **Generate and refine the SSP.** Concord drafts a system security plan from
   your intake answers and the control catalog. It drafts; you confirm.
4. **Close the gaps.** Controls with no implementation, no evidence, or an
   implementation nobody has written up.
5. **Produce the package.** The machine-readable authorization package: system
   security plan, assessment plan, assessment report, plan of action and
   milestones, and component definition, as one download.
6. **Bring in your 3PAO.** Issue the assessor scoped, expiring access to the
   package and the evidence behind it.

### Reading a step's state

| State | Means |
|---|---|
| **done** | Concord can see the work finished. It never guesses this one. |
| **in progress** | Started, not complete. |
| **not started** | Nothing on record, and there is something to do. |
| **unknown** | Concord cannot tell. **Not the same as "not started"** — it is a statement about what Concord knows, not about you. |
| **not available** | Nothing to do here for this system, e.g. no connector exists for your platform. |

That distinction between *unknown* and *not started* runs through the whole
product. A blank where Concord has no information never renders as a failure on
your part.

---

## 12. The day-to-day loops

Once a system is authorized, four things recur.

**Evidence.** Upload or capture it, review it, and it is versioned. Evidence
expires; the dashboard tells you what is going stale before an assessor finds
it. Connector-captured evidence refreshes itself — that is the point of
connecting a source.

**Control tests.** Assertions checked continuously against captured
configuration. A test reports per-resource findings, not one verdict per
control, so "mostly passing" is visible rather than rounded to a fail.

**POA&Ms.** A finding that is not fixed today becomes a plan of action with an
owner and a date. Statuses are `open`, `in_progress`, `completed`,
`risk_accepted` and `closed`. Scan imports open and close them automatically as
findings come and go.

**Tasks and alerts.** The governance overview is the work queue: what is
assigned to you, what is overdue, what changed in a framework you follow.

---

## 13. When something fails and you accept it

This is the part worth reading carefully, because it is the part people get
wrong.

A **waiver** records that your authorizing official accepted a finding. It goes
`requested` → `approved`, and can be `revoked`. An approved waiver **suppresses
the consequence — the alert, the task, the POA&M — and never the evidence.**

The finding stays recorded. The control still reports as failing. The
assessment still shows it. What stops is the daily noise, because somebody
senior decided this risk is accepted.

Two things follow that surprise people:

- **A waiver never makes a failure read as a pass.** If it did, your own
  reporting would be lying to you.
- **A waiver expires.** An expired one stops suppressing and the alerts return,
  with nothing having changed except the date. That is deliberate: an accepted
  risk that nobody revisits is an accepted risk nobody is managing.

Partial waivers work too — accept one failing resource, and the others still
alert.

---

## 14. Working with an external assessor

Your 3PAO does not get an account in your organization. They get a scoped,
expiring credential into an external portal that shows only what you shared.

Concord distinguishes three kinds of external party: **customer**, **assessor**
and **vendor**. An assessor is tied to an *engagement* — this firm, assessing
this system, for this period — so "who were they and what were they entitled to
see" is answerable afterwards.

Revoking access, or an engagement ending, cuts it off immediately. Those are
different reasons and the portal says which.

---

## 15. What Concord will not do for you

Worth knowing up front, because it is deliberate and it is what makes the
output defensible.

- **It will not invent a fact to fill a field.** Where it cannot support a
  value, it omits it and names what is missing, rather than approximating.
  A blank with a reason beside it is the product working.
- **It marks its own drafts.** Machine-written narrative carries a `[DRAFT]`
  marker until a person edits it. Your reviewers can tell which sentences
  nobody has read.
- **It does not claim evidence it has not seen.** If no connector captured
  anything for a system, its documents say the evidence is manual — even where
  Concord ships a connector for that platform, if *your* tenant is not
  capturing with it.
- **It will not tell you a control passes because a risk was accepted.**
  See §13.

If a page shows you less than you expected, look for the sentence explaining
why. There is almost always one, and it is usually the answer.
