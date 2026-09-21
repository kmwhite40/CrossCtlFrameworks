# 3PAO engagements — design

**Status:** design 2026-09-21. Makes a 3PAO a real Concord user class by
extending the external portal, not the internal role enum.

**Depends on** migration `0082_pipeline_stage` (current head).

---

## 1. Why the portal and not the role enum

A 3PAO is an independent assessment firm. Two facts decide the whole design:

- **It is external to the CSP.** `User.organization_id` is a single
  non-nullable FK (`src/ccf/models.py:295`), so an internal user belongs to
  exactly one organization and there is no membership table. A 3PAO modelled as
  a fifth `user_role` could therefore serve exactly one CSP — and FedRAMP's
  independence requirement is precisely that the assessor is *not* of the CSP.
- **Its access ends.** An engagement has a period. A role flag has none; it is
  granted once and persists until somebody remembers to remove it.

`src/ccf/models_portal.py` already holds the right shape: an
`ExternalPrincipal` that "never gets an internal Concord account", an
`ExternalAccessGrant` with a hashed bearer token, an expiry, a revoked flag
and a scope, and an immutable `ExternalPortalAuditEvent`. Its docstring already
names `assessor` as one of three kinds.

**So this is not a new subsystem. It is finishing one that stops short of what
a 3PAO needs.** Sections 2–6 are the four gaps.

### 1.1 The internal `assessor` role stays exactly as it is

`user_role` keeps its `assessor` member. That role is the **CSP's own
assessment staff** — an internal employee who reads the audit log and the
boundary endpoints. A 3PAO is a different party and gets a different mechanism.
Nothing in this change touches `require_role("assessor")` anywhere.

The two must not be merged. Merging them would put an independent firm inside
the tenant's own user table, which is the one thing independence forbids.

### 1.2 This does not reopen the `advisor`/`assessor` CR26 deliverables

Those were ruled out of scope because they are published by assessment firms
about themselves on their own websites, carry no
`certificationPackageOverviewUri`, and describe a firm rather than a system.

Making a firm a Concord user class weakens only the third reason. The first two
stand, so the ruling stands. Recorded here because the decision visibly touches
it and a silent non-decision would look like an oversight.

---

## 2. `kind` is a vocabulary that is not one

`ExternalPrincipal.kind` and `ExternalAccessGrant.kind` are
`String(16)` with the vocabulary in a **trailing comment**:

```python
kind: Mapped[str] = mapped_column(String(16), default="customer")  # customer|assessor|vendor
```

Measured: nothing validates it and nothing branches on it. It is stored, echoed
back in three API responses, and never read for a decision. `kind="assesor"`
stores fine and behaves identically to every other value.

This is the `issm`/`isso` defect in a different table — an authorization-adjacent
vocabulary that exists only in prose, where a typo is indistinguishable from a
real member. The same repo already does this correctly one file away:
`models_packages.py:30` declares `PACKAGE_KINDS` as a tuple.

**`EXTERNAL_PRINCIPAL_KINDS = ("customer", "assessor", "vendor")` moves to
`src/ccf/constants.py` and is enforced** at the service layer, with 422 at the
route. Not a Postgres enum: these are existing `String(16)` columns holding
unknown values in live databases, and a migration that converts them would fail
on the first row that is neither of the three. The migration must **report**
what it found rather than refuse — see §7.

Once `kind` means something, `assessor` can carry the rules in §3–§5.

---

## 3. The engagement is the unit, not the grant

A grant is a **credential**: one token, one expiry. An engagement is a
**relationship**: this firm assesses this system over this window. One
engagement outlives several grants — a token rotates, a second assessor from
the same firm joins — and ending the relationship must end all of them at once.

```python
class AssessmentEngagement(Base):
    __tablename__ = "assessment_engagements"

    id: int
    organization_id: int          # the CSP tenant
    system_id: int                # what is being assessed. NOT NULL
    assessor_principal_id: int    # FK external_principals, kind must be "assessor"
    period_from: datetime         # NOT NULL
    period_to: datetime           # NOT NULL
    authorized_by: str | None     # the internal admin who created it
    independence_note: str | None # what the platform observed (§5)
    revoked_at: datetime | None
    created_at: datetime
```

`ExternalAccessGrant` gains a nullable `engagement_id`. Nullable because every
existing customer and vendor grant has none and always will.

**`system_id` is NOT NULL and is the point.** Today a grant has no system at
all — it is a hand-picked list of package and evidence ids. "This firm assesses
this system" is not expressible, which is why a 3PAO cannot currently be
modelled without it.

---

## 4. An engagement-backed grant must expire, and cannot outlive its engagement

Measured, `create_grant(ttl_days=None)` stores `expires_at=None`, and
`_valid()` (`src/ccf/portal/service.py:145`) treats a null expiry as valid:

```python
if grant.expires_at is not None and grant.expires_at < _now():
```

So a grant can be issued that **never expires**. For a customer share that may
be deliberate. For an assessment credential it is wrong: the engagement has an
end date, and a credential that outlives it is access with no remaining reason.

**Rules, in order of how they fail:**

1. An engagement-backed grant with `ttl_days=None` is **refused**, not
   defaulted. Silently substituting a TTL would put an expiry nobody chose on a
   federal assessment credential.
2. Its `expires_at` is **capped at `period_to`**. A caller asking for 90 days on
   a 30-day engagement gets 30, and is told.
3. Revoking the engagement sets `revoked_at` and **revokes every grant under
   it**. One action ends the relationship.
4. `_valid()` additionally rejects a grant whose engagement is revoked or whose
   `period_to` has passed, **even if the grant's own expiry has not**. The
   engagement is the authority; the token merely carries it.

Rule 4 is the one that needs a test most: rules 1–3 are enforced at issuance,
so a row written before this change, or by a future code path that forgets,
still gets caught at resolution.

---

## 5. Independence is named, never refused

FedRAMP requires the 3PAO be independent of the CSP. **Concord cannot verify
that** — independence is a matter of ownership, contracts and staffing that no
field here records.

It can observe exactly one signal: whether the assessor principal's email
domain, or its `organization_name`, matches the CSP tenant's own. That is weak
evidence in both directions — a legitimate assessor may use a shared mail
domain, and a genuinely conflicted one may not.

So the platform **records what it saw in `independence_note` and never
blocks**. This follows the SCN rule already settled in this programme
(`2026-09-19-cr26-scn-design.md` §2.1): *"check, name, and never refuse"* — an
observation worth telling an operator about is not a thing worth blocking a
federal engagement over. Refusing on a domain match would make a real
engagement unrecordable on evidence that does not support the conclusion.

`independence_note` is an observation, phrased as one. It must not be phrased as
a finding, a warning or a conflict — the platform is reporting a string match,
not an opinion about the firm.

---

## 6. Scope follows the system

An engagement-backed grant does not carry a hand-picked `package_ids` list. Its
contents resolve through `system_id`: `AuthorizationPackage.system_id`
(`src/ccf/models_packages.py:45`) already ties a package to a system.

**Rejected: keeping the hand-picked list for assessors.** Two failures it
permits, both silent. An operator who builds a new package mid-assessment must
remember to re-share it, and nothing says they did not. And a package belonging
to a *different system in the same tenant* can be added to an assessor's grant
by mistake — a cross-system disclosure that the portal's tenant isolation does
not catch, because both systems are in the same tenant. Resolving through
`system_id` makes both unrepresentable rather than merely discouraged.

**Consequence, stated because it is a widening:** an assessor sees packages
created after the engagement starts. That is deliberate — an assessment is of a
system, not of a snapshot — and `period_to` is what bounds it. A test must pin
this so it stays a decision rather than becoming an accident.

Evidence sharing keeps its explicit list. Evidence objects are not
system-scoped in the same way, and narrowing is the safe direction.

---

## 7. The migration reports what it cannot convert

Constraining `kind` (§2) meets rows that already exist. The migration must
**count and report** values outside `EXTERNAL_PRINCIPAL_KINDS` rather than
fail, and leave them untouched: refusing to migrate would block an upgrade over
data an operator cannot see, and rewriting them would destroy the record of what
was there.

Enforcement is at the service layer, on write. Existing odd rows keep working
and are visible; new ones cannot be created.

---

## 8. Testing requirements

1. **An engagement-backed grant with no TTL is refused** — `ValueError` at the
   service, 422 at the route. Asserted on the error, not just the status.
2. **A grant's expiry is capped at `period_to`**, and the caller is told it was
   capped — asserted on the returned value, not only on the stored row.
3. **Revoking an engagement kills every grant under it**, including ones issued
   after the first. Seed two, revoke, assert both resolve to `None`.
4. **A grant whose engagement has ended is rejected at resolution even though
   its own `expires_at` is in the future.** Write the row directly to bypass
   issuance, so the test exercises rule 4 and not rule 2. This is the most
   important test in the change.
5. **An assessor grant cannot reach another system's packages**, including one
   created after the engagement began. Two systems in *one* tenant — the
   tenant-isolation tests do not cover this and would pass regardless.
6. **A package created mid-engagement IS visible** (§6), pinning the widening as
   a decision.
7. **An invalid `kind` is refused at the service and 422 at the route**, and
   `EXTERNAL_PRINCIPAL_KINDS` is asserted against a literal so a silent edit
   fails.
8. **A domain match produces a note and does not block** — the engagement is
   created, `independence_note` is populated, and a second engagement with no
   match has it `None`.
9. **Every `AssessmentEngagement` field crosses the HTTP boundary.** On the
   CR26 modules, deleting result fields from a route left the whole suite green;
   assume the same here until proven otherwise.
10. **Migration round-trips**, and an out-of-vocabulary `kind` row survives
    upgrade and is counted (§7).

Mutation-verify rules 1–4 and 5: remove each guard, confirm a test fails.

---

## 9. Out of scope

- **Attestations and findings authored by the 3PAO.** `ExternalComment` already
  takes `target_type="finding"`, so a 3PAO can comment today. A formal signed
  attestation is a deliverable with its own evidentiary weight and belongs in
  its own spec.
- **A cross-tenant firm identity.** An assessor working for three CSPs gets
  three `ExternalPrincipal` rows, one per tenant. That is deliberate: a single
  shared firm identity would let one CSP's existence leak into another's view,
  and the portal's guarantee is that it "cannot leak across tenants"
  (`models_portal.py:6`).
- **Verifying independence** (§5). Concord observes; it does not conclude.
- **Changing the internal `assessor` role** (§1.1).
- **The `advisor`/`assessor` CR26 deliverables** (§1.2).
