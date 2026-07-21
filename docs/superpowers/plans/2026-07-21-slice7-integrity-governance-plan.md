# Slice 7 — Integrity & Governance Hardening — Implementation Plan

Clears go-live conditions 1, 2, 3, and 5 from the production-readiness recommendation:
evidence integrity (IA-07/08), external-portal referential integrity (DATA-02),
per-org connector credentials (IA-05), and approval-gating / SoD (ISSM-08/09).
Tasks run **sequentially** (migrations chain; some share files). Confirm the current
Alembic head with `alembic heads` before each migration (starts at `0041`).

## Global Constraints

- **Test DB:** `PYTHONPATH=src`, `CCF_DATABASE_URL=postgresql+asyncpg://ccf:ccf@localhost:5433/ccf_test`,
  `CCF_DATABASE_URL_SYNC=postgresql+psycopg://ccf:ccf@localhost:5433/ccf_test`.
- **Migrations:** confirm head with `alembic heads` against the ccf DB; set `down_revision`
  to it; verify up → down → up. For a data-affecting migration, handle existing rows safely
  (orphans/dupes) so it can't fail on real data.
- **TDD**, production-path tests (real records / real functions). Reuse existing vocabularies.
  `ruff` + `mypy` clean on changed files. **Keep the full suite deterministic** — any test
  that seeds GLOBAL/reference rows (ScoringControl, Ksi, FrameworkControl, Control, …) MUST
  clean them up (prior slices leaked such rows; use a try/finally or fixture teardown). The
  only acceptable full-suite failure is the known-flaky
  `test_enterprise.py::test_audit_chain_verifies_and_detects_tampering` (passes in isolation).
- Widened guardrail: run the related suites; fix a stale assertion only when your change
  correctly supersedes it; STOP + report a real regression.

## Task 1 — IA-07: Verify evidence integrity hash on read

**Files:** `src/ccf/evidence/service.py` (+ tests).

**Problem:** `add_version` stores a SHA-256 of the bytes, but `read_version` returns the
bytes with no digest re-check, so a tampered/corrupted blob is served as authentic.

**Requirements:**
1. In `read_version` (read the real function), recompute `sha256(data)` and compare to the
   stored digest before returning; raise a clear integrity error on mismatch. Verify the
   stored-digest field name and the storage read path (`storage.py`).
2. Expose the check where reproducibility/replay reads evidence too, if cheap.
3. Do not change the write path or the storage backend.

**Acceptance:** reading an untampered version returns the bytes; corrupting the stored blob
makes `read_version` raise an integrity error. Test with a real local-storage round-trip.

## Task 2 — IA-08: Make WORM honest (enforce backend; S3 retain-until)

**Files:** `src/ccf/evidence/storage.py`, `src/ccf/evidence/service.py`, `src/ccf/config.py`
(+ tests).

**Problem:** the default `LocalStorage` is a plain filesystem write with no immutability, and
the S3 `ObjectLockMode="COMPLIANCE"` path sets no `ObjectLockRetainUntilDate`, so WORM is not
demonstrably enforced.

**Requirements:**
1. When an evidence object is marked immutable/WORM but the backend is `local`, either refuse
   the WORM claim or emit a clear warning + record that WORM is NOT storage-enforced (don't
   silently claim immutability). Read how `immutable_lock`/object-lock is requested today.
2. For the S3 path, add `ObjectLockRetainUntilDate` derived from the retention policy (read
   `evidence_retention_policies`/config) so a COMPLIANCE lock is actually valid; do not call
   S3 with an incomplete lock.
3. Document (config/docstring) that true WORM requires `evidence_backend=s3` + object lock.

**Acceptance:** requesting WORM on the local backend yields a clear non-enforced signal (not a
false immutability claim); the S3 put includes a retain-until date. Test the local-warning
path and the S3 argument construction (mock boto3 — no real S3).

## Task 3 — DATA-02: External-portal share foreign keys

**Files:** `src/ccf/models_portal.py`, a new migration (+ tests).

**Problem:** `external_package_shares.package_id` and `external_evidence_shares.evidence_object_id`
are plain integers with no FK, so a share can reference a deleted/foreign artifact and dangles
when the artifact is deleted. This is the highest-exposure surface (external portal).

**Requirements:**
1. Add real FKs: `package_id → ccf.authorization_packages.id ON DELETE CASCADE`;
   `evidence_object_id → ccf.evidence_objects.id ON DELETE CASCADE` (verify the real target
   tables/PKs). Update the ORM `mapped_column(..., ForeignKey(...))` too.
2. The migration MUST first delete any share rows whose `package_id`/`evidence_object_id`
   does not exist in the parent (orphans), so the FK can be created on real data. Do the
   cleanup in `upgrade()`.
3. Verify up → down → up.

**Acceptance:** inserting a share with a non-existent package/evidence id fails with an
IntegrityError; deleting the parent removes the share. Test both.

## Task 4 — ISSM-08 & ISSM-09: Approval-gate POA&M closure and risk acceptance

**Files:** `src/ccf/api/routes/poams.py`, `src/ccf/api/routes/risks.py`,
`src/ccf/governance/approvals.py` (read only, to reuse) (+ tests).

**Problem:** closing a POA&M and accepting a risk require no approval precondition and no
validation; SoD is unenforced. (ISSM-09 also: POA&M closure has no evidence/milestone gate.)

**Requirements:**
1. Read `governance/approvals.py` to reuse the existing Approval mechanism (entity_type
   'poam'/'risk'). Make **POA&M closure** require completed milestones OR a linked
   evidence/closure artifact (verify what's available) AND, when auth is enabled, an approval
   by a principal different from the author (SoD). When auth is off (single-operator), keep
   working but record the gap honestly (do not fake an approval).
2. Make **risk acceptance** (`status='accepted'`) require an owner + an expiration/next-review
   date AND, when auth is enabled, an AO approval; block the transition (409) otherwise.
3. Do not invent new approval tables; reuse Approval. Keep existing non-terminal edits working.

**Acceptance:** closing a POA&M with an open milestone and no evidence is rejected; accepting a
risk without owner+expiry (and, auth-on, without an AO approval) returns 409; a properly
approved/validated transition succeeds. Tests cover the reject and success paths.

## Task 5 — IA-05: Per-organization connector credentials

**Files:** `src/ccf/connectors/*` (base + resolution), `src/ccf/governance/collection.py`,
possibly `connector_configs` model + a migration if a credential column is needed
(+ tests). REUSE the Slice-3a cipher (`src/ccf/ai/cipher.py` — `build_cipher`/`CredentialCipher`)
for encrypting connector secrets at rest; do NOT store connector creds in plaintext.

**Problem:** connectors use a single global env credential set for all tenants, and
`collect_all` stamps every capture with the caller's org_id — so an org's SSP evidence can be
sourced from a different (platform) cloud tenant.

**Requirements:**
1. Store connector credentials **per organization** (on `connector_configs` — read the model;
   add an encrypted-credential column + migration if needed, reusing `ccf.ai.cipher`). Resolve
   the org's own credential at capture time; **refuse capture** (clear "not configured for this
   org") when the org has no bound credential rather than silently using the global one.
2. `collect_all`/the scheduler path must attribute captures to the org whose credential was
   used, and not run a global credential under an org's identity.
3. Keep the existing connector interface + M365/AWS providers working; degrade to manual review
   without creds (as today) but per-org.

**Acceptance:** capture for an org without bound credentials returns "not configured" and writes
nothing; a capture for a configured org ties its snapshot to that org and uses that org's
credential; the stored credential is encrypted, never plaintext. Tests cover the not-configured
refusal and the per-org attribution (mock the provider; no real cloud calls).
