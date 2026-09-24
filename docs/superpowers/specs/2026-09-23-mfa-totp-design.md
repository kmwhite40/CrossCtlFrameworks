# Multi-factor authentication — TOTP

**Status:** design 2026-09-23. Concord has no second factor of its own. This
adds one for password login, and nothing else.

---

## 1. Measured

There is no MFA in `src/ccf`. Every match for `mfa`, `totp`, `webauthn` or
`two-factor` is either SSP narrative text (`ssp/platforms.py` describing *a
customer's* Entra ID) or a connector detecting *another system's* Conditional
Access policy. Concord authenticates a human with an email and a password, and
that is all.

What is already right, and is not being changed:

| Concern | State |
|---|---|
| Password hashing | PBKDF2-HMAC-SHA256, 210,000 rounds — FIPS-approved, meets current guidance |
| Credential encryption | AES-256-GCM envelope, `KeyProvider` already abstracted for a KMS |
| Lockout | AC-7 lockout is implemented **once**, in `api/login_service.py`, shared by both surfaces |
| Session revocation | `session_version` bump invalidates every issued token (AC-12) |

So this is an addition, not a repair. The roadmap item that contained it also
named FIPS-validated cryptography: the algorithms above are already
FIPS-approved, and what remains there is running against a validated module,
which is a deployment concern and not in this spec.

---

## 2. Scope

**TOTP only** (RFC 6238), as the one factor that needs no hardware, no vendor
and no outbound network path. Deliberately excluded:

- **SMS and email codes.** NIST SP 800-63B restricts SMS as a restricted
  authenticator. Adding a weak factor and calling the control satisfied would
  be the claim-versus-rendering defect in an authentication system.
- **WebAuthn / PIV-CAC.** Both are wanted and neither is this change. PIV-CAC
  in particular is terminated at the edge and is deployment infrastructure
  before it is application code.

**Password login only.** A user who signs in through OIDC has already been
authenticated by their identity provider, and a second factor is that
provider's to enforce. Concord re-prompting would be theatre: it holds no
evidence about how the IdP authenticated anyone.

**API tokens are unaffected.** They are not interactive authentication and
have no human present to challenge. This is a real limitation and is stated
in §9 rather than hidden.

---

## 3. The half-authenticated state is the whole risk

Between a correct password and a correct code the user is partly
authenticated, and that state has to be carried across a request boundary.

`sign_session`/`read_session` **carry no audience or type claim** (`auth.py:91`
and `:116`). A pending token minted with the same function and the same secret
would therefore verify as a full session cookie. Password alone would be
enough: the second factor would be a redirect a caller could simply skip.

**The codebase has already solved this once and the answer is reused.**
`api/routes/portal.py:73` derives a portal signing key with
`HMAC(auth_session_secret, "ccf-portal-session-v1")`, and its docstring states
the reasoning exactly: two id spaces both starting at 1, no audience claim,
therefore full account takeover by replaying one cookie under the other name.

The pending token is signed with `HMAC(auth_session_secret,
"ccf-mfa-pending-v1")`. A pending value's HMAC never verifies under the session
secret, so it cannot be presented as a session however it is renamed or
relocated.

**Why derivation rather than an audience claim.** An audience claim fails open
when a future reader forgets to check it. A derived key fails closed: the
signature simply does not verify, and no reader has to remember anything.

Further properties of the pending token:

- **Short TTL** — minutes, not hours. It is a step in a flow, not a session.
- **Carries `session_version`**, checked on redemption, so revoking a user's
  sessions also kills a pending login in flight.
- **Single purpose**: it can be exchanged for a session and does nothing else.

---

## 4. Two doors, and neither may be forgotten

`POST /api/auth/login` and `POST /login` both call `authenticate()` and then
issue a session. `api/login_service.py`'s own docstring says why it exists:
*"an attacker simply aims a password spray at whichever surface lacks them."*

The same argument applies with more force to a second factor, so the decision
lives in the same place. `LoginResult` gains **`MFA_REQUIRED`**, returned by
`authenticate()` when the user has an active TOTP credential.

`MFA_REQUIRED` is not `OK`. A surface that does not handle it cannot fall
through to issuing a session, because the only branch that issues one tests for
`OK`. A test asserts that every route calling `authenticate()` handles the new
member — the three-times-recurring second-door defect is the reason it is a
test and not a convention.

---

## 5. Enrolment activates only after a verified code

A user who scans a code, loses the tab, and is then required to present a code
they never successfully generated has locked themselves out of their own
account. So enrolment is two steps:

1. **Begin** — mint a 160-bit secret (RFC 4226 §4 floor), store it encrypted,
   return the `otpauth://` URI. The credential is **pending**, and pending
   credentials do not challenge anyone.
2. **Activate** — the user submits a current code. Only on success is the
   credential marked active and the recovery codes issued.

An un-activated credential is replaced outright if enrolment is begun again.
There is never more than one credential per user.

### 5.1 The secret is encrypted, with its own context

Stored through the existing `CredentialCipher`, which already envelope-encrypts
with a per-secret DEK. The AAD becomes a parameter, defaulting to the current
`b"ccf-cred"` so stored AI credentials keep working, and MFA passes
`b"ccf-mfa"`. Same reasoning as §3 one layer down: without domain separation a
ciphertext from one store decrypts in the other.

This couples MFA to `ai_credential_master_key` being set. That is correct —
storing a shared secret requires a key — but it is named here because the
setting's name does not suggest it gates authentication.

---

## 6. Verification

- **SHA-1, 6 digits, 30-second step.** RFC 6238 defaults, and what authenticator
  apps actually implement. HMAC-SHA1 remains FIPS-approved for HMAC
  (SP 800-107); this is deliberate, not an oversight, and is recorded here
  because the parent roadmap item is about FIPS.
- **±1 step of drift** accepted, for clock skew. No more: each extra step
  widens the guess space.
- **Replay is refused.** RFC 6238 §5.2 requires that a code accepted once is
  not accepted again. The consumed step is recorded on the credential and any
  step less than or equal to it is rejected. Without this, a code observed over
  a shoulder or in a log is valid for the rest of its window.

### 6.1 Failed codes count toward lockout

A second factor with unlimited attempts is not a second factor: six digits is
a million guesses, which is minutes of automation. Every failed code
increments the same `failed_login_attempts` counter and trips the same AC-7
lockout as a failed password. The counter is shared deliberately, so an
attacker cannot spend the password budget and then a separate code budget.

---

## 7. Recovery codes

Ten single-use codes, issued once at activation and shown once. Each is
high-entropy and random.

**Hashed with SHA-256, not PBKDF2.** Password stretching exists because humans
choose guessable passwords; a 160-bit random code has nothing to stretch, and
210,000 rounds × 10 codes on every login attempt is a denial-of-service
surface. This is a deliberate divergence from `hash_password` and is documented
at the call site so it does not read as an oversight.

A consumed code is marked used and never matches again. Using one counts as
authentication and is audited distinctly from a TOTP success, because "signed
in with a recovery code" is a fact an administrator should be able to see.

---

## 8. Enforcement policy

**Correction (independent review, 2026-09-24): this section describes
behaviour that was not built.** `Organization.mfa_policy` exists and is
advisory. It is read in six places -- four display it, two refuse to *remove*
an authenticator it covers -- and it gates no session, route or redirect. A
user in scope who has not enrolled signs in with a password alone and reaches
everything. Nothing writes the column either: no API, no CLI, no form.

The column and its readers now say so at every site, the way `TrustProfile
.published` does. A column that looks like a control and enforces nothing is
worse than one that plainly does nothing, because somebody will report it as
satisfying IA-2(1). It does not.

Enforcement is its own change. The section below is the design it should
follow, and the reason it was not done in one line is the reason it needs its
own: deciding which routes stay reachable while a user is unenrolled is the
whole problem, and getting it wrong locks an organization out of itself.



Per organization, on `Organization`: `optional` (default), `admins`, `all`.

A user in scope of the policy who has no active credential is **not locked
out**. They authenticate and are required to enrol before doing anything else.
Refusing the login instead would make an organization able to lock every one of
its own users out by changing a dropdown, with no way back in.

The default is `optional`, because changing every existing deployment's login
behaviour in a release is not a thing to do implicitly.

---

## 9. Out of scope, said plainly

- **WebAuthn, PIV-CAC, SMS** (§2).
- **MFA for OIDC users** (§2) — the IdP's responsibility.
- **MFA for API tokens.** A token is a bearer credential with no human to
  challenge. A deployment that requires a second factor for humans still has
  single-factor API tokens, and this change does not alter that.
- **KMS-backed key rotation.** `LocalKeyProvider` derives its KEK as a bare
  `sha256(master_key)` rather than through a KDF, and no key version is
  recorded, so rotating the master secret would make every stored credential
  undecryptable with no migration path. Both are real and both are their own
  change; this spec adds a consumer of that cipher, not a repair to it.
- **Re-authentication for sensitive actions.** Step-up auth is a separate
  decision about which actions warrant it.

---

## 10. Testing requirements

1. **A user with active MFA cannot get a session from a password alone**, on
   **both** surfaces. Assert no session cookie is set and no principal
   resolves — not merely that the response was not 200.
2. **A pending token is rejected as a session cookie**, and a session cookie is
   rejected as a pending token. This is §3, and it is the test that matters
   most: assert the failure, then assert it fails *because the signature does
   not verify*, so a later audience check cannot be what is carrying it.
3. **Every route that calls `authenticate()` handles `MFA_REQUIRED`** — by
   inspection of the call sites, so a third login surface fails this file
   rather than quietly issuing sessions.
4. **Replay is refused**: the same code twice in one window succeeds then
   fails. Drive it on a pinned clock, not on wall time.
5. **Drift**: a code from one step earlier and one later is accepted; two steps
   out is not.
6. **Failed codes trip the lockout**, and share the counter with failed
   passwords — spend half the budget on each and assert the account locks.
7. **An un-activated credential challenges nobody** (§5).
8. **A recovery code works once**, and a second use of the same code fails.
9. **Policy `all` requires enrolment without locking the user out** (§8).
10. **The secret is never returned** by any endpoint after enrolment begins,
    and never appears in an audit row or a log line.
11. **Tenant isolation**: one organization's policy never governs another's
    user. `get_session` binds the RLS tenant, so pin this on an unscoped
    session and first assert the other tenant's rows are visible without the
    predicate.

Mutation-verify each guard: remove the replay check, the drift bound, the
lockout increment, the activation gate and the derived secret, and confirm a
named test fails for each. A guard whose removal leaves the suite green is not
protecting anything.
