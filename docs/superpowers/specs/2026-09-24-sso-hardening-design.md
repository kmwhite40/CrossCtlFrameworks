# Single sign-on hardening

**Status:** design 2026-09-24. Five findings measured in `identity/oidc.py` and
`identity/provisioning.py`. Four are fixed here; the fifth is latency.

---

## 1. An unverified email can take over an existing account

`provision_from_oidc` resolves in this order:

1. `(provider, subject)` — the stable identifier.
2. **failing that, `User.email`** — and then writes an `ExternalIdentity`
   linking that local account to the new subject, permanently.

**`email_verified` is never read. Zero matches for it in `src/ccf`.** So an
identity-provider subject presenting an unverified email that matches a local
account is handed that account, keeps it, and inherits its role.

How much that matters depends on the provider, which is exactly why the
platform should not assume. A single corporate provider that verifies every
address makes this inert. One that permits self-registration, or federates to
another, makes it account takeover by registration.

**The rule:** an email claim that is present and explicitly `email_verified:
false` may not create an account or link to one. A provider that omits the
claim entirely is a different case and is treated as §1.1 says.

### 1.1 A missing claim is not a false claim

`email_verified` is optional in OIDC. Treating absence as "unverified" would
break every deployment whose provider does not send it, which is the
absence-of-evidence defect this programme has now recorded several times.

So: **absent is allowed, and configurable.** `oidc_require_email_verified`
(default `false`) makes the claim mandatory for deployments that know their
provider sends it. An explicit `false` is refused either way, because that is
the provider stating a fact, not omitting one.

---

## 2. The client secret is sent to whatever URL discovery names

`exchange_code` reads `token_endpoint` from the discovery document and POSTs
`client_id` **and `client_secret`** to it. Nothing checks that the endpoint
belongs to the configured issuer.

TLS protects the document in transit, so this needs a hostile or mistaken
issuer rather than a network attacker. But the blast radius is the client
secret itself, and the check is one comparison.

**The rule:** every endpoint taken from discovery must share the issuer's
scheme and host, and must be `https`. A document that names a foreign host is
refused with that host in the message, rather than followed.

---

## 3. No PKCE

The authorization request sends no `code_challenge`. The client is
confidential, so an intercepted code is not directly redeemable — but PKCE is
required by OAuth 2.1, expected by federal deployment guidance, and costs one
hash. It is added with `S256`; `plain` is never offered.

The verifier travels in a cookie beside the state, with the same flags and
lifetime, and is checked by the provider rather than by us.

---

## 4. Just-in-time provisioning silently picks the oldest organization

`_default_org_id` is `ORDER BY id LIMIT 1`. On a deployment with several
tenants, a new single-sign-on user lands in whichever organization was created
first — which may not be theirs, and which grants them that tenant's data.

This was recorded rather than fixed when SCIM was narrowed, on the grounds that
narrowing authentication can lock people out. That reasoning holds for
**signing in** and not for **creating an account**:

- **An existing user signs in unchanged.** Their organization is on their own
  row; nothing about this resolution touches them.
- **Creating a user requires knowing the tenant**, and on a multi-tenant
  deployment nothing in the request says which. So JIT creation is refused,
  with the reason, when `oidc_organization_id` is unset and more than one
  organization exists.

Nobody is locked out who could previously get in. What stops is inventing a
tenant assignment for somebody new.

---

## 5. Discovery is re-fetched on every request (latency, not security)

Two extra round trips per sign-in, and a sign-in that fails when the provider's
discovery endpoint is slow even though the token endpoint is fine. Cached with
a short TTL, and the cache is per-issuer so changing the setting takes effect
without a restart.

Not a security fix and not presented as one.

---

## 6. Deliberately not changed

- **Claims still come from `userinfo`, not from a decoded `id_token`.** The
  module's docstring already explains the trade: it keeps the trust boundary at
  the provider over TLS and avoids a JWKS/JWT dependency. Adding id_token
  verification is a real improvement and a separate change with its own
  dependency decision; doing it halfway — decoding without verifying — would be
  worse than not doing it.
- **`nonce`.** It binds an id_token to an authorization request, and this
  client does not consume the id_token. Sending one we never check would be
  theatre.
- **The email fallback itself** (§1 step 2). Removing it would strand every
  deployment whose users predate single sign-on. It is gated on verification
  instead.

---

## 7. Testing requirements

1. **`email_verified: false` is refused**, for both the create and the link
   path, and the refusal names the reason.
2. **An absent claim is allowed by default and refused under
   `oidc_require_email_verified`** — both directions, so §1.1 cannot collapse
   into either extreme.
3. **A discovery document naming a foreign token endpoint is refused**, and the
   client secret is not sent. Assert no request reaches the foreign host, not
   merely that an exception was raised.
4. **`http` and a host mismatch are both refused**, separately.
5. **The authorization URL carries `code_challenge` and `code_challenge_method=S256`**,
   and the verifier is a cookie with the same flags as the state cookie.
6. **The verifier is sent at exchange** and is the one that matches the
   challenge.
7. **JIT creation is refused when the organization is ambiguous**, and an
   existing user signs in during exactly that condition — the pair is the point.
8. **Discovery is fetched once across two authorization requests**, counted not
   timed.
9. **Tenant isolation**: a user's organization comes from their own row, never
   from the resolution in §4. Pin on an unscoped session.

Mutation-verify: remove the verification check, the endpoint-origin check, the
challenge, and the ambiguity refusal — each must fail a named test.
