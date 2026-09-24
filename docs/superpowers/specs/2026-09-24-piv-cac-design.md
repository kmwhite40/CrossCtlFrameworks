# PIV / CAC authentication

**Status:** design 2026-09-24. The last item in the identity-hardening line.

---

## 1. Where the trust boundary actually is

A PIV or CAC credential is presented over mutual TLS. **Concord does not
terminate TLS**, and this change does not make it. The chain is validated by
the terminator — nginx, an ALB, Envoy — against the Federal Common Policy CA,
with revocation checking, and that is where it belongs: it is a TLS
configuration problem with a mature answer, and reimplementing path validation
in application code would be strictly worse.

What the application does is read the identity the terminator established and
map it to an account.

## 2. The failure mode that makes this dangerous

The terminator passes its result in request headers. **A header is forgeable by
anyone who can reach the application directly.** If Concord trusts
`X-SSL-Client-Verify: SUCCESS` from any source, then any client that bypasses
the proxy authenticates as any user. That is a total authentication bypass, and
it is the normal way this integration is got wrong.

So, in order:

1. **Off by default.** `piv_enabled` defaults false. Nothing reads these
   headers until an operator turns it on.
2. **A trusted-proxy list is mandatory.** `piv_trusted_proxies` is a list of
   CIDRs. **Empty means refuse to enable**, not "trust everything" — the
   permissive reading of an unset list is how this becomes a bypass.
3. **The peer address is the immediate connection** (`request.client.host`),
   never `X-Forwarded-For`, which is a header and therefore forgeable by the
   same argument.
4. A request from outside the list has its certificate headers **ignored
   entirely**, not merely distrusted — no partial credit, no fallback to a DN.

## 3. The certificate is parsed, not described

The terminator can pass a subject DN string, and a DN is a poor identifier: the
format varies by terminator, it is ambiguous to compare, and for PIV the thing
that identifies a person is not in it.

Concord reads the **PEM certificate** (`X-SSL-Client-Cert` by default,
configurable) and parses it with `cryptography`, which is already a dependency.
Identity comes from the Subject Alternative Name:

| Source | Where |
|---|---|
| **UPN** (PIV and CAC) | SAN `otherName`, OID `1.3.6.1.4.1.311.20.2.3` |
| **RFC822 email** | SAN `rfc822Name`, used only as a fallback |

The UPN is the subject. For a CAC that is typically `<EDIPI>@mil`; the EDIPI is
not parsed out, because the whole UPN is what is unique and the platform has no
use for the number on its own.

**A certificate with neither is refused**, rather than falling back to the DN.
An identifier the platform cannot compare reliably is not an identifier.

## 4. No account is created from a certificate

Holding a valid PIV card says the federal government issued someone a
credential. It does not say that person should have an account in this tenant.

So there is **no just-in-time provisioning on this path**. The subject maps to
an existing `ExternalIdentity` with `provider="piv"`, or to a user whose email
matches the certificate's RFC822 name **only when that link is established by
an administrator**, or the request is refused with a message saying the
certificate is valid and unlinked.

`ExternalIdentity` already carries `UniqueConstraint("provider", "subject")`, so
this needs **no migration**.

## 4.1 A certificate is not additionally challenged for a code

**Added 2026-09-24, after review.** The original spec did not mention the
second factor at all, so this was a property nobody had decided.

A PIV or CAC credential is already multi-factor: the card is something you
have, the PIN is something you know, and the card checks the PIN itself before
it will sign. Demanding a TOTP code on top adds a third factor of a weaker
kind, and strands a card holder whose phone is not with them at a terminal.

So certificate sign-in mints a session directly, as single sign-on does — and
for the same reason recorded in the MFA spec: the stronger authentication has
already happened somewhere Concord trusts.

What would make this wrong is the platform claiming otherwise. Nothing derives
a compliance statement from `Organization.mfa_policy`; it is read in exactly
one place, to tell a user to enrol. **If that ever changes, the claim has to
account for this path**, or it will assert a coverage it does not have.

## 4.2 Linking is a feature, not a manual step

**Added 2026-09-24, after review.** §4 said "an administrator links the
identity" and §5 scoped out *self-service* linking. Between those two
sentences, administrator linking was built by nobody: the only code creating an
`ExternalIdentity` was the single-sign-on path, so `/auth/piv` could only ever
answer "valid but not linked" and the whole feature was unreachable.

`POST/GET/DELETE /api/identity/piv-links`, admin-only and organization-scoped.
It takes a PEM in preference to a typed subject, so the administrator pastes
what the card presents and Concord extracts the same field the login path will
compare — a hand-typed UPN that differs by one character produces a link that
silently never matches.

Two things the scoping has to get right, both of which failed first:

- **An admin of one tenant must not link a certificate to another tenant's
  user**, which would be account takeover with an audit trail saying it was
  authorised. Answered 404, not 403.
- **`subject` is globally unique while the session is tenant-bound**, so a
  certificate already linked in another organization is invisible to the
  pre-check and only the database constraint catches it. Both paths report the
  same 409, and neither names the holder.

## 5. What this does not do

- **No chain validation, no revocation checking, no OCSP** (§1). The terminator
  does it. Concord requires the terminator to say it did, and refuses when it
  does not say so.
- **No FASC-N parsing.** It is the other PIV identifier, it lives in a
  different `otherName` OID with a packed BCD encoding, and nothing here needs
  it while the UPN is present. Adding it later is additive.
- **No certificate-to-user self-service linking.** An administrator links the
  identity. A user who could link their own certificate to their own account
  could link it to somebody else's.
- **No change to any other login path.** Password and OIDC are untouched.

## 6. Testing requirements

1. **A forged header from an untrusted address authenticates nobody** — the
   whole feature in one test. Assert no principal resolves, not merely a
   non-200.
2. **An empty trusted-proxy list refuses to enable**, rather than trusting
   every peer.
3. **`X-Forwarded-For` cannot put a caller inside the trusted range.**
4. **A verify header that is not `SUCCESS` is refused**, including absent.
5. **The UPN is read from the SAN**, from a real certificate built in the test,
   not from a hand-written string. Build it with `cryptography` so the parser
   is exercised against a genuine encoding.
6. **A certificate with no UPN and no email is refused**, and does not fall
   back to the subject DN.
7. **An unlinked certificate is refused with a distinguishable reason** — valid
   but unknown is not the same as invalid, and an administrator needs to tell
   them apart.
8. **A linked certificate signs the user in**, and the session cookie is the
   ordinary one.
9. **A deactivated user is refused** even with a valid linked certificate.
10. **Tenant isolation**: the identity resolves to its own user's organization.
    Pin on an unscoped session.

Mutation-verify: remove the peer check, the empty-list refusal, the verify
check and the UPN requirement — each must fail a named test.
