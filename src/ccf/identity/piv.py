"""PIV / CAC: reading the identity a TLS terminator established.

Spec: ``docs/superpowers/specs/2026-09-24-piv-cac-design.md``.

**Concord does not terminate TLS and this module does not validate a
certificate chain.** Path validation against the Federal Common Policy CA, with
revocation checking, belongs in the terminator -- nginx, an ALB, Envoy -- where
it is a configuration problem with a mature answer. Reimplementing it here
would be strictly worse.

What this does is read the result the terminator reports, and only from a peer
an operator has said may report it. That last clause is the whole security of
the feature: these are HTTP headers, and a header is forgeable by anyone who
can reach the application directly. Trusting them from any source is a total
authentication bypass, and it is the usual way this integration is got wrong.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, ObjectIdentifier

#: Microsoft's userPrincipalName, the SAN ``otherName`` both PIV and CAC carry.
#: For a CAC this is typically ``<EDIPI>@mil``. The EDIPI is not parsed out of
#: it: the whole UPN is what is unique, and the platform has no use for the
#: number alone.
UPN_OID = ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")

#: What the terminator says when the chain validated. Anything else, including
#: absent, is a refusal -- "NONE" and "FAILED" are both normal nginx values.
VERIFY_SUCCESS = "SUCCESS"


class PivError(RuntimeError):
    """The certificate headers cannot be turned into an identity."""


class PivNotLinkedError(PivError):
    """The certificate is valid and belongs to nobody here.

    Distinct from its parent because an administrator has to tell "this card is
    not one we accept" apart from "this card is fine and nobody has been given
    an account for it". They are different problems with different fixes, and
    collapsing them makes the second one unreportable.
    """


@dataclass(frozen=True)
class CertificateIdentity:
    """What a client certificate says about who is holding it."""

    #: The UPN, used as ``ExternalIdentity.subject``.
    subject: str
    #: The SAN rfc822Name, when present. Used to help an administrator find the
    #: right account, never on its own to authenticate.
    email: str | None


def peer_is_trusted(peer: str | None, trusted_cidrs: list[str]) -> bool:
    """Whether this connection may assert a client certificate.

    ``peer`` is the **immediate** connection address, never ``X-Forwarded-For``
    -- that is a header, and forgeable by exactly the argument that makes this
    check necessary at all.

    An empty ``trusted_cidrs`` returns False. The permissive reading of an
    unset list -- "no restriction configured, so allow" -- is how this becomes
    an authentication bypass, so the unset case is the closed one.
    """
    if not trusted_cidrs or not peer:
        return False
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        return False
    for raw in trusted_cidrs:
        entry = raw.strip()
        if not entry:
            continue
        try:
            if address in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            # A malformed entry is skipped rather than widening the match. It
            # cannot be treated as "allow" and must not abort the others.
            continue
    return False


def identity_from_pem(pem: str) -> CertificateIdentity:
    """Parse a client certificate and pull the identity out of its SAN.

    The terminator can also pass a subject DN, and this deliberately does not
    use it: the format varies between terminators, it is ambiguous to compare,
    and for PIV the thing that identifies a person is not in it. A certificate
    carrying neither a UPN nor an rfc822Name is refused rather than falling
    back to a DN -- an identifier the platform cannot compare reliably is not
    an identifier.
    """
    try:
        cert = x509.load_pem_x509_certificate(pem.strip().encode("ascii"))
    except Exception as e:
        raise PivError("the client certificate could not be parsed") from e

    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
    except x509.ExtensionNotFound as e:
        raise PivError("the client certificate has no subjectAltName") from e

    upn: str | None = None
    for other in san.get_values_for_type(x509.OtherName):  # type: ignore[attr-defined]
        if other.type_id != UPN_OID:
            continue
        # The value is a DER-encoded UTF8String; its content is the tail after
        # the two-byte tag/length header for the lengths a UPN reaches.
        raw = other.value
        upn = _der_utf8_string(raw)
        if upn:
            break

    emails = list(san.get_values_for_type(x509.RFC822Name))  # type: ignore[attr-defined]
    email = emails[0] if emails else None

    if not upn:
        raise PivError(
            "the client certificate carries no userPrincipalName; Concord will "
            "not fall back to the subject DN, which is not a reliable identifier"
        )
    return CertificateIdentity(subject=upn, email=email)


def _der_utf8_string(raw: bytes) -> str | None:
    """Content of a DER UTF8String, tolerating the short and long length forms.

    Written out rather than pulled from an ASN.1 library because this is the
    only DER this application reads, and the alternative is a dependency for
    nine lines.
    """
    if len(raw) < 2 or raw[0] != 0x0C:  # 0x0C = UTF8String
        return None
    length = raw[1]
    start = 2
    if length & 0x80:  # long form: low bits give the number of length bytes
        count = length & 0x7F
        if count == 0 or len(raw) < 2 + count:
            return None
        length = int.from_bytes(raw[2 : 2 + count], "big")
        start = 2 + count
    value = raw[start : start + length]
    if len(value) != length:
        return None
    try:
        return value.decode("utf-8") or None
    except UnicodeDecodeError:
        return None
