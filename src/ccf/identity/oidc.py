"""Thin OIDC client — discovery, authorization URL, and code exchange.

Uses the provider's OIDC discovery document to find the authorization, token
and userinfo endpoints, exchanges an authorization code for tokens, and returns
the userinfo claims. Network I/O only; all inputs come from ``CCF_OIDC_*``.

No JWT signature verification is performed here — claims are read from the
provider's userinfo endpoint over TLS rather than by decoding the ``id_token``,
which avoids a JWKS/JWT dependency while keeping the trust boundary at the
provider. Decoding an ``id_token`` **without** verifying it would be worse than
not decoding it; adding real verification is its own change.

See ``docs/superpowers/specs/2026-09-24-sso-hardening-design.md``.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from typing import Any
from urllib.parse import urlencode, urlsplit

import httpx

from ..config import get_settings
from ..logging import get_logger

log = get_logger(__name__)
_DISCOVERY_SUFFIX = "/.well-known/openid-configuration"

#: Discovery was re-fetched on every authorization AND every callback: two
#: extra round trips per sign-in, and a sign-in that fails when the provider's
#: discovery endpoint is slow even though its token endpoint is fine. Keyed by
#: issuer so changing the setting takes effect without a restart.
_DISCOVERY_TTL_SECONDS = 300
_discovery_cache: dict[str, tuple[float, dict[str, Any]]] = {}

#: Counts fetches that actually left the process, so a test can assert the
#: cache works without timing anything.
_STATS: dict[str, int] = {"discovery_fetches": 0}


def discovery_fetch_count() -> int:
    return _STATS["discovery_fetches"]


def reset_discovery_cache() -> None:
    _discovery_cache.clear()
    _STATS["discovery_fetches"] = 0


class OidcError(RuntimeError):
    """Raised when the OIDC exchange cannot complete."""


def new_state() -> str:
    return secrets.token_urlsafe(24)


def new_code_verifier() -> str:
    """RFC 7636 code verifier: 43-128 chars from the unreserved set."""
    return secrets.token_urlsafe(64)[:96]


def code_challenge(verifier: str) -> str:
    """The S256 challenge. ``plain`` is never offered -- it protects nothing."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _same_origin_https(issuer: str, endpoint: str, *, name: str) -> str:
    """Refuse an endpoint that is not HTTPS on the issuer's own host.

    ``exchange_code`` POSTs ``client_id`` **and ``client_secret``** to
    ``token_endpoint``, taken straight from the discovery document. Nothing
    checked that the endpoint belonged to the configured issuer, so a hostile
    or simply mistaken document could collect the client secret. TLS protects
    the document in transit, so this needs a bad issuer rather than a network
    attacker -- but the blast radius is the secret itself and the check is one
    comparison.
    """
    want, got = urlsplit(issuer), urlsplit(endpoint)
    if got.scheme != "https":
        raise OidcError(f"issuer discovery {name} is not https: {endpoint}")
    if got.netloc.lower() != want.netloc.lower():
        raise OidcError(
            f"issuer discovery {name} points at {got.netloc}, which is not the "
            f"configured issuer {want.netloc}"
        )
    return endpoint


async def _discover(issuer: str) -> dict[str, Any]:
    now = time.time()
    cached = _discovery_cache.get(issuer)
    if cached is not None and now - cached[0] < _DISCOVERY_TTL_SECONDS:
        return cached[1]
    url = issuer.rstrip("/") + _DISCOVERY_SUFFIX
    _STATS["discovery_fetches"] += 1
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        data: dict[str, Any] = resp.json()
    _discovery_cache[issuer] = (now, data)
    return data


def _endpoint(meta: dict[str, Any], issuer: str, name: str) -> str:
    value = meta.get(name)
    if not value or not isinstance(value, str):
        raise OidcError(f"issuer discovery missing {name}")
    return _same_origin_https(issuer, value, name=name)


async def authorization_url(state: str, *, code_verifier: str) -> str:
    """Build the IdP authorization-code redirect URL from configured settings.

    Carries a PKCE ``S256`` challenge. The client is confidential, so an
    intercepted code is not directly redeemable -- but PKCE is required by
    OAuth 2.1, expected by federal deployment guidance, and costs one hash.
    """
    s = get_settings()
    if not (s.oidc_issuer and s.oidc_client_id and s.oidc_redirect_uri):
        raise OidcError("OIDC is not fully configured")
    meta = await _discover(s.oidc_issuer)
    endpoint = _endpoint(meta, s.oidc_issuer, "authorization_endpoint")
    query = urlencode(
        {
            "response_type": "code",
            "client_id": s.oidc_client_id,
            "redirect_uri": s.oidc_redirect_uri,
            "scope": "openid email profile groups",
            "state": state,
            "code_challenge": code_challenge(code_verifier),
            "code_challenge_method": "S256",
        }
    )
    return f"{endpoint}?{query}"


async def exchange_code(code: str, *, code_verifier: str) -> dict[str, Any]:
    """Exchange an authorization code for tokens and return userinfo claims."""
    s = get_settings()
    if not (s.oidc_issuer and s.oidc_client_id and s.oidc_redirect_uri):
        raise OidcError("OIDC is not fully configured")
    meta = await _discover(s.oidc_issuer)
    # Validated BEFORE the secret is sent, not after.
    token_endpoint = _endpoint(meta, s.oidc_issuer, "token_endpoint")
    userinfo_endpoint = _endpoint(meta, s.oidc_issuer, "userinfo_endpoint")
    async with httpx.AsyncClient(timeout=10.0) as client:
        token_resp = await client.post(
            token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": s.oidc_redirect_uri,
                "client_id": s.oidc_client_id,
                "client_secret": s.oidc_client_secret or "",
                "code_verifier": code_verifier,
            },
        )
        token_resp.raise_for_status()
        access_token = token_resp.json().get("access_token")
        if not access_token:
            raise OidcError("token endpoint returned no access_token")
        info_resp = await client.get(
            userinfo_endpoint, headers={"Authorization": f"Bearer {access_token}"}
        )
        info_resp.raise_for_status()
        claims: dict[str, Any] = info_resp.json()
        return claims
