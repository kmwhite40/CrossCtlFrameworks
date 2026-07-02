"""Thin OIDC client — discovery, authorization URL, and code exchange.

Uses the provider's OIDC discovery document to find the authorization, token, and
userinfo endpoints, exchanges an authorization code for tokens, and returns the
userinfo claims. Network I/O only; all inputs come from ``CCF_OIDC_*`` settings.
No JWT signature verification is performed here — claims are read from the
provider's userinfo endpoint over TLS rather than by decoding the id_token, which
avoids a JWKS/JWT dependency while keeping the trust boundary at the provider.
"""

from __future__ import annotations

import secrets
from typing import Any
from urllib.parse import urlencode

import httpx

from ..config import get_settings
from ..logging import get_logger

log = get_logger(__name__)
_DISCOVERY_SUFFIX = "/.well-known/openid-configuration"


class OidcError(RuntimeError):
    """Raised when the OIDC exchange cannot complete."""


def new_state() -> str:
    return secrets.token_urlsafe(24)


async def _discover(issuer: str) -> dict[str, Any]:
    url = issuer.rstrip("/") + _DISCOVERY_SUFFIX
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        data: dict[str, Any] = resp.json()
        return data


async def authorization_url(state: str) -> str:
    """Build the IdP authorization-code redirect URL from configured settings."""
    s = get_settings()
    if not (s.oidc_issuer and s.oidc_client_id and s.oidc_redirect_uri):
        raise OidcError("OIDC is not fully configured")
    meta = await _discover(s.oidc_issuer)
    endpoint = meta.get("authorization_endpoint")
    if not endpoint:
        raise OidcError("issuer discovery missing authorization_endpoint")
    query = urlencode(
        {
            "response_type": "code",
            "client_id": s.oidc_client_id,
            "redirect_uri": s.oidc_redirect_uri,
            "scope": "openid email profile groups",
            "state": state,
        }
    )
    return f"{endpoint}?{query}"


async def exchange_code(code: str) -> dict[str, Any]:
    """Exchange an authorization code for tokens and return userinfo claims."""
    s = get_settings()
    if not (s.oidc_issuer and s.oidc_client_id and s.oidc_redirect_uri):
        raise OidcError("OIDC is not fully configured")
    meta = await _discover(s.oidc_issuer)
    token_endpoint = meta.get("token_endpoint")
    userinfo_endpoint = meta.get("userinfo_endpoint")
    if not token_endpoint or not userinfo_endpoint:
        raise OidcError("issuer discovery missing token/userinfo endpoint")
    async with httpx.AsyncClient(timeout=10.0) as client:
        token_resp = await client.post(
            token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": s.oidc_redirect_uri,
                "client_id": s.oidc_client_id,
                "client_secret": s.oidc_client_secret or "",
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
