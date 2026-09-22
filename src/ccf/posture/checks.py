"""The registry of posture checks, by provider.

The check *types* live in :mod:`ccf.posture.types` and are re-exported here, so
callers have one import site while provider modules can depend on the types
without depending on this registry -- which is what keeps the two acyclic.

The registry is deliberately the same shape as ``etl.sources.DEFAULT_SOURCES``
so P2b's move into ``packs/`` relocates content rather than redesigning it.
"""

from __future__ import annotations

from .providers import aws, m365, puppetdb
from .types import CheckOutcome, PostureCheck, ResourceFinding

__all__ = [
    "CHECK_REGISTRY",
    "ENDPOINT_REGISTRY",
    "CheckOutcome",
    "PostureCheck",
    "ResourceFinding",
    "checks_for",
    "endpoint_for",
    "known_providers",
    "platform_check_keys",
]

#: Provider key -> its checks. Every registered provider now ships checks; the
#: registry keeps the shape it had when they were empty, so P2b still has
#: content to relocate into ``packs/`` rather than a redesign to perform.
CHECK_REGISTRY: dict[str, tuple[PostureCheck, ...]] = {
    "msgraph": m365.CHECKS,
    "puppetdb": puppetdb.CHECKS,
    "aws_govcloud": aws.CHECKS,
}


#: Provider key -> {check key: the collection the check reads}. Symmetric with
#: :data:`CHECK_REGISTRY` and kept beside it so a provider cannot register a
#: check without also saying where its data comes from -- a check with no
#: endpoint cannot be scanned, and resolution refuses to return one.
#:
#: "Where its data comes from" is provider-shaped, not universally a URL: the
#: HTTP providers register a relative path, and ``aws_govcloud`` registers a
#: boto3 ``<service>.<operation>`` source token, because AWS has no request
#: path to register. See ``providers.aws``'s module docstring for why a
#: URL-shaped placeholder was refused, and what it costs pack authors.
ENDPOINT_REGISTRY: dict[str, dict[str, str]] = {
    "msgraph": m365.ENDPOINTS,
    "puppetdb": puppetdb.ENDPOINTS,
    "aws_govcloud": aws.ENDPOINTS,
}


def endpoint_for(provider: str, check_key: str) -> str | None:
    """The collection a platform check reads, or ``None`` if unregistered."""
    return ENDPOINT_REGISTRY.get(provider, {}).get(check_key)


def checks_for(provider: str) -> tuple[PostureCheck, ...]:
    """Checks registered for one provider; empty for an unknown provider."""
    return CHECK_REGISTRY.get(provider, ())


def known_providers() -> frozenset[str]:
    """Every registered provider key.

    A Form B rule names its provider explicitly, and a typo (``"msgrap"``) is
    otherwise silent: it never matches any real connector's key, so the rule
    is accepted at install and then never resolves for any scan, forever
    (``posture.resolve._targets`` just returns ``False``). Validating against
    this set at install turns that into an install-time error instead.
    """
    return frozenset(CHECK_REGISTRY)


def platform_check_keys() -> frozenset[str]:
    """Every key the platform itself provides, across all providers.

    One authority for "is this key the platform's", used by
    ``packs.catalog`` to refuse a pack rule that would collide with a platform
    check. Computed rather than hardcoded so registering a check cannot leave
    the collision test behind.
    """
    return frozenset(check.key for checks in CHECK_REGISTRY.values() for check in checks)
