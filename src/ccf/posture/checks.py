"""The registry of posture checks, by provider.

The check *types* live in :mod:`ccf.posture.types` and are re-exported here, so
callers have one import site while provider modules can depend on the types
without depending on this registry -- which is what keeps the two acyclic.

The registry is deliberately the same shape as ``etl.sources.DEFAULT_SOURCES``
so P2b's move into ``packs/`` relocates content rather than redesigning it.
"""

from __future__ import annotations

from .providers import m365
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

#: Provider key -> its checks. Empty per provider until P3 implements the
#: adapters; the registry exists now so the contract and orchestration are
#: testable, and so P2b has something to relocate into ``packs/``.
CHECK_REGISTRY: dict[str, tuple[PostureCheck, ...]] = {
    "msgraph": m365.CHECKS,
    # Empty until P3 implements the adapter; the key exists so a check filed
    # under it is a registry edit rather than a new dict entry.
    "aws_govcloud": (),
}


#: Provider key -> {check key: the collection the check reads}. Symmetric with
#: :data:`CHECK_REGISTRY` and kept beside it so a provider cannot register a
#: check without also saying where its data comes from -- a check with no
#: endpoint cannot be scanned, and resolution refuses to return one.
ENDPOINT_REGISTRY: dict[str, dict[str, str]] = {
    "msgraph": m365.ENDPOINTS,
    "aws_govcloud": {},
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
