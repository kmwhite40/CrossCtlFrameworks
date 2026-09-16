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
    "CheckOutcome",
    "PostureCheck",
    "ResourceFinding",
    "checks_for",
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


def checks_for(provider: str) -> tuple[PostureCheck, ...]:
    """Checks registered for one provider; empty for an unknown provider."""
    return CHECK_REGISTRY.get(provider, ())
