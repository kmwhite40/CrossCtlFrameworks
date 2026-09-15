"""Provider registration.

Imported for its side effect: each provider module registers itself through
:func:`ccf.enforcement.types.register`, which refuses a check another provider
already claims.
"""

from __future__ import annotations

from .types import PROVIDER_REGISTRY, provider_for

__all__ = ["PROVIDER_REGISTRY", "provider_for"]
