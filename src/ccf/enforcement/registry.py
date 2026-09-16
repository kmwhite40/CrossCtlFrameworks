"""Provider registration.

Imported for its side effect: importing :mod:`ccf.enforcement.providers`
registers each provider through :func:`ccf.enforcement.types.register`, which
refuses a check another provider already claims.
"""

from __future__ import annotations

from . import providers as _providers  # noqa: F401 - imported to register
from .types import PROVIDER_REGISTRY, provider_for, write_credential_keys

__all__ = ["PROVIDER_REGISTRY", "provider_for", "write_credential_keys"]
