"""Config-capture connectors — populate ODP values from live cloud config.

Provider-agnostic: :class:`ConfigConnector` is the contract; :func:`get_connector`
resolves a provider by key. See :mod:`ccf.connectors.base` for the interface.
"""

from __future__ import annotations

from typing import Any

from .aws import AwsGovCloudConnector
from .base import CapturedParameter, ConfigConnector
from .msgraph import MsGraphConnector

_REGISTRY: dict[str, type[ConfigConnector]] = {
    MsGraphConnector.key: MsGraphConnector,
    AwsGovCloudConnector.key: AwsGovCloudConnector,
}


def get_connector(key: str, credential: dict[str, Any] | None = None) -> ConfigConnector | None:
    """Instantiate a connector by key, optionally bound to an org's credential.

    ``credential`` should come from :func:`ccf.connectors.credentials.resolve_credential`
    — never a global/env value. With no credential the connector reports
    ``is_configured() is False`` and captures nothing.
    """
    cls = _REGISTRY.get(key)
    return cls(credential=credential) if cls else None


def list_connectors() -> list[ConfigConnector]:
    """All known connector types, uncredentialed (for listing/UI display only)."""
    return [cls() for cls in _REGISTRY.values()]


def connector_keys() -> tuple[str, ...]:
    """Stable connector keys known to the registry, e.g. ``("msgraph", "aws_govcloud")``."""
    return tuple(_REGISTRY.keys())


__all__ = [
    "AwsGovCloudConnector",
    "CapturedParameter",
    "ConfigConnector",
    "MsGraphConnector",
    "connector_keys",
    "get_connector",
    "list_connectors",
]
