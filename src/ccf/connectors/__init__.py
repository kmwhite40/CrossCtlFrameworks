"""Config-capture connectors — populate ODP values from live cloud config.

Provider-agnostic: :class:`ConfigConnector` is the contract; :func:`get_connector`
resolves a provider by key. See :mod:`ccf.connectors.base` for the interface.
"""

from __future__ import annotations

from .aws import AwsGovCloudConnector
from .base import CapturedParameter, ConfigConnector
from .msgraph import MsGraphConnector

_REGISTRY: dict[str, type[ConfigConnector]] = {
    MsGraphConnector.key: MsGraphConnector,
    AwsGovCloudConnector.key: AwsGovCloudConnector,
}


def get_connector(key: str) -> ConfigConnector | None:
    cls = _REGISTRY.get(key)
    return cls() if cls else None


def list_connectors() -> list[ConfigConnector]:
    return [cls() for cls in _REGISTRY.values()]


__all__ = [
    "AwsGovCloudConnector",
    "CapturedParameter",
    "ConfigConnector",
    "MsGraphConnector",
    "get_connector",
    "list_connectors",
]
