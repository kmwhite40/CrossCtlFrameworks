"""Unit tests for config-capture connectors (interface + Graph mapping)."""

from __future__ import annotations

import asyncio

from ccf.connectors import get_connector, list_connectors
from ccf.connectors.msgraph import MsGraphConnector


def test_registry_resolves_both_providers() -> None:
    keys = {c.key for c in list_connectors()}
    assert keys == {"msgraph", "aws_govcloud"}
    assert get_connector("nope") is None


def test_connectors_report_not_configured_by_default() -> None:
    # No credentials in the test env → capture is a safe no-op, never raises.
    for c in list_connectors():
        assert c.is_configured() is False
        assert asyncio.run(c.capture()) == []


def test_graph_maps_signin_frequency_to_session_lock_odp() -> None:
    payload = {
        "value": [
            {
                "displayName": "Require re-auth",
                "state": "enabled",
                "sessionControls": {
                    "signInFrequency": {"isEnabled": True, "value": 15, "type": "minutes"}
                },
            }
        ]
    }
    caps = MsGraphConnector()._map_conditional_access(payload)
    assert len(caps) == 1
    assert caps[0].odp_key == "inactivity_period"
    assert caps[0].value == "15 minutes"
    assert caps[0].nist_id == "3.1.10"


def test_graph_ignores_disabled_policies() -> None:
    payload = {"value": [{"state": "disabled", "sessionControls": {}}]}
    assert MsGraphConnector()._map_conditional_access(payload) == []
