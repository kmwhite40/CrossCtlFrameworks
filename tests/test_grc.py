"""Unit tests for the GRC operating-system layer (module wiring + constants)."""

from __future__ import annotations

from ccf.api.routes.grc import CONNECTOR_TYPES, _MOCK_DISCOVERY
from ccf.models_grc import (
    AuditEngagement,
    ConnectorConfig,
    ControlTest,
    RegulatoryUpdate,
    TrustProfile,
)


def test_ten_connector_types_all_have_mock_volumes() -> None:
    assert len(CONNECTOR_TYPES) == 10
    for t in CONNECTOR_TYPES:
        assert t in _MOCK_DISCOVERY
        assert _MOCK_DISCOVERY[t] > 0
    # Government clouds are represented.
    assert {"azure_gov", "m365_gcc_high", "aws_govcloud"} <= set(CONNECTOR_TYPES)


def test_models_map_to_expected_tables() -> None:
    assert TrustProfile.__tablename__ == "trust_profiles"
    assert AuditEngagement.__tablename__ == "audit_engagements"
    assert ConnectorConfig.__tablename__ == "connector_configs"
    assert ControlTest.__tablename__ == "control_tests"
    assert RegulatoryUpdate.__tablename__ == "regulatory_updates"


def test_engagement_has_request_and_finding_relationships() -> None:
    assert hasattr(AuditEngagement, "requests")
    assert hasattr(AuditEngagement, "findings")
