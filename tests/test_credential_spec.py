"""The declared credential fields must match what each connector actually needs.

A field list is a *claim*. This programme has already shipped a connector
parity guard that scanned source text and passed vacuously for two of three
connectors, so nothing here reads the declaration and compares it to itself:
every assertion builds a credential from the spec and asks the connector's own
``is_configured()`` what it thinks.

Both directions are checked, because only one of them catches a spec that
over-declares:

* a bundle carrying every field of an accepted group must be usable, and
* removing any single field from that group must make it unusable.
"""

from __future__ import annotations

import pytest

from ccf.connectors import connector_keys, get_connector
from ccf.connectors.credential_spec import SPECS, missing_fields, spec_for
from ccf.integrations import integration_credential_keys

#: Connector types whose ``is_configured`` is a live ConfigConnector method.
_LIVE = tuple(connector_keys())


def _sample(group: tuple[str, ...]) -> dict[str, str]:
    """A plausible non-empty value for each field in an accepted group."""
    return {name: f"sample-{name}" for name in group}


@pytest.fixture
def _aws_capture_available(monkeypatch: pytest.MonkeyPatch):
    """Make AWS's environmental preconditions true so the *credential* logic runs.

    ``AwsConnector.is_configured`` also gates on ``CCF_AWS_CAPTURE_ENABLED``
    and on boto3 being importable, and boto3 is not installed in this
    environment. Left alone, every AWS assertion below would pass by returning
    False for reasons that have nothing to do with the credential -- a test
    that cannot fail, which is the exact trap this module exists to avoid.
    """
    from ccf.config import get_settings

    connector = get_connector("aws_govcloud")
    monkeypatch.setattr(type(connector), "_boto3_available", lambda self: True)
    # Through the environment and the settings cache, not by setting an
    # attribute: `get_settings` is an lru_cache over a pydantic model, so a
    # class-level patch is shadowed by the instance's own field value and the
    # flag would silently stay False.
    monkeypatch.setenv("CCF_AWS_CAPTURE_ENABLED", "true")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_every_storable_connector_type_declares_its_fields() -> None:
    """A type storable through the settings API but absent here renders a form
    with no inputs, and is validated against nothing.

    Only providers that ship in the package are required to declare fields.
    ``PROVIDER_REGISTRY`` is a mutable runtime registry and other test modules
    register demo providers into it, so asserting against it directly makes
    this fail or pass depending on which tests ran first -- and a guard whose
    result depends on test ordering is telling you about the suite, not the
    product.
    """
    # From `registry`, not `types`: importing the latter alone leaves
    # PROVIDER_REGISTRY empty, because `registry` is what imports the providers
    # package that populates it. Run on its own, this guard then checked five
    # read connectors and no write credential at all.
    from ccf.enforcement.registry import PROVIDER_REGISTRY

    shipped_write = {
        provider.write_credential_type
        for provider in PROVIDER_REGISTRY
        # The registry holds provider *classes*, so the module is on the object
        # itself; `type(provider).__module__` is "builtins".
        if getattr(provider, "__module__", "").startswith("ccf.")
    }
    storable = set(_LIVE) | shipped_write | set(integration_credential_keys())
    missing = sorted(storable - set(SPECS))
    assert not missing, f"connector types with no credential spec: {missing}"
    assert "msgraph_write" in storable, (
        "the shipped write-credential provider was not discovered, so this "
        "guard would pass without checking anything"
    )


@pytest.mark.parametrize("connector_type", sorted(set(_LIVE)))
def test_a_complete_bundle_satisfies_the_connector(
    connector_type: str, _aws_capture_available
) -> None:
    """What the spec calls complete, the connector must accept."""
    spec = spec_for(connector_type)
    assert spec is not None
    for group in spec.accepts:
        credential = _sample(group)
        assert missing_fields(connector_type, credential) == ()
        connector = get_connector(connector_type)
        connector.credential = credential
        assert connector.is_configured() is True, (
            f"{connector_type}: the spec calls {sorted(group)} complete but "
            "is_configured() disagrees"
        )


@pytest.mark.parametrize("connector_type", sorted(set(_LIVE)))
def test_dropping_any_declared_field_makes_the_bundle_unusable(
    connector_type: str, _aws_capture_available
) -> None:
    """Catches a spec that over-declares -- a field the connector never reads.

    Without this, a spec could list every field under the sun, every complete
    bundle would still satisfy the connector, and the form would demand values
    nobody needs.
    """
    spec = spec_for(connector_type)
    assert spec is not None
    for group in spec.accepts:
        if len(group) < 2 and len(spec.accepts) > 1:
            # A single-field alternative cannot be reduced without falling back
            # to another accepted group; covered by the group that has fields.
            continue
        for dropped in group:
            credential = {k: v for k, v in _sample(group).items() if k != dropped}
            connector = get_connector(connector_type)
            connector.credential = credential
            assert connector.is_configured() is False, (
                f"{connector_type}: is_configured() accepts a bundle without "
                f"{dropped!r}, so the spec declares a field it does not need"
            )
            assert dropped in missing_fields(connector_type, credential)


def test_a_secret_field_is_declared_for_every_type_that_has_one() -> None:
    """``key_last4`` is derived from a secret field; a spec with none would
    surface the whole JSON bundle as the masked display value."""
    for connector_type, spec in SPECS.items():
        if connector_type == "puppetdb":
            continue  # its token is genuinely optional
        assert any(f.secret for f in spec.fields), (
            f"{connector_type} declares no secret field"
        )


def test_the_connectors_page_only_offers_types_that_can_be_configured() -> None:
    """Creating a connector must lead somewhere.

    The page used to offer ``grc.CONNECTOR_TYPES``, the demo vocabulary paired
    with ``_MOCK_DISCOVERY``. Seven of its ten entries -- azure, azure_gov,
    m365, m365_gcc_high, aws, github, servicenow -- have no connector and no
    credential spec, so creating one produced a row that could never capture
    anything. Meanwhile msgraph, azure_arm, puppetdb, msgraph_write and emass,
    which do work, could not be created through the UI at all.

    Both directions are asserted, since a page offering nothing would satisfy
    the first on its own.
    """
    from ccf.api.routes.ui_grc import _configurable_types

    offered = dict(_configurable_types())
    assert offered, "the connectors page offers no types at all"

    unconfigurable = sorted(set(offered) - set(SPECS))
    assert not unconfigurable, (
        f"offered but not configurable, so creating one leads nowhere: {unconfigurable}"
    )

    # And the Microsoft app registration -- the case this was reported for --
    # is reachable.
    assert "msgraph" in offered
    assert offered["msgraph"] == SPECS["msgraph"].label


def test_the_demo_connector_vocabulary_is_no_longer_what_the_page_offers() -> None:
    """Pins the separation, so a future edit cannot quietly reunite them."""
    from ccf.api.routes.grc import CONNECTOR_TYPES
    from ccf.api.routes.ui_grc import _configurable_types

    offered = {key for key, _label in _configurable_types()}
    demo_only = {"azure", "azure_gov", "m365", "m365_gcc_high", "github", "servicenow"}
    assert demo_only <= set(CONNECTOR_TYPES), "the demo vocabulary changed shape"
    assert not (demo_only & offered), (
        "the connectors page is offering demo types again: "
        f"{sorted(demo_only & offered)}"
    )
