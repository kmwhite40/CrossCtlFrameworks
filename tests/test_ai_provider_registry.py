"""One list of AI providers, and it has to match what the build can construct.

``_SUPPORTED_PROVIDERS`` on the settings page and the if-chain in
``build_provider`` were separate claims that happened to agree. A provider in
the chain but not the tuple was unofferable; one in the tuple but not the
chain stored an *enabled* credential with a masked key whose every use raised
``unknown AI provider``. Nothing here compares a list to itself: each
assertion constructs the provider or asks the gateway to store it.
"""

from __future__ import annotations

import pathlib

import pytest

from ccf.ai.providers import SUPPORTED_PROVIDERS, build_provider
from ccf.ai.providers.base import AIProvider, ProviderError


def test_every_offered_provider_can_actually_be_constructed() -> None:
    """The direction that makes a stored credential useless."""
    assert SUPPORTED_PROVIDERS, "no providers are offered at all"
    for name in SUPPORTED_PROVIDERS:
        provider = build_provider(name, "sk-test-key")
        assert isinstance(provider, AIProvider), f"{name} did not build a provider"


def test_a_provider_outside_the_list_is_refused_by_the_builder() -> None:
    """The other direction: the list cannot quietly over-promise."""
    with pytest.raises(ProviderError):
        build_provider("gemini", "k")


def test_the_settings_page_offers_exactly_what_the_build_supports() -> None:
    """Derived rather than restated, so the two cannot drift again."""
    from ccf.api.routes.ai_settings import _SUPPORTED_PROVIDERS  # noqa: PLC0415

    assert tuple(_SUPPORTED_PROVIDERS) == tuple(SUPPORTED_PROVIDERS)


def _adapter_modules() -> tuple[str, ...]:
    """Provider adapter modules, discovered from the filesystem.

    Discovered rather than listed, because the failure this catches is the
    list being *too short*: with the offered set and the page's set derived
    from one another, dropping a provider shrinks both and every other
    assertion here still passes. That mutation survived the first version of
    this module. A module on disk is evidence the list cannot shrink away
    from.
    """
    package = pathlib.Path(__import__("ccf.ai.providers", fromlist=["x"]).__file__).parent
    return tuple(
        sorted(
            path.stem
            for path in package.glob("*.py")
            if not path.stem.startswith("_") and path.stem != "base"
        )
    )


def test_every_adapter_module_on_disk_is_offered() -> None:
    """A provider someone implemented and forgot to list is unreachable:
    no organization can select it, so the adapter is dead code."""
    modules = _adapter_modules()
    assert modules, "no provider adapter modules were discovered"
    missing = sorted(set(modules) - set(SUPPORTED_PROVIDERS))
    assert not missing, (
        f"implemented but not offered, so unreachable: {missing}"
    )


def test_every_offered_provider_has_an_adapter_module() -> None:
    """And the reverse, from the same independent evidence."""
    extra = sorted(set(SUPPORTED_PROVIDERS) - set(_adapter_modules()))
    assert not extra, f"offered with no adapter module: {extra}"
