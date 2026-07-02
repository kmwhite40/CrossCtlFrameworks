"""Unit tests for automatic implementation-statement composition."""

from __future__ import annotations

from ccf.ssp.statements import compose


def _c(**kw):
    base = dict(
        control_id="AC.L2-3.1.1",
        requirement="limit system access to authorized users",
        responsibility="customer",
        source="platform:m365_gcc_high",
        environment="Microsoft 365 Government (GCC High)",
        services="Entra ID Conditional Access",
    )
    base.update(kw)
    return compose(**base)


def test_inherited_names_provider_and_is_not_draft() -> None:
    text, review = _c(responsibility="inherited", source="vendor:Acme FedRAMP SaaS")
    assert "inherited from Acme FedRAMP SaaS" in text
    assert not text.startswith("[DRAFT]")
    assert review is False


def test_customer_is_draft_and_names_environment() -> None:
    text, review = _c(responsibility="customer")
    assert text.startswith("[DRAFT]")
    assert "Microsoft 365 Government (GCC High)" in text
    assert review is True


def test_not_applicable() -> None:
    text, review = _c(responsibility="not_applicable")
    assert "not applicable" in text.lower()
    assert review is False


def test_odp_and_captured_params_folded_in() -> None:
    text, _ = _c(
        odp_values={"inactivity_period": "15 minutes"},
        captured=[
            {"odp_key": "audit_retention_period", "value": "90 days", "connector": "aws_govcloud"}
        ],
    )
    assert "15 minutes" in text
    assert "captured from aws_govcloud" in text


def test_concise_style_drops_params_and_shortens() -> None:
    text, _ = _c(style="concise", odp_values={"x": "y"})
    assert "Organization-defined parameters" not in text
    assert "configures" in text.lower()


def test_mark_draft_false_omits_prefix() -> None:
    text, _ = _c(responsibility="customer", mark_draft=False)
    assert not text.startswith("[DRAFT]")
