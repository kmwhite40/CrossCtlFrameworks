"""Google Cloud as a declarable platform.

Spec: ``docs/superpowers/specs/2026-09-24-google-cloud-platform-design.md`` §5.

The parametrized suites in ``test_ssp_platforms.py`` already cover ``gcp`` for
FIPS wording and draft marking, because they iterate ``CLOUD_PLATFORMS`` -- that
is what parametrizing them was for. This file holds what is specific to adding
a platform with **no connector**, and the checks that stop a half-added
platform drafting a blank family.
"""

from __future__ import annotations

import pytest

from ccf.governance.automation import PLATFORM_TO_SSP, QUESTIONNAIRE
from ccf.models import ScoringControl
from ccf.ssp.constants import PLATFORM_DOMAIN_RESPONSIBILITY
from ccf.ssp.platforms import (
    CLOUD_PLATFORMS,
    GOV_ENVIRONMENTS,
    PLATFORM_CONNECTOR_KEYS,
    PLATFORMS,
    connector_key_for_platform,
    customer_responsibility_statement,
    normalize_platform,
    platform_label,
    sample_statement,
)

GCP = "gcp"
FAMILIES = ("AC", "AT", "AU", "CA", "CM", "IA", "IR", "MA", "MP", "PE", "PS", "RA", "SC", "SI")

#: Product and brand names belonging to the other platforms. A drafted GCP
#: statement containing any of these is the platform-default defect returning:
#: a system drafted with another provider's services.
FOREIGN_NAMES = (
    "AWS", "Amazon", "Azure", "Microsoft", "Entra", "Intune", "Purview",
    "CloudTrail", "GuardDuty", "Defender", "Sentinel", "Key Vault",
)


def _rec(domain: str = "AC") -> ScoringControl:
    return ScoringControl(
        control_id=f"{domain}.L2-3.1.1",
        nist_id=f"{domain}-2",
        domain=domain,
        title="A control",
        requirement="authorized users are identified and access is limited",
        m365_coverage_status="Customer Responsibility",
    )


_PART = {"label": "a", "text": "authorized users are identified and access is limited"}


# ── §5.7 a half-added platform must fail here, not draft a blank family ─────


#: Microsoft 365 is deliberately absent from ``PLATFORM_DOMAIN_RESPONSIBILITY``:
#: it is the one platform with **per-practice** coverage
#: (``ScoringControl.m365_coverage_status``), so a per-domain table would be a
#: coarser second answer to a question already answered precisely. Named here
#: rather than skipped silently, so the exception is visible.
PER_PRACTICE_PLATFORMS = frozenset({"m365"})


@pytest.mark.parametrize("platform", CLOUD_PLATFORMS)
def test_every_cloud_platform_has_an_environment_and_a_responsibility_model(
    platform: str,
) -> None:
    """Derived from ``CLOUD_PLATFORMS`` rather than hand-listed, so a platform
    added to the label table and nowhere else fails here."""
    assert platform in GOV_ENVIRONMENTS, f"{platform} has no government environment"
    assert GOV_ENVIRONMENTS[platform].strip()
    if platform in PER_PRACTICE_PLATFORMS:
        pytest.skip(f"{platform} carries per-practice coverage instead")
    assert platform in PLATFORM_DOMAIN_RESPONSIBILITY, f"{platform} has no responsibility model"


@pytest.mark.parametrize("platform", CLOUD_PLATFORMS)
@pytest.mark.parametrize("domain", FAMILIES)
def test_every_cloud_platform_names_services_for_every_family(
    platform: str, domain: str
) -> None:
    """A missing family drafts a sentence that names nothing, which reads as an
    author who thought no services were needed."""
    text = sample_statement(platform, _rec(domain), _PART)
    assert "does not recognize" not in text, f"{platform}/{domain} drafted as unrecognized"
    assert "names none here" not in text, f"{platform}/{domain} has no service catalogue entry"


# ── §5.4 the platform-default defect, checked directly ──────────────────────


@pytest.mark.parametrize("domain", FAMILIES)
def test_a_gcp_statement_never_names_another_providers_products(domain: str) -> None:
    """The defect this is the direct check for: a GCP customer's SSP describing
    Microsoft 365, because a default had to resolve to something."""
    text = sample_statement(GCP, _rec(domain), _PART)
    for name in FOREIGN_NAMES:
        assert name not in text, f"{domain} statement names {name!r}: {text[:160]}"


@pytest.mark.parametrize("domain", FAMILIES)
def test_the_customer_responsibility_draft_is_equally_clean(domain: str) -> None:
    text = customer_responsibility_statement(GCP, _rec(domain))
    for name in FOREIGN_NAMES:
        assert name not in text, f"{domain} responsibility names {name!r}"


def test_a_gcp_statement_names_google_services() -> None:
    """The other direction: a check that only forbids things passes on silence."""
    text = sample_statement(GCP, _rec("AC"), _PART)
    assert "Cloud IAM" in text
    assert "Google Cloud" in text


# ── §5.6 the one claim not to make ──────────────────────────────────────────


def test_the_physical_family_names_no_fedramp_level_for_gcp() -> None:
    """Azure and AWS name a level; this module sees only the platform code, and
    Google Cloud's authorization scope varies by service and by Assured
    Workloads configuration. Asserting a level would be a claim Concord cannot
    confirm -- the same defect the FIPS certificate placeholder avoids.
    """
    text = sample_statement(GCP, _rec("PE"), _PART)
    assert "FedRAMP-authorized" in text
    for level in ("FedRAMP High", "FedRAMP Moderate", "FedRAMP Low"):
        assert level not in text, f"PE asserts {level!r}, which this code cannot confirm"


# ── §5.3 no connector, said out loud ────────────────────────────────────────


def test_gcp_has_no_capture_connector_and_says_so() -> None:
    """Deliberate, not an omission.

    ``connector_backing_state`` answers "does this tenant capture anything",
    so a platform with no connector flows through it correctly and produces
    the manual-evidence caveat. A mapping here would claim automated capture
    that does not exist.
    """
    assert GCP not in PLATFORM_CONNECTOR_KEYS
    assert connector_key_for_platform(GCP) is None


def test_the_other_platforms_still_have_theirs() -> None:
    """So the test above cannot pass by the mapping having been emptied."""
    assert connector_key_for_platform("m365") == "msgraph"
    assert connector_key_for_platform("aws_govcloud") == "aws_govcloud"


# ── §5.5 the questionnaire ──────────────────────────────────────────────────


def test_the_questionnaire_offers_gcp_and_it_round_trips() -> None:
    options = next(
        q["options"] for q in QUESTIONNAIRE if q.get("field") == "cloud_platform"
    )
    assert GCP in options
    assert PLATFORM_TO_SSP[GCP] == GCP
    assert normalize_platform(GCP) == GCP


def test_gcp_is_recognised_and_labelled_as_a_product() -> None:
    assert GCP in PLATFORMS
    label = platform_label(GCP)
    assert "Google Cloud" in label
    assert "does not recognize" not in label
