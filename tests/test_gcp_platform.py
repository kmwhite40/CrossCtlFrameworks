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
    manual_evidence_note_for,
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


def test_gcp_has_a_capture_connector() -> None:
    """It did not, and the platform shipped deliberately unmapped so an
    evidence claim would say "no connector exists" rather than imply a capture
    that did not run. The connector exists now, so the mapping is the honest
    state and the note changes with it -- see the test below.
    """
    assert PLATFORM_CONNECTOR_KEYS[GCP] == "gcp"
    assert connector_key_for_platform(GCP) == "gcp"


def test_every_cloud_platform_now_has_a_connector() -> None:
    """Google Cloud was the last one without. Derived from CLOUD_PLATFORMS so
    a platform added later without one fails here and has to decide
    deliberately, as Google Cloud did for a day."""
    missing = [p for p in CLOUD_PLATFORMS if connector_key_for_platform(p) is None]
    assert not missing, f"cloud platforms with no capture connector: {missing}"


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


# ── the output, not just the input ──────────────────────────────────────────
#
# The tests above assert that `gcp` maps to no connector. That is the INPUT to
# the manual-evidence decision, not the decision. A claim was published saying
# a Google Cloud system's evidence claim correctly reports manual evidence;
# this is the check that the claim is true.


def test_a_gcp_system_is_now_told_to_configure_the_connector() -> None:
    """The note follows the connector, which is the whole point of keying the
    choice off the mapping rather than off recognition.

    While Concord shipped none, NO TENANT CAPTURE would have told the reader to
    configure something that did not exist -- an instruction nobody could
    follow. One exists now, so that is exactly the right thing to say, and NO
    CONNECTOR would be the false one.
    """
    from ccf.ssp.platforms import (  # noqa: PLC0415
        MANUAL_EVIDENCE_MARKER,
        NO_TENANT_CAPTURE_NOTE,
    )

    note = manual_evidence_note_for(GCP)
    assert note == NO_TENANT_CAPTURE_NOTE
    assert "NO TENANT CAPTURE" in note
    assert "NO CONNECTOR" not in note
    # And it is still findable by whatever keys off the shared marker.
    assert MANUAL_EVIDENCE_MARKER in note


def test_a_platform_with_no_connector_is_still_told_the_other_thing() -> None:
    """The case Google Cloud used to be, kept under test by the platform that
    still is one: a system that declared no cloud at all."""
    from ccf.ssp.platforms import MANUAL_EVIDENCE_NOTE, NO_PLATFORM  # noqa: PLC0415

    assert connector_key_for_platform(NO_PLATFORM) is None
    assert manual_evidence_note_for(NO_PLATFORM) == MANUAL_EVIDENCE_NOTE


def test_a_platform_that_does_have_a_connector_is_told_the_other_thing() -> None:
    """The positive control: a check that only ever returns one note is not a
    check. AWS GovCloud ships a connector, so an unbacked AWS system is a
    tenant that has not captured -- a different fact with a different fix."""
    from ccf.ssp.platforms import NO_TENANT_CAPTURE_NOTE  # noqa: PLC0415

    note = manual_evidence_note_for("aws_govcloud")
    assert note == NO_TENANT_CAPTURE_NOTE
    assert "NO TENANT CAPTURE" in note


@pytest.mark.parametrize("platform", CLOUD_PLATFORMS)
def test_every_cloud_platform_gets_a_note_that_is_true_of_it(platform: str) -> None:
    """Derived from CLOUD_PLATFORMS, so a platform added later with no
    connector fails here rather than telling its customers to configure one
    that does not exist."""
    from ccf.ssp.platforms import MANUAL_EVIDENCE_MARKER  # noqa: PLC0415

    note = manual_evidence_note_for(platform)
    assert MANUAL_EVIDENCE_MARKER in note
    has_connector = connector_key_for_platform(platform) is not None
    assert ("NO TENANT CAPTURE" in note) is has_connector, (
        f"{platform} has_connector={has_connector} but was given: {note[:60]}"
    )
