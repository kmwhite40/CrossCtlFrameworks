"""DoD/IC framework families were being swept into "Other / Misc".

``classify_header`` matches an ordered list of prefixes, first hit wins, and
anything unmatched falls to ``OTHER``. Against the real workbook that meant
77,155 of 121,944 mappings — 63% — landed in Other, and they were not junk:
they were DoD Cloud Computing SRG impact levels, DISA CCIs, CNSSI 1253
categorisations, RMF KS TAG procedures, JSIG, DoD RAR, NIST SP 800-53B
baselines, Zero Trust overlays and eMASS identifiers.

A separate class of miss: several columns belonged to a framework that was
ALREADY registered, but whose header did not start with the existing prefix —
"All MARS E 2.2" against a ``MARS`` rule, "CDM?" against ``CDM `` (with a
trailing space). Those were bugs rather than gaps.

Org-specific inheritance columns (ServiceNow, Verizon, Equinix, Nexus, COSMOS,
AF IC) stay in OTHER deliberately — they are a customer's boundary, not a
published framework.
"""

from __future__ import annotations

import pytest

from ccf.etl.frameworks import (
    _PREFIX_RULES,
    CORE_HEADERS,
    FRAMEWORKS,
    classify_header,
)

_CODES = {f.code for f in FRAMEWORKS}


@pytest.mark.parametrize(
    "header,expected",
    [
        # DoD Cloud Computing SRG impact levels — the largest single family
        ("IL-4 Mod", "DOD_SRG_IL"),
        ("IL-5 High", "DOD_SRG_IL"),
        ("IL-6 High (IL-5 + Classified Overlay)", "DOD_SRG_IL"),
        ("IL-6 High ", "DOD_SRG_IL"),  # trailing space in the source
        # DISA CCI
        ("CCI Description", "DISA_CCI"),
        ('CCI Rev 5 ("*" are automatically compliant)', "DISA_CCI"),
        ("Consolidated CCIs per Control Roll up COSMOS System Owner", "DISA_CCI"),
        # CNSSI 1253 — the source prefixes these with the C/I/A objective
        ("Integrity CNSSI 1253 High", "CNSSI_1253"),
        ("Confidentiality CNSSI 1253 Moderate", "CNSSI_1253"),
        ("Availability CNSSI 1253 Low", "CNSSI_1253"),
        ("CNSSI Assurance Control?", "CNSSI_1253"),
        # NIST SP 800-53B baselines — likewise C/I/A prefixed
        ("Integrity NIST SP 800-53B Non-NSS High", "NIST_800_53B"),
        ("Confidentiality NIST SP 800-53B Non-NSS Low", "NIST_800_53B"),
        # the rest of the DoD/IC set
        ("RMF TAG Assessment Procedures", "RMF_TAG"),
        ("RMFKS Assess Only AI Models", "RMF_TAG"),
        ("JSIG Sub control", "JSIG"),
        ("DoD RAR Reference", "DOD_RAR"),
        ("DoD Specific Assigned Values (DSPAV)", "DOD_DSPAV"),
        ("Zero Trust Overlay?", "ZERO_TRUST"),
        ("Appendix C ZT User Overlay Pillar", "ZERO_TRUST"),
        ("eMASS Rev. 5 Identifier", "EMASS"),
        # already-registered frameworks whose header missed the prefix
        ("All MARS E 2.2", "MARS_E"),
        ("CDM?", "CDM"),
        ("NIST SP 800-171 Rev 3 Source Controls", "NIST_800_171_R3"),
        ("Microsoft NIST 800-172", "NIST_800_172"),
        ("Microsoft Azure Customer Responsibility Implementation Statements", "AZURE"),
        ("Landing Zone Accelerator on AWS Verified Reference Architecture for FedRAMP High", "AWS"),
    ],
)
def test_dod_and_missed_headers_classify(header: str, expected: str) -> None:
    assert classify_header(header) == expected


@pytest.mark.parametrize(
    "header",
    [
        # A customer's own boundary is not a published framework.
        "Inheritable from Service Now - SaaS CIS/CRM",
        "Verizon Infrastructure",
        "Equinix FISMA Infrastructure",
        "Applicable to Nexus Customer Boundary?",
        "AF IC Inheritance TS",
        "Security Controls Explorer Criticality",
    ],
)
def test_org_specific_columns_stay_other(header: str) -> None:
    assert classify_header(header) == "OTHER"


@pytest.mark.parametrize(
    "header,expected",
    [
        # Guard the ordering: every rule that existed before must still win.
        ("NIST SP 800-53A Rev 5 objective", "NIST_800_53A_R5"),
        ("NIST SP 800-53 Rev. 5", "NIST_800_53_R5"),
        ("NIST CSF 2.0 subcategory", "NIST_CSF_2_0"),
        ("NIST CSF 1.1", "NIST_CSF_1_1"),
        ("FedRAMP Moderate", "FEDRAMP"),
        ("CMMC Rev. 2L2", "CMMC"),
        ("ISO 27001 Mapping", "ISO_27001"),
        ("CIS v8", "CIS_V8"),
    ],
)
def test_pre_existing_rules_still_win(header: str, expected: str) -> None:
    """The DoD block is appended, so nothing above it may change meaning."""
    assert classify_header(header) == expected


def test_every_rule_target_is_a_declared_framework() -> None:
    """A rule pointing at an unregistered code would create orphan mappings."""
    unknown = sorted({code for _, code in _PREFIX_RULES if code not in _CODES})
    assert unknown == [], f"prefix rules target undeclared frameworks: {unknown}"


def test_core_headers_are_never_classified_as_a_framework() -> None:
    for header in CORE_HEADERS:
        assert classify_header(header) is None, f"{header!r} must stay control identity"


def test_the_800_53b_rule_precedes_the_800_53_rule() -> None:
    """`startswith` means a bare "NIST SP 800-53" prefix would swallow 800-53B."""
    order = [p for p, _ in _PREFIX_RULES]
    assert order.index("NIST SP 800-53B") > order.index("NIST SP 800-53")
    # ...which is exactly why the 800-53B columns are matched by their
    # C/I/A-prefixed forms, verified above. A bare "NIST SP 800-53B ..." header
    # would still be taken by the earlier rule, so assert the known headers work.
    assert classify_header("Integrity NIST SP 800-53B Non-NSS High") == "NIST_800_53B"
