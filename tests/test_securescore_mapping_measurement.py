"""Does Microsoft publish an 800-53 mapping, or does Concord have to author one?

That question decides a substantial piece of work, and it is answerable from data
rather than from argument -- so it is measured.

Microsoft Secure Score's ``secureScoreControlProfile`` carries
``complianceInformation``: ``[{certificationName, certificationControls: [{name,
url}]}]``, declared in Graph's v1.0 model and verified against the published
``$metadata``. If it is populated, Concord reads it exactly as it reads AWS's
``RelatedRequirements`` -- provider-attested, canonicalized, unplaceable entries
named. If it is empty, the only route to M365 800-53 coverage is Concord
hand-authoring roughly sixty mappings from Microsoft's product taxonomy, which
are sixty compliance assertions Concord would have to defend to an assessor at
``platform`` trust rather than provider-attested.

Measured once on a live GCC High tenant: **empty on all 200 profiles**, while
``controlScores`` carried 224 control states. One tenant is not every tenant, and
that tenant's credential is no longer available here, which is the whole reason
this is a function an operator can run against their own tenant rather than a
sentence in a document.

The matcher for "is this certification 800-53" was written with no data to check
it against. So the measurement reports every certification name it saw, including
the ones it rejected: a matcher that cannot be verified must not also hide what it
declined.
"""

from __future__ import annotations

from ccf.posture.attested import (
    is_nist_80053_certification,
    securescore_mapping,
)


def _profile(certifications: list[dict] | None = None, **extra) -> dict:
    out: dict = {"id": "p1", "controlCategory": "Identity", "title": "Enable MFA", **extra}
    if certifications is not None:
        out["complianceInformation"] = certifications
    return out


# --------------------------------------------------------------------------
# The matcher, and what it must not hide
# --------------------------------------------------------------------------


def test_the_spellings_microsoft_might_plausibly_use_all_match() -> None:
    """Microsoft's exact spelling is unknown, so the matcher is deliberately
    tolerant of punctuation and revision suffixes."""
    for name in (
        "NIST 800-53",
        "NIST SP 800-53",
        "NIST SP 800-53 Rev. 5",
        "NIST SP 800-53 Revision 5",
        "nist80053",
        "NIST.800-53.r5",
        "FedRAMP (NIST SP 800-53)",
    ):
        assert is_nist_80053_certification(name), name


def test_other_frameworks_do_not_match() -> None:
    for name in (
        "ISO 27001",
        "PCI DSS v3.2.1",
        "CIS AWS Foundations Benchmark",
        "NIST 800-171",
        "NIST CSF",
        "SOC 2",
        "",
        None,
    ):
        assert not is_nist_80053_certification(name), name


def test_every_certification_name_seen_is_reported_even_when_rejected() -> None:
    """The self-correcting half of the measurement.

    If the matcher is wrong about Microsoft's spelling, the rejected name is in
    this list to be read -- rather than the measurement silently reporting zero
    800-53 coverage and nobody being able to tell matcher error from absent data.
    """
    out = securescore_mapping(
        [
            _profile([{"certificationName": "ISO 27001", "certificationControls": []}]),
            _profile(
                [
                    {
                        "certificationName": "Some Framework Nobody Expected",
                        "certificationControls": [],
                    }
                ]
            ),
        ]
    )
    assert out["with_nist_80053"] == 0
    assert out["certifications"] == [
        "ISO 27001",
        "Some Framework Nobody Expected",
    ]


# --------------------------------------------------------------------------
# The measurement itself
# --------------------------------------------------------------------------


def test_an_empty_field_everywhere_is_the_measured_answer() -> None:
    """The state observed on a real tenant: profiles exist, the field does not.

    Reported as 200/0/0 rather than as an error, because it is not an error -- it
    is the finding, and it is the one that decides whether hand-authoring is
    needed.
    """
    out = securescore_mapping([_profile() for _ in range(200)])
    assert out["profiles"] == 200
    assert out["with_any_certification"] == 0
    assert out["with_nist_80053"] == 0
    assert out["controls"] == []
    assert out["certifications"] == []


def test_other_frameworks_present_but_not_800_53_is_a_distinct_answer() -> None:
    """Separate from the above on purpose.

    "Microsoft publishes nothing here" and "Microsoft publishes ISO but not
    800-53" have different consequences: the first says the field is unused, the
    second says it is used and 800-53 was left out. Collapsing them into one
    number would lose the distinction that decides what to do next.
    """
    out = securescore_mapping(
        [
            _profile(
                [
                    {
                        "certificationName": "ISO 27001",
                        "certificationControls": [{"name": "A.9.4.2"}],
                    }
                ]
            )
        ]
    )
    assert out["with_any_certification"] == 1
    assert out["with_nist_80053"] == 0
    assert out["controls"] == []


def test_a_populated_mapping_is_canonicalized() -> None:
    """The case this exists to detect. Ids go through the same normalizer every
    other path uses, not a second one."""
    out = securescore_mapping(
        [
            _profile(
                [
                    {
                        "certificationName": "NIST SP 800-53 Rev. 5",
                        "certificationControls": [
                            {"name": "IA-2", "url": "https://example.gov/ia-2"},
                            {"name": "IA-02(1)"},
                        ],
                    }
                ]
            )
        ]
    )
    assert out["with_nist_80053"] == 1
    assert out["controls"] == ["IA-2", "IA-2(1)"]
    assert out["unreadable"] == []


def test_a_control_name_that_will_not_canonicalize_is_named() -> None:
    """Microsoft's ``certificationControls[].name`` is free text, so some entries
    will be prose. Named rather than dropped, as the AWS side names what it
    cannot place -- otherwise lost coverage is invisible."""
    out = securescore_mapping(
        [
            _profile(
                [
                    {
                        "certificationName": "NIST 800-53",
                        "certificationControls": [
                            {"name": "IA-2"},
                            {
                                "name": (
                                    "Identification and Authentication "
                                    "(Organizational Users)"
                                )
                            },
                        ],
                    }
                ]
            )
        ]
    )
    assert out["controls"] == ["IA-2"]
    assert out["unreadable"] == [
        "Identification and Authentication (Organizational Users)"
    ]


def test_controls_are_deduplicated_across_profiles() -> None:
    """Many Secure Score controls relate to the same 800-53 control. The measure
    is how many *controls* are reachable, not how many references exist."""
    entry = {
        "certificationName": "NIST 800-53",
        "certificationControls": [{"name": "IA-2"}],
    }
    out = securescore_mapping([_profile([entry]), _profile([entry]), _profile([entry])])
    assert out["profiles"] == 3
    assert out["with_nist_80053"] == 3
    assert out["controls"] == ["IA-2"]


def test_a_profile_counted_once_however_many_certifications_match() -> None:
    """``with_nist_80053`` counts profiles, not matching entries, or a profile
    listing 800-53 twice would inflate the numerator past the denominator."""
    out = securescore_mapping(
        [
            _profile(
                [
                    {
                        "certificationName": "NIST 800-53",
                        "certificationControls": [{"name": "IA-2"}],
                    },
                    {
                        "certificationName": "NIST SP 800-53 Rev. 5",
                        "certificationControls": [{"name": "AC-2"}],
                    },
                ]
            )
        ]
    )
    assert out["profiles"] == 1
    assert out["with_nist_80053"] == 1
    assert out["controls"] == ["AC-2", "IA-2"]


def test_malformed_input_does_not_abort_the_measurement() -> None:
    """One bad profile must not cost the measurement, which is the only thing
    that answers the question."""
    out = securescore_mapping(
        [
            "not a profile",  # type: ignore[list-item]
            _profile("not a list"),  # type: ignore[arg-type]
            _profile(
                [{"certificationName": "NIST 800-53", "certificationControls": "nope"}]
            ),
            _profile(["not a mapping"]),  # type: ignore[list-item]
            _profile(
                [
                    {
                        "certificationName": "NIST 800-53",
                        "certificationControls": [{"name": "AC-2"}],
                    }
                ]
            ),
        ]
    )
    assert out["profiles"] == 4, "a non-mapping is not a profile and is not counted"
    assert out["controls"] == ["AC-2"]


def test_no_profiles_at_all_is_zero_rather_than_an_error() -> None:
    out = securescore_mapping([])
    assert out == {
        "profiles": 0,
        "with_any_certification": 0,
        "with_nist_80053": 0,
        "controls": [],
        "unreadable": [],
        "certifications": [],
    }
