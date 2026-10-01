"""Reading AWS's own 800-53 attestation without inheriting its vocabulary.

Concord's thirteen AWS checks each evidence controls Concord chose. Security
Hub's NIST SP 800-53 Rev 5 standard evaluates several hundred AWS-authored
controls and publishes, per finding, which 800-53 requirements each one relates
to (``Compliance.RelatedRequirements``). That mapping is *provider-attested*:
AWS asserts it, so reading it extends coverage into controls Concord has no
check for without hand-authoring a crosswalk.

What this module must not do is adopt the shape of the mapping uncritically.
Three specific ways that goes wrong, each pinned below:

**Raw ids.** ``RelatedRequirements`` entries read ``"NIST.800-53.r5 AC-3"``,
not ``"AC-3"``. A reference implementation of this idea kept them raw and
scored against ``/^[A-Z]{2}-\\d+/``, so every real requirement failed to match
and the account scored zero covered -- a number that validates and is wrong.
Concord already owns the normalizer (``ccf.catalog.canonical.canonicalize``)
and must use it rather than grow a second one.

**Other frameworks in the same list.** The same list carries
``"PCI DSS v3.2.1/2.2"`` and CIS Benchmark references. Those are not 800-53
controls and are not failures either; they are simply other frameworks, and
they are dropped silently and deliberately.

**Statuses that are not verdicts.** ``NOT_AVAILABLE`` means Security Hub could
not evaluate the control. Defaulting it -- or an unrecognised status, or a
missing ``Compliance`` block -- to ``pass`` is the default-pass defect that
makes a posture report unusable. Every non-verdict resolves to
``manual_review_required``, which Concord already renders as "could not
assess" rather than "nobody has looked".
"""

from __future__ import annotations

import pytest

from ccf.fedramp20x import VALIDATION_STATUSES
from ccf.posture.attested import (
    NIST_80053_R5_STANDARD_ID,
    REQUIREMENT_PREFIX,
    attested_controls,
    attested_rows,
    check_key_for,
    requirement_ids,
    verdict_for,
)

_TITLE = "S3 general purpose buckets should block public access"


def _finding(
    control_id: str,
    status: str,
    *,
    related: list[str] | None = None,
    resource: str = "arn:aws-us-gov:s3:::bucket-one",
    title: str = "S3 buckets should block public access",
) -> dict:
    return {
        "Id": f"{control_id}/{resource}",
        "Title": title,
        "Resources": [{"Id": resource, "Type": "AwsS3Bucket"}],
        "Compliance": {
            "Status": status,
            "SecurityControlId": control_id,
            "RelatedRequirements": related
            if related is not None
            else [f"{REQUIREMENT_PREFIX} AC-3", f"{REQUIREMENT_PREFIX} SC-7"],
            "AssociatedStandards": [{"StandardsId": NIST_80053_R5_STANDARD_ID}],
        },
    }


# --------------------------------------------------------------------------
# verdict_for: the default-pass defect, closed from both directions
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("PASSED", "pass"),
        ("FAILED", "fail"),
        ("WARNING", "warn"),
        ("NOT_AVAILABLE", "manual_review_required"),
    ],
)
def test_every_documented_compliance_status_maps(status: str, expected: str) -> None:
    """The four values botocore's ``ComplianceStatus`` enum admits."""
    assert verdict_for(status) == expected


@pytest.mark.parametrize(
    "status",
    [None, "", "   ", "passed", "UNKNOWN", "SKIPPED", "NOT_APPLICABLE", "0"],
)
def test_nothing_else_becomes_a_pass(status: str | None) -> None:
    """An unrecognised status is Concord not knowing, never AWS saying yes.

    ``"passed"`` lowercase is in this list on purpose: silently upper-casing an
    unexpected spelling is how a future API change becomes a wave of passes
    nobody authored.
    """
    assert verdict_for(status) == "manual_review_required"


def test_every_verdict_is_one_concord_can_store() -> None:
    """A verdict outside ``VALIDATION_STATUSES`` fails the model constraint at
    write time, i.e. in production rather than here."""
    for status in ("PASSED", "FAILED", "WARNING", "NOT_AVAILABLE", "nonsense", None):
        assert verdict_for(status) in VALIDATION_STATUSES


# --------------------------------------------------------------------------
# requirement_ids: normalization, foreign frameworks, and what is named
# --------------------------------------------------------------------------


def test_the_prefix_is_stripped_and_the_id_canonicalized() -> None:
    """The defect the reference implementation shipped: ids kept raw."""
    readable, unreadable = requirement_ids(
        [f"{REQUIREMENT_PREFIX} AC-3", f"{REQUIREMENT_PREFIX} AC-02(1)"]
    )
    assert readable == ["AC-3", "AC-2(1)"]
    assert unreadable == []


def test_a_foreign_framework_is_dropped_without_complaint() -> None:
    """PCI and CIS entries are other frameworks, not unreadable 800-53 ids.

    Reporting them as unreadable would fill the diagnostic channel with normal
    traffic, which is how a real signal stops being read.
    """
    readable, unreadable = requirement_ids(
        [
            "PCI DSS v3.2.1/2.2",
            "CIS AWS Foundations Benchmark v1.4.0/1.4",
            f"{REQUIREMENT_PREFIX} SC-7",
        ]
    )
    assert readable == ["SC-7"]
    assert unreadable == []


def test_an_800_53_entry_that_will_not_canonicalize_is_named() -> None:
    """Named, not dropped, and not guessed at.

    ``AC-2(j)`` is a *statement part* of AC-2, not an enhancement. Mapping it
    to AC-2 would let one part-scoped attestation credit a control with twelve
    parts -- so it is reported instead, where a measurement of how much
    coverage this costs can be made from real data rather than assumed now.
    """
    readable, unreadable = requirement_ids(
        [f"{REQUIREMENT_PREFIX} AC-2(j)", f"{REQUIREMENT_PREFIX} AC-3"]
    )
    assert readable == ["AC-3"]
    assert unreadable == [f"{REQUIREMENT_PREFIX} AC-2(j)"]


def test_a_requirement_list_that_is_absent_or_empty_is_not_an_error() -> None:
    for related in (None, [], ["   "]):
        assert requirement_ids(related) == ([], [])


def test_duplicates_collapse_and_order_is_the_provider_s() -> None:
    """Order is preserved so a reader comparing with the console sees the same
    sequence; duplicates collapse because two rows for one pair would be two
    votes on one control."""
    readable, _ = requirement_ids(
        [
            f"{REQUIREMENT_PREFIX} SC-7",
            f"{REQUIREMENT_PREFIX} AC-3",
            f"{REQUIREMENT_PREFIX} SC-07",
        ]
    )
    assert readable == ["SC-7", "AC-3"]


def test_the_prefix_must_match_the_whole_token_not_a_substring() -> None:
    """``NIST.800-53.r4`` is a different revision, and r5 is what AWS's NIST
    standard attests to. Accepting it would attribute an r4 mapping to an r5
    claim."""
    readable, unreadable = requirement_ids(["NIST.800-53.r4 AC-3"])
    assert readable == []
    assert unreadable == []


@pytest.mark.parametrize(
    "entry",
    [
        "NIST.800-53.r5AC-3",
        "NIST.800-53.r5.1 AC-3",
        "NIST.800-53.r5x AC-3",
    ],
)
def test_a_malformed_prefix_is_not_salvaged_into_a_requirement(entry: str) -> None:
    """The reason the prefix is compared as a whole token.

    Found by mutation: matching with ``entry.startswith(REQUIREMENT_PREFIX)``
    and slicing the remainder passed every other test in this file, and it reads
    ``"NIST.800-53.r5AC-3"`` as an attestation about AC-3. That is a guess about
    a malformed entry, and guessing is the one thing this module does not do --
    everywhere else an id that will not parse is named rather than repaired.
    """
    assert requirement_ids([entry]) == ([], [])


# --------------------------------------------------------------------------
# attested_controls: aggregation across resources
# --------------------------------------------------------------------------


def test_one_failing_resource_fails_the_security_control() -> None:
    """Conservative in the same direction ``roll_up_findings`` already is."""
    controls = attested_controls(
        [
            _finding("S3.8", "PASSED", resource="bucket-one"),
            _finding("S3.8", "FAILED", resource="bucket-two"),
            _finding("S3.8", "PASSED", resource="bucket-three"),
        ]
    )
    assert len(controls) == 1
    assert controls[0].security_control_id == "S3.8"
    assert controls[0].verdict == "fail"
    assert controls[0].evaluated == 3
    assert controls[0].failing == 1


def test_an_all_passing_security_control_passes() -> None:
    controls = attested_controls(
        [
            _finding("S3.8", "PASSED", resource="bucket-one"),
            _finding("S3.8", "PASSED", resource="bucket-two"),
        ]
    )
    assert controls[0].verdict == "pass"
    assert controls[0].failing == 0


def test_a_control_whose_every_finding_is_not_available_is_manual_review() -> None:
    """Not a pass, and not silence either."""
    controls = attested_controls(
        [
            _finding("Macie.1", "NOT_AVAILABLE", related=[f"{REQUIREMENT_PREFIX} RA-5"]),
        ]
    )
    assert controls[0].verdict == "manual_review_required"


def test_a_finding_with_no_security_control_id_is_not_a_control() -> None:
    """Third-party product findings share the Security Hub findings store and
    carry no ``SecurityControlId``. Inventing a control id for them would mix
    another vendor's verdicts into AWS's attestation."""
    findings = [
        {"Id": "x", "Compliance": {"Status": "FAILED"}},
        {"Id": "y"},
        _finding("S3.8", "PASSED"),
    ]
    controls = attested_controls(findings)
    assert [c.security_control_id for c in controls] == ["S3.8"]


@pytest.mark.parametrize("compliance", ["FAILED", 7, [], ["Status"], True])
def test_a_compliance_block_that_is_not_a_mapping_does_not_crash_the_scan(
    compliance: object,
) -> None:
    """One malformed finding must not take the whole account's scan with it.

    ``Compliance`` is a structure in the API model, but this ingest reads
    whatever the account actually returns. Without the type guard a string there
    raises ``AttributeError`` on ``.get`` and the ingest aborts mid-page --
    losing every control after it, which reads downstream as a shrunken account
    rather than as an error.
    """
    controls = attested_controls(
        [{"Id": "x", "Compliance": compliance}, _finding("S3.8", "PASSED")]
    )
    assert [c.security_control_id for c in controls] == ["S3.8"]


def test_controls_come_back_in_a_stable_order() -> None:
    """Sorted, so a diff between two scans is about verdicts, not dict order."""
    controls = attested_controls(
        [
            _finding("S3.8", "PASSED"),
            _finding("IAM.4", "FAILED", related=[f"{REQUIREMENT_PREFIX} IA-2"]),
            _finding("CloudTrail.1", "PASSED", related=[f"{REQUIREMENT_PREFIX} AU-2"]),
        ]
    )
    assert [c.security_control_id for c in controls] == ["CloudTrail.1", "IAM.4", "S3.8"]


def test_requirements_merge_across_a_control_s_findings() -> None:
    """Two resources' findings for one control should agree on requirements,
    but if AWS changes a mapping mid-scan the union is the honest answer: a
    requirement AWS related this control to is one it related it to."""
    controls = attested_controls(
        [
            _finding("S3.8", "PASSED", resource="a", related=[f"{REQUIREMENT_PREFIX} AC-3"]),
            _finding("S3.8", "PASSED", resource="b", related=[f"{REQUIREMENT_PREFIX} SC-7"]),
        ]
    )
    assert controls[0].requirements == ("AC-3", "SC-7")


def test_an_unreadable_requirement_survives_aggregation() -> None:
    """It is the only channel that reports lost coverage, so it must not be
    dropped on the way through the aggregation."""
    controls = attested_controls(
        [_finding("IAM.8", "PASSED", related=[f"{REQUIREMENT_PREFIX} AC-2(j)"])]
    )
    assert controls[0].requirements == ()
    assert controls[0].unreadable_requirements == (f"{REQUIREMENT_PREFIX} AC-2(j)",)


# --------------------------------------------------------------------------
# attested_rows: one row per (security control, requirement)
# --------------------------------------------------------------------------


def test_a_control_becomes_one_row_per_requirement() -> None:
    """The shape that makes the existing rollup compute the right thing.

    A Security Hub control relating to AC-3, AC-4 and SC-7 must not credit all
    three from one pass -- that is the over-claim ``posture.evidence`` exists to
    prevent. Splitting into one row per requirement means each row carries
    exactly one control, so Concord's per-control rollup decides AC-3 from
    *every* Security Hub control related to AC-3, and a single narrow check can
    no longer mark three controls satisfied on its own.
    """
    controls = attested_controls(
        [
            _finding(
                "S3.8",
                "PASSED",
                related=[
                    f"{REQUIREMENT_PREFIX} AC-3",
                    f"{REQUIREMENT_PREFIX} AC-4",
                    f"{REQUIREMENT_PREFIX} SC-7",
                ],
            )
        ]
    )
    rows = attested_rows(controls)
    assert [r.control_id for r in rows] == ["AC-3", "AC-4", "SC-7"]
    assert {r.verdict for r in rows} == {"pass"}
    # Each row is evidence about exactly one control, both fields agreeing, so
    # `evidenced_controls` cannot widen pass credit back out again.
    for row in rows:
        assert row.control_ids == [row.control_id]


def test_each_row_has_a_distinct_stable_check_key() -> None:
    """``control_tests`` is unique on ``(system_id, check_key)``, which is what
    makes re-ingest idempotent rather than duplicating every row."""
    controls = attested_controls(
        [
            _finding(
                "S3.8",
                "FAILED",
                related=[f"{REQUIREMENT_PREFIX} AC-3", f"{REQUIREMENT_PREFIX} SC-7"],
            )
        ]
    )
    rows = attested_rows(controls)
    keys = [r.check_key for r in rows]
    assert keys == ["aws.securityhub.S3.8::AC-3", "aws.securityhub.S3.8::SC-7"]
    assert len(set(keys)) == len(keys)


def test_the_longest_realistic_security_control_id_still_fits() -> None:
    """``ControlTest.check_key`` is ``String(128)``, and real ids fit easily.

    This is the half of the length guard that must *not* fire: a drop rule that
    quietly discards ordinary rows would cost real coverage.
    """
    controls = attested_controls(
        [
            _finding(
                "SomeVeryLongAwsServiceName.VariantWithAParameter.17",
                "PASSED",
                related=[f"{REQUIREMENT_PREFIX} AC-2(1)(2)"],
            )
        ]
    )
    rows = attested_rows(controls)
    assert [r.control_id for r in rows] == ["AC-2(1)(2)"]
    assert len(rows[0].check_key) <= 128


def test_a_key_that_would_not_fit_the_column_is_dropped_not_truncated() -> None:
    """Truncating would be worse than dropping.

    ``(system_id, check_key)`` is unique, so two truncated keys that collide
    mean two different Security Hub controls sharing one ``control_tests`` row
    -- each scan overwriting the other's verdict for the same control. Dropping
    loses one row visibly; truncating corrupts one silently.

    The value is synthetic: no real Security Hub id is this long, which is
    exactly why the guard needs a test that actually reaches it rather than one
    that passes because the input happened to be short.
    """
    absurd = "A" * 120
    controls = attested_controls(
        [_finding(absurd, "FAILED", related=[f"{REQUIREMENT_PREFIX} AC-3"])]
    )
    assert len(check_key_for(absurd, "AC-3")) > 128
    assert attested_rows(controls) == ()


def test_a_control_with_no_readable_requirement_yields_no_rows() -> None:
    """There is no control to attribute it to, so there is nothing to write.

    The loss is reported through ``unreadable_requirements`` on the control,
    which the ingest surfaces; it is not written as a row against a guessed
    control id.
    """
    controls = attested_controls(
        [_finding("IAM.8", "FAILED", related=[f"{REQUIREMENT_PREFIX} AC-2(j)"])]
    )
    assert attested_rows(controls) == ()


def test_rows_carry_the_provider_s_title_and_counts() -> None:
    """An operator reading the row needs to know what AWS evaluated, not only
    that something related to AC-3 failed."""
    controls = attested_controls(
        [
            _finding("S3.8", "FAILED", resource="a", title=_TITLE),
            _finding("S3.8", "PASSED", resource="b", title=_TITLE),
        ]
    )
    (row,) = [r for r in attested_rows(controls) if r.control_id == "AC-3"]
    assert row.title == _TITLE
    assert row.evaluated == 2
    assert row.failing == 1
    assert row.security_control_id == "S3.8"
