"""A captured fixture must carry the shapes and none of the customer's account.

The largest residual risk in the attestation ingest is that its payload handling
was written from botocore's service model rather than from what a real account
emits. One capture from one real account closes that permanently -- which is why
the probe can save a fixture.

But a Security Hub finding is full of things that must not land in a git
repository: resource ARNs, bucket and instance names, the AWS account number,
owner addresses in ``Tags``, and whatever the account's own tooling wrote into
``ProductFields``, ``Note`` and ``UserDefinedFields``. So redaction is not a
convenience here, it is the condition on the feature existing, and it happens at
the source -- inside the connector, before anything leaves it -- rather than in
the CLI that writes the file.

The rule is an allowlist, not a denylist. A denylist ("drop Resources, drop
ProductFields") silently ships whatever field AWS adds next; an allowlist ships
only the fields the parser actually reads, so a new field is absent by default
and its absence is visible in the fixture.
"""

from __future__ import annotations

import json
from typing import Any

from ccf.posture.attested import (
    NIST_80053_R5_STANDARD_ID,
    REQUIREMENT_PREFIX,
    redact_finding,
)


def _dirty() -> dict[str, Any]:
    """A finding carrying every kind of identifier that must not survive.

    A **factory**, not a module-level dict. It was a shared dict, and the
    no-mutation test below could not fail: an earlier test calling
    ``redact_finding`` on the shared object had already removed the key the
    mutation removes, so the baseline it captured was itself already modified.
    Found by mutation, and the lesson is about the fixture rather than the code --
    a shared mutable fixture makes every test downstream of it depend on
    execution order.
    """
    return {
        "Id": (
            "arn:aws-us-gov:securityhub:us-gov-west-1:123456789012:subscription/"
            "nist-800-53/v/5.0.0/S3.8/finding/abcd-1234"
        ),
        "AwsAccountId": "123456789012",
        "AwsAccountName": "prod-payments",
        "GeneratorId": "security-control/S3.8",
        "Title": "S3 general purpose buckets should block public access",
        "Description": "This control checks whether the bucket blocks public access.",
        "Region": "us-gov-west-1",
        "FirstObservedAt": "2026-01-02T03:04:05Z",
        "Resources": [
            {
                "Id": "arn:aws-us-gov:s3:::acme-customer-invoices",
                "Type": "AwsS3Bucket",
                "Partition": "aws-us-gov",
                "Region": "us-gov-west-1",
                "Tags": {"Owner": "jane.doe@agency.gov", "CostCentre": "4417"},
                "Details": {
                    "AwsS3Bucket": {
                        "OwnerId": "deadbeef",
                        "Name": "acme-customer-invoices",
                    }
                },
            }
        ],
        "ProductFields": {
            "aws/securityhub/ProductName": "Security Hub",
            "RelatedAWSResources:0/name": (
                "securityhub-s3-bucket-level-public-access-prohibited-1a2b3c"
            ),
            "StandardsControlArn": (
                "arn:aws-us-gov:securityhub:us-gov-west-1:123456789012:control/"
                "nist-800-53/v/5.0.0/S3.8"
            ),
        },
        "Note": {
            "Text": "Accepted by J. Doe pending migration, see ticket SEC-4417",
            "UpdatedBy": "jane.doe",
        },
        "UserDefinedFields": {"internal_system": "payments-core"},
        "Severity": {"Label": "HIGH", "Normalized": 70, "Original": "HIGH"},
        "Workflow": {"Status": "NEW"},
        "RecordState": "ACTIVE",
        "Compliance": {
            "Status": "FAILED",
            "SecurityControlId": "S3.8",
            "RelatedRequirements": [
                f"{REQUIREMENT_PREFIX} AC-3",
                "PCI DSS v3.2.1/2.2",
            ],
            "AssociatedStandards": [{"StandardsId": NIST_80053_R5_STANDARD_ID}],
            "StatusReasons": [
                {
                    "ReasonCode": "CONFIG_EVALUATIONS_EMPTY",
                    "Description": "bucket acme-customer-invoices was not evaluated",
                }
            ],
            "SecurityControlParameters": [
                {"Name": "maxCredentialUsageAge", "Value": ["90"]}
            ],
        },
    }


#: Every string that must not appear anywhere in the redacted output, at any
#: depth. Checked against the serialized JSON so a value surviving inside a
#: nested structure cannot pass.
FORBIDDEN = [
    "123456789012",
    "prod-payments",
    "acme-customer-invoices",
    "jane.doe@agency.gov",
    "jane.doe",
    "4417",
    "SEC-4417",
    "payments-core",
    "deadbeef",
    "1a2b3c",
    "arn:aws-us-gov",
]


def test_nothing_identifying_survives() -> None:
    """The whole point, asserted over the serialized output rather than per key.

    A per-key assertion passes while the same value rides along inside a nested
    dict nobody thought to check -- which is how ``Resources[].Details`` or a
    ``Note`` would have reached a public repository.
    """
    blob = json.dumps(redact_finding(_dirty()))
    leaked = [token for token in FORBIDDEN if token in blob]
    assert leaked == [], f"redaction leaked identifying values: {leaked}\n{blob}"


def test_the_parser_s_inputs_all_survive() -> None:
    """Redaction that drops what the parser reads produces a useless fixture."""
    out = redact_finding(_dirty())
    assert out["Title"] == _dirty()["Title"]
    comp = out["Compliance"]
    assert comp["Status"] == "FAILED"
    assert comp["SecurityControlId"] == "S3.8"
    assert comp["RelatedRequirements"] == [
        f"{REQUIREMENT_PREFIX} AC-3",
        "PCI DSS v3.2.1/2.2",
    ]
    assert comp["AssociatedStandards"] == [{"StandardsId": NIST_80053_R5_STANDARD_ID}]


def test_the_allowlist_is_an_allowlist() -> None:
    """A field AWS adds tomorrow must be absent, not shipped.

    This is the difference between an allowlist and a denylist, and the reason
    this is an allowlist: a denylist ships every future field by default, and the
    first one carrying a resource name would leak silently.
    """
    out = redact_finding({**_dirty(), "SomeFieldAwsAddedLater": "arn:aws:secret:thing"})
    assert "SomeFieldAwsAddedLater" not in out
    assert "secret" not in json.dumps(out)

    compliance = {**_dirty()["Compliance"], "NewComplianceField": "acme-customer-invoices"}
    out = redact_finding({**_dirty(), "Compliance": compliance})
    assert "NewComplianceField" not in out["Compliance"]
    assert "acme-customer-invoices" not in json.dumps(out)


def test_the_resource_count_survives_without_the_resources() -> None:
    """How many resources a control evaluated is part of the shape being pinned;
    which resources they were is not."""
    out = redact_finding(_dirty())
    assert out["ResourceCount"] == 1
    assert "Resources" not in out


def test_a_finding_with_no_compliance_block_is_still_representable() -> None:
    """The fixture has to be able to carry the malformed cases too -- they are the
    ones the parser's guards exist for."""
    out = redact_finding({"Id": "arn:aws:x", "Title": "t"})
    assert out["Compliance"] == {}
    assert "arn" not in json.dumps(out)


def test_redaction_does_not_mutate_its_input() -> None:
    """It runs inside the connector on live data; mutating a finding there would
    change what the parser above it then sees."""
    finding = _dirty()
    before = json.dumps(finding, sort_keys=True)
    redact_finding(finding)
    assert json.dumps(finding, sort_keys=True) == before


def test_a_non_mapping_is_refused_rather_than_coerced() -> None:
    for junk in ("a string", 7, None, ["list"]):
        assert redact_finding(junk) == {}  # type: ignore[arg-type]


def test_status_reasons_keep_the_code_and_drop_the_prose() -> None:
    """``ReasonCode`` is a closed vocabulary and is useful in a fixture.
    ``Description`` interpolates the resource name, which is the leak."""
    out = redact_finding(_dirty())
    assert out["Compliance"]["StatusReasons"] == [
        {"ReasonCode": "CONFIG_EVALUATIONS_EMPTY"}
    ]
