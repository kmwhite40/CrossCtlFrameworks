# tests/test_cr26_validation.py
"""CR26 document validation: resolves offline, or not at all.

The load-bearing property is that $ref resolution never touches the network.
Ten of the eleven schemas reference common-definitions by absolute URL, and
jsonschema 4.26 raises Unresolvable rather than fetching -- so without a
registry built from the vendored files, every complete document fails.

The trap this file is shaped around: resolution is LAZY. A document that fails
an earlier `required` check never descends into the $ref, so a "minimal invalid
document" fixture passes with no registry at all. Every test below that claims
something about reference resolution uses a document complete enough to reach
one.
"""

from __future__ import annotations

import socket

import pytest

from ccf.cr26.validation import (
    CR26_KINDS,
    ValidationReport,
    enforced_formats,
    schema_path,
    validate_document,
)


def _valid_sdr() -> dict:
    """An SDR complete enough that validation descends into the $ref'd property.

    certificationPackageOverviewUri is $ref'd to common-definitions, so this
    document -- unlike an empty one -- cannot validate without the registry.
    """
    return {
        "certificationPackageOverviewUri": "https://example.gov/cpo.json",
        "fedRampRequirements": [
            {"frrID": "SDR-CSO-FRR", "frrImplementation": ["Implemented as described."]}
        ],
    }


class _NoNetwork(socket.socket):
    def __init__(self, *a: object, **k: object) -> None:
        raise AssertionError("validation attempted a network connection")


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Block sockets outright. 'It worked on my machine' is not the claim."""
    monkeypatch.setattr(socket, "socket", _NoNetwork)


def test_every_kind_resolves_to_a_vendored_schema() -> None:
    missing = [k for k in CR26_KINDS if schema_path(k) is None]
    assert missing == []


def test_all_eleven_schemas_have_a_kind() -> None:
    assert len(CR26_KINDS) == 11


def test_a_valid_document_validates_with_no_network(no_network: None) -> None:
    """The whole point of vendoring. Sockets are blocked; this must still pass."""
    report = validate_document(_valid_sdr(), "sdr")
    assert report.ok is True, report.errors
    assert report.mode == "official"


def test_the_ref_is_actually_resolved_not_skipped(no_network: None) -> None:
    """Prove the $ref is exercised: a value that violates the $ref'd definition
    must be REJECTED. If resolution were silently skipped this would pass."""
    doc = _valid_sdr()
    doc["certificationPackageOverviewUri"] = 12345  # not a string/uri
    report = validate_document(doc, "sdr")
    assert report.ok is False
    assert any("certificationPackageOverviewUri" in e for e in report.errors), report.errors


def test_a_missing_required_property_is_reported(no_network: None) -> None:
    report = validate_document({"fedRampRequirements": []}, "sdr")
    assert report.ok is False
    assert any("certificationPackageOverviewUri" in e for e in report.errors), report.errors


def test_a_non_object_document_is_reported_not_raised() -> None:
    report = validate_document(["not", "an", "object"], "sdr")
    assert isinstance(report, ValidationReport)
    assert report.ok is False


def test_an_unknown_kind_is_reported_not_raised() -> None:
    report = validate_document({}, "no-such-kind")
    assert report.ok is False
    assert report.mode == "none"


def test_the_cpo_schema_also_validates_offline(no_network: None) -> None:
    """Ten of eleven schemas carry absolute $refs; SDR must not be the only
    one the registry covers."""
    report = validate_document({}, "cpo")
    assert report.ok is False  # empty document, but it must not RAISE
    assert report.mode == "official"


def test_the_enforced_format_set_is_what_this_environment_actually_checks() -> None:
    """jsonschema registers a format checker only when that format's optional
    validator is installed. Here date and email are enforced; date-time and uri
    are NOT -- rfc3339-validator and rfc3986-validator are absent, and a
    malformed value silently passes.

    Pinning the live set makes the gap a recorded fact. Without this, a future
    test written to prove a malformed date-time is caught could never pass, and
    one written to prove a document validates would pass vacuously.
    """
    enforced = enforced_formats()
    assert "date" in enforced
    assert "email" in enforced
    assert "date-time" not in enforced
    assert "uri" not in enforced


def test_an_unenforced_format_lets_a_malformed_value_through(no_network: None) -> None:
    """The honest consequence of the gap above, asserted rather than implied.

    metadata.lastUpdated is declared format: date-time, which this environment
    does NOT enforce, so a plainly malformed value validates. When someone
    later installs rfc3339-validator this test flips -- and it should, loudly,
    because that is a real change in what the spine guarantees.
    """
    doc = _valid_sdr()
    doc["metadata"] = {"version": "1", "lastUpdated": "not-a-date", "updateSource": "x"}
    report = validate_document(doc, "sdr")
    assert report.ok is True, report.errors
