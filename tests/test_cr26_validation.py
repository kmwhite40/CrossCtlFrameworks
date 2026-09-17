# tests/test_cr26_validation.py
"""CR26 document validation: resolves offline, or not at all.

The load-bearing property is that $ref resolution never touches the network.
Ten of the eleven schemas reference common-definitions by absolute URL.
jsonschema resolves a $ref through whatever registry it is given: with none at
all it falls back to fetching over the network; with a registry, anything
absent from it raises Unresolvable -- with zero sockets attempted. So the
registry built from the vendored files is the entire network barrier, not a
convenience, and every test below that claims something about reference
resolution runs with sockets blocked to prove it.

The trap this file is shaped around: resolution is LAZY. A document that fails
an earlier `required` check -- or simply never includes the property carrying
the $ref -- never descends into it, so a "minimal invalid document" fixture
passes identically with or without a registry and proves nothing. Every test
below that claims something about reference resolution uses a document
complete enough to actually reach the $ref it is testing, and a parametrized
sweep proves this for every one of the ten kinds that carries an absolute ref
-- not just the one or two easiest to hand-build a fixture for.
"""

from __future__ import annotations

import json
import socket
from typing import Any

import pytest
from jsonschema.validators import validator_for
from referencing import Registry, Resource

import ccf.cr26.validation as _cr26_validation
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
    assert report.mode == "none"


def test_an_unknown_kind_is_reported_not_raised() -> None:
    report = validate_document({}, "no-such-kind")
    assert report.ok is False
    assert report.mode == "none"


def test_the_cpo_schema_rejects_a_malformed_logo_uri_offline(no_network: None) -> None:
    """CPO's only absolute $ref sits at serviceIdentification.properties.logo,
    well below the required checks an empty document already fails on -- so an
    empty-document fixture (this test's previous form) passed identically with
    or without a registry and proved nothing about reference resolution. This
    document descends far enough to actually reach the $ref: 'logo' is present
    with a value ($ref'd to a string/uri definition) that cannot satisfy it.
    """
    doc = {"serviceIdentification": {"logo": 12345}}  # not a string/uri
    report = validate_document(doc, "cpo")
    assert report.ok is False
    assert report.mode == "official"
    assert any("logo" in e for e in report.errors), report.errors


def _find_first_absolute_ref_path(schema: Any) -> tuple[Any, ...] | None:
    """The schema-keyword path (e.g. ``("properties", "logo")``) to the first
    ``$ref`` in ``schema`` that points at another document by absolute URL --
    found by walking the schema, not by reading it and hand-picking one."""

    def _walk(node: Any, path: tuple[Any, ...]) -> tuple[Any, ...] | None:
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str) and ref.startswith("https://"):
                return path
            for key, value in node.items():
                found = _walk(value, (*path, key))
                if found is not None:
                    return found
        elif isinstance(node, list):
            for index, value in enumerate(node):
                found = _walk(value, (*path, index))
                if found is not None:
                    return found
        return None

    return _walk(schema, ())


def _instance_reaching(path: tuple[Any, ...], leaf: Any) -> Any:
    """Build the smallest instance whose structure makes ``path`` -- a
    schema-keyword path from :func:`_find_first_absolute_ref_path` -- actually
    get validated, with ``leaf`` as the value at the end of it.

    No ``required`` property along the way needs to be satisfied: ``$ref``
    resolution is lazy, but only in the sense that jsonschema applies a
    property's subschema (a bare ``$ref`` included) to whatever value is
    actually present in the instance for it, regardless of whether other
    required siblings are present or absent.
    """
    if not path:
        return leaf
    head, *rest = path
    if head == "properties":
        prop, *rest = rest
        return {prop: _instance_reaching(tuple(rest), leaf)}
    if head == "items":
        return [_instance_reaching(tuple(rest), leaf)]
    return _instance_reaching(tuple(rest), leaf)


def _kinds_with_absolute_ref() -> list[str]:
    """Every CR26 kind whose vendored schema references another document by
    absolute URL -- ten of eleven, found programmatically rather than by
    reading the spec's survey and hand-copying the list."""
    kinds = []
    for kind in CR26_KINDS:
        path = schema_path(kind)
        assert path is not None
        schema = json.loads(path.read_text(encoding="utf-8"))
        if _find_first_absolute_ref_path(schema) is not None:
            kinds.append(kind)
    return kinds


def _registry_missing_common_definitions() -> Any:
    """Every vendored schema except common-definitions -- the one resource
    every absolute $ref in these schemas actually needs, deliberately
    withheld."""
    resources = []
    for kind, (_filename, _rule) in CR26_KINDS.items():
        if kind == "common":
            continue
        path = schema_path(kind)
        assert path is not None
        doc = json.loads(path.read_text(encoding="utf-8"))
        uri = doc.get("$id")
        if uri:
            resources.append((uri, Resource.from_contents(doc)))
    return Registry().with_resources(resources)


@pytest.mark.parametrize("kind", sorted(_kinds_with_absolute_ref()))
def test_every_kind_with_an_absolute_ref_actually_resolves_it(
    kind: str, no_network: None
) -> None:
    """A hand-written test proves resolution for one kind (sdr) and, with the
    fix above, a second (cpo). That leaves eight more carrying absolute refs
    with nothing proving they need the registry at all. This sweeps all ten
    programmatically: build a document that reaches each kind's own $ref
    location, then show resolution genuinely depends on common-definitions
    being registered -- present, it resolves without raising; deliberately
    withheld, it raises -- with zero sockets attempted either way.
    """
    path = schema_path(kind)
    assert path is not None
    schema = json.loads(path.read_text(encoding="utf-8"))
    ref_path = _find_first_absolute_ref_path(schema)
    assert ref_path is not None, f"{kind} was selected as having an absolute $ref"
    doc = _instance_reaching(ref_path, 999999)  # wrong type for every referenced def

    # The real registry, via the real entry point: resolves, never raises.
    report = validate_document(doc, kind)
    assert isinstance(report, ValidationReport)
    assert report.mode == "official"

    # common-definitions deliberately withheld: must raise. This is the
    # discriminating half -- if it did NOT raise here, the $ref would have
    # been silently skipped rather than resolved above.
    cls = validator_for(schema)
    stripped = cls(schema, registry=_registry_missing_common_definitions())
    with pytest.raises(Exception, match="Unresolvable"):
        list(stripped.iter_errors(doc))


def test_validate_document_reports_rather_than_raises_on_an_incomplete_registry(
    monkeypatch: pytest.MonkeyPatch, no_network: None
) -> None:
    """_registry() now fails loudly if it is ever built incomplete (see its
    docstring) -- but the point of a report-shaped API is that no bug upstream
    of it should be able to surface to a caller as an unhandled traceback.
    Force validate_document down exactly that path: swap in a registry that is
    missing common-definitions and confirm a ValidationReport comes back.
    """
    monkeypatch.setattr(_cr26_validation, "_registry", _registry_missing_common_definitions)
    report = validate_document(_valid_sdr(), "sdr")
    assert isinstance(report, ValidationReport)
    assert report.ok is False
    assert report.mode == "none"


def test_the_enforced_format_set_is_what_this_environment_actually_checks() -> None:
    """jsonschema registers a format checker only when that format's optional
    validator is installed. Here date and email are enforced; date-time and uri
    are NOT -- rfc3339-validator and rfc3986-validator are absent, and a
    malformed value silently passes.

    Pinning the whole live set, not just the four formats this module's schemas
    happen to use, makes the gap a recorded fact and means a dependency change
    that quietly adds or drops any checker cannot pass silently. Without this,
    a future test written to prove a malformed date-time is caught could never
    pass, and one written to prove a document validates would pass vacuously.
    """
    assert enforced_formats() == (
        "date",
        "email",
        "idn-email",
        "idn-hostname",
        "ipv4",
        "ipv6",
        "regex",
        "time",
        "uuid",
    )


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
