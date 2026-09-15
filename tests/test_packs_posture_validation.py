"""A pack that installs must be evaluable -- so posture rules fail closed here."""

from __future__ import annotations

import pytest

from ccf.packs.catalog import list_available, load_pack, validate_manifest
from ccf.posture.checks import platform_check_keys
from ccf.posture.providers import m365


def _manifest(*rules: dict) -> dict:
    return {
        "id": "test-pack",
        "name": "Test",
        "version": "1.0.0",
        "schema_version": "1",
        "controls": [{"control_id": "AC-2", "title": "Account Management"}],
        "rules": list(rules),
    }


def _form_a(**over) -> dict:
    definition = {"evaluator": m365.STALE_ACCOUNTS.key, "parameters": {"threshold_days": 60}}
    definition.update(over.pop("definition", {}))
    rule = {"key": "org.stale_accounts.60d", "kind": "posture", "definition": definition}
    rule.update(over)
    return rule


def _form_b(**over) -> dict:
    definition = {
        "provider": "msgraph",
        "resource_type": "entra_user",
        "endpoint": "/v1.0/users?$select=id,userPrincipalName,userType",
        "expected": "no guest account exists",
        "control_ids": ["AC-2", "AC-6"],
        "mode": "per_resource",
        "resource_id_field": "userPrincipalName",
        "predicate": {"op": "not_equals", "path": "userType", "value": "Guest"},
    }
    definition.update(over.pop("definition", {}))
    rule = {"key": "org.no_guests", "kind": "posture", "definition": definition}
    rule.update(over)
    return rule


# ── the change is additive ───────────────────────────────────────────────────


def test_every_bundled_pack_still_validates() -> None:
    """None declare posture rules, which is how this proves it is additive."""
    available = list_available()
    assert available, "no bundled packs found -- the test proves nothing"
    for entry in available:
        assert validate_manifest(load_pack(entry["path"])) == []


def test_a_manifest_with_no_rules_validates() -> None:
    manifest = _manifest()
    del manifest["rules"]
    assert validate_manifest(manifest) == []


def test_a_non_posture_rule_is_left_alone() -> None:
    """The existing 'assert' and 'reliability' kinds are not validated here."""
    rule = {"key": "whatever", "kind": "assert", "definition": {"metric": "x", "op": "eq"}}
    assert validate_manifest(_manifest(rule)) == []


# ── both forms accepted ──────────────────────────────────────────────────────


def test_a_valid_form_a_rule_validates() -> None:
    assert validate_manifest(_manifest(_form_a())) == []


def test_a_valid_form_b_rule_validates() -> None:
    assert validate_manifest(_manifest(_form_b())) == []


def test_form_a_needs_no_parameters() -> None:
    assert validate_manifest(_manifest(_form_a(definition={"parameters": {}}))) == []


# ── exactly one form ─────────────────────────────────────────────────────────


def test_neither_form_is_rejected() -> None:
    errors = validate_manifest(_manifest({"key": "k", "kind": "posture", "definition": {}}))
    assert errors and "evaluator" in errors[0] and "predicate" in errors[0]


def test_both_forms_at_once_is_rejected() -> None:
    """Which one would win is not a question a manifest should be able to pose."""
    rule = _form_a(definition={"predicate": {"op": "truthy", "path": "x"}})
    errors = validate_manifest(_manifest(rule))
    assert errors and "exactly one" in errors[0].lower()


def test_a_definition_that_is_not_an_object_is_rejected() -> None:
    errors = validate_manifest(_manifest({"key": "k", "kind": "posture", "definition": []}))
    assert errors


def test_a_rule_without_a_key_is_rejected() -> None:
    rule = _form_b()
    del rule["key"]
    errors = validate_manifest(_manifest(rule))
    assert errors and "key" in errors[0]


# ── collision with a platform check is an error, not an override ─────────────


def test_a_key_colliding_with_a_platform_check_is_rejected() -> None:
    """Silently overriding would let a pack weaken a platform check with an
    audit trail showing only "pack installed"."""
    rule = _form_b(key=m365.MFA_REGISTERED.key)
    errors = validate_manifest(_manifest(rule))
    assert errors
    assert m365.MFA_REGISTERED.key in errors[0]


def test_platform_check_keys_covers_every_registered_provider() -> None:
    keys = platform_check_keys()
    for check in m365.CHECKS:
        assert check.key in keys


def test_two_rules_with_the_same_key_are_rejected() -> None:
    errors = validate_manifest(_manifest(_form_b(), _form_b()))
    assert errors and "duplicate" in " ".join(errors).lower()


# ── Form A specifics ─────────────────────────────────────────────────────────


def test_an_unknown_evaluator_is_rejected() -> None:
    errors = validate_manifest(_manifest(_form_a(definition={"evaluator": "nope"})))
    assert errors and "nope" in errors[0]


def test_an_unaccepted_parameter_is_rejected() -> None:
    rule = _form_a(definition={"parameters": {"threshhold_days": 60}})
    errors = validate_manifest(_manifest(rule))
    assert errors and "threshhold_days" in errors[0]


def test_a_non_integer_threshold_is_rejected_at_install() -> None:
    """Not at scan, where it would be a TypeError inside a tenant's job."""
    rule = _form_a(definition={"parameters": {"threshold_days": "60"}})
    assert validate_manifest(_manifest(rule))


# ── Form B specifics ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "missing", ["provider", "resource_type", "endpoint", "expected", "control_ids", "predicate"]
)
def test_form_b_requires_each_field(missing: str) -> None:
    definition = dict(_form_b()["definition"])
    del definition[missing]
    rule = {"key": "org.no_guests", "kind": "posture", "definition": definition}
    errors = validate_manifest(_manifest(rule))
    assert errors, f"{missing} was not required"
    assert missing in " ".join(errors)


def test_an_unknown_mode_is_rejected() -> None:
    errors = validate_manifest(_manifest(_form_b(definition={"mode": "sometimes"})))
    assert errors and "sometimes" in errors[0]


def test_mode_defaults_to_per_resource_when_absent() -> None:
    definition = dict(_form_b()["definition"])
    del definition["mode"]
    rule = {"key": "org.no_guests", "kind": "posture", "definition": definition}
    assert validate_manifest(_manifest(rule)) == []


def test_an_unknown_op_is_rejected() -> None:
    rule = _form_b(definition={"predicate": {"op": "matches_regex", "path": "x", "value": "y"}})
    errors = validate_manifest(_manifest(rule))
    assert errors and "matches_regex" in errors[0]


def test_a_nested_unknown_op_is_rejected() -> None:
    """Composites must be walked, or an invalid child ships inside a valid parent."""
    rule = _form_b(
        definition={
            "predicate": {
                "op": "all_of",
                "predicates": [
                    {"op": "truthy", "path": "a"},
                    {"op": "regex", "path": "b", "value": "c"},
                ],
            }
        }
    )
    errors = validate_manifest(_manifest(rule))
    assert errors and "regex" in " ".join(errors)


def test_an_empty_composite_is_rejected() -> None:
    """Vacuously true would pass every resource."""
    rule = _form_b(definition={"predicate": {"op": "all_of", "predicates": []}})
    assert validate_manifest(_manifest(rule))


def test_a_predicate_without_a_path_is_rejected() -> None:
    rule = _form_b(definition={"predicate": {"op": "truthy"}})
    errors = validate_manifest(_manifest(rule))
    assert errors and "path" in " ".join(errors)


def test_equals_without_a_value_is_rejected() -> None:
    rule = _form_b(definition={"predicate": {"op": "equals", "path": "x"}})
    errors = validate_manifest(_manifest(rule))
    assert errors and "value" in " ".join(errors)


def test_intersects_without_a_values_list_is_rejected() -> None:
    rule = _form_b(definition={"predicate": {"op": "intersects", "path": "x", "values": "a"}})
    assert validate_manifest(_manifest(rule))


def test_a_control_id_that_does_not_canonicalize_is_rejected() -> None:
    """A control id nothing can look up silently orphans the check's findings."""
    rule = _form_b(definition={"control_ids": ["AC-2", "not a control"]})
    errors = validate_manifest(_manifest(rule))
    assert errors and "not a control" in " ".join(errors)


def test_an_empty_control_ids_list_is_rejected() -> None:
    """A check evidencing nothing has no reason to run."""
    assert validate_manifest(_manifest(_form_b(definition={"control_ids": []})))


def test_a_cmmc_style_control_id_is_rejected_with_guidance() -> None:
    """Capability edges and checks both key on canonical 800-53; a CMMC practice
    would never match, so it is refused rather than stored unmatched."""
    errors = validate_manifest(_manifest(_form_b(definition={"control_ids": ["AC.L2-3.1.1"]})))
    assert errors
