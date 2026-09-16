"""Declarative posture predicates -- and every way one could wrongly pass."""

from __future__ import annotations

import pytest

from ccf.posture.declared import (
    MODES,
    OPS,
    DeclaredSpec,
    PredicateError,
    evaluate_declared,
    evaluate_predicate,
    resolve_path,
)
from ccf.posture.providers import m365


def _spec(**kw) -> DeclaredSpec:
    base = dict(
        mode="per_resource",
        resource_type="entra_user",
        resource_id_field="userPrincipalName",
        predicate={"op": "truthy", "path": "ok"},
        expected="the thing is so",
    )
    base.update(kw)
    return DeclaredSpec(**base)


# ── resolve_path ─────────────────────────────────────────────────────────────


def test_resolve_path_walks_dotted_segments() -> None:
    row = {"signInActivity": {"lastSignInDateTime": "2026-01-01T00:00:00Z"}}
    assert resolve_path(row, "signInActivity.lastSignInDateTime") == "2026-01-01T00:00:00Z"


def test_resolve_path_returns_none_for_a_missing_segment() -> None:
    assert resolve_path({"a": {"b": 1}}, "a.zzz") is None
    assert resolve_path({}, "a.b.c") is None


def test_resolve_path_returns_none_when_a_segment_is_not_a_mapping() -> None:
    """Traversing into a scalar must not raise mid-scan."""
    assert resolve_path({"a": "string"}, "a.b") is None


def test_resolve_path_distinguishes_an_explicit_null_from_a_missing_key() -> None:
    """Both are undeterminable, but only one is a malformed predicate path.

    Kept as a documented equivalence: Graph omits fields it cannot report, so
    treating them the same is correct -- but it must be deliberate.
    """
    assert resolve_path({"a": None}, "a") is None
    assert resolve_path({}, "a") is None


# ── the ops ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("predicate", "row", "expected"),
    [
        ({"op": "truthy", "path": "x"}, {"x": True}, True),
        ({"op": "truthy", "path": "x"}, {"x": False}, False),
        ({"op": "falsy", "path": "x"}, {"x": False}, True),
        ({"op": "falsy", "path": "x"}, {"x": "set"}, False),
        ({"op": "equals", "path": "x", "value": "a"}, {"x": "a"}, True),
        ({"op": "equals", "path": "x", "value": "a"}, {"x": "b"}, False),
        ({"op": "not_equals", "path": "x", "value": "Guest"}, {"x": "Member"}, True),
        ({"op": "not_equals", "path": "x", "value": "Guest"}, {"x": "Guest"}, False),
        ({"op": "contains", "path": "x", "value": "block"}, {"x": ["block", "mfa"]}, True),
        ({"op": "contains", "path": "x", "value": "block"}, {"x": ["mfa"]}, False),
        (
            {"op": "intersects", "path": "x", "values": ["other", "exchangeActiveSync"]},
            {"x": ["browser", "other"]},
            True,
        ),
        (
            {"op": "intersects", "path": "x", "values": ["other"]},
            {"x": ["browser"]},
            False,
        ),
    ],
)
def test_each_op_evaluates(predicate: dict, row: dict, expected: bool) -> None:
    assert evaluate_predicate(predicate, row) is expected


def test_all_of_requires_every_child() -> None:
    p = {
        "op": "all_of",
        "predicates": [
            {"op": "equals", "path": "state", "value": "enabled"},
            {"op": "contains", "path": "grants", "value": "block"},
        ],
    }
    assert evaluate_predicate(p, {"state": "enabled", "grants": ["block"]}) is True
    assert evaluate_predicate(p, {"state": "disabled", "grants": ["block"]}) is False


def test_any_of_requires_one_child() -> None:
    p = {
        "op": "any_of",
        "predicates": [
            {"op": "equals", "path": "state", "value": "enabled"},
            {"op": "equals", "path": "state", "value": "enabledForReportingButNotEnforced"},
        ],
    }
    assert evaluate_predicate(p, {"state": "enabled"}) is True
    assert evaluate_predicate(p, {"state": "disabled"}) is False


def test_all_of_is_false_not_undeterminable_when_a_determinable_child_fails() -> None:
    """A definite failure outranks a missing sibling: the row IS non-compliant."""
    p = {
        "op": "all_of",
        "predicates": [
            {"op": "equals", "path": "state", "value": "enabled"},
            {"op": "truthy", "path": "absent"},
        ],
    }
    assert evaluate_predicate(p, {"state": "disabled"}) is False


def test_all_of_is_undeterminable_when_a_child_is_and_none_failed() -> None:
    p = {
        "op": "all_of",
        "predicates": [
            {"op": "equals", "path": "state", "value": "enabled"},
            {"op": "truthy", "path": "absent"},
        ],
    }
    assert evaluate_predicate(p, {"state": "enabled"}) is None


def test_any_of_is_undeterminable_when_nothing_matched_and_a_child_was_unknown() -> None:
    p = {
        "op": "any_of",
        "predicates": [
            {"op": "equals", "path": "state", "value": "enabled"},
            {"op": "truthy", "path": "absent"},
        ],
    }
    assert evaluate_predicate(p, {"state": "disabled"}) is None


# ── every way to wrongly report pass ────────────────────────────────────────


def test_a_missing_path_is_undeterminable_not_false() -> None:
    assert evaluate_predicate({"op": "truthy", "path": "absent"}, {}) is None


def test_falsy_on_a_missing_path_is_undeterminable_not_true() -> None:
    """The dangerous direction: absence must not satisfy a "must be off" check."""
    assert evaluate_predicate({"op": "falsy", "path": "absent"}, {}) is None


def test_contains_on_a_non_list_is_undeterminable() -> None:
    """A string "contains" a substring; treating that as list membership is how
    a check silently passes."""
    predicate = {"op": "contains", "path": "x", "value": "block"}
    assert evaluate_predicate(predicate, {"x": "blocked"}) is None


def test_intersects_on_a_non_list_is_undeterminable() -> None:
    assert (
        evaluate_predicate({"op": "intersects", "path": "x", "values": ["a"]}, {"x": "a"})
        is None
    )


def test_an_unknown_op_raises_rather_than_returning_false() -> None:
    with pytest.raises(PredicateError):
        evaluate_predicate({"op": "matches_regex", "path": "x", "value": "y"}, {"x": "y"})


def test_a_missing_op_raises() -> None:
    with pytest.raises(PredicateError):
        evaluate_predicate({"path": "x"}, {"x": 1})


def test_a_composite_without_children_raises() -> None:
    """An empty all_of is vacuously true -- which would pass everything."""
    with pytest.raises(PredicateError):
        evaluate_predicate({"op": "all_of", "predicates": []}, {})


def test_intersects_without_values_raises() -> None:
    with pytest.raises(PredicateError):
        evaluate_predicate({"op": "intersects", "path": "x"}, {"x": ["a"]})


def test_the_op_vocabulary_is_closed() -> None:
    """The validator and the evaluator must share one vocabulary."""
    assert sorted(OPS) == [
        "all_of", "any_of", "contains", "equals", "falsy", "intersects",
        "not_equals", "truthy",
    ]
    assert sorted(MODES) == ["any_row", "per_resource"]


# ── per_resource mode ────────────────────────────────────────────────────────


def test_per_resource_emits_one_finding_per_row() -> None:
    findings = evaluate_declared(
        _spec(), [{"userPrincipalName": "a@x.gov", "ok": True},
                  {"userPrincipalName": "b@x.gov", "ok": False}]
    )
    assert [(f.resource_id, f.verdict) for f in findings] == [
        ("a@x.gov", "pass"),
        ("b@x.gov", "fail"),
    ]


def test_an_undeterminable_row_is_manual_review_not_pass() -> None:
    findings = evaluate_declared(
        _spec(predicate={"op": "truthy", "path": "absent"}), [{"userPrincipalName": "u1"}]
    )
    assert [f.verdict for f in findings] == ["manual_review_required"]
    assert "absent" in findings[0].observed


def test_no_rows_yields_no_findings() -> None:
    """roll_up_findings maps that to not_applicable, which is existing behaviour."""
    assert evaluate_declared(_spec(), []) == []


def test_a_row_missing_its_id_field_still_gets_a_finding() -> None:
    """Never silently drop a resource -- an unidentified failure is still a failure."""
    findings = evaluate_declared(_spec(), [{"id": "abc-123", "ok": False}])
    assert len(findings) == 1
    assert findings[0].resource_id == "abc-123"


def test_a_row_with_no_identifier_at_all_is_labelled_not_dropped() -> None:
    findings = evaluate_declared(_spec(), [{"ok": False}])
    assert len(findings) == 1
    assert findings[0].resource_id == "unknown"


# ── any_row mode ─────────────────────────────────────────────────────────────


def test_any_row_mode_passes_once_on_the_first_match() -> None:
    findings = evaluate_declared(
        _spec(mode="any_row", resource_type="m365_tenant",
              predicate={"op": "equals", "path": "state", "value": "enabled"}),
        [{"state": "disabled"}, {"state": "enabled"}],
        resource_id="tenant-1",
    )
    assert len(findings) == 1
    assert findings[0].verdict == "pass"
    assert findings[0].resource_id == "tenant-1"


def test_any_row_mode_with_no_matching_row_fails_once() -> None:
    findings = evaluate_declared(
        _spec(mode="any_row", resource_type="m365_tenant",
              predicate={"op": "equals", "path": "state", "value": "enabled"}),
        [{"state": "disabled"}, {"state": "reportOnly"}],
        resource_id="tenant-1",
    )
    assert len(findings) == 1
    assert findings[0].verdict == "fail"


def test_any_row_mode_with_nothing_determinable_is_manual_review() -> None:
    """Rows were returned but none could answer -- that is not a clean fail."""
    findings = evaluate_declared(
        _spec(mode="any_row", resource_type="m365_tenant",
              predicate={"op": "truthy", "path": "absent"}),
        [{"state": "disabled"}],
        resource_id="tenant-1",
    )
    assert [f.verdict for f in findings] == ["manual_review_required"]


def test_any_row_mode_with_no_rows_is_manual_review_not_fail() -> None:
    """An unread collection and an empty one are indistinguishable here, and
    "no policy exists" must not be asserted from "nothing was returned"."""
    findings = evaluate_declared(
        _spec(mode="any_row", resource_type="m365_tenant",
              predicate={"op": "equals", "path": "state", "value": "enabled"}),
        [],
        resource_id="tenant-1",
    )
    assert [f.verdict for f in findings] == ["manual_review_required"]


def test_an_unknown_mode_raises() -> None:
    with pytest.raises(PredicateError):
        evaluate_declared(_spec(mode="sometimes"), [{"ok": True}])


# ── the golden equivalence: does the declarative form reproduce the platform? ─


MFA_AS_DECLARED = DeclaredSpec(
    mode="per_resource",
    resource_type="entra_user",
    resource_id_field="userPrincipalName",
    # isMfaCapable, not isMfaRegistered: the platform evaluator decides the
    # verdict on whether the registered method is one the tenant's current
    # authentication methods policy actually allows -- see
    # m365.evaluate_mfa_registered.
    predicate={"op": "truthy", "path": "isMfaCapable"},
    expected="every user has a multi-factor authentication method registered",
    pass_observed="MFA-capable: a policy-allowed method is registered",
    fail_observed="not MFA-capable: no MFA method registered",
)

LEGACY_AUTH_AS_DECLARED = DeclaredSpec(
    mode="any_row",
    resource_type="m365_tenant",
    resource_id_field=None,
    predicate={
        "op": "all_of",
        "predicates": [
            {"op": "equals", "path": "state", "value": "enabled"},
            {"op": "intersects", "path": "conditions.clientAppTypes",
             "values": ["exchangeActiveSync", "other"]},
            {"op": "contains", "path": "grantControls.builtInControls", "value": "block"},
        ],
    },
    expected="an enabled Conditional Access policy blocks legacy authentication clients",
)


def test_declared_form_reproduces_the_platform_mfa_check() -> None:
    """``detail`` legitimately differs -- the platform check records userType and
    isAdmin, which no predicate declares -- so equivalence is asserted on
    (resource_id, verdict, observed)."""
    rows = [
        {"userPrincipalName": "a@x.gov", "isMfaCapable": True, "isMfaRegistered": True,
         "userType": "Member"},
        {"userPrincipalName": "b@x.gov", "isMfaCapable": False, "isMfaRegistered": False,
         "userType": "Guest"},
        {"id": "no-upn-object-id", "isMfaCapable": False, "isMfaRegistered": False},
    ]
    hand = m365.evaluate_mfa_registered(rows)
    declared = evaluate_declared(MFA_AS_DECLARED, rows)
    assert [(f.resource_id, f.verdict, f.observed) for f in declared] == [
        (f.resource_id, f.verdict, f.observed) for f in hand
    ]


@pytest.mark.parametrize(
    "policies",
    [
        [{"id": "p1", "state": "enabled",
          "conditions": {"clientAppTypes": ["exchangeActiveSync"]},
          "grantControls": {"builtInControls": ["block"]}}],
        [{"id": "p1", "state": "disabled",
          "conditions": {"clientAppTypes": ["other"]},
          "grantControls": {"builtInControls": ["block"]}}],
        [{"id": "p1", "state": "enabledForReportingButNotEnforced",
          "conditions": {"clientAppTypes": ["other"]},
          "grantControls": {"builtInControls": ["block"]}}],
        [{"id": "p1", "state": "enabled",
          "conditions": {"clientAppTypes": ["browser"]},
          "grantControls": {"builtInControls": ["block"]}}],
        [{"id": "p1", "state": "enabled",
          "conditions": {"clientAppTypes": ["other"]},
          "grantControls": {"builtInControls": ["mfa"]}}],
    ],
    ids=["blocking", "disabled", "report-only", "wrong-client-types", "grants-mfa-not-block"],
)
def test_declared_form_reproduces_the_platform_legacy_auth_verdict(policies: list) -> None:
    """Every branch of _blocks_legacy_auth, including the two states that look
    enabled but enforce nothing."""
    hand = m365.evaluate_legacy_auth_blocked(policies, tenant_id="t-1")
    declared = evaluate_declared(LEGACY_AUTH_AS_DECLARED, policies, resource_id="t-1")
    assert [f.verdict for f in declared] == [f.verdict for f in hand]
    assert [f.resource_id for f in declared] == [f.resource_id for f in hand]
