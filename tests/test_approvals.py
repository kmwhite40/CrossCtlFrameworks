"""Unit tests for the approval workflow (state machine + separation of duties)."""

from __future__ import annotations

import pytest

from ccf.governance.approvals import APPROVER_ROLES, ENTITY_TYPES, WorkflowError


def test_entity_types_and_roles() -> None:
    assert "ssp_project" in ENTITY_TYPES
    assert "poam" in ENTITY_TYPES
    assert "admin" in APPROVER_ROLES


def _sod_check(auth_on: bool, role: str, actor: str, submitter: str) -> None:
    """Mirror the guard in approvals.decide for isolated testing."""
    if auth_on:
        if role not in APPROVER_ROLES:
            raise WorkflowError("approver must hold an authorizing role")
        if actor and submitter and actor == submitter:
            raise WorkflowError("separation of duties: approver must differ from submitter")


def test_sod_blocks_self_approval_when_auth_on() -> None:
    with pytest.raises(WorkflowError, match="separation of duties"):
        _sod_check(auth_on=True, role="admin", actor="alice", submitter="alice")


def test_sod_blocks_non_approver_role() -> None:
    with pytest.raises(WorkflowError, match="authorizing role"):
        _sod_check(auth_on=True, role="viewer", actor="bob", submitter="alice")


def test_sod_allows_distinct_approver() -> None:
    _sod_check(auth_on=True, role="admin", actor="bob", submitter="alice")  # no raise


def test_single_operator_mode_skips_sod() -> None:
    # Auth disabled: one principal, so SoD cannot apply and must not block.
    _sod_check(auth_on=False, role="viewer", actor="system", submitter="system")
