"""The POA&M status vocabulary is declared once and derived everywhere.

It used to be redefined in five private module tuples, inlined as a literal at
eleven more sites, re-transcribed as a regex in the API layer, and spelled a
*different* way in the OSCAL exporters (``not_in(("closed","completed"))``,
which includes ``risk_accepted`` in "open" where every dashboard excludes it).
Adding a sixth status meant hand-auditing all of them, and the ``not_in`` form
would have silently made any new status count as open in the exported package.

Two "open" sets survive on purpose — they answer different questions and must
not be collapsed. These tests pin both the derivation and the divergence.
"""

from __future__ import annotations

import re
from pathlib import Path

from ccf.api.routes.poams import STATUSES
from ccf.api.routes.tasks import _OPEN as TASK_OPEN
from ccf.constants import (
    POAM_ACTIVE_STATUSES,
    POAM_CLOSED_STATUSES,
    POAM_STATUSES,
    POAM_UNRESOLVED_STATUSES,
)
from ccf.models import POAM

_SRC = Path(__file__).resolve().parents[1] / "src" / "ccf"


def test_db_enum_is_built_from_the_shared_vocabulary() -> None:
    """The column, not a copy of it, is the thing that must agree."""
    assert tuple(POAM.__table__.c.status.type.enums) == POAM_STATUSES


def test_every_status_lands_in_exactly_one_bucket() -> None:
    """A sixth status must fail loudly here rather than silently pick a bucket.

    ``risk_accepted`` is deliberately in neither active nor closed: it is
    accepted residual risk, tracked in its own dashboard bucket.
    """
    covered = set(POAM_ACTIVE_STATUSES) | set(POAM_CLOSED_STATUSES) | {"risk_accepted"}
    assert covered == set(POAM_STATUSES), (
        f"status(es) in no bucket: {set(POAM_STATUSES) - covered}"
    )
    assert not set(POAM_ACTIVE_STATUSES) & set(POAM_CLOSED_STATUSES)


def test_the_two_open_sets_differ_only_by_risk_accepted() -> None:
    """The divergence is intentional and must stay exactly this shape."""
    assert set(POAM_UNRESOLVED_STATUSES) - set(POAM_ACTIVE_STATUSES) == {"risk_accepted"}


def test_api_validator_is_derived_not_retyped() -> None:
    for s in POAM_STATUSES:
        assert re.match(STATUSES, s), f"{s} rejected by the API validator"
    assert not re.match(STATUSES, "deferred")


def test_no_private_redefinition_of_the_open_set_remains() -> None:
    """Each of these was its own tuple literal before."""
    for rel in (
        "ingest/scanners.py",
        "governance/control_tests.py",
        "governance/conmon.py",
        "api/routes/systems.py",
    ):
        src = (_SRC / rel).read_text(encoding="utf-8")
        assert '= ("open", "in_progress")' not in src, f"{rel}: private tuple still declared"
        assert "POAM_ACTIVE_STATUSES" in src, f"{rel}: does not use the shared constant"


def test_oscal_export_enumerates_open_positively() -> None:
    """``not_in(("closed","completed"))`` made any future status default to OPEN.

    Positively enumerating means a new status defaults to excluded from the
    authorization package instead — the safe direction for an AO-facing export.
    """
    src = (_SRC / "api" / "routes" / "oscal.py").read_text(encoding="utf-8")
    assert 'not_in(("closed", "completed"))' not in src
    assert "POAM_UNRESOLVED_STATUSES" in src


def test_task_vocabulary_was_not_folded_in() -> None:
    """Task is a different entity: its open set includes "blocked"."""
    assert "blocked" in TASK_OPEN
    assert set(TASK_OPEN) != set(POAM_ACTIVE_STATUSES)
