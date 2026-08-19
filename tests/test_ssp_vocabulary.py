"""One column, one vocabulary.

``SSPControlEntry.implementation_status`` and ``control_origination`` are plain
JSONB lists with no DB constraint. Two seeders wrote them, and they disagreed:
the CMMC path emitted the canonical capitalised set from ``ssp.constants``,
while the 800-53 path emitted a lowercase/hyphenated set — ``["planned"]``,
``["system-specific"]`` — that appears nowhere in ``constants``.

Every consumer compares case-sensitively: the evidence-required gate in
``ssp/completeness.py``, the editor's checkbox filter in ``api/routes/ui.py``,
and the docx renderer. So an 800-53 entry rendered with *no* status selected,
the first HTML save silently rewrote the stored value, and the
"implemented without evidence" gate could not fire for it.

Writes were also unvalidated — the handler applies the body with a blind
``setattr`` — so any string at all could be stored.
"""

from __future__ import annotations

import inspect

import pytest
from pydantic import ValidationError

from ccf.api.routes.ssp import EntryUpdate
from ccf.ssp import constants, nist80053
from ccf.ssp.completeness import _EVIDENCE_REQUIRED_STATUSES


def test_named_defaults_belong_to_their_vocabularies() -> None:
    assert constants.PLANNED in constants.IMPLEMENTATION_STATUS_OPTIONS
    assert constants.ORG_SYSTEM_SPECIFIC in constants.CONTROL_ORIGINATION_OPTIONS


def test_the_80053_seeder_emits_canonical_values() -> None:
    """The defect: this seeder used its own vocabulary."""
    src = inspect.getsource(nist80053)
    assert '"implementation_status": ["planned"]' not in src
    assert '"control_origination": ["system-specific"]' not in src
    assert "constants.PLANNED" in src
    assert "constants.ORG_SYSTEM_SPECIFIC" in src


@pytest.mark.parametrize(
    "field,good",
    [
        ("implementation_status", "Implemented"),
        ("implementation_status", "Not Applicable"),
        ("control_origination", "Shared"),
        ("control_origination", "Inherited"),
    ],
)
def test_canonical_values_are_accepted(field: str, good: str) -> None:
    assert getattr(EntryUpdate(**{field: [good]}), field) == [good]


@pytest.mark.parametrize(
    "field,bad",
    [
        # the old 800-53 vocabulary
        ("implementation_status", "planned"),
        ("control_origination", "system-specific"),
        # case variants of a real value — these silently disabled the gate
        ("implementation_status", "implemented"),
        ("implementation_status", "IMPLEMENTED"),
        # anything at all, which the blind setattr used to accept
        ("implementation_status", "bogus"),
        ("control_origination", ""),
    ],
)
def test_off_vocabulary_values_are_rejected(field: str, bad: str) -> None:
    with pytest.raises(ValidationError):
        EntryUpdate(**{field: [bad]})


def test_omitted_fields_are_still_optional() -> None:
    """The validator must not turn a partial update into a required-field error."""
    body = EntryUpdate(responsible_role="ISSO")
    assert body.implementation_status is None
    assert body.control_origination is None


def test_the_evidence_gate_can_match_every_seeded_status() -> None:
    """The gate compares case-sensitively against the canonical set.

    With one vocabulary this holds by construction; with two it could not.
    """
    assert set(constants.IMPLEMENTATION_STATUS_OPTIONS) >= _EVIDENCE_REQUIRED_STATUSES


def test_editor_options_serve_the_same_vocabulary_the_api_accepts() -> None:
    """The editor offered the canonical set regardless of framework.

    That was only wrong while a second vocabulary existed. Now the options
    endpoint and the validator are the same list, so a value the editor offers
    can always be saved.
    """
    for value in constants.IMPLEMENTATION_STATUS_OPTIONS:
        assert EntryUpdate(implementation_status=[value]).implementation_status == [value]
    for value in constants.CONTROL_ORIGINATION_OPTIONS:
        assert EntryUpdate(control_origination=[value]).control_origination == [value]
