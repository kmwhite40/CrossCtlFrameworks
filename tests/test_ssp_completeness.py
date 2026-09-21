"""Unit tests for SSP completeness/readiness scoring."""

from __future__ import annotations

from ccf.ssp.completeness import assess, is_draft_or_placeholder
from ccf.ssp.constants import GENERIC_ROLE_FLAG
from ccf.ssp.statements import DRAFT_PREFIX

_FULL_META = {
    "system_type": "Cloud",
    "fips199": {"overall": "moderate"},
    "authorization_boundary": "the tenant",
    "roles": {
        "system_owner": {"name": "A"},
        "isso": {"name": "B"},
        "authorizing_official": {"name": "C"},
    },
}


def _entry(**kw):
    base = dict(
        control_id="AC.L2-3.1.1",
        part_narratives=[{"text": "The organization does X."}],
        responsible_role="System Owner",
        implementation_status=["Implemented"],
        control_origination=["Inherited"],
        odp_definitions=[],
        odp_values={},
        evidence_ref="s3://evidence/default-config-export.pdf",
    )
    base.update(kw)
    return base


def test_full_ssp_is_ready() -> None:
    r = assess(_FULL_META, [_entry(), _entry(control_id="AC.L2-3.1.2")])
    assert r["controls_complete"] == 2
    assert r["missing_sections"] == []
    assert r["ready"] is True
    assert r["score"] == 100.0


def test_missing_front_matter_flagged() -> None:
    r = assess({}, [_entry()])
    assert "System Owner" in r["missing_sections"]
    assert "FIPS-199 categorization" in r["missing_sections"]
    assert r["ready"] is False


def test_control_gaps_detected() -> None:
    bad = _entry(
        control_id="AU.L2-3.3.1",
        part_narratives=[{"text": ""}],
        responsible_role=None,
        odp_definitions=[{"key": "audit_retention_period"}],
        odp_values={},
    )
    r = assess(_FULL_META, [bad])
    gaps = r["control_gaps"][0]["gaps"]
    assert "no implementation narrative" in gaps
    assert "no responsible role" in gaps
    assert any("unfilled parameter" in g for g in gaps)


def test_all_draft_ssp_with_no_evidence_is_not_ready() -> None:
    """An SSP of auto-composed [DRAFT] statements with zero evidence must not
    score 100% ready — draft narratives and unresolved ODP placeholders both
    need a human to review them before the control counts as complete."""
    draft_entry = _entry(
        control_id="AC.L2-3.1.1",
        part_narratives=[{"text": DRAFT_PREFIX + "The platform provides the capability."}],
        evidence_ref=None,
    )
    placeholder_entry = _entry(
        control_id="AC.L2-3.1.2",
        part_narratives=[{"text": "Sessions are locked after [Assignment: inactivity period]."}],
        evidence_ref=None,
    )
    r = assess(_FULL_META, [draft_entry, placeholder_entry])
    assert r["ready"] is False
    assert r["controls_complete"] == 0
    assert r["score"] < 100.0
    gap_map = {g["control_id"]: g["gaps"] for g in r["control_gaps"]}
    assert "draft narrative — needs review" in gap_map["AC.L2-3.1.1"]
    assert "draft narrative — needs review" in gap_map["AC.L2-3.1.2"]


def test_implemented_without_evidence_is_gapped() -> None:
    """A control marked Implemented (or Partially Implemented) with no linked
    evidence — neither an entry-level evidence reference nor evidence on the
    underlying control implementation — must be flagged, not scored complete."""
    no_evidence = _entry(
        control_id="AC.L2-3.1.1",
        implementation_status=["Implemented"],
        evidence_ref=None,
    )
    partial_no_evidence = _entry(
        control_id="AC.L2-3.1.3",
        implementation_status=["Partially Implemented"],
        evidence_ref=None,
    )
    r = assess(_FULL_META, [no_evidence, partial_no_evidence])
    assert r["ready"] is False
    assert r["controls_complete"] == 0
    gap_map = {g["control_id"]: g["gaps"] for g in r["control_gaps"]}
    assert "implemented without evidence" in gap_map["AC.L2-3.1.1"]
    assert "implemented without evidence" in gap_map["AC.L2-3.1.3"]


def test_complete_entry_with_evidence_ref_has_no_new_gaps() -> None:
    """A real (non-draft) narrative, filled ODPs, and an entry-level evidence
    reference should not trip either new gate."""
    good = _entry(
        control_id="AC.L2-3.1.1",
        part_narratives=[{"text": "The organization enforces MFA for all remote access."}],
        implementation_status=["Implemented"],
        evidence_ref="s3://evidence/ac-3.1.1-config-export.pdf",
    )
    r = assess(_FULL_META, [good])
    assert r["control_gaps"] == []
    assert r["controls_complete"] == 1
    assert r["ready"] is True
    assert r["score"] == 100.0


def test_selection_placeholder_with_qualifier_is_caught() -> None:
    """NIST notation for a Selection placeholder is ``[Selection (one or more):
    ...]`` (see ssp/odp.py's _SELECTION_RE) — not the bare ``[Selection: ...]``
    the token list used to look for. An unresolved Selection placeholder using
    the real NIST notation must still be flagged as a draft narrative."""
    entry = _entry(
        control_id="AC.L2-3.1.1",
        part_narratives=[
            {"text": "Access is limited to [Selection (one or more): keyboard; card; biometric]."}
        ],
    )
    r = assess(_FULL_META, [entry])
    gaps = r["control_gaps"][0]["gaps"]
    assert "draft narrative — needs review" in gaps


def test_generic_fallback_responsible_role_does_not_satisfy_named_party_gate() -> None:
    """FR-13: ssp/seed.py falls back to the generic "{Domain} Lead / System
    Owner" label (flagged with GENERIC_ROLE_FLAG) when no named system_owner/
    ISSO role is on file. That bare fallback must not silently count as a
    real, named responsible party — it must still be gapped."""
    bad = _entry(responsible_role=f"Access Control Lead / System Owner — {GENERIC_ROLE_FLAG}")
    r = assess(_FULL_META, [bad])
    gaps = r["control_gaps"][0]["gaps"]
    assert any("responsible role" in g and "generic" in g.lower() for g in gaps)
    assert r["controls_complete"] == 0


def test_named_responsible_role_has_no_generic_role_gap() -> None:
    """A real name (or a human-entered role like "System Owner" with no
    generic-fallback flag) does not trip the new gate."""
    good = _entry(responsible_role="Jane Doe (System Owner)")
    r = assess(_FULL_META, [good])
    assert r["control_gaps"] == []
    assert r["controls_complete"] == 1


def test_complete_entry_with_control_implementation_evidence_has_no_new_gaps() -> None:
    """When there's no entry-level evidence reference, linked evidence on the
    underlying control implementation also satisfies the evidence gate."""
    good = _entry(
        control_id="AC.L2-3.1.1",
        part_narratives=[{"text": "The organization enforces MFA for all remote access."}],
        implementation_status=["Implemented"],
        control_implementation={"evidence": [{"title": "MFA config export"}]},
    )
    r = assess(_FULL_META, [good])
    assert r["control_gaps"] == []
    assert r["ready"] is True


def test_is_draft_or_placeholder_matches_the_marker_with_or_without_a_space() -> None:
    """The draft-marker widening. ``DRAFT_PREFIX`` is ``"[DRAFT] "`` WITH a
    trailing space, and the old predicate tested it as a plain substring, so a
    marker not followed by a space (a human typing ``"[DRAFT]"`` with nothing
    after it, or at the end of a sentence like ``"Done. [DRAFT]"``) was not
    recognised as a draft. ``is_draft_or_placeholder`` now matches the marker
    either way.

    Every shape flagged before this change must still be flagged -- this is a
    widening, not a narrowing.
    """
    # Newly caught: the marker with nothing (or no space) after it.
    assert is_draft_or_placeholder("[DRAFT]") is True
    assert is_draft_or_placeholder("Done. [DRAFT]") is True
    # Still caught: every shape that was already flagged.
    assert is_draft_or_placeholder("[DRAFT] Describe the implementation.") is True
    assert is_draft_or_placeholder("Done. [DRAFT] ") is True
    assert is_draft_or_placeholder("We use [DRAFT] mode") is True
    # Still NOT flagged: ordinary text with no marker at all.
    assert is_draft_or_placeholder("The organization enforces MFA.") is False


def test_draft_prefix_construction_is_unchanged_by_the_widening() -> None:
    """The widening changes DETECTION only. ``DRAFT_PREFIX`` itself must keep
    its trailing space so ``DRAFT_PREFIX + text`` still constructs
    ``"[DRAFT] text"`` -- every producer (``ssp/statements.py``,
    ``ssp/platforms.py``, ``ssp/nist80053.py``, ``governance/automation.py``)
    depends on that literal shape."""
    assert DRAFT_PREFIX == "[DRAFT] "
    assert DRAFT_PREFIX + "The platform provides the capability." == (
        "[DRAFT] The platform provides the capability."
    )
