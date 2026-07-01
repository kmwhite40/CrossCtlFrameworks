"""Unit tests for organization-defined parameter extraction and rendering."""

from __future__ import annotations

from ccf.ssp.odp import extract_odps, odps_for, render


def test_extract_assignment_and_selection() -> None:
    text = (
        "Terminate a session after [Assignment: organization-defined time period] using "
        "[Selection (one or more): a lock; a logout]."
    )
    odps = extract_odps(text)
    kinds = {o.kind for o in odps}
    assert "assignment" in kinds and "selection" in kinds
    sel = next(o for o in odps if o.kind == "selection")
    assert sel.choices == ["a lock", "a logout"]


def test_curated_overlay_by_nist_id() -> None:
    defs = odps_for("3.6.2", "Report incidents to authorities.")
    keys = {d["key"] for d in defs}
    assert "incident_report_timeframe" in keys
    # A control with no curated ODPs and no markers yields nothing.
    assert odps_for("3.1.1", "Limit system access to authorized users.") == []


def test_render_substitutes_and_flags_missing() -> None:
    body = "Retain audit records for {{audit_retention_period}} on {{environment}}."
    text, missing = render(
        body,
        {"audit_retention_period": "90 days"},
        {"environment": "AWS GovCloud (US)"},
    )
    assert text == "Retain audit records for 90 days on AWS GovCloud (US)."
    assert missing == []


def test_render_reports_blank_parameters() -> None:
    text, missing = render("Lock after {{inactivity_period}}.", {}, {})
    assert "[ORGANIZATION-DEFINED: inactivity_period]" in text
    assert missing == ["inactivity_period"]
