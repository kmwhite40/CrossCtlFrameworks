"""Revision diffing: control set, prose, parameters, baseline membership."""

from __future__ import annotations

import json

from ccf.catalog.diff import ControlChange, diff_revisions
from ccf.catalog.oscal import OscalCatalog, OscalControl, OscalParam
from ccf.etl.sources import diff_content_index


def _ctl(
    cid: str,
    *,
    title: str = "T",
    statement: str = "S",
    guidance: str = "G",
    withdrawn: bool = False,
    params: tuple[OscalParam, ...] = (),
) -> OscalControl:
    return OscalControl(
        canonical_id=cid,
        title=title,
        statement=statement,
        guidance=guidance,
        withdrawn=withdrawn,
        incorporated_into=[],
        param_ids=[p.id for p in params],
        params=list(params),
    )


def _cat(*controls: OscalControl, baselines: dict[str, set[str]] | None = None) -> OscalCatalog:
    c = OscalCatalog(version="5.2.0")
    for ctl in controls:
        c.controls[ctl.canonical_id] = ctl
    c.baselines = baselines or {"low": set(), "moderate": set(), "high": set()}
    return c


def test_detects_added_and_removed_controls() -> None:
    d = diff_revisions(_cat(_ctl("AC-1")), _cat(_ctl("AC-1"), _ctl("AC-2")))
    assert d.added == ("AC-2",)
    assert d.removed == ()

    d2 = diff_revisions(_cat(_ctl("AC-1"), _ctl("AC-2")), _cat(_ctl("AC-1")))
    assert d2.removed == ("AC-2",)


def test_detects_withdrawal_transitions() -> None:
    d = diff_revisions(_cat(_ctl("AC-1")), _cat(_ctl("AC-1", withdrawn=True)))
    assert d.newly_withdrawn == ("AC-1",)
    assert d.un_withdrawn == ()

    d2 = diff_revisions(_cat(_ctl("AC-1", withdrawn=True)), _cat(_ctl("AC-1")))
    assert d2.un_withdrawn == ("AC-1",)


def test_detects_prose_changes_separately() -> None:
    d = diff_revisions(
        _cat(_ctl("AC-1", title="Old", statement="S", guidance="G")),
        _cat(_ctl("AC-1", title="New", statement="S2", guidance="G")),
    )
    (change,) = d.changed
    assert change.canonical_id == "AC-1"
    assert change.title_changed is True
    assert change.statement_changed is True
    assert change.guidance_changed is False


def test_detects_parameter_changes() -> None:
    p_old = OscalParam(id="ac-1_prm_1", label="frequency", guidance="", choices=[])
    p_new = OscalParam(id="ac-1_prm_1", label="frequency", guidance="", choices=["annually"])
    p_extra = OscalParam(id="ac-1_prm_2", label="role", guidance="", choices=[])

    d = diff_revisions(
        _cat(_ctl("AC-1", params=(p_old,))),
        _cat(_ctl("AC-1", params=(p_new, p_extra))),
    )
    (change,) = d.changed
    assert change.params_added == ("ac-1_prm_2",)
    assert change.params_changed == ("ac-1_prm_1",)
    assert change.params_removed == ()


def test_detects_baseline_membership_shift() -> None:
    old = _cat(
        _ctl("AC-1"), _ctl("AC-2"), baselines={"low": {"AC-1"}, "moderate": set(), "high": set()}
    )
    new = _cat(
        _ctl("AC-1"), _ctl("AC-2"), baselines={"low": {"AC-2"}, "moderate": set(), "high": set()}
    )
    d = diff_revisions(old, new)
    assert d.baseline_entered["low"] == ("AC-2",)
    assert d.baseline_left["low"] == ("AC-1",)


def test_identical_catalogs_produce_empty_diff() -> None:
    a = _cat(_ctl("AC-1"), baselines={"low": {"AC-1"}})
    b = _cat(_ctl("AC-1"), baselines={"low": {"AC-1"}})
    d = diff_revisions(a, b)
    assert d.is_empty() is True
    assert d.to_dict()["added"] == []


def test_unchanged_control_is_not_reported_as_changed() -> None:
    p = OscalParam(id="ac-1_prm_1", label="frequency", guidance="", choices=["annually"])
    d = diff_revisions(_cat(_ctl("AC-1", params=(p,))), _cat(_ctl("AC-1", params=(p,))))
    assert d.changed == ()


def test_control_level_result_matches_content_index_diff() -> None:
    """The control-set computation must agree with the poller's own index diff."""
    d = diff_revisions(_cat(_ctl("AC-1"), _ctl("AC-2")), _cat(_ctl("AC-2"), _ctl("AC-3")))
    idx = diff_content_index({"AC-1": "x", "AC-2": "y"}, {"AC-2": "y", "AC-3": "z"})
    assert list(d.added) == idx["added"]
    assert list(d.removed) == idx["removed"]


def test_control_change_to_dict_is_serialisable() -> None:
    change = ControlChange(
        canonical_id="AC-1",
        title_changed=True,
        statement_changed=False,
        guidance_changed=False,
        params_added=("p1",),
        params_removed=(),
        params_changed=(),
    )
    payload = json.dumps(change.to_dict())
    assert "AC-1" in payload
