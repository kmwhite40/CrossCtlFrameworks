# tests/test_catalog_params.py
from ccf.catalog.oscal import OscalParam, _parse_param, load_oscal_catalog


def test_ac2_has_odp_params():
    cat = load_oscal_catalog()
    ac2 = cat.get("AC-2")
    assert ac2 is not None
    # Real catalog param ids are zero-padded (e.g. "ac-02_odp.01"), not "ac-2...".
    assert ac2.params and ac2.params[0].id.startswith("ac-02")
    assert ac2.params[0].label  # non-empty label
    assert [p.id for p in ac2.params] == ac2.param_ids  # param_ids preserved


def test_param_choices_captured_from_select():
    # Construct a small fixture param dict matching the real catalog's select shape
    # and verify _parse_param captures the choices.
    fixture = {
        "id": "ac-02_odp.05",
        "label": "frequency",
        "guidelines": [{"prose": "Some guidance text."}],
        "props": [{"name": "label", "value": "AC-02_ODP[05]"}],
        "select": {"choice": ["daily", "weekly", "monthly"]},
    }
    param = _parse_param(fixture)
    assert isinstance(param, OscalParam)
    assert param.id == "ac-02_odp.05"
    assert param.label == "frequency"
    assert param.guidance == "Some guidance text."
    assert param.choices == ["daily", "weekly", "monthly"]


def test_real_catalog_has_a_control_with_select_choices():
    # Iterate the real bundled catalog to confirm at least one control's params
    # include non-empty select choices, and that the loader captures them.
    cat = load_oscal_catalog()
    found = False
    for control in cat.controls.values():
        for param in control.params:
            if param.choices:
                found = True
                assert all(isinstance(c, str) and c for c in param.choices)
                break
        if found:
            break
    assert found, "expected at least one control param with select choices"


def test_param_label_falls_back_to_prop_when_no_top_level_label():
    fixture = {
        "id": "ac-02_odp.01",
        "guidelines": [],
        "props": [{"name": "label", "value": "AC-02_ODP[01]"}],
    }
    param = _parse_param(fixture)
    assert param.label == "AC-02_ODP[01]"


def test_multipart_statement_includes_nested_items():
    # Real 800-53 controls carry statement text in nested labeled item parts;
    # the loader must concatenate them, not return an empty statement.
    cat = load_oscal_catalog()
    stmt = cat.get("AC-2").statement
    assert len(stmt) > 200
    assert "a." in stmt and "Assign account managers" in stmt
