import pytest

from ccf.catalog.canonical import canonicalize


@pytest.mark.parametrize("raw,expected", [
    ("AC-2", "AC-2"),
    ("AC-02", "AC-2"),
    ("ac-2", "AC-2"),
    ("AC-2 (1)", "AC-2(1)"),
    ("AC-2(1)", "AC-2(1)"),
    ("ac-02 (01)", "AC-2(1)"),
    ("AC-2 (1)(2)", "AC-2(1)(2)"),
    ("  SC-7  ", "SC-7"),
    ("PM-31", "PM-31"),
])
def test_canonicalizes_valid_ids(raw, expected):
    cid = canonicalize(raw)
    assert cid is not None and cid.value == expected


@pytest.mark.parametrize("raw", [
    None, "", "   ", "n/a", "AC.L2-3.1.1", "3.1.1", "See AC-2",
    "Access Control", "AC", "AC-",
])
def test_rejects_non_800_53_ids(raw):
    assert canonicalize(raw) is None


def test_parses_parts():
    cid = canonicalize("AC-2 (1)")
    assert cid.family == "AC" and cid.number == 2 and cid.enhancements == (1,)


def test_real_world_control_number_forms_never_crash():
    samples = ["AC-2", "AC-02", "AC-2 (1)", "AC-2(1)", "SC-7", "PM-31", "AU-2(3)",
               "AC.L2-3.1.1", "3.1.1", "", "N/A", "See AC-2", None]
    for s in samples:
        canonicalize(s)  # must not raise; return value unimportant here
