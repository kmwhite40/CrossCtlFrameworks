"""Unit tests for the catalog-currency OSCAL parser and drift diff."""

from __future__ import annotations

from ccf.etl.sources import _diff_index, parse_oscal_catalog

SAMPLE = b"""{"catalog":{"metadata":{"version":"5.2.0"},"groups":[
  {"id":"ac","title":"Access Control","controls":[
    {"id":"ac-1","title":"Policy and Procedures",
     "parts":[{"name":"statement","prose":"Develop policy",
               "parts":[{"name":"item","prose":"Review annually"}]}],
     "controls":[
       {"id":"ac-1.1","title":"Automated Enhancement",
        "parts":[{"name":"statement","prose":"Automate it"}]}
     ]}
  ]}]}}"""


def test_parse_walks_groups_and_enhancements() -> None:
    revision, index = parse_oscal_catalog(SAMPLE)
    assert revision == "5.2.0"
    # Both the base control and its nested enhancement are indexed.
    assert set(index) == {"ac-1", "ac-1.1"}
    assert all(len(h) == 16 for h in index.values())


def test_content_hash_is_prose_sensitive() -> None:
    _, base = parse_oscal_catalog(SAMPLE)
    mutated = SAMPLE.replace(b"Review annually", b"Review quarterly")
    _, changed = parse_oscal_catalog(mutated)
    # Nested prose change flips ac-1's hash but not the untouched enhancement.
    assert changed["ac-1"] != base["ac-1"]
    assert changed["ac-1.1"] == base["ac-1.1"]


def test_diff_index_reports_add_modify_remove() -> None:
    old = {"ac-1": "aaaa", "ac-2": "bbbb"}
    new = {"ac-1": "zzzz", "ac-3": "cccc"}
    diff = _diff_index(old, new)
    assert diff == {"added": ["ac-3"], "modified": ["ac-1"], "removed": ["ac-2"]}
