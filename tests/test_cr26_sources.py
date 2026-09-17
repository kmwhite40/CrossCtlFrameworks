# tests/test_cr26_sources.py
"""The eleven CR26 schemas are watched for upstream drift.

kind="generic" is content-hash only, and that is the right call for the same
reason etl/sources.py already records for baseline profiles: a profile is not
a catalog, and a schema is not one either. Nothing parses a schema into tables.
auto_ingest=False means drift is surfaced for a human, never adopted silently
-- a schema that changed under us is exactly the event a person needs to see.
"""

from __future__ import annotations

from ccf.cr26.validation import CR26_KINDS
from ccf.etl.sources import DEFAULT_SOURCES

RULESET_VERSION = "2026-06-24"
_CR26 = [s for s in DEFAULT_SOURCES if s["key"].startswith("cr26_schema_")]


def test_there_is_one_source_row_per_vendored_schema() -> None:
    assert len(_CR26) == len(CR26_KINDS) == 11
    assert {s["key"] for s in _CR26} == {f"cr26_schema_{k}" for k in CR26_KINDS}


def test_each_row_points_at_the_file_that_was_vendored() -> None:
    """Row and vendored file must name the same upstream artefact, or the
    poller watches one thing while validation uses another."""
    by_key = {s["key"]: s for s in _CR26}
    for kind, (filename, _rule) in CR26_KINDS.items():
        assert by_key[f"cr26_schema_{kind}"]["url"].endswith(f"/{filename}")


def test_the_rows_are_content_hash_only_and_never_auto_ingested() -> None:
    for s in _CR26:
        assert s["kind"] == "generic", s["key"]
        assert s.get("auto_ingest", False) is False, s["key"]
        assert s["authority"] == "FedRAMP", s["key"]
        assert s["enabled"] is True, s["key"]


def test_every_url_carries_the_pinned_ruleset_revision() -> None:
    """A row pointing at an unversioned 'latest' URL would silently track
    upstream and defeat the pin."""
    for s in _CR26:
        assert f"-schema-{RULESET_VERSION}.json" in s["url"], s["key"]


def test_the_keys_do_not_collide_with_existing_sources() -> None:
    keys = [s["key"] for s in DEFAULT_SOURCES]
    assert len(keys) == len(set(keys))
