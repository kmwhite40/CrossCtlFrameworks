"""Unit tests for the catalog-currency OSCAL parser and drift diff."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy import select

import ccf.oscal.validation as _oscal_validation
from ccf.db import session_scope
from ccf.etl.sources import _diff_index, parse_oscal_catalog, seed_sources
from ccf.models import CatalogSource

#: Where the vendored OSCAL specification schemas -- and the MANIFEST.json
#: that pins their digests -- actually live, resolved the same way
#: ccf.oscal.validation.official_schema_path resolves its default (no
#: CCF_OSCAL_SCHEMA_DIR) directory, so this stays correct if that ever moves.
_OSCAL_SCHEMA_MANIFEST = Path(_oscal_validation.__file__).with_name("schemas") / "MANIFEST.json"

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


@pytest.mark.usefixtures("isolate_source_rows")
async def test_seed_sources_sets_the_oscal_ssp_schema_drift_baseline() -> None:
    """``nist_oscal_schema_ssp`` must not start life with a NULL last_sha256.

    Left NULL, its first poll would report "changed" against nothing, and
    worse, silently adopt whatever upstream ``OSCAL/main`` served that day as
    the baseline -- so a schema that had already moved past the vendored
    v1.1.2 pin by the time of the first poll would never be reported at all.
    This is exactly the blindness the CR26 schema rows are seeded against
    (see ``seed_sources``' docstring); this row shares the property and, for
    a while, did not share the fix.

    The expected digest is read from the vendored MANIFEST.json itself, not
    pasted in as a literal, so this test tracks the manifest rather than a
    snapshot of it.
    """
    manifest = json.loads(_OSCAL_SCHEMA_MANIFEST.read_text(encoding="utf-8"))
    expected = str(manifest["files"]["oscal_ssp_schema.json"])

    async with session_scope() as session:
        await seed_sources(session)
        row = (
            await session.execute(
                select(CatalogSource).where(CatalogSource.key == "nist_oscal_schema_ssp")
            )
        ).scalar_one()
        assert row.last_sha256 == expected
