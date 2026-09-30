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


# ---------------------------------------------------------------------------
# A disabled source has to say why it is disabled
# ---------------------------------------------------------------------------
#
# Found by turning the scheduler on. `nist_800_53a_r5_assessment` shipped
# enabled against a URL NIST does not publish -- the whole
# `usnistgov/oscal-content` tree contains no path matching `53A` -- so every
# poll recorded a 404 and every cycle logged `catalog.check_failed`. Nothing was
# broken by it, which is the problem: a source that can only ever fail trains
# whoever reads the alert digest to skim past it, and the next failure that
# matters is in the same list.
#
# Two rules, because each catches a different way this recurs.


def test_every_disabled_default_source_records_why() -> None:
    """`enabled: False` with no comment is indistinguishable from an accident.

    The next person to read the list cannot tell a deliberate "the upstream
    refuses non-browser fetches" from somebody's half-finished edit, and the
    safe-looking move is to flip it back on. The reason has to be next to the
    flag.
    """
    import inspect  # noqa: PLC0415
    import re  # noqa: PLC0415

    from ccf.etl import sources as sources_module  # noqa: PLC0415

    text = inspect.getsource(sources_module)
    # Each entry is a dict literal; find the block each disabled flag sits in by
    # walking back to the opening brace of its entry.
    disabled_keys = [s["key"] for s in sources_module.DEFAULT_SOURCES if not s.get("enabled", True)]
    assert disabled_keys, "no source is disabled; this guard has nothing to check"

    undocumented: list[str] = []
    for key in disabled_keys:
        start = text.index(f'"key": "{key}"')
        end = text.index('"enabled": False', start)
        block = text[start:end]
        # A comment somewhere in the entry, above the flag.
        if not re.search(r"^\s*#", block, flags=re.M):
            undocumented.append(key)
    assert not undocumented, (
        f"these sources are disabled with no comment saying why: {undocumented}. "
        "An undocumented flag reads as an accident and gets flipped back."
    )


def test_no_default_source_is_enabled_against_a_known_dead_upstream() -> None:
    """An allowlist of upstreams that do not exist, so nobody re-adds them.

    Deliberately not a network call: a test that fetches every source URL would
    fail on an egress-restricted build machine and pass for the wrong reason on
    a machine with a caching proxy, and it would turn NIST's uptime into this
    suite's uptime. The knowledge is recorded instead, next to the reason.
    """
    from ccf.etl import sources as sources_module  # noqa: PLC0415

    #: URL fragment -> why nothing will ever fetch it.
    dead = {
        "NIST_SP-800-53A_rev5_catalog.json": (
            "NIST does not publish 800-53A Rev. 5 as OSCAL; the oscal-content "
            "tree has no 53A path at all. Concord's assessment objectives come "
            "from the curated cross-mapping workbook instead."
        ),
    }
    offenders: list[str] = []
    for spec in sources_module.DEFAULT_SOURCES:
        if not spec.get("enabled", True):
            continue
        for fragment, why in dead.items():
            if fragment in str(spec.get("url", "")):
                offenders.append(f"{spec['key']} -> {fragment}: {why}")
    assert not offenders, (
        "these sources are enabled against an upstream that does not exist, so "
        f"every poll will record an error forever: {offenders}"
    )
