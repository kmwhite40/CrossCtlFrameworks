"""Adapter-level tests for official OSCAL schema validation (no DB required).

Covers the two things the feasibility spike found broken in a naive jsonschema
wiring: OSCAL's draft-07 + `#anchor` refs (handled by `validator_for` instead of
a hardcoded dialect) and its ECMA Unicode-property regex patterns (`\\p{L}` etc.,
which Python `re` cannot compile at all) — the latter is the key regression test:
a token-populated document must not crash validation.
"""

from __future__ import annotations

import re

from ccf.oscal.validation import _translate_ecma_pattern, official_schema_path, validate_document


def test_translate_ecma_pattern():
    out = _translate_ecma_pattern(r"^(\p{L}|_)(\p{L}|\p{N}|[.\-_])*$")
    assert r"\p{" not in out
    re.compile(out)  # must compile under Python re


def test_official_schema_resolves_from_package_by_default(monkeypatch):
    # No CCF_OSCAL_SCHEMA_DIR set -> resolves the in-package schemas dir.
    from ccf.config import get_settings  # noqa: PLC0415

    get_settings.cache_clear()
    p = official_schema_path("ssp")
    assert p is not None and p.name.endswith(".json")


def test_token_populated_ssp_does_not_crash_and_runs_official():
    doc = {
        "system-security-plan": {
            "uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "metadata": {
                "title": "t",
                "last-modified": "2026-01-01T00:00:00Z",
                "version": "1",
                "oscal-version": "1.1.2",
                "props": [{"name": "x", "value": "y"}],
            },
        }
    }
    report = validate_document(doc)  # must NOT raise (the \p regex bug)
    assert report.mode == "official"  # packaged schema resolved
    assert not report.ok  # this partial doc is genuinely invalid
    assert report.errors
