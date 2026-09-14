"""Seeded sources cover every baseline, and the reliability check sees revisions."""

from __future__ import annotations

from sqlalchemy import delete

from ccf.db import session_scope
from ccf.etl.sources import DEFAULT_SOURCES, parse_commit_url
from ccf.models import CatalogRevision
from ccf.reliability.checks import _check_catalog_integrity


def _keys() -> set[str]:
    return {s["key"] for s in DEFAULT_SOURCES}


def test_all_three_80053b_baselines_are_registered_sources() -> None:
    """_BASELINE_FILES needs all three, but only HIGH was ever registered."""
    assert {
        "nist_800_53_r5_low_baseline",
        "nist_800_53_r5_moderate_baseline",
        "nist_800_53_r5_high_baseline",
    } <= _keys()


def test_csf_and_800_171_are_registered_sources() -> None:
    assert "nist_csf_2_0_catalog" in _keys()
    assert "nist_800_171_r3_catalog" in _keys()


def test_every_source_declares_a_url_and_kind() -> None:
    for s in DEFAULT_SOURCES:
        assert s["url"], f"{s['key']} has no url"
        assert s.get("kind", "oscal_catalog"), f"{s['key']} has no kind"


def test_source_keys_are_unique() -> None:
    keys = [s["key"] for s in DEFAULT_SOURCES]
    assert len(keys) == len(set(keys))


def test_oscal_source_urls_are_commit_pinnable() -> None:
    """OSCAL sources must be GitHub raw URLs so revisions can be commit-pinned."""
    for s in DEFAULT_SOURCES:
        if s.get("kind", "oscal_catalog") != "oscal_catalog":
            continue
        repo, ref, path = parse_commit_url(s["url"])
        assert repo and ref and path, f"{s['key']} is not commit-pinnable: {s['url']}"


async def test_reliability_check_reports_the_adopted_revision() -> None:
    """The existing catalog check is extended, not replaced, to see revisions."""
    async with session_scope() as session:
        check = await _check_catalog_integrity(session)
    assert check.name == "catalog_integrity"
    # Migration 0066 adopted the bundled revision, so it must be named here.
    assert "bundled" in check.message


async def test_reliability_check_survives_a_missing_revision_table_row() -> None:
    """A deployment with no adopted revision must degrade, not fail."""
    async with session_scope() as session:
        await session.execute(delete(CatalogRevision))
        check = await _check_catalog_integrity(session)
        assert check.name == "catalog_integrity"
        assert "no adopted revision" in check.message.lower()
        await session.rollback()
