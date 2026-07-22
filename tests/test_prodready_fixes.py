"""Regression tests for the production-readiness fixes.

Covers the defects repaired in the hardening pass: SSP readiness gating, ODP
completeness, objectives parsing, assessment summarization, the ETL family
classifier + header-contract enforcement, defensive logging, and the extended
row-level-security coverage.
"""

from __future__ import annotations

import openpyxl
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import ccf.logging as ccf_logging
from ccf.assessment.seed import summarize_results
from ccf.config import get_settings
from ccf.db import session_scope, set_session_tenant
from ccf.etl.pipeline import FAMILY_RE, ingest_workbook
from ccf.etl.validate import HeaderContractError
from ccf.models import Organization, Task
from ccf.scoring.parser import split_objectives
from ccf.ssp.completeness import assess

# Reset the global async engine around every test in this module (the DB tests
# below reuse the singleton engine, which binds to a per-test event loop). Mirrors
# tests/test_auth.py — safe for the pure tests too.
pytestmark = pytest.mark.usefixtures("fresh_engine")

# --- pure-function fixes ----------------------------------------------------


def test_split_objectives_strips_dangling_semicolon() -> None:
    """A part ending in '; and' must not keep the orphaned semicolon."""
    parts = split_objectives("[a] X is defined; and\n[b] Y is set.")
    assert parts[0] == {"label": "a", "text": "X is defined"}
    assert parts[1]["text"] == "Y is set."


_FULL_META = {
    "system_type": "Cloud",
    "fips199": {"overall": "moderate"},
    "authorization_boundary": "boundary",
    "roles": {
        "system_owner": {"name": "A"},
        "isso": {"name": "B"},
        "authorizing_official": {"name": "C"},
    },
}


def _complete_entry(**kw):
    base = dict(
        control_id="AC.L2-3.1.1",
        part_narratives=[{"text": "The organization does X."}],
        responsible_role="System Owner",
        implementation_status=["Implemented"],
        control_origination=["Inherited"],
        odp_definitions=[],
        odp_values={},
        evidence_ref="s3://evidence/default-config-export.pdf",
    )
    base.update(kw)
    return base


def test_readiness_requires_all_controls_complete() -> None:
    """A high blended score must NOT mark an SSP ready while a control is empty."""
    entries = [_complete_entry(control_id=f"AC.L2-3.1.{i}") for i in range(19)]
    entries.append(
        _complete_entry(
            control_id="AC.L2-3.1.99",
            part_narratives=[{"text": ""}],
            responsible_role=None,
            implementation_status=[],
            control_origination=[],
        )
    )
    r = assess(_FULL_META, entries)
    assert r["controls_complete"] == 19
    assert r["controls_total"] == 20
    assert r["score"] >= 95  # the 80/20 blend still scores high...
    assert r["ready"] is False  # ...but readiness now demands every control complete


def test_readiness_zero_controls_not_ready() -> None:
    assert assess(_FULL_META, [])["ready"] is False


def test_odp_zero_value_counts_as_filled() -> None:
    """A parameter value of 0 is a filled value, not a gap."""
    entry = _complete_entry(
        odp_definitions=[{"key": "threshold"}],
        odp_values={"threshold": 0},
    )
    r = assess(_FULL_META, [entry])
    assert r["controls_complete"] == 1
    assert r["control_gaps"] == []


def test_summarize_results_handles_none_finding() -> None:
    """A null finding is treated as 'not_assessed', not counted as assessed."""

    class _R:
        def __init__(self, finding, domain="AC", reviewed=False):
            self.finding = finding
            self.domain = domain
            self.reviewed = reviewed

    out = summarize_results([_R(None), _R("satisfied"), _R("not_assessed")])
    assert out["total"] == 3
    assert out["assessed"] == 1  # only the "satisfied" row
    assert None not in out["by_finding"]
    assert out["by_finding"]["not_assessed"] == 2


def test_family_regex_matches_leading_and_trailing_code() -> None:
    for label in ("(AC) Access Control", "Access Control (AC)"):
        m = FAMILY_RE.search(label)
        assert m is not None and m.group(1) == "AC"


def test_configure_logging_tolerates_bad_level(monkeypatch: pytest.MonkeyPatch) -> None:
    """A misspelled CCF_LOG_LEVEL must not crash logging setup."""
    class _S:
        log_level = "BOGUS"
        log_json = False

    monkeypatch.setattr(ccf_logging, "get_settings", _S)
    ccf_logging.configure_logging()  # must not raise


# --- DB-backed fixes --------------------------------------------------------


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.mark.asyncio
async def test_rls_covers_governance_tables() -> None:
    """Org-scoped operational tables (e.g. tasks) inherit tenant isolation (0022)."""
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")

    async with session_scope() as s:  # unscoped (bypass)
        await set_session_tenant(s, None)
        await s.execute(delete(Task).where(Task.title == "RlsTask"))
        ids = []
        for name in ("RlsTaskOrgA", "RlsTaskOrgB"):
            org = (
                await s.execute(select(Organization).where(Organization.name == name))
            ).scalar_one_or_none() or Organization(name=name)
            if org.id is None:
                s.add(org)
                await s.flush()
            s.add(Task(organization_id=org.id, title="RlsTask"))
            ids.append(org.id)
        await s.flush()
        org_a, org_b = ids

    # Tenant A sees only its own task even with no app-layer filter.
    async with session_scope() as s:
        await set_session_tenant(s, org_a)
        rows = (
            await s.execute(select(Task.organization_id).where(Task.title == "RlsTask"))
        ).scalars().all()
        assert org_a in rows and org_b not in rows

    async with session_scope() as s:  # cleanup
        await set_session_tenant(s, None)
        await s.execute(delete(Task).where(Task.title == "RlsTask"))


@pytest.mark.asyncio
async def test_ingest_enforces_header_contract_without_data_rows(tmp_path) -> None:
    """A header-only assessment sheet missing required headers must FAIL the run
    (previously validation was skipped when there were no data rows)."""
    wb = openpyxl.Workbook()
    a = wb.active
    a.title = "SP.800-53Ar5_assessment"
    a.append(["family", "identifier"])  # valid sheet, but missing required headers
    path = tmp_path / "headeronly.xlsx"
    wb.save(path)

    engine = create_async_engine(str(get_settings().database_url))
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as session:
            with pytest.raises(HeaderContractError):
                await ingest_workbook(session, path)
            await session.rollback()
    finally:
        await engine.dispose()
