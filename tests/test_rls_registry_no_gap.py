"""Registry test (2026-08-12 RLS-coverage design): the set of ccf tables that
carry ``organization_id`` directly and have no ``tenant_isolation`` policy
must be empty. This is the test that stops the gap this slice closes from
reopening — a twelfth table added later with ``organization_id`` and no
policy fails this test immediately, with no new test to write, distinct from
``tests/test_rls_coverage.py``'s hardcoded 121-table snapshot (which only
notices a *removed* policy, not a newly-added unpolicied table, since
`found - EXPECTED` there is asserted empty but nothing asserts anything
about tables neither set mentions).

A second assertion covers the other side: tables with *neither*
``organization_id`` nor a ``tenant_isolation`` policy are legitimate only if
they are genuinely global reference data — the fourteen named in the design
doc's "The remaining fourteen" section, verified live against
``information_schema.columns`` to carry no ``organization_id`` at all. A new
global-looking table is not assumed exempt; it must appear on this explicit
allow-list, so adding it is a decision made in review, not an omission
discovered later. (A table scoped via a parent FK rather than a direct
``organization_id`` column — e.g. ``poams`` via ``system_id`` — is neither
caught nor missed by either assertion here: it already carries its own
``tenant_isolation`` policy, covered by ``tests/test_rls_coverage.py``, and
is absent from both of this module's queries because it lacks
``organization_id`` *and* has a policy.)
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text

from ccf.config import get_settings
from ccf.db import session_scope

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


#: Global reference data with no tenant dimension (2026-08-12 design, "The
#: remaining fourteen"). Verified live: none of these carry an
#: organization_id column, so none is scoped by any tenant. A future table on
#: this side of the split must be added here explicitly, in the same review
#: that adds the table — test_tables_without_organization_id_match_the_named_global_allowlist
#: below fails loudly if it is not.
GLOBAL_TABLES: frozenset[str] = frozenset(
    {
        "controls",
        "frameworks",
        "control_families",
        "framework_mappings",
        "worksheets",
        "worksheet_rows",
        "ingestion_runs",
        "catalog_sources",
        "catalog_checks",
        "scoring_controls",
        "statement_templates",
        "ksis",
        "ai_action_definitions",
        "alembic_version",
    }
)

_ORG_TABLES_WITHOUT_POLICY_SQL = text(
    "SELECT c.relname FROM pg_class c "
    "JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE n.nspname = 'ccf' AND c.relkind = 'r' "
    "AND EXISTS (SELECT 1 FROM information_schema.columns col "
    "  WHERE col.table_schema = 'ccf' AND col.table_name = c.relname "
    "  AND col.column_name = 'organization_id') "
    "AND NOT EXISTS (SELECT 1 FROM pg_policy p "
    "  WHERE p.polrelid = c.oid AND p.polname = 'tenant_isolation')"
)

_TABLES_WITHOUT_ORG_COLUMN_OR_POLICY_SQL = text(
    "SELECT c.relname FROM pg_class c "
    "JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE n.nspname = 'ccf' AND c.relkind = 'r' "
    "AND NOT EXISTS (SELECT 1 FROM information_schema.columns col "
    "  WHERE col.table_schema = 'ccf' AND col.table_name = c.relname "
    "  AND col.column_name = 'organization_id') "
    "AND NOT EXISTS (SELECT 1 FROM pg_policy p "
    "  WHERE p.polrelid = c.oid AND p.polname = 'tenant_isolation')"
)


async def test_no_tenant_owned_table_is_missing_its_rls_policy() -> None:
    """The load-bearing assertion: every ccf table with organization_id has a
    tenant_isolation policy. An empty result is the pass condition.
    """
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    async with session_scope() as s:
        rows = (await s.execute(_ORG_TABLES_WITHOUT_POLICY_SQL)).scalars().all()
    assert rows == [], (
        f"tenant-owned table(s) with no tenant_isolation policy: {sorted(rows)} — "
        "add the policy (see migration 0060 for the pattern) before this can pass"
    )


async def test_tables_without_organization_id_match_the_named_global_allowlist() -> None:
    """The other side of the split, defended explicitly rather than by
    omission: a table with neither organization_id nor a policy is legitimate
    only if it is on GLOBAL_TABLES.
    """
    if not str(get_settings().database_url).startswith("postgresql"):
        pytest.skip("RLS is a PostgreSQL feature")
    async with session_scope() as s:
        rows = (await s.execute(_TABLES_WITHOUT_ORG_COLUMN_OR_POLICY_SQL)).scalars().all()
    found = frozenset(rows)
    missing_from_allowlist = found - GLOBAL_TABLES
    stale_in_allowlist = GLOBAL_TABLES - found
    assert not missing_from_allowlist, (
        f"unpolicied table(s) not on GLOBAL_TABLES: {sorted(missing_from_allowlist)} — "
        "either give it organization_id + a tenant_isolation policy, or add it to "
        "GLOBAL_TABLES with a documented reason it has no tenant dimension"
    )
    assert not stale_in_allowlist, (
        f"GLOBAL_TABLES names table(s) that no longer exist or now carry a policy: "
        f"{sorted(stale_in_allowlist)} — update the allow-list"
    )
