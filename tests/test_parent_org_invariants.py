"""Rows added by 0099/0100 cannot reference another organization's records.

Foreign keys are checked without row-level security, so without 0101 a
session could store a row it owns that points at another tenant's risk,
vendor, engagement, system or user. ``ccf.assert_parent_org`` refuses it.

Two checks:

* **Behavioural**, on an unscoped session (RLS bypassed, so only the trigger
  can refuse): a cross-organization reference fails and the same-organization
  one succeeds, for a direct parent, a user, and a POA&M (resolved through its
  system).
* **Completeness**, from the catalog: every foreign key on the new tables
  that points at an organization-owned table is covered by a trigger. A
  column added later without one fails here by name.
"""

from __future__ import annotations

import itertools
import os
from datetime import date

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import POAM, Organization, Risk, System, User
from ccf.models_program import (
    RISK_PROGRAM_TABLES,
    TENANT_TABLES,
    BusinessUnit,
    RiskAssessment,
    RiskTreatmentAction,
    RiskTreatmentPlan,
)

pytestmark = pytest.mark.usefixtures("fresh_engine")
_SEQ = itertools.count()


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _org_with_records(tag: str) -> dict[str, int]:
    async with session_scope() as s:
        org = Organization(name=f"ParentOrg-{tag}")
        s.add(org)
        await s.flush()
        user = User(email=f"p-{tag}@x.test", organization_id=org.id, role="admin", active=True)
        system = System(organization_id=org.id, name=f"sys-{tag}")
        s.add_all([user, system])
        await s.flush()
        risk = Risk(system_id=system.id, title=f"r-{tag}", status="open")
        poam = POAM(system_id=system.id, title=f"p-{tag}", severity="low", status="open")
        s.add_all([risk, poam])
        await s.flush()
        plan = RiskTreatmentPlan(
            organization_id=org.id, risk_id=risk.id, strategy="mitigate", status="planned"
        )
        s.add(plan)
        await s.flush()
        return {
            "org": org.id,
            "user": user.id,
            "system": system.id,
            "risk": risk.id,
            "poam": poam.id,
            "plan": plan.id,
        }


@pytest.fixture
async def orgs() -> tuple[dict[str, int], dict[str, int]]:
    tag = f"po{next(_SEQ)}x{os.getpid()}{os.urandom(2).hex()}"
    return await _org_with_records(f"a{tag}"), await _org_with_records(f"b{tag}")


async def _insert(row: object) -> None:
    async with session_scope() as s:
        s.add(row)
        await s.flush()


async def test_a_risk_assessment_cannot_point_at_another_orgs_risk(orgs) -> None:
    a, b = orgs
    with pytest.raises(DBAPIError, match="same organization"):
        await _insert(
            RiskAssessment(
                organization_id=a["org"],
                risk_id=b["risk"],
                assessed_on=date.today(),
                method="qualitative",
            )
        )
    await _insert(
        RiskAssessment(
            organization_id=a["org"],
            risk_id=a["risk"],
            assessed_on=date.today(),
            method="qualitative",
        )
    )


async def test_an_owner_must_belong_to_the_organization(orgs) -> None:
    a, b = orgs
    with pytest.raises(DBAPIError, match="same organization"):
        await _insert(BusinessUnit(organization_id=a["org"], name="x", owner_user_id=b["user"]))
    await _insert(BusinessUnit(organization_id=a["org"], name="y", owner_user_id=a["user"]))


async def test_a_treatment_action_cannot_link_another_orgs_poam(orgs) -> None:
    """POA&Ms carry no organization_id; the trigger resolves it via the system."""
    a, b = orgs
    with pytest.raises(DBAPIError, match="same organization"):
        await _insert(
            RiskTreatmentAction(
                organization_id=a["org"],
                plan_id=a["plan"],
                description="d",
                status="open",
                poam_id=b["poam"],
            )
        )
    await _insert(
        RiskTreatmentAction(
            organization_id=a["org"],
            plan_id=a["plan"],
            description="d",
            status="open",
            poam_id=a["poam"],
        )
    )


async def test_a_system_cannot_join_another_orgs_business_unit(orgs) -> None:
    a, b = orgs
    async with session_scope() as s:
        bu = BusinessUnit(organization_id=b["org"], name="bu")
        s.add(bu)
        await s.flush()
        bu_id = bu.id
    with pytest.raises(DBAPIError, match="same organization"):
        async with session_scope() as s:
            await s.execute(
                text("UPDATE ccf.systems SET business_unit_id = :bu WHERE id = :sid"),
                {"bu": bu_id, "sid": a["system"]},
            )


_FKS_SQL = text(
    """
    SELECT c.relname AS tbl, a.attname AS col, pc.relname AS parent
      FROM pg_constraint k
      JOIN pg_class c ON c.oid = k.conrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
      JOIN pg_class pc ON pc.oid = k.confrelid
      JOIN pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = ANY (k.conkey)
     WHERE k.contype = 'f' AND n.nspname = 'ccf'
       AND c.relname = ANY (:tables)
       AND pc.relname <> 'organizations'
       AND (pc.relname = 'poams' OR EXISTS (
             SELECT 1 FROM information_schema.columns ic
              WHERE ic.table_schema = 'ccf' AND ic.table_name = pc.relname
                AND ic.column_name = 'organization_id'))
    """
)

_TRIGGERS_SQL = text(
    """
    SELECT c.relname AS tbl, t.tgname AS trigger
      FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
     WHERE NOT t.tgisinternal AND t.tgname LIKE 'parent_org_%'
    """
)


async def test_every_reference_to_an_org_owned_table_is_guarded() -> None:
    tables = [*TENANT_TABLES, *RISK_PROGRAM_TABLES, "systems"]
    async with session_scope() as s:
        fks = (await s.execute(_FKS_SQL, {"tables": tables})).all()
        triggers = {(r.tbl, r.trigger) for r in (await s.execute(_TRIGGERS_SQL)).all()}
    assert len(fks) >= 30, f"catalog query found only {len(fks)} foreign keys"
    unguarded = [
        f"{fk.tbl}.{fk.col} -> {fk.parent}"
        for fk in fks
        if fk.tbl != "systems" or fk.col == "business_unit_id"
        if (fk.tbl, f"parent_org_{fk.tbl}_{fk.col}"[:63]) not in triggers
    ]
    assert not unguarded, "references with no same-organization trigger:\n" + "\n".join(unguarded)
