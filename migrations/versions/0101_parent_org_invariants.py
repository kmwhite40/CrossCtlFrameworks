"""Every reference from a 0099/0100 row stays inside its own organization.

Revision ID: 0101_parent_org_invariants
Revises: 0100_risk_program
Create Date: 2026-10-20

Foreign-key checks bypass row-level security, so before this an org-A session
could insert a row carrying ``organization_id = A`` that points at org B's
risk, vendor, engagement, system or user: the RLS ``WITH CHECK`` passes (the
row is A's) and the FK passes (the parent exists). The pages validate
ownership; this makes the database refuse it as well.

``ccf.assert_parent_org(fk_column, parent_table)`` is a row trigger: when the
foreign key is set, the parent's organization must equal the row's. It runs
with the caller's rights, so under a tenant's RLS another tenant's parent is
invisible and reads as a mismatch -- a cross-tenant reference is refused
without revealing whether the parent exists. ``poams`` carry no
``organization_id`` and resolve through their system.
"""

from __future__ import annotations

from alembic import op

revision = "0101_parent_org_invariants"
down_revision = "0100_risk_program"
branch_labels = None
depends_on = None

#: (table, foreign-key column, parent table). Users are parents too: an owner,
#: chair or member must belong to the row's organization.
REFERENCES: tuple[tuple[str, str, str], ...] = (
    ("systems", "business_unit_id", "business_units"),
    ("risk_appetites", "owner_user_id", "users"),
    ("key_risk_indicators", "risk_id", "risks"),
    ("key_risk_indicators", "owner_user_id", "users"),
    ("kri_readings", "kri_id", "key_risk_indicators"),
    ("business_units", "parent_id", "business_units"),
    ("business_units", "owner_user_id", "users"),
    ("teams", "business_unit_id", "business_units"),
    ("team_members", "team_id", "teams"),
    ("team_members", "user_id", "users"),
    ("committees", "chair_user_id", "users"),
    ("committee_members", "committee_id", "committees"),
    ("committee_members", "user_id", "users"),
    ("committee_meetings", "committee_id", "committees"),
    ("strategic_objectives", "owner_user_id", "users"),
    ("objective_links", "objective_id", "strategic_objectives"),
    ("compliance_obligations", "owner_user_id", "users"),
    ("compensating_controls", "system_id", "systems"),
    ("audit_workpapers", "engagement_id", "audit_engagements"),
    ("vendor_contracts", "vendor_id", "vendors"),
    ("vendor_contracts", "owner_user_id", "users"),
    ("contract_obligations", "contract_id", "vendor_contracts"),
    ("due_diligence_items", "vendor_id", "vendors"),
    ("vendor_findings", "vendor_id", "vendors"),
    ("vendor_findings", "questionnaire_id", "vendor_questionnaires"),
    ("projects", "owner_user_id", "users"),
    ("project_links", "project_id", "projects"),
    ("risk_assessments", "risk_id", "risks"),
    ("risk_treatment_plans", "risk_id", "risks"),
    ("risk_treatment_plans", "owner_user_id", "users"),
    ("risk_treatment_actions", "plan_id", "risk_treatment_plans"),
    ("risk_treatment_actions", "owner_user_id", "users"),
    ("risk_treatment_actions", "poam_id", "poams"),
)


def _trigger(table: str, column: str) -> str:
    return f"parent_org_{table}_{column}"[:63]


def upgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION ccf.assert_parent_org() RETURNS trigger
        LANGUAGE plpgsql AS $$
        DECLARE
          fk text := TG_ARGV[0];
          parent text := TG_ARGV[1];
          parent_id bigint;
          parent_org integer;
        BEGIN
          EXECUTE format('SELECT ($1).%I', fk) USING NEW INTO parent_id;
          IF parent_id IS NULL THEN
            RETURN NEW;
          END IF;
          IF parent = 'poams' THEN
            SELECT s.organization_id INTO parent_org
              FROM ccf.poams p JOIN ccf.systems s ON s.id = p.system_id
             WHERE p.id = parent_id;
          ELSE
            EXECUTE format('SELECT organization_id FROM ccf.%I WHERE id = $1', parent)
              USING parent_id INTO parent_org;
          END IF;
          IF parent_org IS DISTINCT FROM NEW.organization_id THEN
            RAISE EXCEPTION '%.% must reference a % row of the same organization',
              TG_TABLE_NAME, fk, parent
              USING ERRCODE = 'foreign_key_violation';
          END IF;
          RETURN NEW;
        END $$
        """
    )
    for table, column, parent in REFERENCES:
        op.execute(
            f"CREATE TRIGGER {_trigger(table, column)} BEFORE INSERT OR UPDATE OF "
            f"{column}, organization_id ON ccf.{table} FOR EACH ROW "
            f"EXECUTE FUNCTION ccf.assert_parent_org('{column}', '{parent}')"
        )


def downgrade() -> None:
    for table, column, _ in REFERENCES:
        op.execute(f"DROP TRIGGER IF EXISTS {_trigger(table, column)} ON ccf.{table}")
    op.execute("DROP FUNCTION IF EXISTS ccf.assert_parent_org()")
