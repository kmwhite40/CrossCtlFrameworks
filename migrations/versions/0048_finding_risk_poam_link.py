"""Finding->Risk/POA&M provenance (ISSM-04/05).

Two gaps closed here:

* ``risks.source_ref`` — a stable back-reference to the originating record
  (e.g. ``audit_finding:{id}``), mirroring ``poams.source_ref`` (0038), so a
  Risk created from an accepted finding is traceable back to what generated
  it.
* ``audit_findings.{system_id,organization_id,poam_id,risk_id}`` — findings
  previously had no link to the system they concern nor to any POA&M/Risk
  opened from them, orphaning them from the remediation program. All four are
  nullable: a finding may be raised before its system is known, and most
  findings are never promoted.

Revision ID: 0048_finding_risk_poam_link
Revises: 0047_framework_controls_global
Create Date: 2026-07-22
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0048_finding_risk_poam_link"
down_revision = "0047_framework_controls_global"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("risks", sa.Column("source_ref", sa.String(128)), schema="ccf")
    op.create_index("ix_ccf_risks_source_ref", "risks", ["source_ref"], schema="ccf")

    op.add_column(
        "audit_findings",
        sa.Column(
            "system_id", sa.Integer, sa.ForeignKey("ccf.systems.id", ondelete="SET NULL")
        ),
        schema="ccf",
    )
    op.add_column(
        "audit_findings",
        sa.Column(
            "organization_id",
            sa.Integer,
            sa.ForeignKey("ccf.organizations.id", ondelete="SET NULL"),
        ),
        schema="ccf",
    )
    op.add_column(
        "audit_findings",
        sa.Column("poam_id", sa.Integer, sa.ForeignKey("ccf.poams.id", ondelete="SET NULL")),
        schema="ccf",
    )
    op.add_column(
        "audit_findings",
        sa.Column("risk_id", sa.Integer, sa.ForeignKey("ccf.risks.id", ondelete="SET NULL")),
        schema="ccf",
    )
    op.create_index(
        "ix_ccf_audit_findings_system_id", "audit_findings", ["system_id"], schema="ccf"
    )
    op.create_index(
        "ix_ccf_audit_findings_organization_id",
        "audit_findings",
        ["organization_id"],
        schema="ccf",
    )
    op.create_index("ix_ccf_audit_findings_poam_id", "audit_findings", ["poam_id"], schema="ccf")
    op.create_index("ix_ccf_audit_findings_risk_id", "audit_findings", ["risk_id"], schema="ccf")


def downgrade() -> None:
    op.drop_index("ix_ccf_audit_findings_risk_id", table_name="audit_findings", schema="ccf")
    op.drop_index("ix_ccf_audit_findings_poam_id", table_name="audit_findings", schema="ccf")
    op.drop_index(
        "ix_ccf_audit_findings_organization_id", table_name="audit_findings", schema="ccf"
    )
    op.drop_index("ix_ccf_audit_findings_system_id", table_name="audit_findings", schema="ccf")
    op.drop_column("audit_findings", "risk_id", schema="ccf")
    op.drop_column("audit_findings", "poam_id", schema="ccf")
    op.drop_column("audit_findings", "organization_id", schema="ccf")
    op.drop_column("audit_findings", "system_id", schema="ccf")

    op.drop_index("ix_ccf_risks_source_ref", table_name="risks", schema="ccf")
    op.drop_column("risks", "source_ref", schema="ccf")
