"""An approval belongs to its entity's organization.

Revision ID: 0114_approval_entity_org
Revises: 0113_ssp_edit_reopens_approval
Create Date: 2026-11-06

``approvals.organization_id`` was the submitter's organization, so an
approval a platform-wide (unscoped) administrator submitted or decided was
stored with none. Row-level security then hid it from the entity's own
tenant: their pages read it as never submitted, their next request collided
with it on ``uq_approval_entity``, and migration 0113's trigger -- running as
the tenant -- could not reach it to reopen an edited SSP. The application now
stores the entity's organization; this backfills the rows stored without it.
"""

from __future__ import annotations

from alembic import op

revision = "0114_approval_entity_org"
down_revision = "0113_ssp_edit_reopens_approval"
branch_labels = None
depends_on = None

_BACKFILL = {
    "ssp_project": "SELECT organization_id FROM ccf.ssp_projects WHERE id = a.entity_id::int",
    "poam": (
        "SELECT s.organization_id FROM ccf.poams p JOIN ccf.systems s ON s.id = p.system_id "
        "WHERE p.id = a.entity_id::int"
    ),
    "risk": (
        "SELECT coalesce(r.organization_id, s.organization_id) FROM ccf.risks r "
        "LEFT JOIN ccf.systems s ON s.id = r.system_id WHERE r.id = a.entity_id::int"
    ),
    "assessment": (
        "SELECT s.organization_id FROM ccf.assessments x JOIN ccf.systems s "
        "ON s.id = x.system_id WHERE x.id = a.entity_id::int"
    ),
    "policy_version": (
        "SELECT p.organization_id FROM ccf.policy_versions v JOIN ccf.policies p "
        "ON p.id = v.policy_id WHERE v.id = a.entity_id::int"
    ),
}


def upgrade() -> None:
    for entity_type, owner in _BACKFILL.items():
        op.execute(
            f"UPDATE ccf.approvals a SET organization_id = ({owner}) "
            f"WHERE a.organization_id IS NULL AND a.entity_type = '{entity_type}' "
            "AND a.entity_id ~ '^[0-9]+$'"
        )


def downgrade() -> None:
    # Which rows had no organization before is not recorded; the backfilled
    # value is the correct one either way, so nothing is undone.
    pass
