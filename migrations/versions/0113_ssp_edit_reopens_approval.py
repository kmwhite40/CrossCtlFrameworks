"""Changing an approved SSP's content returns it, and its approval, to draft.

Revision ID: 0113_ssp_edit_reopens_approval
Revises: 0112_approval_purpose
Create Date: 2026-11-06

An approval is of the text the reviewer read. Control statements are written
by the editor's routes, statement generation, autofill, templates and the UI's
forms; none of them looked at the plan's status, so an approved plan could be
rewritten and stay ``approved``. A trigger is the one place no writer can
miss.

- ``ssp_control_entries``: an insert, a delete, or an update that changes any
  column but ``updated_at`` / ``sort_order``, on a plan in ``approved`` or
  ``final``, sets the plan to ``draft``.
- ``ssp_projects``: an update that changes the plan's content while leaving
  its status alone sets it to ``draft``. Not content: the status and the
  timestamps. The revision log (``version`` / ``revision_history``) *is*: the
  document prints it, so an entry added after approval -- "1.0, approved by
  the AO", say -- is text the reviewer never read. Record the version before
  submitting. A column added later counts as content until listed here -- the
  safe direction.
- Whenever a plan leaves ``approved`` / ``final``, its approval returns to
  draft, so the plan must be submitted and decided again -- what withdrawing
  it through the API already did -- and an ``approval_reopened`` event says so.

Comparisons are on ``to_jsonb`` of the row minus the excluded keys, so a
whole-form client re-saving identical values reopens nothing.
"""

from __future__ import annotations

from alembic import op

revision = "0113_ssp_edit_reopens_approval"
down_revision = "0112_approval_purpose"
branch_labels = None
depends_on = None

_APPROVED = "('approved', 'final')"


def upgrade() -> None:
    op.execute(
        f"""
        CREATE OR REPLACE FUNCTION ccf.ssp_project_content_reopens() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          IF OLD.status IN {_APPROVED} AND NEW.status = OLD.status
             AND (to_jsonb(NEW) - 'status' - 'updated_at' - 'created_at')
                 IS DISTINCT FROM
                 (to_jsonb(OLD) - 'status' - 'updated_at' - 'created_at') THEN
            NEW.status := 'draft';
          END IF;
          RETURN NEW;
        END $$
        """
    )
    op.execute(
        "CREATE TRIGGER ssp_project_content_reopens BEFORE UPDATE ON ccf.ssp_projects "
        "FOR EACH ROW EXECUTE FUNCTION ccf.ssp_project_content_reopens()"
    )
    op.execute(
        f"""
        CREATE OR REPLACE FUNCTION ccf.ssp_project_reopens_approval() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          IF OLD.status IN {_APPROVED} AND NEW.status NOT IN {_APPROVED} THEN
            UPDATE ccf.approvals SET state = 'draft'
             WHERE entity_type = 'ssp_project' AND entity_id = NEW.id::text
               AND state = 'approved';
            -- Said where the timeline reads it: a plan quietly losing its
            -- approval is a defect of its own.
            INSERT INTO ccf.events (organization_id, verb, entity_type, entity_id, summary,
                                    payload)
            VALUES (NEW.organization_id, 'approval_reopened', 'ssp_project', NEW.id::text,
                    'SSP ' || NEW.id || ' left ' || OLD.status || ' (' || NEW.status
                      || '): its approval must be decided again',
                    jsonb_build_object('from', OLD.status, 'to', NEW.status));
          END IF;
          RETURN NULL;
        END $$
        """
    )
    op.execute(
        # Not ``AFTER UPDATE OF status``: that fires only when the statement
        # names the column, and the BEFORE trigger above changes it unnamed.
        "CREATE TRIGGER ssp_project_reopens_approval AFTER UPDATE "
        "ON ccf.ssp_projects FOR EACH ROW "
        "EXECUTE FUNCTION ccf.ssp_project_reopens_approval()"
    )
    op.execute(
        f"""
        CREATE OR REPLACE FUNCTION ccf.ssp_entry_reopens_project() RETURNS trigger
        LANGUAGE plpgsql AS $$
        DECLARE
          project integer;
        BEGIN
          IF TG_OP = 'UPDATE' THEN
            IF (to_jsonb(NEW) - 'updated_at' - 'sort_order')
               IS NOT DISTINCT FROM (to_jsonb(OLD) - 'updated_at' - 'sort_order') THEN
              RETURN NULL;
            END IF;
          END IF;
          project := CASE WHEN TG_OP = 'DELETE' THEN OLD.project_id ELSE NEW.project_id END;
          UPDATE ccf.ssp_projects SET status = 'draft'
           WHERE id = project AND status IN {_APPROVED};
          RETURN NULL;
        END $$
        """
    )
    op.execute(
        "CREATE TRIGGER ssp_entry_reopens_project AFTER INSERT OR UPDATE OR DELETE "
        "ON ccf.ssp_control_entries FOR EACH ROW "
        "EXECUTE FUNCTION ccf.ssp_entry_reopens_project()"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS ssp_entry_reopens_project ON ccf.ssp_control_entries")
    op.execute("DROP TRIGGER IF EXISTS ssp_project_reopens_approval ON ccf.ssp_projects")
    op.execute("DROP TRIGGER IF EXISTS ssp_project_content_reopens ON ccf.ssp_projects")
    op.execute("DROP FUNCTION IF EXISTS ccf.ssp_entry_reopens_project()")
    op.execute("DROP FUNCTION IF EXISTS ccf.ssp_project_reopens_approval()")
    op.execute("DROP FUNCTION IF EXISTS ccf.ssp_project_content_reopens()")
