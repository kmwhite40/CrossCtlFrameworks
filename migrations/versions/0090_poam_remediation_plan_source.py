"""Who wrote a POA&M's remediation plan, so a re-scan cannot destroy an edit.

A failed automated control test now seeds ``remediation_plan`` with deterministic
guidance, and a later scan of the same failing check has to refresh it -- the
observed condition and the failing-resource counts move. What it must *not* do is
overwrite an analyst's work.

The first implementation decided that by prose: overwrite when the stored text
started with ``"Remediation objective:"``. That reads as a marker but behaves as
a trap. An analyst appending a milestone or correcting the recommended action
keeps the first line -- the most natural edit there is -- and their work is
silently destroyed on the next scan. It is also the same mistake
``0089_scoring_status_provenance`` fixed one migration ago, one table over:
provenance carried in free text that nothing maintains.

``remediation_plan_source`` makes it structural. ``generated`` is the only value
a scan may overwrite. ``ai`` is set by the AI-action mutation path
(``ai_actions.service``), whose drafted text carries its own provenance badge and
must not be silently replaced either. ``analyst`` is a person's own words.

Every existing row backfills to ``analyst`` -- the safe direction. Nothing wrote
this column before, so there is no way to know which stored plans were machine
drafted, and treating an unknown plan as refreshable would destroy exactly the
work this column exists to protect. A plan seeded by ``_seed_gap_poams`` is
therefore also frozen; it will be relabelled the next time something rewrites it,
which costs a stale paragraph and never costs somebody's editing.

Revision ID: 0090_poam_remediation_source
Revises: 0089_scoring_status_provenance
Create Date: 2026-09-26
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0090_poam_remediation_source"
down_revision = "0089_scoring_status_provenance"
branch_labels = None
depends_on = None

_SOURCES = ("generated", "ai", "analyst")


def upgrade() -> None:
    op.add_column(
        "poams",
        sa.Column(
            "remediation_plan_source",
            sa.String(16),
            nullable=False,
            server_default="analyst",
        ),
        schema="ccf",
    )
    # A CHECK rather than an enum: the vocabulary is small and this table
    # already spells its other vocabularies (`severity`, `status`) as enums
    # created long ago -- adding a new type for three values would leave a
    # type to migrate the next time one is added.
    values = ", ".join(f"'{s}'" for s in _SOURCES)
    op.create_check_constraint(
        "ck_poam_remediation_plan_source",
        "poams",
        f"remediation_plan_source IN ({values})",
        schema="ccf",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_poam_remediation_plan_source", "poams", type_="check", schema="ccf"
    )
    op.drop_column("poams", "remediation_plan_source", schema="ccf")
