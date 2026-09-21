"""3PAO engagements: the relationship a portal credential carries the authority of.

``assessment_engagements`` records that one external assessor principal assesses
one system, for one tenant, over one period. The external portal already had the
credential (``external_access_grants``: a hashed bearer token, an expiry, a
revoked flag) but no relationship behind it, so "this firm assesses this system"
was not expressible and a 3PAO could not be modelled. See
``docs/superpowers/specs/2026-09-21-3pao-engagement-design.md``.

``external_access_grants.engagement_id`` is NULLABLE: every existing customer and
vendor grant has none and always will. It is ``ON DELETE CASCADE`` rather than
``SET NULL`` -- nulling it would silently turn a bounded assessment credential
into an unbounded one.

**Out-of-vocabulary ``kind`` rows are counted and reported, never rewritten.**
``ExternalPrincipal.kind``/``ExternalAccessGrant.kind`` were ``String(16)``
columns with their vocabulary in a trailing comment, so a live database may
already hold values outside it. Converting them to a Postgres enum would fail on
the first such row -- blocking an upgrade over data the operator cannot see --
and rewriting them would destroy the record of what was there. So this migration
counts them, says so in the migration log, and leaves them exactly as they are.
Enforcement is at the service layer, on write (``ccf.portal.service
._require_kind``): existing odd rows keep working and stay visible, new ones
cannot be created.

Tenancy: ``assessment_engagements`` carries ``organization_id`` and gets the
direct ``organization_id = ccf.current_tenant()`` policy, so it joins
``tests/test_rls_coverage.py``'s ``EXPECTED_TENANT_ISOLATION_TABLES`` (count
138 -> 139). ``external_access_grants`` gains a column only, and was already in
that set.

Revision ID: 0083_3pao_engagements
Revises: 0082_pipeline_stage
Create Date: 2026-09-21
"""

from __future__ import annotations

import logging

import sqlalchemy as sa
from alembic import op

revision = "0083_3pao_engagements"
down_revision = "0082_pipeline_stage"
branch_labels = None
depends_on = None

_SCHEMA = "ccf"
_PREDICATE = "(ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())"

#: Matches the logger alembic's own "Running upgrade X -> Y" lines use, so the
#: report below appears in the same stream an operator is already watching
#: (same approach as 0057).
log = logging.getLogger("alembic.runtime.migration")

#: Spelled out here independently of ``ccf.constants.EXTERNAL_PRINCIPAL_KINDS``
#: -- a migration must not shift under a later edit to application code. Nothing
#: cross-checks the two, which is why tests/test_3pao_engagements.py asserts the
#: constant against a literal of its own.
_KINDS = ("customer", "assessor", "vendor")

#: (table, column) pairs holding the external-principal vocabulary.
_KIND_COLUMNS = (
    ("external_principals", "kind"),
    ("external_access_grants", "kind"),
)


def report_out_of_vocabulary_kinds(bind: sa.engine.Connection) -> dict[str, int]:
    """Count rows whose ``kind`` is outside the vocabulary, per table, and log it.

    Reports; never fails and never rewrites. A returned ``{}`` means every row
    is a recognised member. Importable so a test can exercise the counting
    itself rather than only the fact that ``upgrade()`` did not crash.
    """
    counts: dict[str, int] = {}
    for table, column in _KIND_COLUMNS:
        found = bind.execute(
            sa.text(
                # Identifiers are module constants, never caller input.
                f"SELECT count(*) FROM {_SCHEMA}.{table} "
                f"WHERE {column} IS NOT NULL AND {column} <> ALL(:kinds)"
            ),
            {"kinds": list(_KINDS)},
        ).scalar_one()
        if found:
            counts[table] = int(found)
    if counts:
        detail = ", ".join(f"{table}: {n} row(s)" for table, n in sorted(counts.items()))
        log.warning(
            "0083_3pao_engagements: external kind values outside "
            "(%s) found and LEFT UNCHANGED -- %s. They keep working and stay "
            "visible; the service layer refuses new ones.",
            "|".join(_KINDS),
            detail,
        )
    else:
        log.info(
            "0083_3pao_engagements: every external kind value is within (%s).",
            "|".join(_KINDS),
        )
    return counts


def upgrade() -> None:
    op.create_table(
        "assessment_engagements",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "system_id",
            sa.Integer(),
            sa.ForeignKey("ccf.systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "assessor_principal_id",
            sa.Integer(),
            sa.ForeignKey("ccf.external_principals.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("period_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_to", sa.DateTime(timezone=True), nullable=False),
        sa.Column("authorized_by", sa.String(length=255), nullable=True),
        sa.Column("independence_note", sa.Text(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            server_default=sa.text("now()"), nullable=False,
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_ccf_assessment_engagements_org", "assessment_engagements",
        ["organization_id"], schema=_SCHEMA,
    )
    op.create_index(
        "ix_ccf_assessment_engagements_system", "assessment_engagements",
        ["system_id"], schema=_SCHEMA,
    )
    op.create_index(
        "ix_ccf_assessment_engagements_principal", "assessment_engagements",
        ["assessor_principal_id"], schema=_SCHEMA,
    )

    op.add_column(
        "external_access_grants",
        sa.Column(
            "engagement_id",
            sa.Integer(),
            sa.ForeignKey("ccf.assessment_engagements.id", ondelete="CASCADE"),
            nullable=True,
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_ccf_external_access_grants_engagement", "external_access_grants",
        ["engagement_id"], schema=_SCHEMA,
    )

    # Standard since 0054: grant only if the role exists, so a developer
    # database without ccf_app migrates cleanly.
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    op.execute("ALTER TABLE ccf.assessment_engagements ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE ccf.assessment_engagements FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON ccf.assessment_engagements "
        f"FOR ALL USING {_PREDICATE} WITH CHECK {_PREDICATE}"
    )

    report_out_of_vocabulary_kinds(op.get_bind())


def downgrade() -> None:
    # The column goes first: it is the FK into the table being dropped, and an
    # engagement-backed grant without its engagement is not a grant this branch
    # knows how to validate.
    op.drop_index(
        "ix_ccf_external_access_grants_engagement", "external_access_grants", schema=_SCHEMA
    )
    op.drop_column("external_access_grants", "engagement_id", schema=_SCHEMA)
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON ccf.assessment_engagements")
    op.drop_table("assessment_engagements", schema=_SCHEMA)
