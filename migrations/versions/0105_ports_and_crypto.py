"""SSP inventories: ports/protocols/services and cryptographic modules.

Revision ID: 0105_ports_and_crypto
Revises: 0104_policy_documents
Create Date: 2026-10-20

See ``ccf.models_boundary``. A ``validated`` module must carry a CMVP
certificate number; the constraint keeps a bare claim of validation out of the
table, since Concord does not verify certificates itself.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0105_ports_and_crypto"
down_revision = "0104_policy_documents"
branch_labels = None
depends_on = None

_PREDICATE = "(ccf.current_tenant() IS NULL OR organization_id = ccf.current_tenant())"
_TABLES = ("ports_protocols_services", "crypto_modules")


def _in(col: str, values: tuple[str, ...]) -> str:
    return f"{col} IN ({', '.join(repr(v) for v in values)})"


def _common() -> list[sa.Column]:
    return [
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "organization_id", sa.Integer(),
            sa.ForeignKey("ccf.organizations.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "system_id", sa.Integer(),
            sa.ForeignKey("ccf.systems.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "component_id", sa.BigInteger(),
            sa.ForeignKey("ccf.system_components.id", ondelete="SET NULL"),
        ),
    ]


def _stamps() -> list[sa.Column]:
    return [
        sa.Column("oscal_uuid", sa.String(36), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    ]


def upgrade() -> None:
    op.create_table(
        "ports_protocols_services",
        *_common(),
        sa.Column("port", sa.String(16)),
        sa.Column("protocol", sa.String(8), nullable=False),
        sa.Column("service", sa.String(128), nullable=False),
        sa.Column("purpose", sa.Text()),
        sa.Column("direction", sa.String(16), nullable=False),
        sa.Column("used_by", sa.String(255)),
        *_stamps(),
        sa.CheckConstraint(
            _in("protocol", ("tcp", "udp", "icmp", "sctp", "other")), name="ck_pps_protocol"
        ),
        sa.CheckConstraint(
            _in("direction", ("inbound", "outbound", "internal", "bidirectional")),
            name="ck_pps_direction",
        ),
        schema="ccf",
    )
    op.create_table(
        "crypto_modules",
        *_common(),
        sa.Column("module_name", sa.String(255), nullable=False),
        sa.Column("vendor", sa.String(255)),
        sa.Column("module_version", sa.String(128)),
        sa.Column("cmvp_certificate", sa.String(16)),
        sa.Column("validation_status", sa.String(16), nullable=False),
        sa.Column("security_level", sa.Integer()),
        sa.Column("usage", sa.String(24), nullable=False),
        sa.Column("notes", sa.Text()),
        *_stamps(),
        sa.CheckConstraint(
            _in("validation_status", ("validated", "in_process", "historical", "not_validated")),
            name="ck_crypto_status",
        ),
        sa.CheckConstraint(
            "validation_status <> 'validated' OR cmvp_certificate IS NOT NULL",
            name="ck_crypto_validated_has_certificate",
        ),
        sa.CheckConstraint(
            "security_level IS NULL OR security_level BETWEEN 1 AND 4", name="ck_crypto_level"
        ),
        schema="ccf",
    )
    for table in _TABLES:
        for col in ("organization_id", "system_id"):
            op.create_index(f"ix_{table}_{col}", table, [col], schema="ccf")
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ccf_app') THEN "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ccf TO ccf_app; "
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ccf TO ccf_app; END IF; END $$"
    )
    for table in _TABLES:
        op.execute(f"ALTER TABLE ccf.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE ccf.{table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON ccf.{table} "
            f"FOR ALL USING {_PREDICATE} WITH CHECK {_PREDICATE}"
        )


def downgrade() -> None:
    for table in reversed(_TABLES):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON ccf.{table}")
        op.drop_table(table, schema="ccf")
