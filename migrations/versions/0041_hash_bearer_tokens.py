"""Store bearer tokens hashed at rest (IA-09).

``ccf.users.api_token`` and ``ccf.external_access_grants.token`` currently hold
plaintext bearer credentials — a DB read, backup, or an audit-log leak yields a
directly usable credential. This adds ``api_token_hash`` / ``token_hash``
columns, backfills them by SHA-256 hashing each existing plaintext value in
place (via pgcrypto's ``digest()``, byte-identical to ``ccf.auth.hash_token``,
so already-issued tokens keep authenticating), then drops the plaintext
columns. The application (``ccf.api.auth_deps``, ``ccf.portal.service``) looks
tokens up by hash from this point on; it never reads the plaintext columns.

Downgrade recreates the plaintext-shaped columns for schema compatibility, but
cannot recover the original values — hashing is one-way. Tokens are seeded
with their own hash as a placeholder so downgraded rows remain distinct/valid
SQL, but they will not authenticate; any token issued before a downgrade must
be reissued.

Revision ID: 0041_hash_bearer_tokens
Revises: 0040_unique_natural_keys
Create Date: 2026-07-21
"""

from __future__ import annotations

from alembic import op

revision = "0041_hash_bearer_tokens"
down_revision = "0040_unique_natural_keys"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- users.api_token -> users.api_token_hash ---------------------------
    op.execute("ALTER TABLE ccf.users ADD COLUMN api_token_hash VARCHAR(64)")
    op.execute(
        "UPDATE ccf.users SET api_token_hash = encode(digest(api_token, 'sha256'), 'hex') "
        "WHERE api_token IS NOT NULL"
    )
    op.drop_index("ix_ccf_users_api_token", table_name="users", schema="ccf")
    op.execute("ALTER TABLE ccf.users DROP COLUMN api_token")
    op.create_index(
        "ix_ccf_users_api_token_hash", "users", ["api_token_hash"], unique=True, schema="ccf"
    )

    # --- external_access_grants.token -> external_access_grants.token_hash -
    op.execute("ALTER TABLE ccf.external_access_grants ADD COLUMN token_hash VARCHAR(64)")
    op.execute(
        "UPDATE ccf.external_access_grants "
        "SET token_hash = encode(digest(token, 'sha256'), 'hex')"
    )
    op.drop_index(
        "ix_ccf_external_access_grants_token", table_name="external_access_grants", schema="ccf"
    )
    op.execute("ALTER TABLE ccf.external_access_grants DROP COLUMN token")
    op.execute("ALTER TABLE ccf.external_access_grants ALTER COLUMN token_hash SET NOT NULL")
    op.create_index(
        "ix_ccf_external_access_grants_token_hash",
        "external_access_grants",
        ["token_hash"],
        unique=True,
        schema="ccf",
    )


def downgrade() -> None:
    # --- external_access_grants.token_hash -> external_access_grants.token -
    op.drop_index(
        "ix_ccf_external_access_grants_token_hash",
        table_name="external_access_grants",
        schema="ccf",
    )
    op.execute("ALTER TABLE ccf.external_access_grants ADD COLUMN token VARCHAR(64)")
    # One-way hash: the plaintext cannot be recovered. Seed with the hash so
    # the column stays populated/unique/non-null; these placeholders will
    # never authenticate — reissue any grant that needs to keep working.
    op.execute("UPDATE ccf.external_access_grants SET token = token_hash")
    op.execute("ALTER TABLE ccf.external_access_grants ALTER COLUMN token SET NOT NULL")
    op.execute("ALTER TABLE ccf.external_access_grants DROP COLUMN token_hash")
    op.create_index(
        "ix_ccf_external_access_grants_token",
        "external_access_grants",
        ["token"],
        unique=True,
        schema="ccf",
    )

    # --- users.api_token_hash -> users.api_token ----------------------------
    op.drop_index("ix_ccf_users_api_token_hash", table_name="users", schema="ccf")
    op.execute("ALTER TABLE ccf.users ADD COLUMN api_token VARCHAR(64)")
    op.execute("UPDATE ccf.users SET api_token = api_token_hash WHERE api_token_hash IS NOT NULL")
    op.execute("ALTER TABLE ccf.users DROP COLUMN api_token_hash")
    op.create_index(
        "ix_ccf_users_api_token", "users", ["api_token"], unique=True, schema="ccf"
    )
