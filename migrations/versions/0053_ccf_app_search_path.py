"""Fix pgvector operator resolution for the ccf_app RLS role.

``ccf.prep.retriever.retrieve()`` compiles ``PrepEmbedding.embedding.cosine_distance(...)``
to the unqualified ``<=>`` operator. The ``vector`` extension (0051) was created
into schema ``ccf`` (wherever the migrating role's own search_path put it), and
that operator is only visible to a query when ``ccf`` is on ``search_path``.

That happened to hold for the bootstrap login role only by coincidence: Postgres
expands the ``$user`` token in the default ``"$user", public`` search_path using
``CURRENT_USER`` (the *active* role), not ``SESSION_USER`` (the *authenticated*
login role) — and this app authenticates once as the bootstrap role and then
does ``SET ROLE ccf_app`` per scoped request (``ccf.db.set_session_tenant``), all
within the same already-established session. So for the bootstrap role,
``$user`` expands to its own name and — only because that role happens to be
named ``ccf``, matching the schema — resolves. The instant ``SET ROLE ccf_app``
runs, ``CURRENT_USER`` becomes ``ccf_app`` and ``$user`` expands to a schema
that does not exist, silently dropping ``ccf`` from the effective search path.
Every retrieval request from a real, RLS-scoped (org-scoped) caller therefore
hit ``operator does not exist: ccf.vector <=> ccf.vector`` — a hard 500 for
every normal tenant, invisible in any test that never exercises the scoped
``SET ROLE`` path (auth disabled -> unscoped -> ``RESET ROLE``, never
``ccf_app``).

The obvious-looking fix, ``ALTER ROLE ccf_app SET search_path = ...``, does
**not** work here and was verified NOT to (via psql against a live ``SET
ROLE``-based session, mirroring exactly what ``set_session_tenant`` does):
role-level ``ALTER ROLE ... SET`` defaults are applied at session start based
on the role used to *authenticate the connection*, not on a role adopted via
``SET ROLE`` mid-session — and this app never authenticates as ``ccf_app``, it
only ever switches to it after connecting as the bootstrap role. A
database-level default, by contrast, is applied once at connection time
(regardless of which role authenticated) and — because ``SET ROLE`` never
touches ``search_path`` — survives every subsequent ``SET ROLE`` in that same
session. Verified empirically end-to-end: with this in place,
``SET ROLE ccf_app; select vector <=> vector`` resolves correctly.

**Two operational caveats this fix does not remove:**

* ``ALTER DATABASE ... SET`` requires ownership of the database (or
  superuser). The migration role in this app's own Docker/CI setup owns the
  database it migrates, so this passes here — but on managed Postgres (RDS,
  Cloud SQL, etc.) where the migration role is a privileged application role
  rather than the actual database owner, this statement fails, and the
  underlying vulnerability (a hard 500 for every scoped tenant on retrieval)
  reappears with no application-level workaround short of an operator running
  it manually as an owner/superuser role.
* A database-level default only takes effect for **new** connections opened
  after it is set — not connections already open in a pool at the moment this
  migration runs. A long-lived pool (this app's ``asyncpg`` pool via
  ``create_async_engine``, or any external pooler such as PgBouncer in front
  of it) keeps using each existing connection's stale ``search_path`` until
  that connection is recycled/closed and reopened. A deploy that runs
  migrations and then keeps the same running API process (rather than
  restarting it, or recreating the pool) can therefore still 500 on
  already-open connections until they cycle out naturally or the process is
  restarted.

Revision ID: 0053_ccf_app_search_path
Revises: 0052_prep_tables
Create Date: 2026-08-10
"""

from __future__ import annotations

from alembic import op

revision = "0053_ccf_app_search_path"
down_revision = "0052_prep_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # current_database() rather than a literal name: this runs unmodified
    # against every environment (dev/test/CI) regardless of the database's
    # actual name. ALTER DATABASE takes an identifier, not an expression, so
    # the name is built and executed dynamically inside a DO block.
    op.execute(
        "DO $$ BEGIN "
        "EXECUTE format('ALTER DATABASE %I SET search_path = ccf, public', "
        "current_database()); "
        "END $$"
    )


def downgrade() -> None:
    op.execute(
        "DO $$ BEGIN "
        "EXECUTE format('ALTER DATABASE %I RESET search_path', current_database()); "
        "END $$"
    )
