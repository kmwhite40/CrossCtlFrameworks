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
  it manually as an owner/superuser role. **Because of that, this migration
  catches exactly that failure (a savepoint isolates it -- see ``upgrade()``)
  and logs it loudly with the manual step to run, rather than raising.**
  Before that, a permission failure here raised straight out of
  ``alembic upgrade head`` and aborted the *entire* migration chain at 0052 —
  not just this fix — blocking every migration after it, prep-related or not,
  on any platform where the migrating role isn't the database owner. That is
  a strictly worse outcome than the vulnerability this migration exists to
  close: a stuck deploy instead of one degraded feature.
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
* ``downgrade()``'s ``ALTER DATABASE ... RESET search_path`` unconditionally
  clears the database-level default back to Postgres's own built-in default
  (effectively ``"$user", public``) — it does **not** restore whatever an
  operator may have set as the database's default *before* this migration
  ever ran. A downgrade on a database that had a deliberate, pre-existing
  ``search_path`` default therefore silently loses it. Documented here rather
  than fixed, since capturing "the prior value" would require reading it back
  before ``upgrade()`` overwrites it and persisting that somewhere durable
  across the downgrade -- out of scope for what this migration is actually
  for. An operator relying on a non-default database-level ``search_path``
  should record it before running this migration.

Revision ID: 0053_ccf_app_search_path
Revises: 0052_prep_tables
Create Date: 2026-08-10
"""

from __future__ import annotations

import logging

from alembic import op
from sqlalchemy import text as sa_text
from sqlalchemy.exc import DBAPIError

revision = "0053_ccf_app_search_path"
down_revision = "0052_prep_tables"
branch_labels = None
depends_on = None

#: Matches the logger name alembic's own "Running upgrade X -> Y" messages
#: use, so this shows up through the same handler with no extra configuration.
log = logging.getLogger("alembic.runtime.migration")

#: Keyed by the same ``action`` passed to :func:`_alter_database_search_path`
#: -- the manual step for a failed ``upgrade()`` (SET) is not the same
#: statement as for a failed ``downgrade()`` (RESET); printing the wrong one
#: would send an operator recovering from a failed downgrade to re-run the
#: very statement they were trying to undo.
_MANUAL_STEPS = {
    "set": (
        "ALTER DATABASE <dbname> SET search_path = ccf, public;  "
        "-- run as the database owner or a superuser, then restart the API "
        "process (or recycle its connection pool) so already-open connections "
        "pick up the new default."
    ),
    "reset": (
        "ALTER DATABASE <dbname> RESET search_path;  "
        "-- run as the database owner or a superuser, then restart the API "
        "process (or recycle its connection pool) so already-open connections "
        "pick up the reset default."
    ),
}


def _alter_database_search_path(sql: str, *, action: str) -> None:
    """Run one ``ALTER DATABASE ... search_path`` statement, tolerating a
    permission failure rather than aborting the whole migration chain.

    A savepoint isolates the statement: if ``ALTER DATABASE`` fails (most
    commonly ``InsufficientPrivilege`` on managed Postgres, where the
    migrating role does not own the database), only this statement rolls
    back -- the migration's own transaction stays usable, so Alembic's
    closing commit still succeeds and every migration after this one can
    still run. Without the savepoint, the failed statement would leave the
    transaction aborted and Alembic's commit would raise a second, more
    confusing error on top of the original one.
    """
    bind = op.get_bind()
    try:
        with bind.begin_nested():
            bind.execute(sa_text(sql))
    except DBAPIError as exc:
        log.warning(
            "0053_ccf_app_search_path: could not %s the database-level "
            "search_path default -- likely missing ownership on managed "
            "Postgres (RDS, Cloud SQL, etc). Every scoped (SET ROLE ccf_app) "
            "prep retrieval request will 500 with 'operator does not exist: "
            "ccf.vector <=> ccf.vector' until this is corrected manually. "
            "MANUAL STEP REQUIRED: %s Original error: %s",
            action,
            _MANUAL_STEPS[action],
            exc,
        )


def upgrade() -> None:
    # current_database() rather than a literal name: this runs unmodified
    # against every environment (dev/test/CI) regardless of the database's
    # actual name. ALTER DATABASE takes an identifier, not an expression, so
    # the name is built and executed dynamically inside a DO block.
    _alter_database_search_path(
        "DO $$ BEGIN "
        "EXECUTE format('ALTER DATABASE %I SET search_path = ccf, public', "
        "current_database()); "
        "END $$",
        action="set",
    )


def downgrade() -> None:
    _alter_database_search_path(
        "DO $$ BEGIN "
        "EXECUTE format('ALTER DATABASE %I RESET search_path', current_database()); "
        "END $$",
        action="reset",
    )
