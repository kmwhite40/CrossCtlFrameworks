"""Alembic environment — sync mode using psycopg (v3)."""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from ccf.config import get_settings
from ccf.models import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

settings = get_settings()
config.set_main_option("sqlalchemy.url", str(settings.database_url_sync))

target_metadata = Base.metadata


def include_name(name, type_, parent_names):
    # Only manage objects in our schemas.
    if type_ == "schema":
        return name in {"ccf", "ccf_raw", "ccf_audit"}
    return True


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        include_schemas=True,
        include_name=include_name,
        version_table_schema="ccf",
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        future=True,
    )
    with connectable.connect() as connection:
        # Ensure target schemas exist before Alembic tries to create its
        # version table inside ccf.
        connection.exec_driver_sql("CREATE SCHEMA IF NOT EXISTS ccf")
        connection.exec_driver_sql("CREATE SCHEMA IF NOT EXISTS ccf_raw")
        connection.exec_driver_sql("CREATE SCHEMA IF NOT EXISTS ccf_audit")
        connection.commit()

        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_schemas=True,
            include_name=include_name,
            version_table_schema="ccf",
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
