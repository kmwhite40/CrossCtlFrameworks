"""Application configuration (pydantic-settings)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration resolved from environment variables / `.env`."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="CCF_",
        extra="ignore",
    )

    env: str = Field(default="dev", description="Deployment environment")
    log_level: str = Field(default="INFO")
    log_json: bool = Field(default=False)

    database_url: str = Field(
        default="postgresql+asyncpg://ccf:ccf@localhost:5432/ccf",
        description="Async SQLAlchemy DSN for Postgres",
    )
    database_url_sync: str = Field(
        default="postgresql+psycopg://ccf:ccf@localhost:5432/ccf",
        description="Sync DSN used by Alembic migrations / CLI",
    )

    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    api_cors_origins: list[str] = Field(default_factory=lambda: ["*"])

    data_dir: Path = Field(default=Path("/data"))
    workbook_path: Path = Field(default=Path("/data/NIST Cross Mappings Rev. 1.1.xlsx"))

    # Concord Reader flavor: SQLite + single-exe + hide write UI + 403 on mutations.
    readonly: bool = Field(
        default=False,
        description="When true, hide ops UI and block POST/PATCH/DELETE.",
    )

    # Audit trail: record state-changing requests to ccf.audit_log.
    audit_enabled: bool = Field(default=True)
    audit_default_actor: str = Field(default="system")

    # Config-capture connectors. Populate an organization's ODP values / evidence
    # from live cloud configuration. All optional — a connector reports
    # "not configured" until its credentials are set, so the scaffolding is safe
    # to ship disabled. Microsoft Graph defaults target the Government cloud
    # (graph.microsoft.us / login.microsoftonline.us).
    graph_tenant_id: str | None = Field(default=None)
    graph_client_id: str | None = Field(default=None)
    graph_client_secret: str | None = Field(default=None)
    graph_base_url: str = Field(default="https://graph.microsoft.us")
    graph_login_url: str = Field(default="https://login.microsoftonline.us")
    aws_region: str = Field(default="us-gov-west-1")  # GovCloud West by default
    aws_profile: str | None = Field(default=None)  # named AWS profile (optional)
    aws_capture_enabled: bool = Field(default=False)

    # In-app automation scheduler. When enabled, background jobs run the catalog
    # poll, ConMon scan, alert digest, and connector collection on a cadence.
    scheduler_enabled: bool = Field(default=False)
    scheduler_interval_hours: float = Field(default=24.0)

    # Outbound notification delivery (best-effort). Set a Slack/Teams incoming
    # webhook to fan critical alerts out of the app.
    notify_webhook_url: str | None = Field(default=None)
    notify_min_severity: str = Field(default="critical")  # info|warning|critical

    # AI-assisted authoring (Anthropic). Narratives/remediation plans/risk text.
    anthropic_api_key: str | None = Field(default=None)
    anthropic_model: str = Field(default="claude-sonnet-5")
    anthropic_base_url: str = Field(default="https://api.anthropic.com")

    # Authentication / RBAC / multi-tenancy. Off by default so local dev and the
    # read-only reader stay open; turn on for shared/production deployments.
    auth_enabled: bool = Field(default=False)
    auth_session_secret: str = Field(default="dev-insecure-change-me")
    auth_session_ttl_hours: int = Field(default=12)

    @property
    def is_sqlite(self) -> bool:
        return "sqlite" in str(self.database_url)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
