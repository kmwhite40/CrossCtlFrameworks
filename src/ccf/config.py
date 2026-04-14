"""Application configuration (pydantic-settings)."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, PostgresDsn
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

    database_url: PostgresDsn = Field(
        default="postgresql+asyncpg://ccf:ccf@localhost:5432/ccf",  # type: ignore[arg-type]
        description="Async SQLAlchemy DSN for Postgres",
    )
    database_url_sync: PostgresDsn = Field(
        default="postgresql+psycopg://ccf:ccf@localhost:5432/ccf",  # type: ignore[arg-type]
        description="Sync DSN used by Alembic migrations / CLI",
    )

    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    api_cors_origins: list[str] = Field(default_factory=lambda: ["*"])

    data_dir: Path = Field(default=Path("/data"))
    workbook_path: Path = Field(
        default=Path("/data/NIST Cross Mappings Rev. 1.1.xlsx")
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
