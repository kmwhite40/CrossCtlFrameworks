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

    # Typed, auditable AI actions. Disabled by default: with AI off, actions run
    # against a deterministic, citation-first stub provider (safe for local/dev and
    # tests). AI never mutates an authoritative record without human approval.
    ai_enabled: bool = Field(default=False)
    ai_provider: str = Field(default="stub")  # none|stub|anthropic|openai|local
    ai_model: str | None = Field(default=None)
    ai_require_human_approval: bool = Field(default=True)
    ai_max_context_docs: int = Field(default=8)
    ai_store_prompts: bool = Field(default=True)
    ai_allow_uncited_drafts: bool = Field(default=False)

    # Organization-scoped AI provider credentials (Slice 3a). Credentials are stored
    # envelope-encrypted; the data-encryption key is wrapped by a pluggable key
    # provider. "local" wraps with ai_credential_master_key (set a strong random
    # value in any shared deployment); aws_kms/azure_kv/gcp_sm/vault are future
    # drop-ins. With no master key configured, credential storage is disabled
    # (fail-closed) rather than storing keys unwrapped.
    ai_credential_key_provider: str = Field(default="local")  # local|aws_kms|azure_kv|gcp_sm|vault
    ai_credential_master_key: str | None = Field(default=None)

    # Authentication / RBAC / multi-tenancy. Off by default so local dev and the
    # read-only reader stay open; turn on for shared/production deployments.
    auth_enabled: bool = Field(default=False)
    auth_session_secret: str = Field(default="dev-insecure-change-me")
    auth_session_ttl_hours: int = Field(default=12)

    # Enterprise SSO — OIDC authorization-code login + SCIM provisioning. All
    # optional and disabled by default: with OIDC off the app keeps its local
    # session login, so local/dev needs no IdP. JIT provisioning creates a local
    # user on first successful OIDC login (role from group mapping / default).
    oidc_enabled: bool = Field(default=False)
    oidc_issuer: str | None = Field(default=None)
    oidc_client_id: str | None = Field(default=None)
    oidc_client_secret: str | None = Field(default=None)
    oidc_redirect_uri: str | None = Field(default=None)
    oidc_allowed_domains: list[str] = Field(default_factory=list)
    auth_jit_provisioning: bool = Field(default=True)
    scim_enabled: bool = Field(default=False)
    scim_bearer_token: str | None = Field(default=None)

    # FedRAMP 20x: when true, the OSCAL-shaped package export is structurally
    # validated against Concord's OSCAL-subset checks before it is returned
    # (structural validation only — not official OSCAL schema conformance).
    fedramp20x_oscal_validate: bool = Field(default=False)

    # Official OSCAL schema validation. Point CCF_OSCAL_SCHEMA_DIR at a directory
    # holding the upstream NIST OSCAL JSON Schemas (e.g. oscal_ssp_schema.json)
    # to validate exports against the real schema; otherwise Concord falls back to
    # its built-in structural checks and reports a degraded status. When
    # CCF_OSCAL_REQUIRE_OFFICIAL_SCHEMA is set, a missing official schema is a hard
    # failure rather than a warning.
    oscal_schema_dir: Path | None = Field(default=None)
    oscal_require_official_schema: bool = Field(default=False)

    # Evidence repository — versioned, content-addressed evidence objects with a
    # pluggable storage backend. Local filesystem by default (no external deps);
    # 's3' targets an S3-compatible, optionally object-locked (WORM) bucket via
    # boto3 when installed, degrading to local storage otherwise.
    #
    # IMPORTANT: true WORM/immutability is only storage-enforced with
    # evidence_backend="s3" *and* evidence_object_lock_enabled=True on a bucket
    # that has S3 Object Lock enabled. With evidence_backend="local", the
    # filesystem has no immutability guarantee — approval-time locking
    # (EvidenceObject.immutable_lock) is application-level only (it blocks new
    # versions through the API, but does not protect bytes on disk from direct
    # modification), and a WORM request against it is logged as
    # "evidence.worm_not_storage_enforced" rather than silently claimed.
    evidence_backend: str = Field(
        default="local",
        description=(
            "Evidence content-storage backend: local|s3. True, storage-enforced "
            "WORM requires 's3' with evidence_object_lock_enabled and a bucket "
            "with S3 Object Lock enabled — the local backend cannot enforce "
            "immutability at the storage layer."
        ),
    )
    evidence_local_dir: Path = Field(default=Path("./data/evidence"))
    evidence_s3_bucket: str | None = Field(default=None)
    evidence_object_lock_enabled: bool = Field(
        default=False,
        description=(
            "Request WORM/object-lock on evidence writes. Only storage-enforced "
            "when evidence_backend='s3' (S3 Object Lock, COMPLIANCE mode, with an "
            "ObjectLockRetainUntilDate derived from the applicable retention "
            "policy/default). On evidence_backend='local' this cannot be "
            "storage-enforced: the write proceeds but logs "
            "'evidence.worm_not_storage_enforced' instead of a false immutability "
            "claim."
        ),
    )
    evidence_object_lock_retention_days: int = Field(
        default=365,
        description=(
            "Default retention window (days) used to derive the S3 "
            "ObjectLockRetainUntilDate when evidence_object_lock_enabled is set "
            "and no per-organization/framework EvidenceRetentionPolicy applies."
        ),
    )

    # ---- Evidence preparation pipeline (parse → screen → expand → classify → embed)
    prep_enabled: bool = Field(default=False)
    # Screening is deliberately inclusive: false positives are cheap (resolved by
    # downstream classification), false negatives are unrecoverable. This value is
    # compared against ts_rank_cd(..., normalization=32) -- bounded to 0..1 -- from
    # ccf.prep.screen.score_line, not a raw/unnormalized rank. 0.72 was derived by
    # measuring real policy sentences against the fully-ingested 800-53A catalog
    # (~1,200 base/enhancement controls): it sits strictly between the highest
    # score any exercised administrative/boilerplate line reached (0.71) and the
    # lowest score a genuine control-relevant sentence reached (0.74), so it
    # separates the two on the one corpus that matters without needing to be
    # re-tuned as the catalog is re-ingested. See test_prep_screen.py's
    # realistic-scale test and task-9-report.md for the measurements.
    prep_screen_threshold: float = Field(default=0.72)
    # Lines either side of a trigger line when no block/table/section bound applies.
    prep_expand_window: int = Field(default=4)
    # Embeddings resolve independently of the generation provider: Anthropic has no
    # embeddings endpoint, so an org generating with Anthropic still embeds elsewhere.
    prep_embed_provider: str = Field(default="openai")
    prep_embed_model: str = Field(default="text-embedding-3-small")
    # Validation only — pgvector column width is fixed at 1024 in the schema. A
    # mismatch fails the embed stage loudly rather than writing truncated vectors.
    prep_embed_dimensions: int = Field(default=1024)
    prep_worker_batch_size: int = Field(default=10)
    # `ccf prep-worker --loop`'s sleep between cycles that claimed nothing.
    # Without a sleep, an empty queue makes --loop spin the claim query in a
    # tight loop (previously it didn't even do that -- it exited after the
    # first empty cycle, see the CLI's own docstring correction). Short enough
    # that a freshly enqueued job is picked up promptly; long enough that an
    # idle worker isn't hammering the jobs table.
    prep_worker_poll_interval_seconds: float = Field(default=5.0)
    # How often a long-running `--loop` worker re-checks for stale (crashed
    # mid-stage) jobs, rather than only once at process start. Deliberately
    # smaller than `prep_job_stale_after_minutes` (the staleness window
    # itself, default 60 min): the retry-cap machinery below only makes
    # progress -- a stale job gets requeued, reclaimed, and (after
    # `prep_job_max_attempts` reclaims) dead-lettered -- if reaping actually
    # runs again after startup. At the 60-minute window's own timescale, that
    # would take `prep_job_max_attempts` hours to fully engage. Not every
    # cycle either, to avoid extra DB round trips when the queue is busy and
    # cycles run back-to-back with no sleep in between.
    prep_worker_reap_interval_seconds: float = Field(default=300.0)
    prep_job_stale_after_minutes: int = Field(default=60)
    # A job that fails gracefully (advance() raises, or a stage completes to
    # run.status="failed") stops after one attempt already -- claim() only
    # selects "pending" jobs, so a "failed" one is never reclaimed. The gap is a
    # job whose worker crashes mid-stage every time: reap_stale requeues it to
    # "pending" forever, burning a full stage's worth of parsing/model calls on
    # every cycle. reap_stale dead-letters (leaves status="failed" with
    # last_error set, instead of requeuing) a stale job at or past this many
    # claim attempts, so a poisoned job stops cycling and becomes visible.
    prep_job_max_attempts: int = Field(default=5)

    # ---- Objective-level assessment engine (slice 2)
    # Off by default: like the prep pipeline, this spends money on model calls.
    assessment_engine_enabled: bool = Field(default=False)
    assessment_engine_batch_size: int = Field(default=5)
    # A guard against a pathological catalog row set -- NOT a claim about how
    # many objectives a real control can have. Measured against the real
    # workbook (data/NIST Cross Mappings Rev. 1.1.xlsx, replaying
    # etl/pipeline.py's ingest semantics, 2026-08-10): 300 control groups,
    # p50 10 objectives, p90 27, max 98 (AC-4; SI-4 88, AC-16 85, SA-8 83,
    # SC-7 79, AC-2 77, AC-3 65 round out the top seven -- AC-2 is also the
    # design spec's own worked example). 60 sat below that observed max and
    # silently made those controls, including the spec's own example,
    # impossible to evaluate. 150 stays comfortably above the observed
    # ceiling while still catching a genuine extraction/grouping bug.
    assessment_engine_max_objectives_per_control: int = Field(default=150)
    # Passed to ccf.prep.retriever.retrieve as `limit` for each objective.
    assessment_engine_retrieval_limit: int = Field(default=8)
    # Added early (Task 8, not the Task 10 that was originally scoped to add
    # these) because ccf.assessment.engine.jobs.reap needs both to call
    # ccf.queue.reap_stale_jobs -- same style and reasoning as
    # prep_job_stale_after_minutes/prep_job_max_attempts above, mirrored for
    # the assessment_jobs queue.
    assessment_job_stale_after_minutes: int = Field(default=60)
    assessment_job_max_attempts: int = Field(default=5)
    # `ccf assessment-worker`'s own batch/cadence settings -- named and
    # documented identically to their prep_worker_* counterparts above (see
    # those comments for the full reasoning): poll_interval_seconds is the
    # `--loop` sleep between cycles that claimed nothing, and
    # reap_interval_seconds is how often a long-running `--loop` worker
    # re-checks for stale jobs rather than only once at process start.
    assessment_worker_poll_interval_seconds: float = Field(default=30.0)
    assessment_worker_reap_interval_seconds: float = Field(default=300.0)

    # Compliance pack runtime — extra directory of installable packs (in addition
    # to the packs bundled with Concord). Local-first: no packs dir is required.
    packs_dir: Path | None = Field(default=None)

    @property
    def is_sqlite(self) -> bool:
        return "sqlite" in str(self.database_url)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


_DEV_ENVS = frozenset({"dev", "local", "test"})
_DEFAULT_SESSION_SECRET = "dev-insecure-change-me"


def enforce_secure_config(settings: Settings) -> list[str]:
    """Fail closed on insecure configuration outside a dev environment (IA-01/IA-11).

    Raises ``RuntimeError`` — refusing startup — when ``env`` is not dev/local/test and
    a hard-unsafe setting is active (auth disabled, or the default session secret,
    which together let any request act as an unscoped global admin). Returns a list of
    non-fatal warnings (e.g. wildcard CORS) for the caller to log. In dev environments
    it is a no-op so local/reader use stays frictionless.
    """
    env = (settings.env or "").lower()
    if env in _DEV_ENVS:
        return []
    problems: list[str] = []
    warnings: list[str] = []
    if not settings.auth_enabled:
        problems.append("auth is disabled (set CCF_AUTH_ENABLED=true)")
    if settings.auth_session_secret == _DEFAULT_SESSION_SECRET:
        problems.append("session secret is the insecure default (set CCF_AUTH_SESSION_SECRET)")
    if settings.api_cors_origins == ["*"]:
        warnings.append("CORS is wildcard '*' — restrict CCF_API_CORS_ORIGINS in production")
    if problems:
        raise RuntimeError(
            f"Refusing to start: insecure configuration for env={env!r}: "
            + "; ".join(problems)
        )
    return warnings
