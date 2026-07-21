"""Evidence WORM honesty — local backend cannot enforce it (warn, don't claim it
silently), and the S3 COMPLIANCE lock must carry a valid ObjectLockRetainUntilDate.

boto3 is not installed in the test environment (and even if it were, no test here
touches a real S3 endpoint): S3Storage._client is monkeypatched to return a Mock so
we can assert on exactly the arguments that would be sent to ``put_object``.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from alembic import command
from alembic.config import Config

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.evidence import service
from ccf.evidence.storage import LocalStorage, S3Storage
from ccf.models import Organization
from ccf.models_evidence import EvidenceRetentionPolicy

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _local_evidence_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("CCF_EVIDENCE_BACKEND", "local")
    monkeypatch.setenv("CCF_EVIDENCE_LOCAL_DIR", str(tmp_path / "evidence"))
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


# --- LocalStorage: WORM request degrades to a warning, never a false claim ---


def test_local_storage_put_without_retain_until_is_silent(tmp_path, monkeypatch) -> None:
    warn = MagicMock()
    monkeypatch.setattr("ccf.evidence.storage.log.warning", warn)
    backend = LocalStorage(tmp_path)
    backend.put("abc123", b"hello")
    warn.assert_not_called()


def test_local_storage_put_with_retain_until_warns_not_storage_enforced(
    tmp_path, monkeypatch
) -> None:
    warn = MagicMock()
    monkeypatch.setattr("ccf.evidence.storage.log.warning", warn)
    backend = LocalStorage(tmp_path)
    retain_until = datetime.now(UTC) + timedelta(days=365)

    ref = backend.put("abc123", b"hello", retain_until=retain_until)

    warn.assert_called_once()
    event, kwargs = warn.call_args[0][0], warn.call_args[1]
    assert event == "evidence.worm_not_storage_enforced"
    assert kwargs["backend"] == "local"
    assert "not enforce" in kwargs["detail"] or "cannot enforce" in kwargs["detail"]
    # The write itself still succeeds — this is a signal, not a refusal.
    assert ref.startswith("file://")
    assert backend.get(ref) == b"hello"


def test_local_storage_is_not_worm_capable() -> None:
    assert LocalStorage.worm_capable is False


# --- S3Storage: COMPLIANCE lock must carry a valid retain-until date ---


def test_s3_storage_put_includes_object_lock_and_retain_until(monkeypatch) -> None:
    mock_client = MagicMock()
    backend = S3Storage("evidence-bucket", object_lock=True)
    monkeypatch.setattr(backend, "_client", lambda: mock_client)
    retain_until = datetime(2027, 7, 21, tzinfo=UTC)

    ref = backend.put("deadbeef", b"payload", "text/plain", retain_until=retain_until)

    mock_client.put_object.assert_called_once()
    call_kwargs = mock_client.put_object.call_args.kwargs
    assert call_kwargs["Bucket"] == "evidence-bucket"
    assert call_kwargs["ObjectLockMode"] == "COMPLIANCE"
    assert call_kwargs["ObjectLockRetainUntilDate"] == retain_until
    assert call_kwargs["ContentType"] == "text/plain"
    assert ref == "s3://evidence-bucket/evidence/de/deadbeef"


def test_s3_storage_put_refuses_incomplete_lock_without_retain_until(monkeypatch) -> None:
    mock_client = MagicMock()
    backend = S3Storage("evidence-bucket", object_lock=True)
    monkeypatch.setattr(backend, "_client", lambda: mock_client)

    with pytest.raises(ValueError, match="retain-until"):
        backend.put("deadbeef", b"payload")

    mock_client.put_object.assert_not_called()


def test_s3_storage_put_without_object_lock_ignores_retain_until(monkeypatch) -> None:
    mock_client = MagicMock()
    backend = S3Storage("evidence-bucket", object_lock=False)
    monkeypatch.setattr(backend, "_client", lambda: mock_client)

    backend.put("deadbeef", b"payload", retain_until=datetime.now(UTC))

    call_kwargs = mock_client.put_object.call_args.kwargs
    assert "ObjectLockMode" not in call_kwargs
    assert "ObjectLockRetainUntilDate" not in call_kwargs


def test_s3_storage_is_worm_capable() -> None:
    assert S3Storage.worm_capable is True


# --- service.add_version: end-to-end WORM-request behavior per backend --------


@pytest.mark.asyncio
async def test_add_version_on_local_backend_warns_when_object_lock_requested(
    monkeypatch,
) -> None:
    monkeypatch.setenv("CCF_EVIDENCE_OBJECT_LOCK_ENABLED", "true")
    get_settings.cache_clear()
    warn = MagicMock()
    monkeypatch.setattr("ccf.evidence.storage.log.warning", warn)

    async with session_scope() as s:
        org = Organization(name="WormLocalOrg")
        s.add(org)
        await s.flush()
        obj = await service.create_object(s, org_id=org.id, title="local worm")
        version = await service.add_version(s, obj, data=b"bytes-on-disk")
        assert version.storage_backend == "local"

    warn.assert_called_once()
    assert warn.call_args[0][0] == "evidence.worm_not_storage_enforced"
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_add_version_object_lock_disabled_never_warns(monkeypatch) -> None:
    warn = MagicMock()
    monkeypatch.setattr("ccf.evidence.storage.log.warning", warn)

    async with session_scope() as s:
        org = Organization(name="WormOffOrg")
        s.add(org)
        await s.flush()
        obj = await service.create_object(s, org_id=org.id, title="no worm requested")
        await service.add_version(s, obj, data=b"plain bytes")

    warn.assert_not_called()


@pytest.mark.asyncio
async def test_resolve_retention_days_prefers_framework_then_org_then_default() -> None:
    async with session_scope() as s:
        org = Organization(name="RetentionOrg")
        s.add(org)
        await s.flush()

        # No policy at all -> configured default.
        obj_default = await service.create_object(
            s, org_id=org.id, title="default", framework="FEDRAMP"
        )
        assert (
            await service._resolve_retention_days(s, obj_default)
        ) == get_settings().evidence_object_lock_retention_days

        # Org-wide policy (no framework) applies when no framework-specific match.
        s.add(EvidenceRetentionPolicy(organization_id=org.id, name="org-wide", retain_days=200))
        await s.flush()
        assert (await service._resolve_retention_days(s, obj_default)) == 200

        # Framework-specific policy beats the org-wide one.
        s.add(
            EvidenceRetentionPolicy(
                organization_id=org.id,
                name="fedramp",
                retain_days=2555,
                applies_to_framework="FEDRAMP",
            )
        )
        await s.flush()
        assert (await service._resolve_retention_days(s, obj_default)) == 2555

        # A different framework still falls back to the org-wide policy.
        obj_other = await service.create_object(
            s, org_id=org.id, title="other", framework="SOC2"
        )
        assert (await service._resolve_retention_days(s, obj_other)) == 200


@pytest.mark.asyncio
async def test_add_version_s3_backend_computes_retain_until(monkeypatch) -> None:
    """End-to-end: with evidence_backend=s3 + object lock, add_version derives a
    retain-until date from the retention policy and the S3 client receives a
    complete COMPLIANCE lock (mocked boto3 — no real S3)."""
    monkeypatch.setenv("CCF_EVIDENCE_BACKEND", "s3")
    monkeypatch.setenv("CCF_EVIDENCE_S3_BUCKET", "evidence-bucket")
    monkeypatch.setenv("CCF_EVIDENCE_OBJECT_LOCK_ENABLED", "true")
    get_settings.cache_clear()

    mock_boto3 = MagicMock()
    mock_client = MagicMock()
    mock_boto3.client.return_value = mock_client
    monkeypatch.setitem(__import__("sys").modules, "boto3", mock_boto3)

    async with session_scope() as s:
        org = Organization(name="WormS3Org")
        s.add(org)
        await s.flush()
        s.add(
            EvidenceRetentionPolicy(
                organization_id=org.id,
                name="fedramp",
                retain_days=2555,
                applies_to_framework="FEDRAMP",
            )
        )
        await s.flush()
        obj = await service.create_object(
            s, org_id=org.id, title="s3 worm", framework="FEDRAMP"
        )
        before = datetime.now(UTC)
        version = await service.add_version(s, obj, data=b"s3 bytes")
        assert version.storage_backend == "s3"

    mock_client.put_object.assert_called_once()
    call_kwargs = mock_client.put_object.call_args.kwargs
    assert call_kwargs["ObjectLockMode"] == "COMPLIANCE"
    retain_until = call_kwargs["ObjectLockRetainUntilDate"]
    expected_min = before + timedelta(days=2555) - timedelta(seconds=5)
    expected_max = datetime.now(UTC) + timedelta(days=2555) + timedelta(seconds=5)
    assert expected_min <= retain_until <= expected_max

    get_settings.cache_clear()


def test_config_documents_worm_requires_s3_and_object_lock() -> None:
    fields = type(get_settings()).model_fields
    backend_desc = (fields["evidence_backend"].description or "").lower()
    lock_desc = (fields["evidence_object_lock_enabled"].description or "").lower()
    assert "s3" in backend_desc and "worm" in backend_desc
    assert "s3" in lock_desc
    assert date.today()  # sanity: date import used
