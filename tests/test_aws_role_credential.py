"""AWS access by role: AssumeRole from a per-partition broker with an External
ID that is Concord's, never the caller's.

boto3 is an optional dependency and is not installed in the test environment,
so the connector's lazy ``import boto3`` is answered by a fake module that
records every call.
"""

from __future__ import annotations

import os
import sys
import types
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.connectors import aws_identity
from ccf.connectors import credentials as connector_credentials
from ccf.connectors.aws import AwsGovCloudConnector
from ccf.connectors.credential_spec import IncompleteCredential
from ccf.db import session_scope
from ccf.governance.control_tests import _capture_identity_is_tenants_own
from ccf.models import Organization, User
from ccf.models_grc import ConnectorConfig

pytestmark = pytest.mark.usefixtures("fresh_engine")

GOV_ROLE = "arn:aws-us-gov:iam::123456789012:role/ConcordConnectorReadOnly"
BROKER = "arn:aws-us-gov:iam::999999999999:role/concord-broker"


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _env() -> Iterator[None]:
    os.environ["CCF_AI_CREDENTIAL_MASTER_KEY"] = "unit-test-master-key-32-chars-xx"
    os.environ["CCF_AWS_CAPTURE_ENABLED"] = "true"
    os.environ["CCF_AWS_BROKER_PROFILE_GOVCLOUD"] = "concord-broker-gov"
    os.environ["CCF_AWS_BROKER_ARN_GOVCLOUD"] = BROKER
    get_settings.cache_clear()
    yield
    for k in ("CCF_AI_CREDENTIAL_MASTER_KEY", "CCF_AWS_CAPTURE_ENABLED",
              "CCF_AWS_BROKER_PROFILE_GOVCLOUD", "CCF_AWS_BROKER_ARN_GOVCLOUD",
              "CCF_AUTH_ENABLED", "CCF_AUTH_SESSION_SECRET"):
        os.environ.pop(k, None)
    get_settings.cache_clear()


# ── the identity rules, pure ─────────────────────────────────────────────────


def test_region_partition_is_exact() -> None:
    assert aws_identity.region_partition("us-gov-west-1") == "aws-us-gov"
    assert aws_identity.region_partition("us-east-1") == "aws"
    for unsupported in ("cn-north-1", "us-iso-east-1", "us-gov-central-9", ""):
        assert aws_identity.region_partition(unsupported) is None, unsupported


@pytest.mark.parametrize(
    ("arn", "region", "message"),
    [
        ("arn:aws:iam::123456789012:role/ConcordConnectorX", "us-gov-west-1", "partition"),
        ("arn:aws-us-gov:iam::123456789012:role/AdminRole", "us-gov-west-1", "ConcordConnector"),
        ("arn:aws-us-gov:iam::12345:role/ConcordConnectorX", "us-gov-west-1", "12-digit"),
        ("arn:aws-us-gov:iam::123456789012:user/ConcordConnectorX", "us-gov-west-1", "role"),
        (GOV_ROLE, "cn-north-1", "supported"),
    ],
)
def test_a_role_that_cannot_work_is_refused_before_any_call(
    arn: str, region: str, message: str
) -> None:
    with pytest.raises(aws_identity.RoleConfigError, match=message):
        aws_identity.validate_role(arn, region)


def test_account_id_must_match_the_role() -> None:
    with pytest.raises(aws_identity.RoleConfigError, match="account_id"):
        aws_identity.validate_role(GOV_ROLE, "us-gov-west-1", account_id="000000000000")


def test_errors_are_classified_and_never_echo_the_aws_message() -> None:
    class _DeniedError(Exception):
        def __init__(self) -> None:
            super().__init__(f"User: {BROKER} is not authorized")
            self.response = {"Error": {"Code": "AccessDenied",
                                       "Message": f"User: {BROKER} is not authorized"}}

    reason = aws_identity.classify(_DeniedError())
    assert BROKER not in reason and "trust policy" in reason


# ── storing a role credential ────────────────────────────────────────────────


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=f"{name}-{uuid.uuid4().hex[:6]}")
        s.add(org)
        await s.flush()
        return org.id


@pytest.mark.asyncio
async def test_the_external_id_is_concords_and_stable() -> None:
    org = await _org("RoleCredA")
    async with session_scope() as s:
        cfg = await connector_credentials.set_credential(
            s, org, "aws_govcloud",
            {"role_arn": GOV_ROLE, "external_id": "attacker-chosen", "region": "us-gov-west-1"},
        )
        first = cfg.config["external_id"]
        assert aws_identity.EXTERNAL_ID_RE.match(first)
        stored = await connector_credentials.resolve_credential(s, org, "aws_govcloud")
        assert stored is not None and stored["external_id"] == first
        # Saving again keeps it: a new ID would break the customer's trust policy.
        await connector_credentials.set_credential(
            s, org, "aws_govcloud", {"role_arn": GOV_ROLE, "region": "us-gov-west-1"}, config=cfg
        )
        assert cfg.config["external_id"] == first


@pytest.mark.asyncio
async def test_one_authentication_method_per_bundle() -> None:
    org = await _org("RoleCredB")
    async with session_scope() as s:
        with pytest.raises(IncompleteCredential, match="one way"):
            await connector_credentials.set_credential(
                s, org, "aws_govcloud",
                {"role_arn": GOV_ROLE, "access_key_id": "AKIA", "secret_access_key": "x"},
            )
        with pytest.raises(IncompleteCredential, match="ConcordConnector"):
            await connector_credentials.set_credential(
                s, org, "aws_govcloud",
                {"role_arn": "arn:aws-us-gov:iam::123456789012:role/Admin"},
            )


@pytest.mark.asyncio
async def test_a_generated_field_is_never_stored_from_a_request() -> None:
    org = await _org("RoleCredD")
    async with session_scope() as s:
        await connector_credentials.set_credential(
            s, org, "aws_govcloud",
            {"access_key_id": "AKIA", "secret_access_key": "x", "external_id": "planted"},
        )
        stored = await connector_credentials.resolve_credential(s, org, "aws_govcloud")
    assert stored is not None and "external_id" not in stored


def test_switching_method_in_the_form_drops_the_old_one() -> None:
    stored = {"access_key_id": "AKIA", "secret_access_key": "x", "region": "us-gov-west-1"}
    kept = connector_credentials.without_other_aws_methods(stored, {"role_arn": GOV_ROLE})
    assert kept == {"region": "us-gov-west-1"}
    assert connector_credentials.without_other_aws_methods(stored, {"region": "x"}) == stored


# ── assuming the role ────────────────────────────────────────────────────────


class _Recorder:
    def __init__(self) -> None:
        self.sessions: list[dict[str, Any]] = []
        self.assumes: list[dict[str, Any]] = []
        self.identity: dict[str, Any] = {
            "Account": "123456789012",
            "Arn": "arn:aws-us-gov:sts::123456789012:assumed-role/ConcordConnectorReadOnly/x",
        }

    def module(self) -> types.ModuleType:
        rec = self

        class _Sts:
            def assume_role(self, **kw: Any) -> dict[str, Any]:
                rec.assumes.append(kw)
                return {"Credentials": {
                    "AccessKeyId": "ASIA", "SecretAccessKey": "s", "SessionToken": "t",
                    "Expiration": datetime.now(UTC) + timedelta(hours=1),
                }}

            def get_caller_identity(self) -> dict[str, Any]:
                return rec.identity

        class _Session:
            def __init__(self, **kw: Any) -> None:
                rec.sessions.append(kw)

            def client(self, name: str, region_name: str | None = None) -> Any:
                return _Sts()

        mod = types.ModuleType("boto3")
        mod.Session = _Session  # type: ignore[attr-defined]
        return mod


@pytest.fixture
def boto(monkeypatch: pytest.MonkeyPatch) -> _Recorder:
    rec = _Recorder()
    monkeypatch.setitem(sys.modules, "boto3", rec.module())
    monkeypatch.setattr(AwsGovCloudConnector, "_boto3_available", lambda self: True)
    return rec


def _role_connector() -> AwsGovCloudConnector:
    return AwsGovCloudConnector({
        "role_arn": GOV_ROLE, "external_id": "concord-" + "a" * 32, "region": "us-gov-west-1",
    })


def test_the_role_is_assumed_from_the_partition_broker_with_the_external_id(
    boto: _Recorder,
) -> None:
    conn = _role_connector()
    assert conn.is_configured()
    conn._session()
    conn._session()  # cached: one STS call per assumed session, not per reader
    assert len(boto.assumes) == 1
    call = boto.assumes[0]
    assert call["RoleArn"] == GOV_ROLE and call["ExternalId"] == "concord-" + "a" * 32
    assert {"profile_name": "concord-broker-gov"} in boto.sessions
    # The session handed to readers is the assumed one, never the broker's.
    assert boto.sessions[-1] == {"aws_access_key_id": "ASIA", "aws_secret_access_key": "s",
                                 "aws_session_token": "t"}


def test_no_broker_for_the_partition_means_no_session(
    boto: _Recorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CCF_AWS_BROKER_PROFILE_GOVCLOUD")
    get_settings.cache_clear()
    with pytest.raises(aws_identity.RoleConfigError, match="no broker"):
        _role_connector()._session()
    assert boto.assumes == []


@pytest.mark.asyncio
async def test_verify_requires_the_configured_role_and_account(boto: _Recorder) -> None:
    assert (await _role_connector().verify())["connected"] is True
    boto.identity = {"Account": "222222222222",
                     "Arn": "arn:aws-us-gov:sts::222222222222:assumed-role/Other/x"}
    result = await _role_connector().verify()
    assert result["connected"] is False and "not the configured role" in result["reason"]


@pytest.mark.asyncio
async def test_an_assumed_tenant_role_is_the_tenants_own_identity() -> None:
    org = await _org("RoleCredC")
    async with session_scope() as s:
        await connector_credentials.set_credential(
            s, org, "aws_govcloud", {"role_arn": GOV_ROLE, "region": "us-gov-west-1"}
        )
        assert await _capture_identity_is_tenants_own(s, org, "aws_govcloud") is True


# ── the page ──────────────────────────────────────────────────────────────────


async def _admin_and_connector(name: str, role: str = "admin") -> tuple[dict[str, str], int]:
    async with session_scope() as s:
        org = Organization(name=f"{name}-{uuid.uuid4().hex[:6]}")
        s.add(org)
        await s.flush()
        u = User(email=f"{uuid.uuid4().hex[:6]}@{name.lower()}.test", organization_id=org.id,
                 role=role, active=True, password_hash=hash_password("pw"),
                 api_token=new_api_token())
        s.add(u)
        cfg = ConnectorConfig(organization_id=org.id, connector_type="aws_govcloud",
                              name="aws")
        s.add(cfg)
        await s.flush()
        return {"Authorization": f"Bearer {u.api_token}"}, cfg.id


@pytest.mark.asyncio
async def test_the_page_generates_rotates_and_never_takes_the_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CCF_AUTH_ENABLED", "true")
    monkeypatch.setenv("CCF_AUTH_SESSION_SECRET", "test-secret")
    get_settings.cache_clear()
    hdr, cfg_id = await _admin_and_connector("RolePageA")
    viewer_hdr, _ = await _admin_and_connector("RolePageB", role="control_owner")
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        assert (await c.post(f"/connectors/{cfg_id}/aws-external-id",
                             headers=viewer_hdr)).status_code in (403, 404)
        r = await c.post(f"/connectors/{cfg_id}/aws-external-id", headers=hdr)
        assert r.status_code == 303
        async with session_scope() as s:
            first = (await s.get(ConnectorConfig, cfg_id)).config["external_id"]
        # A second press without confirming does not rotate.
        r = await c.post(f"/connectors/{cfg_id}/aws-external-id", headers=hdr)
        assert "error" in r.headers["location"]
        # The credential form cannot set it.
        r = await c.post(f"/connectors/{cfg_id}/credential", headers=hdr,
                         data={"role_arn": GOV_ROLE, "external_id": "concord-" + "b" * 32,
                               "region": "us-gov-west-1"})
        assert r.status_code == 303 and "error" not in r.headers["location"]
        page = await c.get(f"/connectors/{cfg_id}", headers=hdr)
        assert first in page.text and BROKER in page.text and "sts:ExternalId" in page.text
        r = await c.post(f"/connectors/{cfg_id}/aws-external-id", headers=hdr,
                         data={"confirm": "rotate"})
        assert r.status_code == 303
    async with session_scope() as s:
        cfg = (await s.execute(select(ConnectorConfig).where(
            ConnectorConfig.id == cfg_id))).scalar_one()
        rotated = cfg.config["external_id"]
        stored = await connector_credentials.resolve_credential(
            s, cfg.organization_id, "aws_govcloud")
    assert rotated != first
    assert stored is not None and stored["external_id"] == rotated  # the bundle follows
    assert cfg.status == "error"  # not ready until the trust policy is updated


# ── m365-docs-hub ADR 0005 (2026-10-20): prove before storing ─────────────────


class _Rejected(Exception):  # noqa: N818 -- botocore ClientError shape
    def __init__(self, code: str) -> None:
        super().__init__(f"An error occurred ({code}) secret text AKIASECRET")
        self.response = {"Error": {"Code": code}}


def _sts_raises(boto: _Recorder, code: str) -> None:
    mod = sys.modules["boto3"]
    real_session = mod.Session

    class _Bad(real_session):  # type: ignore[misc, valid-type]
        def client(self, name: str, region_name: str | None = None) -> Any:
            class _S:
                def get_caller_identity(self) -> dict[str, Any]:
                    raise _Rejected(code)
            return _S()

    mod.Session = _Bad  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_rejected_keys_are_never_stored(boto: _Recorder) -> None:
    _sts_raises(boto, "InvalidClientTokenId")
    org = await _org("ProveA")
    async with session_scope() as s:
        with pytest.raises(IncompleteCredential, match="not stored") as exc:
            await connector_credentials.set_credential(
                s, org, "aws_govcloud",
                {"access_key_id": "AKIAEXAMPLE", "secret_access_key": "wrong"}, prove=True,
            )
        assert "AKIASECRET" not in str(exc.value)  # AWS's text is never passed through
        rows = (await s.execute(select(ConnectorConfig).where(
            ConnectorConfig.organization_id == org,
            ConnectorConfig.encrypted_credential.is_not(None)))).scalars().all()
    assert rows == []


@pytest.mark.asyncio
async def test_the_account_recorded_is_the_one_sts_reports(boto: _Recorder) -> None:
    org = await _org("ProveB")
    async with session_scope() as s:
        await connector_credentials.set_credential(
            s, org, "aws_govcloud",
            {"access_key_id": "AKIAEXAMPLE", "secret_access_key": "s"}, prove=True,
        )
        stored = await connector_credentials.resolve_credential(s, org, "aws_govcloud")
        assert stored is not None and stored["account_id"] == "123456789012"
        with pytest.raises(IncompleteCredential, match="different AWS account"):
            await connector_credentials.set_credential(
                s, org, "aws_govcloud",
                {"access_key_id": "AKIAEXAMPLE", "secret_access_key": "s",
                 "account_id": "999999999999"}, prove=True,
            )


@pytest.mark.asyncio
async def test_session_tokens_go_only_with_temporary_keys() -> None:
    org = await _org("ProveC")
    async with session_scope() as s:
        with pytest.raises(IncompleteCredential, match="needs its session token"):
            await connector_credentials.set_credential(
                s, org, "aws_govcloud", {"access_key_id": "ASIAX", "secret_access_key": "s"})
        with pytest.raises(IncompleteCredential, match="only with a temporary"):
            await connector_credentials.set_credential(
                s, org, "aws_govcloud",
                {"access_key_id": "AKIAX", "secret_access_key": "s", "session_token": "t"})


@pytest.mark.asyncio
async def test_the_display_tag_comes_from_the_key_id_not_the_secret() -> None:
    org = await _org("ProveD")
    async with session_scope() as s:
        cfg = await connector_credentials.set_credential(
            s, org, "aws_govcloud",
            {"access_key_id": "AKIAIDENTWXYZ", "secret_access_key": "topsecretQRST"})
    assert cfg.key_last4 is not None
    assert "QRST" not in cfg.key_last4 and "WXYZ" in cfg.key_last4


# ── permission check ─────────────────────────────────────────────────────────


class _Denied(Exception):  # noqa: N818 -- botocore ClientError shape
    def __init__(self, code: str, operation: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}}
        self.operation_name = operation


def test_permission_check_names_only_clear_denials(monkeypatch: pytest.MonkeyPatch) -> None:
    from ccf.posture.providers import aws as aws_checks  # noqa: PLC0415

    conn = AwsGovCloudConnector({"access_key_id": "AKIA", "secret_access_key": "x"})
    calls: list[str] = []

    def readers(self: Any) -> dict[str, Any]:
        def denied() -> list[Any]:
            calls.append("gd")
            raise _Denied("AccessDeniedException", "GetDetector")

        def expired() -> list[Any]:
            raise _Denied("ExpiredToken", "ListKeys")

        def partly() -> list[Any]:
            return [{"Bucket": "a"}, {"Bucket": "b", "Unreadable": "AccessDenied"}]

        def rds() -> list[Any]:
            calls.append("rds")
            return []

        table = {tok: (lambda: []) for tok in aws_checks.ENDPOINTS.values()}
        table[aws_checks.ENDPOINTS[aws_checks.GUARDDUTY_ENABLED.key]] = denied
        table[aws_checks.ENDPOINTS[aws_checks.KMS_KEY_ROTATION.key]] = expired
        table[aws_checks.ENDPOINTS[aws_checks.TRAIL_BUCKET_OBJECT_LOCK.key]] = partly
        table[aws_checks.ENDPOINTS[aws_checks.RDS_STORAGE_ENCRYPTED.key]] = rds
        return table

    monkeypatch.setattr(AwsGovCloudConnector, "_readers", readers)
    out = {r["check"]: r for r in conn.permission_check()}
    gd = out[aws_checks.GUARDDUTY_ENABLED.key]
    assert gd["status"] == "missing" and gd["actions"] == ["guardduty:GetDetector"]
    assert out[aws_checks.KMS_KEY_ROTATION.key]["status"] == "unknown"  # a bad key, not a policy
    assert out[aws_checks.TRAIL_BUCKET_OBJECT_LOCK.key]["status"] == "missing"
    assert out[aws_checks.CONFIG_RECORDER.key]["status"] == "granted"
    assert calls.count("rds") == 1  # one shared fleet read for two RDS checks


def test_organizations_is_asked_in_its_home_region(monkeypatch: pytest.MonkeyPatch) -> None:
    regions: list[str | None] = []

    class _S:
        def client(self, name: str, region_name: str | None = None) -> Any:
            regions.append(region_name)

            class _O:
                def describe_organization(self) -> Any:
                    raise _Denied("AccessDeniedException", "DescribeOrganization")
            return _O()

    monkeypatch.setattr(AwsGovCloudConnector, "_session", lambda self: _S())
    AwsGovCloudConnector({"access_key_id": "AKIA", "secret_access_key": "x",
                          "region": "us-east-2"}).organization_inventory()
    AwsGovCloudConnector({"access_key_id": "AKIA", "secret_access_key": "x",
                          "region": "us-gov-east-1"}).organization_inventory()
    assert regions == ["us-east-1", "us-gov-west-1"]


@pytest.mark.asyncio
async def test_the_api_answers_an_unusable_credential_with_422(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CCF_AUTH_ENABLED", "true")
    monkeypatch.setenv("CCF_AUTH_SESSION_SECRET", "test-secret")
    get_settings.cache_clear()
    hdr, _ = await _admin_and_connector("ProveE")
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        r = await c.post("/api/connector-settings/credentials/aws_govcloud", headers=hdr,
                         json={"secret": {"access_key_id": "ASIAX", "secret_access_key": "s"}})
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_both_write_routes_prove_before_storing(
    boto: _Recorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CCF_AUTH_ENABLED", "true")
    monkeypatch.setenv("CCF_AUTH_SESSION_SECRET", "test-secret")
    get_settings.cache_clear()
    _sts_raises(boto, "InvalidClientTokenId")
    hdr, cfg_id = await _admin_and_connector("ProveF")
    bad = {"access_key_id": "AKIAEXAMPLE", "secret_access_key": "wrong"}
    async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t") as c:
        r = await c.post("/api/connector-settings/credentials/aws_govcloud", headers=hdr,
                         json={"secret": bad})
        assert r.status_code == 422 and "not stored" in r.json()["detail"]
        r = await c.post(f"/connectors/{cfg_id}/credential", headers=hdr, data=bad)
        assert "error" in r.headers["location"]
    async with session_scope() as s:
        cfg = await s.get(ConnectorConfig, cfg_id)
        assert cfg is not None and cfg.encrypted_credential is None
        stored = (await s.execute(select(ConnectorConfig).where(
            ConnectorConfig.organization_id == cfg.organization_id,
            ConnectorConfig.encrypted_credential.is_not(None)))).scalars().all()
    assert stored == []
