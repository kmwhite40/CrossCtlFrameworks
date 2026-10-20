"""DoD impact-level checks: AWS's own scope table, the system's declared level,
GovCloud partition, customer-managed keys."""

from __future__ import annotations

import dataclasses
import os
import uuid
from collections.abc import Iterator
from datetime import date
from types import SimpleNamespace
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.connectors import aws_service_scope as scope
from ccf.connectors import credentials as connector_credentials
from ccf.connectors.aws import AwsGovCloudConnector
from ccf.db import session_scope
from ccf.models import Organization, System, User
from ccf.posture.parameters import with_system_parameters
from ccf.posture.providers import aws as a
from ccf.posture.resolve import ResolvedCheck
from ccf.posture.scan import scan_for_system

pytestmark = pytest.mark.usefixtures("fresh_engine")

ACCT = "123456789012"


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _v(findings: list[Any]) -> list[str]:
    return [f.verdict for f in findings]


# ── AWS's table, as shipped ───────────────────────────────────────────────────


def test_the_shipped_table_is_awss_and_dated() -> None:
    doc = scope.load()
    assert doc["source"] == scope.SOURCE_URL
    assert doc["source_last_updated"] == "2026-10-14" and len(doc["source_sha256"]) == 64
    assert sum(r["il5_govcloud"] == "authorized" for r in doc["services"]) == 146


def test_reading_the_table_honestly() -> None:
    ec2 = scope.row_for_namespace("EC2")
    assert ec2 is not None and scope.status_at(ec2, "IL5") == "authorized"
    # Listed, blank at IL5: the only case a check may fail.
    macie = scope.row_for_namespace("Macie2")
    assert macie is not None and scope.status_at(macie, "IL5") == "not_in_scope"
    # AWS's own text is not an authorization.
    grafana = scope.row_for_namespace("Grafana")
    assert grafana is not None and scope.status_at(grafana, "IL5") == "other"
    # No row at all: never assumed either way.
    assert scope.row_for_namespace("ElasticLoadBalancingV2") is None
    # Config's namespace differs from the SDK name the table lists.
    config = scope.row_for_namespace("Config")
    assert config is not None and config["service"] == "AWS Config"
    # The m365-docs-hub list called these prohibited at IL5; AWS says otherwise.
    for ns in ("SageMaker", "Bedrock", "WorkSpaces"):
        row = scope.row_for_namespace(ns)
        assert row is not None and scope.status_at(row, "IL5") == "authorized", ns


#: The real page embeds the table with escaped attribute quotes (``\\"``).
_PAGE = (
    '<div><table width=\\"100%\\"><tr><th>SERVICES / PROGRAMS</th><th>SDKs</th>'
    "<th>DoD CSP SRG IL2 (East/West)</th><th>DoD CSP SRG IL2 (GovCloud)</th>"
    "<th>DoD CSP SRG IL4 (GovCloud)</th><th>DoD CSP SRG IL5 (GovCloud)</th>"
    "<th>DoD CSP SRG IL6 (AWS Secret Region)</th></tr>"
    "<tr><td>Amazon S3</td><td>s3</td><td>&#10003;</td><td>&#10003;</td><td>&#10003;</td>"
    "<td>&#10003;</td><td>&#10003;</td></tr>"
    "<tr><td>AWS Shield</td><td>shield</td><td>&#10003;</td><td></td><td></td><td></td>"
    "<td></td></tr></table></div><p>Last updated: October 14, 2026</p>"
)


def test_the_parser_reads_the_escaped_table_and_requires_a_date() -> None:
    rows = scope.parse_scope_table(_PAGE)
    assert [r["service"] for r in rows] == ["Amazon S3", "AWS Shield"]
    assert rows[0]["il5_govcloud"] == "authorized" and rows[1]["il5_govcloud"] is None
    doc = scope.build_document(_PAGE, retrieved_on=date(2026, 10, 20))
    assert doc["source_last_updated"] == "2026-10-14"
    was = {"services": [{"service": "AWS Shield", "il5_govcloud": "authorized"},
                        {"service": "Amazon S3", "il5_govcloud": "authorized"}]}
    assert scope.il5_changes(was, doc) == ["AWS Shield: 'authorized' -> None"]
    with pytest.raises(ValueError, match="Last updated"):
        scope.build_document(_PAGE.replace("Last updated", "Updated"),
                             retrieved_on=date(2026, 10, 20))
    with pytest.raises(ValueError, match="IL5"):
        scope.parse_scope_table("<table><tr><th>nothing</th></tr></table>")


# ── evaluators ────────────────────────────────────────────────────────────────

GOV = [{"Arn": f"arn:aws-us-gov:sts::{ACCT}:assumed-role/ConcordConnector/x"}]
COM = [{"Arn": f"arn:aws:sts::{ACCT}:assumed-role/ConcordConnector/x"}]


def test_partition() -> None:
    assert _v(a.evaluate_il_govcloud_partition(GOV, account_id=ACCT)) == ["not_applicable"]
    assert _v(a.evaluate_il_govcloud_partition(GOV, account_id=ACCT,
                                               dod_impact_level="IL5")) == ["pass"]
    assert _v(a.evaluate_il_govcloud_partition(COM, account_id=ACCT,
                                               dod_impact_level="IL4")) == ["fail"]
    assert _v(a.evaluate_il_govcloud_partition(COM, account_id=ACCT,
                                               dod_impact_level="IL2")) == ["not_applicable"]
    assert _v(a.evaluate_il_govcloud_partition(GOV, account_id=ACCT,
                                               dod_impact_level="IL6")) == [
        "manual_review_required"]
    assert _v(a.evaluate_il_govcloud_partition([{}], account_id=ACCT,
                                               dod_impact_level="IL5")) == [
        "manual_review_required"]


def test_service_scope() -> None:
    rows = [{"resourceType": "AWS::EC2::Instance", "count": 3},
            {"resourceType": "AWS::EC2::VPC", "count": 1},
            {"resourceType": "AWS::ShieldRegional::Protection", "count": 1},
            {"resourceType": "AWS::ElasticLoadBalancingV2::LoadBalancer", "count": 2},
            {"resourceType": "AWS::Grafana::Workspace", "count": 1}]
    assert _v(a.evaluate_il_service_scope(rows, account_id=ACCT)) == ["not_applicable"]
    found = {f.resource_id.split("/")[1]: f for f in
             a.evaluate_il_service_scope(rows, account_id=ACCT, dod_impact_level="IL5")}
    assert found["EC2"].verdict == "pass" and found["EC2"].detail["resources"] == 4
    assert found["ShieldRegional"].verdict == "fail"
    assert found["ElasticLoadBalancingV2"].verdict == "manual_review_required"
    # "3PAO Assessment" in the cell is AWS's note, not an authorization -- and
    # not a refusal either.
    assert found["Grafana"].verdict == "manual_review_required"
    assert "2026-10-14" in found["EC2"].detail["source"]
    assert _v(a.evaluate_il_service_scope([], account_id=ACCT, dod_impact_level="IL5")) == [
        "manual_review_required"]


def test_customer_keys() -> None:
    rows = [
        {"ResourceType": "aws_s3_bucket", "ResourceId": "a", "Encrypted": True,
         "Algorithm": "aws:kms", "KeyManager": "CUSTOMER"},
        {"ResourceType": "aws_s3_bucket", "ResourceId": "b", "Encrypted": True,
         "Algorithm": "AES256"},
        {"ResourceType": "aws_db_instance", "ResourceId": "c", "Encrypted": True,
         "KeyManager": "AWS"},
        {"ResourceType": "aws_db_instance", "ResourceId": "d", "Encrypted": False},
        {"ResourceType": "aws_s3_bucket", "ResourceId": "e", "Unreadable": "AccessDenied"},
        {"ResourceType": "aws_ebs_default", "ResourceId": "f", "Encrypted": True,
         "KeyId": "k"},
    ]
    assert _v(a.evaluate_il_customer_keys(rows, account_id=ACCT, dod_impact_level="IL4")) == [
        "not_applicable"]
    assert _v(a.evaluate_il_customer_keys(rows, account_id=ACCT, dod_impact_level="IL5")) == [
        "pass", "fail", "fail", "fail", "manual_review_required", "manual_review_required"]


# ── readers ───────────────────────────────────────────────────────────────────


class _ClientError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


def _scripted(monkeypatch: pytest.MonkeyPatch, script: dict[tuple[str, str], Any]) -> Any:
    class _Pager:
        def __init__(self, svc: str, op: str) -> None:
            self.svc, self.op = svc, op

        def paginate(self, **kw: Any) -> Any:
            return script[(self.svc, self.op)](**kw)

    class _S:
        def client(self, svc: str, region_name: str | None = None) -> Any:
            class _C:
                def get_paginator(self, op: str) -> _Pager:
                    return _Pager(svc, op)

                def __getattr__(self, op: str) -> Any:
                    return script[(svc, op)]
            return _C()

    session = _S()
    monkeypatch.setattr(AwsGovCloudConnector, "_session", lambda self: session)
    return AwsGovCloudConnector({"access_key_id": "AKIA", "secret_access_key": "x"})


def test_resource_counts_reader_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    pages = iter([{"resourceCounts": [{"resourceType": "AWS::S3::Bucket", "count": 2}],
                   "nextToken": "t"},
                  {"resourceCounts": [{"resourceType": "AWS::IAM::Role", "count": 5}]}])
    conn = _scripted(monkeypatch, {("config", "get_discovered_resource_counts"):
                                   lambda **_: next(pages)})
    assert [r["resourceType"] for r in conn._read_resource_counts()] == [
        "AWS::S3::Bucket", "AWS::IAM::Role"]


def test_data_at_rest_reader_resolves_key_managers(monkeypatch: pytest.MonkeyPatch) -> None:
    def enc(Bucket: str) -> dict[str, Any]:  # noqa: N803
        if Bucket == "plain":
            raise _ClientError("ServerSideEncryptionConfigurationNotFoundError")
        if Bucket == "locked":
            raise _ClientError("AccessDenied")
        rule = ({"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": "cmk"} if Bucket == "cmk-bucket"
                else {"SSEAlgorithm": "AES256"})
        return {"ServerSideEncryptionConfiguration": {
            "Rules": [{"ApplyServerSideEncryptionByDefault": rule}]}}

    described: list[str] = []

    def describe(KeyId: str) -> dict[str, Any]:  # noqa: N803
        described.append(KeyId)
        return {"KeyMetadata": {"KeyManager": "CUSTOMER" if KeyId == "cmk" else "AWS"}}

    conn = _scripted(monkeypatch, {
        ("s3", "list_buckets"): lambda **_: {"Buckets": [
            {"Name": "cmk-bucket"}, {"Name": "sse-s3"}, {"Name": "plain"}, {"Name": "locked"}]},
        ("s3", "get_bucket_encryption"): enc,
        ("kms", "describe_key"): describe,
        ("ec2", "get_ebs_encryption_by_default"): lambda **_: {"EbsEncryptionByDefault": True},
        ("ec2", "get_ebs_default_kms_key_id"): lambda **_: {"KmsKeyId": "alias/aws/ebs"},
        ("rds", "describe_db_instances"): lambda **_: [{"DBInstances": [
            {"DBInstanceIdentifier": "db", "StorageEncrypted": True, "KmsKeyId": "cmk"}]}],
    })
    rows = {r["ResourceId"]: r for r in conn._read_data_at_rest_keys()}
    assert rows["cmk-bucket"]["KeyManager"] == "CUSTOMER"
    assert rows["sse-s3"]["Algorithm"] == "AES256"
    assert rows["plain"]["Encrypted"] is False
    assert rows["locked"]["Unreadable"] == "AccessDenied"
    assert rows["db"]["KeyManager"] == "CUSTOMER"
    assert described.count("cmk") == 1  # cached across the bucket and the database
    verdicts = {f.resource_id: f.verdict for f in a.evaluate_il_customer_keys(
        list(rows.values()), account_id=ACCT, dod_impact_level="IL5")}
    assert verdicts["cmk-bucket"] == "pass" and verdicts["sse-s3"] == "fail"


# ── the level comes from the system, never a pack ────────────────────────────


def test_a_pack_cannot_choose_the_level() -> None:
    rc = ResolvedCheck(check=a.IL_GOVCLOUD_PARTITION, endpoint="x", source="pack:p",
                       evaluator_key=a.IL_GOVCLOUD_PARTITION.key,
                       parameters={"dod_impact_level": "IL2"})
    (filled,) = with_system_parameters((rc,), SimpleNamespace(dod_impact_level="IL5"))
    assert filled.parameters == {"dod_impact_level": "IL5"}
    (other,) = with_system_parameters(
        (ResolvedCheck(check=a.VPC_FLOW_LOGS, endpoint="x", source="platform"),),
        SimpleNamespace(dod_impact_level="IL5"),
    )
    assert other.parameters is None


def test_a_pack_rule_wrapping_an_il_evaluator_still_gets_the_systems_level() -> None:
    # Form A: the pack's own rule key, the platform's evaluator. Looked up by
    # check key alone it would get no level and never be judged at all.
    wrapped = dataclasses.replace(a.IL_CUSTOMER_KEYS, key="pack.acme.cmk")
    rc = ResolvedCheck(check=wrapped, endpoint="x", source="pack:acme",
                       evaluator_key=a.IL_CUSTOMER_KEYS.key)
    (filled,) = with_system_parameters((rc,), SimpleNamespace(dod_impact_level="IL5"))
    assert filled.parameters == {"dod_impact_level": "IL5"}


def test_a_resolved_check_needs_only_what_the_scan_reads() -> None:
    # The scan's contract with a resolved check is check/endpoint/source;
    # test doubles in test_posture_scan carry exactly that.
    bare = SimpleNamespace(check=a.VPC_FLOW_LOGS, endpoint="x", source="platform")
    assert with_system_parameters((bare,), SimpleNamespace(dod_impact_level="IL5")) == (bare,)


@pytest.fixture
def _aws_scan(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(AwsGovCloudConnector, "_boto3_available", lambda self: True)
    monkeypatch.setenv("CCF_AWS_CAPTURE_ENABLED", "true")
    monkeypatch.setenv("CCF_AI_CREDENTIAL_MASTER_KEY", "unit-test-master-key-32-chars-xx")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_a_scan_judges_the_systems_declared_level(
    _aws_scan: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(AwsGovCloudConnector, "_read_caller_identity", lambda self: COM)
    monkeypatch.setattr(AwsGovCloudConnector, "_account_id", _async_account)
    async with session_scope() as s:
        org = Organization(name=f"IL-{uuid.uuid4().hex[:6]}")
        s.add(org)
        await s.flush()
        il5 = System(organization_id=org.id, name="il5", dod_impact_level="IL5")
        none = System(organization_id=org.id, name="not dod")
        s.add_all([il5, none])
        await s.flush()
        await connector_credentials.set_credential(
            s, org.id, "aws_govcloud", {"access_key_id": "AKIA", "secret_access_key": "x"})
        ids = (il5.id, none.id)
    verdicts = []
    for sid in ids:
        async with session_scope() as s:
            out = await scan_for_system(s, system_id=sid, connector_key="aws_govcloud",
                                        check_keys={a.IL_GOVCLOUD_PARTITION.key})
        verdicts.append(out["results"][0]["verdict"])
    assert verdicts[0] == "fail"  # IL5 in a commercial account
    assert verdicts[1] != "fail"  # no level declared: nothing to judge


async def _async_account(self: Any) -> str:
    return ACCT


# ── setting the level ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_only_an_admin_sets_a_valid_level() -> None:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    try:
        async with session_scope() as s:
            org = Organization(name=f"ILSet-{uuid.uuid4().hex[:6]}")
            s.add(org)
            await s.flush()
            sysm = System(organization_id=org.id, name="sys")
            s.add(sysm)
            hdr = {}
            for role in ("admin", "control_owner"):
                u = User(email=f"{role}-{uuid.uuid4().hex[:5]}@il.test", organization_id=org.id,
                         role=role, active=True, password_hash=hash_password("pw"),
                         api_token=new_api_token())
                s.add(u)
                await s.flush()
                hdr[role] = {"Authorization": f"Bearer {u.api_token}"}
            sid = sysm.id
        async with AsyncClient(transport=ASGITransport(app=create_app()),
                               base_url="http://t") as c:
            url = f"/api/systems/{sid}/dod-impact-level"
            r = await c.put(url, json={"dod_impact_level": "IL5"}, headers=hdr["control_owner"])
            assert r.status_code == 403
            r = await c.put(url, json={"dod_impact_level": "IL3"}, headers=hdr["admin"])
            assert r.status_code == 422
            r = await c.put(url, json={"dod_impact_level": "il5"}, headers=hdr["admin"])
            assert r.status_code == 200 and r.json()["dod_impact_level"] == "IL5"
            r = await c.post(f"/ato/{sid}/impact-level", data={"dod_impact_level": ""},
                             headers=hdr["control_owner"])
            assert "error" in r.headers["location"]
    finally:
        os.environ.pop("CCF_AUTH_ENABLED", None)
        os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
        get_settings.cache_clear()
