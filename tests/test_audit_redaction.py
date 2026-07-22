"""Unit tests for audit-log secret redaction (no DB).

Regression guard for finding CISO-07: the audit middleware redaction list must mask
API-key-style credential fields (api_key / anthropic_api_key / aws_secret_access_key)
before request bodies are persisted to the tamper-evident audit_log, while leaving
benign fields intact.
"""

from __future__ import annotations

from ccf.api.audit import _redact


def test_redacts_api_key_family() -> None:
    body = {
        "anthropic_api_key": "sk-ant-secret",
        "openai_api_key": "sk-proj-secret",
        "aws_secret_access_key": "AKIAEXAMPLE",
        "private_key": "-----BEGIN PRIVATE KEY-----",
        "db_credential": "hunter2",
        "password": "pw",
        "token": "t",
        "api_token": "at",
        "secret": "s",
    }
    out = _redact(body)
    for k in body:
        assert out[k] == "***", f"{k} was not redacted"


def test_does_not_over_redact_benign_fields() -> None:
    body = {"name": "Acme System", "description": "a control", "identifier": "AC-2"}
    out = _redact(body)
    assert out == body


def test_redacts_nested_and_lists() -> None:
    body = {
        "connector": {"anthropic_api_key": "x", "label": "prod"},
        "items": [{"secret": "y", "title": "ok"}],
    }
    out = _redact(body)
    assert out["connector"]["anthropic_api_key"] == "***"
    assert out["connector"]["label"] == "prod"
    assert out["items"][0]["secret"] == "***"
    assert out["items"][0]["title"] == "ok"
