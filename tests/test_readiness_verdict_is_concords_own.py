"""A provider's ``verify()`` may not overwrite Concord's readiness verdict.

``provider_readiness`` flattens a connector's ``verify()`` return into the top
level of its payload *and* nests the same dict under ``provider``. A dict literal
lets later keys win, and the spread sits after every computed field — so a
connector whose ``verify()`` happened to return ``status`` or ``ready`` would
silently replace the readiness verdict with its own word for it.

That is not cosmetic. The payload is **persisted** (``cfg.readiness_detail``) and
``cfg.readiness_status`` is set from ``out["status"]``, so a provider-supplied
``status`` would become Concord's recorded readiness for that connector — a value
that validates and is wrong, written to the database.

No shipped connector returns a colliding key: AWS returns account / arn /
partition / region / govcloud, Graph returns tenant / graph_endpoint, ARM returns
subscription / tenant / arm_endpoint, GCP returns project_id / project_number /
service_account, PuppetDB returns endpoint / nodes / limit. The defect was that
nothing stopped the next one, and the exclusion list was ``{"connected",
"reason"}`` rather than the payload's own field names.

These tests use a deliberately hostile connector rather than waiting for a real
one to collide.
"""

from __future__ import annotations

import itertools
import re
from pathlib import Path
from typing import Any

import pytest

from ccf.connectors import readiness as readiness_mod
from ccf.connectors.base import ConfigConnector
from ccf.connectors.readiness import _RESERVED_READINESS_KEYS, provider_readiness
from ccf.db import session_scope
from ccf.models import Organization

_SEQ = itertools.count()


class _LyingConnector(ConfigConnector):
    """A connector whose ``verify()`` claims the readiness fields for itself."""

    key = "liar"

    def is_configured(self) -> bool:
        return True

    async def verify(self) -> dict[str, Any]:
        return {
            "connected": False,
            "reason": "the provider's own reason",
            # Every field the payload computes. A real connector would do this by
            # accident, naming one field badly.
            # Deliberately *type-distinguishable* from the truth wherever the
            # honest value could coincide with a plausible claim. `configured` is
            # genuinely True here, so claiming `True` would make a
            # "differs from the claim" assertion unfalsifiable -- the first draft
            # of this test did exactly that and failed for the wrong reason.
            "status": "ready",
            "ready": "yes-truthy-string",
            "configured": "yes-truthy-string",
            "connector": "something-else",
            "checks": ["not a check descriptor"],
            "checks_expected": 9999,
            "required_permissions": ["nonsense"],
            "checked_at": "1970-01-01T00:00:00+00:00",
            "provider": {"nested": "collision"},
            # And one legitimate detail field, which must survive.
            "tenant": "contoso.onmicrosoft.us",
        }

    async def capture(self) -> list[Any]:
        return []


async def _readiness_with_liar(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    async def _no_credential(*a: object, **k: object) -> None:
        return None

    monkeypatch.setattr(readiness_mod, "resolve_credential", _no_credential)
    monkeypatch.setattr(
        readiness_mod, "get_connector", lambda key, credential=None: _LyingConnector()
    )
    # No registered checks for this key, which is fine: the assertions below are
    # about the verdict fields, and `resolve_checks` returns an empty tuple.
    async with session_scope() as session:
        org = Organization(name=f"LiarOrg{next(_SEQ)}")
        session.add(org)
        await session.flush()
        return await provider_readiness(
            session,
            organization_id=org.id,
            connector_key="liar",
            persist=False,
        )


async def test_a_provider_cannot_claim_to_be_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The verdict is Concord's: the connector said ``connected: False``.

    It also said ``status: "ready"`` and ``ready: True``. Concord's own
    computation is ``unavailable`` — configured but verification failed — and that
    is what must survive, because it is what gets persisted as
    ``cfg.readiness_status``.
    """
    out = await _readiness_with_liar(monkeypatch)
    assert out["connected"] is False
    assert out["ready"] is False, "a provider talked its way into ready"
    assert out["status"] == "unavailable", out["status"]


async def test_the_reason_is_concords_derived_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``reason`` is excluded from the spread and derived from ``verify()``'s own
    reason, so the provider's text still reaches a reader -- through the field
    Concord controls."""
    out = await _readiness_with_liar(monkeypatch)
    assert out["reason"] == "the provider's own reason"


#: What Concord must compute for the lying connector: configured (it says so),
#: not connected and therefore unavailable, with its own key and its own
#: check descriptors. Stated as the truth rather than as "not the claim", because
#: for a field whose honest value coincides with a plausible claim the second form
#: cannot fail.
_CONCORDS_OWN: dict[str, object] = {
    "connector": "liar",
    "status": "unavailable",
    "ready": False,
    "configured": True,
    "checks": [],
    "checks_expected": 0,
    "required_permissions": [],
}


@pytest.mark.parametrize("field", sorted(_CONCORDS_OWN))
async def test_no_reserved_field_is_overwritten(
    field: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Named per field, so a regression says which one the provider captured."""
    out = await _readiness_with_liar(monkeypatch)
    assert out[field] == _CONCORDS_OWN[field], (
        f"provider_readiness[{field!r}] is {out[field]!r}, not Concord's "
        f"{_CONCORDS_OWN[field]!r}"
    )


async def test_checked_at_is_a_timestamp_concord_generated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Asserted apart from the table because the honest value is "now", which no
    literal can express. The provider claimed the epoch."""
    out = await _readiness_with_liar(monkeypatch)
    assert out["checked_at"] != "1970-01-01T00:00:00+00:00"
    assert out["checked_at"].startswith("20")


async def test_every_reserved_field_is_exercised_by_the_liar() -> None:
    """The parametrized test above is only as good as what the liar claims.

    If a field is reserved but the hostile connector never claims it, the guard
    for that field passes without testing anything.
    """
    claimed = set(await _LyingConnector().verify())
    unexercised = sorted(_RESERVED_READINESS_KEYS - claimed)
    assert unexercised == [], (
        f"reserved but never claimed by the test connector: {unexercised}"
    )


async def test_the_connector_key_is_the_registered_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``connector`` identifies which connector this readiness is *about*. A
    provider renaming it would misattribute the whole record."""
    out = await _readiness_with_liar(monkeypatch)
    assert out["connector"] == "liar"


async def test_legitimate_detail_still_reaches_the_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The flattening exists for a reason, and the fix must not remove it.

    ``tenant`` is a real Graph detail field; it is not a payload field name, so it
    belongs at the top level and under ``provider``.
    """
    out = await _readiness_with_liar(monkeypatch)
    assert out["tenant"] == "contoso.onmicrosoft.us"
    assert out["provider"]["tenant"] == "contoso.onmicrosoft.us"


async def test_the_nested_provider_block_is_concords_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``provider`` is built by Concord from the verification dict, so a
    ``provider`` key inside that dict must not replace the block itself."""
    out = await _readiness_with_liar(monkeypatch)
    assert isinstance(out["provider"], dict)
    # Concord builds this block from the verification dict, so a stray `provider`
    # key inside that dict lands *within* the block as data rather than replacing
    # it. The distinction is the point: the block is Concord's construction.
    assert out["provider"] != {"nested": "collision"}, (
        "the provider replaced the block Concord builds"
    )
    assert out["provider"].get("provider") == {"nested": "collision"}
    assert out["provider"]["tenant"] == "contoso.onmicrosoft.us"


def test_the_reserved_set_covers_every_payload_field() -> None:
    """The exclusion set has to track the payload, or it rots.

    Read off the source rather than restated, so a field added to the payload
    without being reserved fails here rather than on the day a connector names a
    field badly.
    """
    src = Path("src/ccf/connectors/readiness.py").read_text(encoding="utf-8")
    block = src[src.index('        out = {\n            "connector": connector.key,') :]
    block = block[: block.index("\n    if persist")]
    fields = set(re.findall(r'^\s+"([a-z_]+)":', block, re.M))
    missing = sorted(fields - _RESERVED_READINESS_KEYS)
    assert missing == [], (
        f"payload fields not reserved against a provider overwrite: {missing}"
    )
