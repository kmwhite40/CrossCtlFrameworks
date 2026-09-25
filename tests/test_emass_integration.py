"""Filing a POA&M into eMASS.

Unverified against a live instance -- eMASS needs a registered api-key and a
CAC-backed user-uid against a real deployment. These run against
``tests.fake_emass``, which encodes the published specification's stated
behaviour. They prove the mapping matches the specification, not that the
specification matches the service.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone

import httpx
import pytest

from ccf.integrations.emass import EmassTarget, _epoch, normalise_base_url
from ccf.integrations.types import (
    IntegrationNotConfigured,
    IntegrationRefused,
    IntegrationUnavailable,
)
from tests.fake_emass import FakeEmass


@dataclass
class _Poam:
    """Just the attributes the mapping reads."""

    id: int = 1
    title: str = "Weak spot"
    weakness: str | None = "Session tokens carry no audience claim"
    severity: str = "high"
    status: str = "open"
    source: str | None = "assessment"
    remediation_plan: str | None = "Derive a key per purpose."
    resources_required: str | None = None
    point_of_contact: str | None = None
    scheduled_completion: date | None = date(2026, 3, 1)
    due_on: date | None = None
    closed_on: date | None = None


def _target(fake: FakeEmass, **kwargs) -> EmassTarget:
    return EmassTarget(
        base_url="https://emass.example.mil",
        api_key="key-123",
        user_uid="uid-456",
        system_id=fake.system_id,
        transport=fake.transport,
        **kwargs,
    )


# --- the four traps ----------------------------------------------------------


@pytest.mark.asyncio
async def test_a_date_is_sent_as_unix_seconds_not_milliseconds() -> None:
    """Milliseconds are *accepted* by eMASS and land tens of millennia out.

    The fake refuses a value that large, so a regression to
    ``timestamp() * 1000`` fails here rather than silently writing a wrong
    date onto a federal record.
    """
    fake = FakeEmass()
    await _target(fake).create(_target(fake).content_for(_Poam()))
    stored = next(iter(fake.poams.values()))
    assert stored["scheduledCompletionDate"] == _epoch(date(2026, 3, 1))
    assert (
        datetime.fromtimestamp(stored["scheduledCompletionDate"], timezone.utc).date()
        == date(2026, 3, 1)
    )


def test_the_date_is_the_same_wherever_the_container_runs() -> None:
    """`datetime.combine(...).timestamp()` reads a naive value as *local* time.

    Filed from a server west of Greenwich, the same POA&M would carry a
    scheduled completion one day later than the one on screen.
    """
    assert _epoch(date(2026, 3, 1)) == 1772323200


@pytest.mark.asyncio
async def test_the_body_is_an_array_even_for_one_poam() -> None:
    import json

    fake = FakeEmass()
    target = _target(fake)
    await target.create(target.content_for(_Poam()))
    sent = json.loads(fake.requests[-1].content)
    assert isinstance(sent, list) and len(sent) == 1


@pytest.mark.asyncio
async def test_a_200_carrying_a_per_item_failure_is_not_treated_as_filed() -> None:
    """eMASS answers 200 for the batch while rejecting the individual item.

    Reading the HTTP status alone records a POA&M as filed that eMASS never
    accepted -- the claim-versus-rendering defect in its outbound form, and
    the single most likely way this integration would lie.
    """
    fake = FakeEmass(reject_next="Control acronym is not in this system's baseline.")
    target = _target(fake)
    with pytest.raises(IntegrationRefused) as caught:
        await target.create(target.content_for(_Poam()))
    assert "Control acronym is not in this system's baseline." in str(caught.value)
    assert fake.poams == {}


@pytest.mark.asyncio
async def test_the_vocabularies_are_mapped_to_emass_own_words() -> None:
    """Concord's `critical`/`open` are not words eMASS accepts."""
    fake = FakeEmass()
    target = _target(fake)
    await target.create(target.content_for(_Poam(severity="critical", status="open")))
    stored = next(iter(fake.poams.values()))
    assert stored["severity"] == "Very High"
    assert stored["status"] == "Ongoing"


# --- conditional requirements ------------------------------------------------


@pytest.mark.asyncio
async def test_a_completed_poam_carries_a_completion_date_not_a_scheduled_one() -> None:
    """eMASS validates conditionally on status, and refuses the wrong pairing."""
    fake = FakeEmass()
    target = _target(fake)
    await target.create(
        target.content_for(
            _Poam(status="completed", closed_on=date(2026, 2, 14))
        )
    )
    stored = next(iter(fake.poams.values()))
    assert stored["status"] == "Completed"
    assert stored["completionDate"] == _epoch(date(2026, 2, 14))
    assert "scheduledCompletionDate" not in stored


@pytest.mark.asyncio
async def test_an_unset_field_is_omitted_rather_than_sent_as_null() -> None:
    """An explicit null is not an absent key to eMASS's conditional validator."""
    fake = FakeEmass()
    target = _target(fake)
    content = target.content_for(_Poam(resources_required=None, point_of_contact=None))
    assert "resourcesRequired" not in content
    assert "pocOrganization" not in content
    assert None not in content.values()


# --- round trip and refusals -------------------------------------------------


@pytest.mark.asyncio
async def test_an_update_carries_the_poam_id_in_the_item() -> None:
    """The identifier travels in the body; the endpoint is the collection."""
    fake = FakeEmass()
    target = _target(fake)
    created = await target.create(target.content_for(_Poam()))
    assert created.created is True

    result = await target.update(created.external_id, target.content_for(_Poam(title="Now fixed")))
    assert result.created is False
    assert result.external_id == created.external_id

    import json

    sent = json.loads(fake.requests[-1].content)[0]
    assert sent["poamId"] == int(created.external_id)


@pytest.mark.asyncio
async def test_an_unreachable_instance_is_not_reported_as_a_rejected_poam() -> None:
    def _boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    target = EmassTarget(
        base_url="https://emass.example.mil",
        api_key="k",
        user_uid="u",
        system_id=42,
        transport=httpx.MockTransport(_boom),
    )
    with pytest.raises(IntegrationUnavailable):
        await target.create({"severity": "High"})


@pytest.mark.asyncio
async def test_a_missing_credential_is_a_refusal_with_emass_own_words() -> None:
    fake = FakeEmass()
    target = EmassTarget(
        base_url="https://emass.example.mil",
        api_key="k",
        user_uid="u",
        system_id=99,  # not the fake's system
        transport=fake.transport,
    )
    with pytest.raises(IntegrationRefused) as caught:
        await target.create(target.content_for(_Poam()))
    assert "Unknown system." in str(caught.value)


def test_the_base_url_must_be_an_origin_over_https() -> None:
    assert normalise_base_url("https://emass.example.mil/") == "https://emass.example.mil"
    for bad in ("http://emass.example.mil", "https://emass.example.mil/api", "nope", ""):
        with pytest.raises(IntegrationNotConfigured):
            normalise_base_url(bad)


def test_an_incomplete_configuration_is_refused_before_any_call() -> None:
    for kwargs in (
        {"api_key": "", "user_uid": "u", "system_id": 1},
        {"api_key": "k", "user_uid": "", "system_id": 1},
        {"api_key": "k", "user_uid": "u", "system_id": 0},
    ):
        with pytest.raises(IntegrationNotConfigured):
            EmassTarget(base_url="https://emass.example.mil", **kwargs)
