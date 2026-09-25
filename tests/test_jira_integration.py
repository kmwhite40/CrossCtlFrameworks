"""Filing a POA&M into Jira, and the refusals that keep it honest.

Every HTTP assertion runs through the real :class:`JiraTracker` against
``tests.fake_jira.FakeJira``, which enforces what Jira Cloud enforces. The
fake exists because the interesting failures are in what we *send* -- the ADF
document, the field set that differs between create and update, the label
shape -- and a mock of the tracker's own methods would assert none of it.
"""

from __future__ import annotations

import base64

import pytest

from ccf.integrations.jira import JiraTracker, _adf, normalise_base_url
from ccf.integrations.types import (
    IntegrationNotConfigured,
    IntegrationRefused,
    IntegrationUnavailable,
    IssueContent,
)
from tests.fake_jira import FakeJira

_CONTENT = IssueContent(
    key="poam:1",
    title="Session tokens carry no audience claim",
    body="Weakness\nAnything signed with the session secret verifies.\n\nRemediation plan\nDerive a key per purpose.",
    labels=("concord", "poam-1", "severity-high"),
)


def _tracker(fake: FakeJira, **kwargs) -> JiraTracker:
    return JiraTracker(
        base_url="https://acme.atlassian.net",
        email="svc@acme.test",
        api_token="ATATT-secret",
        project_key="SEC",
        transport=fake.transport,
        **kwargs,
    )


# --- what we send ------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_created_issue_carries_an_adf_description_not_a_string() -> None:
    """v3 rejects a plain string, and the 400 names the field but not the reason.

    Pinned against the fake's own ADF check rather than by inspecting our
    payload, so the assertion fails the way Jira would.
    """
    fake = FakeJira()
    result = await _tracker(fake).create(_CONTENT)

    assert result.created is True
    assert result.external_id == "SEC-1"
    assert result.url == "https://acme.atlassian.net/browse/SEC-1"
    description = fake.issues["SEC-1"]["description"]
    assert description["type"] == "doc" and description["version"] == 1
    paragraphs = [
        block["content"][0]["text"] for block in description["content"] if block.get("content")
    ]
    assert paragraphs[0].startswith("Weakness")
    assert any(p.startswith("Remediation plan") for p in paragraphs)


@pytest.mark.asyncio
async def test_an_update_omits_the_fields_jira_refuses_after_creation() -> None:
    """`project` and `issuetype` are settable once. Sending them again is a 400.

    The fake refuses them on PUT exactly as Jira does, so a regression that
    reused the create field set would fail here rather than in production on
    the second push of every POA&M.
    """
    fake = FakeJira()
    created = await _tracker(fake).create(_CONTENT)

    updated = IssueContent(
        key=_CONTENT.key, title="Now with a fix", body="Closed out.", labels=("concord",)
    )
    result = await _tracker(fake).update(created.external_id, updated)

    assert result.created is False
    assert result.external_id == "SEC-1"
    assert fake.issues["SEC-1"]["summary"] == "Now with a fix"
    put = [r for r in fake.requests if r.method == "PUT"][-1]
    import json as _json

    sent = _json.loads(put.content)["fields"]
    assert "project" not in sent and "issuetype" not in sent


@pytest.mark.asyncio
async def test_labels_never_carry_the_whitespace_jira_rejects() -> None:
    """Jira refuses a label with a space, naming the field but not the value."""
    fake = FakeJira()
    spaced = IssueContent(
        key="poam:2", title="t", body="b", labels=("needs review", "concord")
    )
    await _tracker(fake).create(spaced)
    assert fake.issues["SEC-1"]["labels"] == ["needs-review", "concord"]


@pytest.mark.asyncio
async def test_the_due_date_is_withheld_unless_the_operator_opts_in() -> None:
    """`duedate` is on a project's screens or it is not; assuming it is, is a 400.

    Both directions are asserted: off by default, and actually sent when
    enabled -- a "safe default" that silently ignored the setting would pass a
    test that only checked the default.
    """
    from datetime import date

    content = IssueContent(key="poam:3", title="t", body="b", due_on=date(2026, 3, 1))

    default = FakeJira()
    await _tracker(default).create(content)
    assert "duedate" not in default.issues["SEC-1"]

    opted_in = FakeJira()
    await _tracker(opted_in, send_due_date=True).create(content)
    assert opted_in.issues["SEC-1"]["duedate"] == "2026-03-01"


@pytest.mark.asyncio
async def test_the_credential_is_sent_as_basic_email_colon_token() -> None:
    fake = FakeJira()
    await _tracker(fake).create(_CONTENT)
    header = fake.requests[0].headers["authorization"]
    assert header.startswith("Basic ")
    assert base64.b64decode(header.split(" ", 1)[1]).decode() == "svc@acme.test:ATATT-secret"


# --- refusals ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_jiras_own_complaint_reaches_the_operator_verbatim() -> None:
    """A 400 that says which field and why is the difference between a
    five-second configuration fix and an afternoon. Discarding it for a generic
    "push failed" is the defect this asserts against."""
    fake = FakeJira(issue_types=("Bug",))  # the configured "Task" does not exist
    with pytest.raises(IntegrationRefused) as caught:
        await _tracker(fake).create(_CONTENT)
    assert caught.value.status == 400
    assert "issuetype" in str(caught.value)
    assert "The issue type selected is invalid: Task" in str(caught.value)


@pytest.mark.asyncio
async def test_an_unreachable_site_is_not_reported_as_a_rejected_ticket() -> None:
    """A transient outage is worth retrying unchanged; a rejection never is.

    Recording the first as the second is how an outage becomes a POA&M that
    looks permanently unfileable.
    """
    import httpx

    def _boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("name resolution failed")

    tracker = JiraTracker(
        base_url="https://acme.atlassian.net",
        email="svc@acme.test",
        api_token="t",
        project_key="SEC",
        transport=httpx.MockTransport(_boom),
    )
    with pytest.raises(IntegrationUnavailable):
        await tracker.create(_CONTENT)


@pytest.mark.asyncio
async def test_a_2xx_without_an_issue_key_is_refused_not_stored() -> None:
    """A captive portal or SSO interstitial can answer 200 with an HTML body.

    Storing whatever that returned as an issue key produces a POA&M that
    claims to be filed in Jira and links nowhere -- the claim-versus-rendering
    shape, in its outbound form.
    """
    import httpx

    tracker = JiraTracker(
        base_url="https://acme.atlassian.net",
        email="svc@acme.test",
        api_token="t",
        project_key="SEC",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, text="<html>sign in</html>")
        ),
    )
    with pytest.raises(IntegrationRefused):
        await tracker.create(_CONTENT)


def test_the_base_url_must_be_an_origin_over_https() -> None:
    """The API token is sent on every request to this URL.

    A stored value carrying a path, or plain http, is a way to hand a token
    bearing full user authority somewhere the operator never named.
    """
    assert normalise_base_url("https://acme.atlassian.net/") == "https://acme.atlassian.net"
    for bad in (
        "http://acme.atlassian.net",
        "https://acme.atlassian.net/wiki",
        "https://acme.atlassian.net/?next=x",
        "acme.atlassian.net",
        "",
    ):
        with pytest.raises(IntegrationNotConfigured):
            normalise_base_url(bad)


def test_a_body_of_only_blank_lines_still_makes_a_valid_document() -> None:
    """ADF rejects an empty `content` array, so the degenerate case needs a shape."""
    document = _adf("\n\n   \n\n")
    assert document["type"] == "doc"
    assert document["content"] == [{"type": "paragraph"}]


def test_an_issue_must_carry_a_title() -> None:
    with pytest.raises(ValueError):
        IssueContent(key="poam:1", title="   ", body="b")
