"""File and update Jira Cloud issues from Concord records. Never reads back.

Targets the Jira Cloud REST API v3, authenticated with an Atlassian API token
over HTTP Basic (``email:token``) as Atlassian documents. Three things about
that API shape this module more than anything else:

* **v3 takes rich text, not strings.** ``description`` must be an Atlassian
  Document Format document; posting a plain string gets a 400 that names the
  field but not the reason. :func:`_adf` builds the minimal valid document.
* **Field availability is per project, not per API.** ``duedate`` and
  ``priority`` are on a project's screens or they are not, and naming a
  priority a project has never defined is a 400. So neither is sent by
  default: severity travels as a label, which every project accepts. An
  operator who wants a real due date opts in per organization, and the
  remote's own complaint reaches them if their project disagrees.
* **Issue type names are per project too.** ``Task`` is the default because it
  exists in every out-of-the-box project template, and is overridable.

The base URL is pinned to https and to the host the operator configured; an
API token is a bearer of full user authority, and following a redirect to
another origin with it in the header would hand it away.
"""

from __future__ import annotations

import base64
from typing import Any
from urllib.parse import urlsplit

import httpx

from .types import (
    IntegrationNotConfigured,
    IntegrationRefused,
    IntegrationUnavailable,
    IssueContent,
    PushResult,
)

_TIMEOUT = 20.0

PROVIDER = "jira"
CREDENTIAL_TYPE = "jira"

#: Secret keys a stored Jira credential must carry.
REQUIRED_SECRET_FIELDS = ("base_url", "email", "api_token")


def _adf(body: str) -> dict[str, Any]:
    """Wrap plain text in the smallest valid Atlassian Document Format document.

    Blank lines separate paragraphs; a paragraph with no text is emitted with
    no ``content`` key at all, because ADF rejects an empty ``content`` array.
    """
    paragraphs = [p.strip() for p in body.replace("\r\n", "\n").split("\n\n")]
    content: list[dict[str, Any]] = []
    for paragraph in paragraphs:
        if not paragraph:
            continue
        content.append(
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": paragraph}],
            }
        )
    if not content:
        content = [{"type": "paragraph"}]
    return {"type": "doc", "version": 1, "content": content}


def normalise_base_url(raw: str) -> str:
    """Return the site's origin, or refuse it.

    Refuses anything that is not https, carries no host, or embeds a path --
    the credential is sent on every request to this URL, so it may only ever
    be an origin the operator named, never something a stored value can
    redirect through.
    """
    parts = urlsplit(raw.strip())
    if parts.scheme != "https" or not parts.netloc:
        raise IntegrationNotConfigured(
            f"Jira base URL must be an https origin, got {raw!r}"
        )
    if parts.path.strip("/") or parts.query or parts.fragment:
        raise IntegrationNotConfigured(
            f"Jira base URL must be an origin with no path, got {raw!r}"
        )
    return f"https://{parts.netloc}"


class JiraTracker:
    """An organization's Jira project, as somewhere Concord can file tickets."""

    provider = PROVIDER
    credential_type = CREDENTIAL_TYPE

    def __init__(
        self,
        *,
        base_url: str,
        email: str,
        api_token: str,
        project_key: str,
        issue_type: str = "Task",
        send_due_date: bool = False,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not project_key.strip():
            raise IntegrationNotConfigured("no Jira project key is configured")
        if not email.strip() or not api_token.strip():
            raise IntegrationNotConfigured("the Jira credential is incomplete")
        self._base = normalise_base_url(base_url)
        self._project = project_key.strip()
        self._issue_type = issue_type.strip() or "Task"
        self._send_due_date = send_due_date
        token = base64.b64encode(f"{email.strip()}:{api_token}".encode()).decode()
        self._headers = {
            "Authorization": f"Basic {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        # A seam for tests to drive a faithful fake of the Jira API through the
        # real request-building code. Production passes nothing: the point of
        # the fake is to exercise what this module actually sends, which a
        # mock of `create`/`update` would skip over entirely.
        self._transport = transport

    # -- mapping --------------------------------------------------------------

    def _fields(self, content: IssueContent, *, creating: bool) -> dict[str, Any]:
        fields: dict[str, Any] = {
            "summary": content.title[:255],
            "description": _adf(content.body),
        }
        if creating:
            # Neither may be changed after creation, and sending them on an
            # update is a 400 on most projects.
            fields["project"] = {"key": self._project}
            fields["issuetype"] = {"name": self._issue_type}
        if content.labels:
            # Jira rejects a label containing whitespace with a 400 naming the
            # field but not the offending value, so they are joined here.
            fields["labels"] = [label.replace(" ", "-") for label in content.labels]
        if self._send_due_date and content.due_on is not None:
            fields["duedate"] = content.due_on.isoformat()
        return fields

    def browse_url(self, issue_key: str) -> str:
        return f"{self._base}/browse/{issue_key}"

    # -- transport ------------------------------------------------------------

    async def _request(self, method: str, path: str, payload: dict[str, Any]) -> httpx.Response:
        url = f"{self._base}{path}"
        try:
            async with httpx.AsyncClient(
                timeout=_TIMEOUT, follow_redirects=False, transport=self._transport
            ) as client:
                response = await client.request(
                    method, url, headers=self._headers, json=payload
                )
        except httpx.HTTPError as exc:  # network, DNS, TLS, timeout
            raise IntegrationUnavailable(f"could not reach Jira at {self._base}: {exc}") from exc
        if response.status_code >= 400:
            raise IntegrationRefused(
                _explain(response), status=response.status_code
            )
        return response

    async def create(self, content: IssueContent) -> PushResult:
        response = await self._request(
            "POST", "/rest/api/3/issue", {"fields": self._fields(content, creating=True)}
        )
        key = _issue_key(response)
        return PushResult(external_id=key, url=self.browse_url(key), created=True)

    async def update(self, external_id: str, content: IssueContent) -> PushResult:
        # A successful update is 204 with an empty body: there is nothing to
        # read back, and the key we were given is the key it still has.
        await self._request(
            "PUT",
            f"/rest/api/3/issue/{external_id}",
            {"fields": self._fields(content, creating=False)},
        )
        return PushResult(
            external_id=external_id, url=self.browse_url(external_id), created=False
        )


def _issue_key(response: httpx.Response) -> str:
    """The created issue's key, or a refusal naming what came back instead.

    A 2xx whose body is not the documented ``{"key": ...}`` means we are not
    talking to the API we think we are -- a captive portal, an SSO
    interstitial, a proxy error page served with the wrong status. Storing
    whatever that returned as an issue key would produce a POA&M that claims
    to be filed in Jira and links nowhere.
    """
    try:
        data = response.json()
    except ValueError as exc:
        raise IntegrationRefused(
            "Jira returned a non-JSON body for a created issue", status=response.status_code
        ) from exc
    key = data.get("key") if isinstance(data, dict) else None
    if not isinstance(key, str) or not key:
        raise IntegrationRefused(
            "Jira accepted the request but returned no issue key",
            status=response.status_code,
        )
    return key


def _explain(response: httpx.Response) -> str:
    """Jira's own complaint, which is specific and worth surfacing verbatim."""
    try:
        data = response.json()
    except ValueError:
        return f"Jira returned {response.status_code}"
    if not isinstance(data, dict):
        return f"Jira returned {response.status_code}"
    messages: list[str] = []
    errors = data.get("errors")
    if isinstance(errors, dict):
        messages.extend(f"{field}: {text}" for field, text in sorted(errors.items()))
    listed = data.get("errorMessages")
    if isinstance(listed, list):
        messages.extend(str(m) for m in listed)
    if not messages:
        return f"Jira returned {response.status_code}"
    return f"Jira returned {response.status_code} -- " + "; ".join(messages)
