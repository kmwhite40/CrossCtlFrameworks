"""File a POA&M into eMASS. Never reads back.

**Unverified against a live instance.** Written from the published eMASS REST
API specification. eMASS requires a registered ``api-key`` plus a CAC-backed
``user-uid`` against a real deployment, so nothing here has been exercised
against the real service -- only against ``tests.fake_emass``, which encodes
the specification's stated behaviour. Treat the mapping as reviewed, not
proven, until a deployment confirms it.

Four things about that API shape this module, and each is a trap the obvious
implementation falls into:

* **Dates are Unix epoch seconds**, not ISO strings. A date sent as
  ``"2026-03-01"`` is rejected, and -- worse -- a date sent as milliseconds is
  *accepted* and lands roughly fifty thousand years out.
* **The body is an array**, even for one POA&M, and the response is an array
  of per-item results.
* **A 200 can contain a failure.** Each element of ``data`` carries its own
  ``success`` flag; eMASS answers 200 for the batch while reporting that an
  individual item was rejected. Trusting the HTTP status alone records a
  POA&M as filed that eMASS never accepted -- the claim-versus-rendering
  defect in its outbound form.
* **The vocabularies are closed and exact.** ``severity`` and ``status`` take
  specific words with specific casing, and Concord's own vocabularies are
  neither the same words nor the same size.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, time
from typing import Any
from urllib.parse import urlsplit

import httpx

from .types import (
    IntegrationNotConfigured,
    IntegrationRefused,
    IntegrationUnavailable,
    PushResult,
)

_TIMEOUT = 30.0

PROVIDER = "emass"
CREDENTIAL_TYPE = "emass"

REQUIRED_SECRET_FIELDS = ("base_url", "api_key", "user_uid")

#: Concord severity -> eMASS severity. eMASS carries five levels and Concord
#: four, so `critical` maps to `Very High` and nothing maps to `Very Low`:
#: inventing a fifth Concord level to fill the gap would put a severity on a
#: federal record that no assessor assigned.
_SEVERITY = {
    "critical": "Very High",
    "high": "High",
    "moderate": "Moderate",
    "low": "Low",
}

#: Concord status -> eMASS status. `closed` and `completed` both become
#: `Completed`: eMASS has no separate closed state, and `Archived` means
#: something else entirely (removed from active reporting), so using it here
#: would drop the item out of the package's POA&M list.
_STATUS = {
    "open": "Ongoing",
    "in_progress": "Ongoing",
    "completed": "Completed",
    "closed": "Completed",
    "risk_accepted": "Risk Accepted",
}


def _epoch(value: date | None) -> int | None:
    """Midnight UTC of ``value`` as Unix **seconds**.

    Seconds, not milliseconds: eMASS accepts a millisecond value without
    complaint and stores a date tens of thousands of years in the future,
    which passes every validation this platform could write and is visibly
    wrong only to a human reading the package.

    UTC explicitly. ``datetime.combine(...).timestamp()`` reads a naive
    datetime as *local* time, so the same POA&M filed from a server west of
    Greenwich would carry a scheduled completion date one day later than the
    one on the screen -- a date on a federal record, silently wrong by a day
    depending on where the container happens to run.
    """
    if value is None:
        return None
    return int(datetime.combine(value, time.min, tzinfo=UTC).timestamp())


def normalise_base_url(raw: str) -> str:
    """Return the eMASS origin, or refuse it.

    Same rule as the Jira target and for the same reason: the api-key and the
    user-uid go on every request to this URL, so it may only be an origin the
    operator named.
    """
    parts = urlsplit(raw.strip())
    if parts.scheme != "https" or not parts.netloc:
        raise IntegrationNotConfigured(
            f"eMASS base URL must be an https origin, got {raw!r}"
        )
    if parts.path.strip("/") or parts.query or parts.fragment:
        raise IntegrationNotConfigured(
            f"eMASS base URL must be an origin with no path, got {raw!r}"
        )
    return f"https://{parts.netloc}"


class EmassTarget:
    """An organization's eMASS system, as somewhere Concord files POA&Ms."""

    provider = PROVIDER
    credential_type = CREDENTIAL_TYPE

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        user_uid: str,
        system_id: int,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not api_key.strip() or not user_uid.strip():
            raise IntegrationNotConfigured("the eMASS credential is incomplete")
        if not system_id:
            raise IntegrationNotConfigured("no eMASS system id is configured")
        self._base = normalise_base_url(base_url)
        self._system_id = int(system_id)
        self._headers = {
            "api-key": api_key.strip(),
            "user-uid": user_uid.strip(),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        self._transport = transport

    # -- mapping --------------------------------------------------------------

    def content_for(self, poam: Any) -> dict[str, Any]:
        """Map a POA&M onto eMASS's own POA&M fields.

        Unset fields are omitted rather than sent as null: eMASS validates
        conditionally on status, and an explicit null is not the same as an
        absent key to that validator.
        """
        status = _STATUS.get(poam.status or "", "Ongoing")
        item: dict[str, Any] = {
            "status": status,
            "vulnerabilityDescription": poam.weakness or poam.title,
            "sourceIdentVuln": poam.source or "Concord",
            "severity": _SEVERITY.get(poam.severity or "", "Moderate"),
            # Concord's own id, so a second push finds the same record even if
            # the stored link were ever lost.
            "externalUid": f"concord-poam-{poam.id}",
            "comments": (
                f"Filed from Concord POA&M #{poam.id}. Concord remains the record "
                "of truth for this item's compliance status."
            ),
        }
        if poam.remediation_plan:
            item["recommendations"] = poam.remediation_plan
        if poam.resources_required:
            item["resourcesRequired"] = poam.resources_required
        if poam.point_of_contact:
            item["pocOrganization"] = poam.point_of_contact

        scheduled = poam.scheduled_completion or poam.due_on
        if status == "Completed":
            # eMASS requires a completion date for a completed item and
            # refuses a scheduled one alongside it.
            item["completionDate"] = _epoch(poam.closed_on or scheduled or date.today())
        elif scheduled is not None:
            item["scheduledCompletionDate"] = _epoch(scheduled)
        return item

    def package_url(self, poam_id: str) -> str:
        return f"{self._base}/#/id/{self._system_id}/poams/{poam_id}"

    # -- transport ------------------------------------------------------------

    async def _request(self, method: str, payload: list[dict[str, Any]]) -> dict[str, Any]:
        url = f"{self._base}/api/systems/{self._system_id}/poams"
        try:
            async with httpx.AsyncClient(
                timeout=_TIMEOUT, follow_redirects=False, transport=self._transport
            ) as client:
                response = await client.request(
                    method, url, headers=self._headers, json=payload
                )
        except httpx.HTTPError as exc:
            raise IntegrationUnavailable(f"could not reach eMASS at {self._base}: {exc}") from exc
        if response.status_code >= 400:
            raise IntegrationRefused(_explain(response), status=response.status_code)
        return _first_success(response)

    async def create(self, content: dict[str, Any]) -> PushResult:
        data = await self._request("POST", [content])
        poam_id = str(data.get("poamId") or "")
        if not poam_id:
            raise IntegrationRefused("eMASS accepted the POA&M but returned no poamId")
        return PushResult(external_id=poam_id, url=self.package_url(poam_id), created=True)

    async def update(self, external_id: str, content: dict[str, Any]) -> PushResult:
        # The identifier travels in the item, not the path: the endpoint is the
        # system's POA&M collection for both verbs.
        item = dict(content)
        item["poamId"] = int(external_id)
        await self._request("PUT", [item])
        return PushResult(
            external_id=external_id, url=self.package_url(external_id), created=False
        )


def _first_success(response: httpx.Response) -> dict[str, Any]:
    """The single item's result, refusing a per-item failure inside a 200.

    eMASS answers 200 for the batch and reports each element's outcome in its
    own ``success`` flag. Reading only the HTTP status records a POA&M as
    filed that eMASS rejected.
    """
    try:
        body = response.json()
    except ValueError as exc:
        raise IntegrationRefused(
            "eMASS returned a non-JSON body", status=response.status_code
        ) from exc
    if not isinstance(body, dict):
        raise IntegrationRefused("eMASS returned an unexpected body")
    data = body.get("data")
    if not isinstance(data, list) or not data:
        raise IntegrationRefused("eMASS returned no POA&M result")
    item = data[0]
    if not isinstance(item, dict):
        raise IntegrationRefused("eMASS returned an unexpected POA&M result")
    if item.get("success") is not True:
        raise IntegrationRefused(
            "eMASS rejected the POA&M: "
            + str(item.get("message") or item.get("error") or "no reason given"),
            status=response.status_code,
        )
    return item


def _explain(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return f"eMASS returned {response.status_code}"
    if not isinstance(body, dict):
        return f"eMASS returned {response.status_code}"
    parts: list[str] = []
    meta = body.get("meta")
    if isinstance(meta, dict) and meta.get("errorMessage"):
        parts.append(str(meta["errorMessage"]))
    data = body.get("data")
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item.get("message"):
                parts.append(str(item["message"]))
    if not parts:
        return f"eMASS returned {response.status_code}"
    return f"eMASS returned {response.status_code} -- " + "; ".join(parts)
