"""A stand-in for the eMASS POA&M API, encoding the specification's behaviour.

Sits at the transport layer so assertions run through the real request-building
code. It enforces the constraints the specification states and that the obvious
implementation violates:

* the body is an array, even for one POA&M;
* dates are Unix **seconds** -- a value large enough to be milliseconds is
  rejected here, because the real service accepts it and stores a date tens of
  thousands of years out;
* ``severity`` and ``status`` are closed vocabularies with exact casing;
* a ``Completed`` item needs ``completionDate`` and an ``Ongoing`` one needs
  ``scheduledCompletionDate``;
* and a batch can answer **200 while reporting a per-item failure**, which is
  the response shape most likely to be mis-read as success.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

SEVERITIES = ("Very Low", "Low", "Moderate", "High", "Very High")
STATUSES = ("Ongoing", "Risk Accepted", "Completed", "Not Applicable", "Archived")

#: Seconds since the epoch for the year 5000 -- any value above this was almost
#: certainly sent in milliseconds.
_ABSURDLY_FAR_FUTURE = 95_617_584_000


class FakeEmass:
    def __init__(self, *, system_id: int = 42, reject_next: str | None = None) -> None:
        self.system_id = system_id
        self.reject_next = reject_next
        self.poams: dict[int, dict[str, Any]] = {}
        self.requests: list[httpx.Request] = []
        self._counter = 0

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if not request.headers.get("api-key") or not request.headers.get("user-uid"):
            return httpx.Response(
                401, json={"meta": {"code": 401, "errorMessage": "Missing credentials."}}
            )
        if request.url.path != f"/api/systems/{self.system_id}/poams":
            return httpx.Response(
                404, json={"meta": {"code": 404, "errorMessage": "Unknown system."}}
            )

        body = json.loads(request.content or b"null")
        if not isinstance(body, list):
            return httpx.Response(
                400,
                json={"meta": {"code": 400, "errorMessage": "Request body must be an array."}},
            )

        results: list[dict[str, Any]] = []
        for item in body:
            results.append(self._one(item, creating=request.method == "POST"))
        # The batch succeeds at the HTTP level even when an item did not.
        return httpx.Response(200, json={"meta": {"code": 200}, "data": results})

    def _one(self, item: dict[str, Any], *, creating: bool) -> dict[str, Any]:
        if self.reject_next:
            message, self.reject_next = self.reject_next, None
            return {"systemId": self.system_id, "success": False, "message": message}

        problem = self._validate(item, creating=creating)
        if problem:
            return {"systemId": self.system_id, "success": False, "message": problem}

        if creating:
            self._counter += 1
            poam_id = 5000 + self._counter
            self.poams[poam_id] = dict(item)
        else:
            poam_id = int(item["poamId"])
            if poam_id not in self.poams:
                return {
                    "systemId": self.system_id,
                    "success": False,
                    "message": f"POA&M {poam_id} not found.",
                }
            self.poams[poam_id].update(item)
        return {"systemId": self.system_id, "poamId": poam_id, "success": True}

    def _validate(self, item: dict[str, Any], *, creating: bool) -> str | None:
        if not creating and "poamId" not in item:
            return "poamId is required to update a POA&M."
        if item.get("severity") not in SEVERITIES:
            return f"severity must be one of {', '.join(SEVERITIES)}."
        status = item.get("status")
        if status not in STATUSES:
            return f"status must be one of {', '.join(STATUSES)}."
        if not item.get("vulnerabilityDescription"):
            return "vulnerabilityDescription is required."
        for field in ("scheduledCompletionDate", "completionDate"):
            value = item.get(field)
            if value is None:
                continue
            if not isinstance(value, int) or isinstance(value, bool):
                return f"{field} must be an integer Unix timestamp."
            if value > _ABSURDLY_FAR_FUTURE:
                return f"{field} looks like milliseconds; seconds are required."
        if status == "Ongoing" and "scheduledCompletionDate" not in item:
            return "An Ongoing POA&M requires scheduledCompletionDate."
        if status == "Completed" and "completionDate" not in item:
            return "A Completed POA&M requires completionDate."
        return None
