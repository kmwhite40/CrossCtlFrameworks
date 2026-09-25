"""A faithful stand-in for the Jira Cloud REST API v3.

Not a mock of :class:`ccf.integrations.jira.JiraTracker`. It sits at the
transport layer, so every assertion runs through the real request-building
code -- the ADF document, the Basic credential, the field set that differs
between create and update. A mock of ``create``/``update`` would skip exactly
the parts most likely to be wrong.

It enforces the constraints the real API enforces and that this programme is
most likely to get wrong:

* ``description`` must be an ADF document, not a string (a real 400).
* ``project`` and ``issuetype`` are settable on create and rejected on update.
* an unknown project key, an unknown issue type, and a label containing
  whitespace are each a 400 with Jira's own error shape.
* a successful update is ``204`` with an empty body.
"""

from __future__ import annotations

import json
from typing import Any

import httpx


class FakeJira:
    """Records what was sent and answers the way Jira Cloud does."""

    def __init__(
        self,
        *,
        projects: tuple[str, ...] = ("SEC",),
        issue_types: tuple[str, ...] = ("Task", "Bug"),
        allowed_fields: tuple[str, ...] = (
            "project",
            "issuetype",
            "summary",
            "description",
            "labels",
            "duedate",
        ),
    ) -> None:
        self.projects = projects
        self.issue_types = issue_types
        self.allowed_fields = allowed_fields
        self.issues: dict[str, dict[str, Any]] = {}
        self.requests: list[httpx.Request] = []
        self._counter = 0

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    # -- the API ---------------------------------------------------------------

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.headers.get("authorization", "").split(" ")[0] != "Basic":
            return _error(401, messages=["Client must be authenticated."])

        path = request.url.path
        payload = json.loads(request.content or b"{}")
        fields = payload.get("fields")
        if not isinstance(fields, dict):
            return _error(400, errors={"fields": "must be an object"})

        if request.method == "POST" and path == "/rest/api/3/issue":
            return self._create(fields)
        if request.method == "PUT" and path.startswith("/rest/api/3/issue/"):
            return self._update(path.rsplit("/", 1)[-1], fields)
        return _error(404, messages=[f"No route for {request.method} {path}"])

    def _create(self, fields: dict[str, Any]) -> httpx.Response:
        bad = self._validate(fields, creating=True)
        if bad is not None:
            return bad
        self._counter += 1
        key = f"{fields['project']['key']}-{self._counter}"
        self.issues[key] = dict(fields)
        return httpx.Response(
            201, json={"id": str(10000 + self._counter), "key": key, "self": f"/{key}"}
        )

    def _update(self, key: str, fields: dict[str, Any]) -> httpx.Response:
        if key not in self.issues:
            return _error(404, messages=["Issue does not exist or you do not have permission."])
        bad = self._validate(fields, creating=False)
        if bad is not None:
            return bad
        self.issues[key].update(fields)
        return httpx.Response(204)

    # -- what the real API refuses --------------------------------------------

    def _validate(self, fields: dict[str, Any], *, creating: bool) -> httpx.Response | None:
        errors: dict[str, str] = {}
        for name in fields:
            if name not in self.allowed_fields:
                errors[name] = (
                    f"Field '{name}' cannot be set. It is not on the appropriate "
                    "screen, or unknown."
                )
        if creating:
            project = (fields.get("project") or {}).get("key")
            if project not in self.projects:
                errors["project"] = "project is required"
            issue_type = (fields.get("issuetype") or {}).get("name")
            if issue_type not in self.issue_types:
                errors["issuetype"] = (
                    f"The issue type selected is invalid: {issue_type}"
                )
        else:
            for immutable in ("project", "issuetype"):
                if immutable in fields:
                    errors[immutable] = (
                        f"Field '{immutable}' cannot be set. It is not on the "
                        "appropriate screen, or unknown."
                    )
        description = fields.get("description")
        if description is not None and not _is_adf(description):
            errors["description"] = "Operation value must be an Atlassian Document"
        for label in fields.get("labels") or []:
            if not isinstance(label, str) or " " in label:
                errors["labels"] = "Labels may not contain spaces."
        summary = fields.get("summary")
        if creating and not summary:
            errors["summary"] = "You must specify a summary of the issue."
        if isinstance(summary, str) and len(summary) > 255:
            errors["summary"] = "Summary must be less than 255 characters."
        return _error(400, errors=errors) if errors else None


def _is_adf(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and value.get("type") == "doc"
        and value.get("version") == 1
        and isinstance(value.get("content"), list)
    )


def _error(
    status: int,
    *,
    errors: dict[str, str] | None = None,
    messages: list[str] | None = None,
) -> httpx.Response:
    return httpx.Response(
        status, json={"errorMessages": messages or [], "errors": errors or {}}
    )
