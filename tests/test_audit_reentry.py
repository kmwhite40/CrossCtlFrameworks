"""Regression tests for the audit-middleware double-invocation-on-exception bug.

``audit_middleware`` is registered as a Starlette ``BaseHTTPMiddleware`` dispatch
function (``app.middleware("http")(audit_middleware)`` in ``ccf.api.main``).
``BaseHTTPMiddleware`` has a well-documented reliability hazard: under certain
exception/re-entry conditions the ASGI machinery can invoke a dispatch function
more than once for what is logically the *same* client request — and because
the underlying ASGI ``scope`` (and therefore ``request.state``) is shared across
those re-entries, a naive dispatch function has no way to tell "first pass" from
"replay". For ``audit_middleware`` that means a second pass re-reads the
(cached) request body, re-resolves the principal, and re-runs the
select-latest-hash + insert sequence — writing a **second** ``AuditLog`` row for
one logical mutation. Because both rows are computed from the same
``prev_hash`` (the row that was latest *before either* insert), the second row
forks the hash chain: two rows both claim the same predecessor, and
``/api/audit/verify`` breaks — not just for this request, but permanently for
every row appended afterwards, since the chain is a whole-table invariant.

The literal Starlette-level double-dispatch is timing/version-sensitive and did
not reproduce over an HTTP round-trip against the currently pinned Starlette
(which already includes upstream's `create_collapsing_task_group` mitigation
for the classic single-layer case). The exact mechanism this repo was
root-caused against — re-entry sharing ``request.state`` across dispatch
invocations — is reproduced directly and deterministically below by invoking
``audit_middleware`` twice with the *same* ``Request`` instance, which is
precisely the condition an idempotency guard on ``request.state`` must defend
against regardless of which upstream code path triggers the re-entry.
"""

from __future__ import annotations

import json

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select
from starlette.requests import Request
from starlette.responses import JSONResponse

from ccf.api.audit import audit_middleware
from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import AuditLog

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _mutating_request(path: str, body: bytes) -> Request:
    """Build a bare POST ``Request`` with a JSON body, no auth headers."""
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "POST",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "scheme": "http",
        "server": ("test", 80),
        "client": ("test", 123),
        "headers": [(b"content-type", b"application/json")],
        "state": {},
    }
    consumed = {"done": False}

    async def receive() -> dict[str, object]:
        if consumed["done"]:
            return {"type": "http.disconnect"}
        consumed["done"] = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive)


async def _audit_count() -> int:
    async with session_scope() as s:
        return int((await s.execute(select(func.count()).select_from(AuditLog))).scalar_one())


@pytest.mark.asyncio
async def test_middleware_reentry_writes_audit_row_exactly_once() -> None:
    """Simulating BaseHTTPMiddleware re-entry must not duplicate the audit row.

    Two dispatch invocations against the *same* ``Request`` (same
    ``request.state``) is exactly the condition a Starlette re-entry produces.
    Before the idempotency-guard fix this writes two ``AuditLog`` rows, forking
    the hash chain; after the fix, exactly one.
    """
    body = json.dumps({"customer_name": "ReentryCo"}).encode()
    request = _mutating_request("/api/__reentry_widgets/999", body)

    async def call_next(_request: Request) -> JSONResponse:
        return JSONResponse({"id": 999}, status_code=201)

    before = await _audit_count()

    # First pass — the "real" dispatch.
    await audit_middleware(request, call_next)
    # Second pass on the SAME request/state — simulates the documented
    # BaseHTTPMiddleware re-entry-on-exception behavior.
    await audit_middleware(request, call_next)

    after = await _audit_count()
    assert after - before == 1, (
        f"expected exactly one audit row for the mutation, got {after - before} "
        "(middleware re-entry is writing a duplicate row and forking the hash chain)"
    )


@pytest.mark.asyncio
async def test_raising_route_does_not_double_invoke_or_write_audit_row() -> None:
    """A route that raises must be invoked exactly once and must not audit-write.

    5xx (unhandled exception) is not a 2xx/3xx mutation outcome, so no audit
    row should ever be written for it — and the route body itself must not run
    twice.
    """
    app = create_app()
    call_count = {"n": 0}

    @app.post("/api/__reentry_widgets")
    async def _raising_widget() -> dict:
        call_count["n"] += 1
        raise RuntimeError("simulated downstream failure")

    before = await _audit_count()
    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://t"
    ) as c:
        resp = await c.post("/api/__reentry_widgets", json={"x": 1})

    assert resp.status_code == 500
    assert call_count["n"] == 1, "route handler was invoked more than once"

    after = await _audit_count()
    assert after == before, "a raising (5xx) request must not write an audit row"


@pytest.mark.asyncio
async def test_successful_mutation_writes_exactly_one_audit_row() -> None:
    """Normal-path sanity: a single successful mutating request → one audit row."""
    app = create_app()

    @app.post("/api/__reentry_widgets_ok")
    async def _ok_widget() -> dict:
        return {"ok": True}

    before = await _audit_count()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        resp = await c.post("/api/__reentry_widgets_ok", json={"x": 1})

    assert resp.status_code == 200
    after = await _audit_count()
    assert after - before == 1
