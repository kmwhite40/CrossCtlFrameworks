"""The audit hash chain is GLOBAL, so every append must see the GLOBAL head.

``ccf.models.AuditLog`` is append-only and SHA-256 hash-chained: each row's
``row_hash`` covers its content plus the previous row's ``row_hash``, and
``/api/audit/verify`` walks the whole table from genesis in ``id`` order. That
is the platform's tamper evidence (AU-9), so a ``ok=False`` it produces for
*legitimate* traffic is not a cosmetic bug: it makes a real tamper
indistinguishable from ordinary multi-tenant writes.

Three ways the append path could read a head that is not the real head, each
pinned below. All three were live on ``main`` at ``c88234a`` and each one
forks the chain permanently -- every row appended afterwards inherits the
break:

1. **Through the RLS clamp.** Migration 0044 put a ``tenant_isolation`` policy
   on ``audit_log``. ``record_event`` appends inside the *caller's* session,
   which ``ccf.api.deps.get_session`` clamps to the caller's org, so its
   "latest row" SELECT returned the latest row *that tenant could see*. Another
   org's row sitting at the head was invisible. (``audit_middleware`` was never
   affected: it opens its own session and resets it to unscoped. The verifier
   was fixed the same way at ``349e510``; the writer was missed.)
2. **Across concurrent transactions.** Two appends that read the head before
   either commits both chain onto the same predecessor.
3. **Within one transaction.** ``record_event`` used to ``session.add`` without
   flushing, and these sessions are ``autoflush=False``, so a second event in
   the same transaction re-read the head and did not see the first.

The two tamper-detection tests at the bottom are the other half: none of the
above may be paid for by weakening detection. They mutate ``row_hash``,
``prev_hash`` and a payload field separately and require each to be caught.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select
from starlette.requests import Request
from starlette.responses import JSONResponse

from ccf.api.audit import audit_middleware, record_event, row_hash
from ccf.api.routes.audit import verify_chain
from ccf.auth import Principal
from ccf.config import get_settings
from ccf.db import get_session_factory, session_scope, set_session_tenant
from ccf.models import AuditLog, Organization

pytestmark = pytest.mark.usefixtures("fresh_engine")

_GENESIS = "0" * 64
_ENTITY = "audit_chain_mt"
#: Path segment for the middleware-written rows. Deliberately not prefixed
#: "audit": ``_SKIP_PREFIXES`` drops every ``/api/audit*`` path, so a name
#: like ``/api/audit_chain_mt/1`` is silently never audited at all.
_MW_ENTITY = "chainmt"


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _reset_chain() -> None:
    """Start from an empty chain.

    ``verify_chain`` walks the *entire* table from genesis, so an assertion
    about linkage is only deterministic against a fully controlled chain --
    the same reasoning (and the same ``delete(AuditLog)``) as
    ``tests/test_audit_rbac.py``'s interleaved-chain regression test. Each
    test here empties the table again in a ``finally``, so it leaves the chain
    valid (trivially) rather than leaving its own rows behind for another
    module to trip over in the full suite.
    """
    async with session_scope() as s:
        await s.execute(delete(AuditLog))


async def _org_id(name: str) -> int:
    async with session_scope() as s:
        org = (
            await s.execute(select(Organization).where(Organization.name == name))
        ).scalar_one_or_none()
        if org is None:
            org = Organization(name=name)
            s.add(org)
            await s.flush()
        return org.id


async def _append_as(org_id: int, tag: str) -> None:
    """One ``record_event`` on a session clamped to ``org_id``, as a request is.

    ``set_session_tenant`` is what ``ccf.api.deps.get_session`` does for every
    authenticated request, so this is the production append path, not a
    hand-built row.
    """
    factory = get_session_factory()
    async with factory() as s:
        await set_session_tenant(s, org_id)
        await record_event(
            s,
            actor=f"{tag}@audit-chain-mt.test",
            action="create",
            entity_type=_ENTITY,
            entity_id=tag,
            diff={"tag": tag},
        )
        await s.commit()


async def _append_via_middleware(org_id: int, tag: int) -> None:
    """One audit row written by the real ``audit_middleware``, scoped to ``org_id``.

    This is the only append path that sets ``organization_id`` -- the middleware
    resolves it from the request principal. ``record_event`` leaves it NULL, and
    the ``tenant_isolation`` predicate lets *every* tenant see NULL-org rows, so
    a chain built only from ``record_event`` calls would be fully visible to any
    clamped session and could not show the RLS-clamped head read at all. The
    middleware is driven directly (same technique as
    ``tests/test_audit_reentry.py``) rather than over HTTP so the row's org is
    exactly the one this test names.
    """
    path = f"/api/{_MW_ENTITY}/{tag}"
    principal = Principal(
        user_id=1, email=f"mw-{tag}@audit-chain-mt.test", org_id=org_id, role="admin"
    )
    body = json.dumps({"tag": tag}).encode()
    consumed = {"done": False}

    async def receive() -> dict[str, object]:
        if consumed["done"]:
            return {"type": "http.disconnect"}
        consumed["done"] = True
        return {"type": "http.request", "body": body, "more_body": False}

    request = Request(
        {
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
            "state": {"principal": principal},
        },
        receive,
    )

    async def call_next(_request: Request) -> JSONResponse:
        return JSONResponse({"ok": True}, status_code=201)

    await audit_middleware(request, call_next)


async def _chain_break() -> tuple[int, str, str] | None:
    """The first row whose linkage fails, as ``(id, expected_prev, stored_prev)``.

    Recomputed here rather than read off ``verify_chain`` so a failure names
    the row and the two hashes instead of just ``ok=False``.
    """
    async with session_scope() as s:
        rows = (await s.execute(select(AuditLog).order_by(AuditLog.id))).scalars().all()
    prev = _GENESIS
    for r in rows:
        if r.row_hash is None:
            continue
        content = {
            "actor": r.actor,
            "action": r.action,
            "entity_type": r.entity_type,
            "entity_id": r.entity_id,
            "diff": r.diff,
        }
        if r.prev_hash != prev or r.row_hash != row_hash(r.prev_hash or _GENESIS, content):
            return (r.id, prev, r.prev_hash or "")
        prev = r.row_hash
    return None


async def _verify() -> dict:
    """``GET /api/audit/verify``'s handler, on an unscoped session."""
    async with session_scope() as s:
        return await verify_chain(
            session=s,
            _principal=Principal(
                user_id=None,
                email="chain@audit-chain-mt.test",
                org_id=None,
                role="admin",
            ),
        )


# --- 1. the head must be the global head, not the tenant-visible head ---------


@pytest.mark.asyncio
async def test_interleaved_tenant_scoped_appends_keep_one_linear_chain() -> None:
    """Org A, org B, org A -- each appending from its own clamped session.

    Row 2 is org B's and carries ``organization_id = org_b``, so an org A
    session cannot see it under ``tenant_isolation``. If the head lookup runs
    through that clamp, row 3 chains onto row 1 and the chain forks at row 3.
    """
    await _reset_chain()
    org_a = await _org_id("Audit Chain MT Org A")
    org_b = await _org_id("Audit Chain MT Org B")
    try:
        await _append_as(org_a, "a1")
        await _append_via_middleware(org_b, 1)
        await _append_as(org_a, "a2")

        # Without this the test degrades silently: a NULL-org middle row is
        # visible to org A's clamped session and the scenario evaporates.
        async with session_scope() as s:
            middle = (
                await s.execute(
                    select(AuditLog).where(AuditLog.entity_type == _MW_ENTITY)
                )
            ).scalar_one()
            assert middle.organization_id == org_b, (
                "the interleaved row must be scoped to the other org, or org A's "
                "clamped session would see it and nothing is being tested"
            )

        break_at = await _chain_break()
        assert break_at is None, (
            f"row {break_at[0]} chains onto {break_at[2][:12]} but the row before it "
            f"by id hashes to {break_at[1][:12]}"
        )
        verdict = await _verify()
        assert verdict["ok"] is True and verdict["checked"] == 3
    finally:
        await _reset_chain()


# --- 2. concurrent appends must not both claim the same predecessor -----------


@pytest.mark.asyncio
async def test_two_tenants_appending_concurrently_do_not_fork_the_chain() -> None:
    """Two tenants writing at once is ordinary traffic, not an edge case.

    Both sessions are opened and clamped before either appends, and each holds
    its transaction open after recording, so without serialization both read
    the same head and the second row's ``prev_hash`` points past its real
    predecessor.
    """
    await _reset_chain()
    org_a = await _org_id("Audit Chain MT Org A")
    org_b = await _org_id("Audit Chain MT Org B")

    async def writer(org_id: int, tag: str, gate: asyncio.Event) -> None:
        factory = get_session_factory()
        async with factory() as s:
            await set_session_tenant(s, org_id)
            await gate.wait()
            await record_event(
                s,
                actor=f"{tag}@audit-chain-mt.test",
                action="create",
                entity_type=_ENTITY,
                entity_id=tag,
                diff={"tag": tag},
            )
            # Hold the transaction open: this is the window in which an
            # unserialized second appender reads a head that is about to change.
            await asyncio.sleep(0.05)
            await s.commit()

    try:
        gate = asyncio.Event()
        tasks = [
            asyncio.create_task(writer(org_a, "conc-a", gate)),
            asyncio.create_task(writer(org_b, "conc-b", gate)),
        ]
        gate.set()
        await asyncio.gather(*tasks)

        break_at = await _chain_break()
        assert break_at is None, (
            f"concurrent appends forked the chain at row {break_at[0]}: it chains onto "
            f"{break_at[2][:12]}, its predecessor by id hashes to {break_at[1][:12]}"
        )
        assert (await _verify())["ok"] is True
    finally:
        await _reset_chain()


# --- 3. two events in one transaction must chain to each other ----------------


@pytest.mark.asyncio
async def test_two_events_in_one_transaction_chain_to_each_other() -> None:
    """``record_event`` twice on one session, with no flush by the caller.

    ``ccf.portal.service._audit`` is exactly this shape. Without a flush inside
    ``record_event`` the second call's SELECT never sees the first row, so both
    rows claim the same predecessor.
    """
    await _reset_chain()
    org_a = await _org_id("Audit Chain MT Org A")
    try:
        factory = get_session_factory()
        async with factory() as s:
            await set_session_tenant(s, org_a)
            for tag in ("same-txn-1", "same-txn-2"):
                await record_event(
                    s,
                    actor="same@audit-chain-mt.test",
                    action="create",
                    entity_type=_ENTITY,
                    entity_id=tag,
                    diff={"tag": tag},
                )
            await s.commit()

        break_at = await _chain_break()
        assert break_at is None, (
            f"second event in the same transaction forked the chain at row {break_at[0]}"
        )
        assert (await _verify())["ok"] is True
    finally:
        await _reset_chain()


# --- 4. none of the above may weaken tamper detection -------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["row_hash", "prev_hash", "actor", "diff"])
async def test_a_real_tamper_is_still_detected(field: str) -> None:
    """Mutate one stored field of a chained row; verification must object.

    ``row_hash`` and ``prev_hash`` are the chain links themselves; ``actor``
    and ``diff`` are payload fields covered by ``row_hash``. Each is mutated
    separately, on a chain built by the real append path, and restored
    afterwards.
    """
    await _reset_chain()
    org_a = await _org_id("Audit Chain MT Org A")
    org_b = await _org_id("Audit Chain MT Org B")
    try:
        await _append_as(org_a, "t1")
        await _append_as(org_b, "t2")
        await _append_as(org_a, "t3")
        assert (await _verify())["ok"] is True, "chain must be intact before tampering"

        async with session_scope() as s:
            row = (
                await s.execute(
                    select(AuditLog).where(AuditLog.entity_id == "t2").limit(1)
                )
            ).scalar_one()
            row_id, original = row.id, getattr(row, field)
            tampered = {
                "row_hash": "f" * 64,
                "prev_hash": "e" * 64,
                "actor": "evil@attacker.test",
                "diff": {"tag": "rewritten-by-attacker"},
            }[field]
            assert tampered != original
            setattr(row, field, tampered)

        verdict = await _verify()
        assert verdict["ok"] is False, f"tampering with {field} went undetected"
        assert verdict["broken_at_id"] is not None
        # Detection must name the altered row, not merely notice damage later.
        assert verdict["broken_at_id"] == row_id

        async with session_scope() as s:
            row = (
                await s.execute(select(AuditLog).where(AuditLog.id == row_id))
            ).scalar_one()
            setattr(row, field, original)
        assert (await _verify())["ok"] is True, "restore must return the chain to intact"
    finally:
        await _reset_chain()


@pytest.mark.asyncio
async def test_a_forged_row_that_hashes_itself_correctly_is_still_detected() -> None:
    """An out-of-band row whose own hash is self-consistent but does not link.

    Every mutation above is caught by recomputing ``row_hash`` over the row's
    own content. This one is not: the forged row's ``row_hash`` is a correct
    hash of its ``prev_hash`` + content, so only the *linkage* half of
    ``verify_chain`` -- ``r.prev_hash != prev`` -- can object. That is the same
    shape the three bugs above produced accidentally, which is precisely why
    the linkage check may not be dropped in exchange for them.
    """
    await _reset_chain()
    org_a = await _org_id("Audit Chain MT Org A")
    try:
        await _append_as(org_a, "f1")
        await _append_as(org_a, "f2")
        assert (await _verify())["ok"] is True

        async with session_scope() as s:
            first = (
                await s.execute(select(AuditLog).where(AuditLog.entity_id == "f1"))
            ).scalar_one()
            content = {
                "actor": "forger@audit-chain-mt.test",
                "action": "create",
                "entity_type": _ENTITY,
                "entity_id": "forged",
                "diff": {"tag": "forged"},
            }
            # Chains onto the FIRST row, not the head — a fork, self-consistently hashed.
            s.add(
                AuditLog(
                    **content,
                    organization_id=org_a,
                    prev_hash=first.row_hash,
                    row_hash=row_hash(first.row_hash or _GENESIS, content),
                )
            )

        async with session_scope() as s:
            forged = (
                await s.execute(select(AuditLog).where(AuditLog.entity_id == "forged"))
            ).scalar_one()
            recomputed = row_hash(
                forged.prev_hash or _GENESIS,
                {
                    "actor": forged.actor,
                    "action": forged.action,
                    "entity_type": forged.entity_type,
                    "entity_id": forged.entity_id,
                    "diff": forged.diff,
                },
            )
            assert forged.row_hash == recomputed, (
                "the forged row must hash itself correctly, or this test is just "
                "the content-mutation test again"
            )
            forged_id = forged.id

        verdict = await _verify()
        assert verdict["ok"] is False, "a forged, self-consistent fork went undetected"
        assert verdict["broken_at_id"] == forged_id
    finally:
        await _reset_chain()


@pytest.mark.asyncio
async def test_recording_an_event_leaves_the_caller_session_still_clamped() -> None:
    """``unscoped_read`` must hand the session back scoped exactly as it found it.

    ``record_event`` suspends the RLS clamp to read the global chain head. The
    session it does that to is the *caller's*, and the caller keeps using it
    after the audit row is written -- so a suspension that is not restored
    would turn the rest of the request into an unscoped, cross-tenant session.
    Asserted by effect rather than by reading the GUC back: after recording,
    an org A session must still be unable to see org B's audit row.
    """
    await _reset_chain()
    org_a = await _org_id("Audit Chain MT Org A")
    org_b = await _org_id("Audit Chain MT Org B")
    try:
        await _append_via_middleware(org_b, 2)

        factory = get_session_factory()
        async with factory() as s:
            await set_session_tenant(s, org_a)
            visible_before = (
                await s.execute(
                    select(AuditLog.id).where(AuditLog.entity_type == _MW_ENTITY)
                )
            ).scalars().all()
            assert visible_before == [], (
                "org B's row must be invisible to an org A session to begin with, "
                "or this test cannot show anything"
            )

            await record_event(
                s,
                actor="clamp@audit-chain-mt.test",
                action="create",
                entity_type=_ENTITY,
                entity_id="clamp",
                diff={"tag": "clamp"},
            )

            visible_after = (
                await s.execute(
                    select(AuditLog.id).where(AuditLog.entity_type == _MW_ENTITY)
                )
            ).scalars().all()
            assert visible_after == [], (
                "the RLS tenant clamp was not restored after the chain-head read"
            )
            await s.commit()
    finally:
        await _reset_chain()
