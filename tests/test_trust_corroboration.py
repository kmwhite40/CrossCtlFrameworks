"""The Trust Center says what it can back — and never edits what was typed.

``framework_badges`` is operator-typed JSONB that nothing corroborated. The
measured reality is why this annotates rather than derives: every one of the 14
systems on the dev catalog carries ``ato_status='none'`` and the one existing
badge reads ``{"framework": "CMMC L2", "status": "In progress"}``, so a derived
Trust Center would render nothing at all.

What this file pins, per ``docs/superpowers/specs/2026-09-22-trust-corroboration-design.md`` §6:

* the over-claim -- "Authorized" with no authorized system -- is ``contradicted``;
* ``unsupported`` reads as *absence of a platform record*, never as doubt about
  the claim, with the exact phrasing pinned (§2.1: on a page about an
  organization's security posture, absence of evidence rendered as evidence of
  absence is defamatory, not merely imprecise);
* a genuinely authorized system corroborates;
* a lapsed authorization is reported even with no badge to attach it to;
* the stored JSONB is **byte-identical** before and after a render;
* the export carries the same states as the page, field for field;
* another tenant's systems never corroborate this one's badges.

Two harness notes, both of which have silently produced false passes here
before:

* Rendering and export assertions run under **real auth** with role-bearing
  principals. With auth disabled every request is ``SYSTEM_PRINCIPAL``
  (``is_global``, ``org_id=None``), which short-circuits ``require_role`` and
  leaves every query unscoped -- a page test written that way renders every
  tenant's rows and proves nothing about scoping.
* The tenant-isolation test runs on an **unscoped** ``session_scope()``, not
  over HTTP. ``get_session`` binds the RLS tenant, so an HTTP-only test cannot
  tell an explicit ``organization_id`` predicate from RLS doing the work; it
  first asserts the other tenant's rows *are* visible without the predicate,
  so the isolation it then asserts is the module's own.

This file seeds no ``Control`` rows, so it needs no private identifier
namespace; it deletes the organizations it creates in ``finally``.
"""

from __future__ import annotations

import itertools
import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from markupsafe import escape
from sqlalchemy import delete, select, text

from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.governance.trust_corroboration import (
    CONTRADICTED,
    CORROBORATED,
    LOOSE_MATCH_NOTE,
    STATE_LABELS,
    UNSUPPORTED,
    UNSUPPORTED_DETAIL,
    classify_claim,
    corroborate_badges,
)
from ccf.models import Organization, System, User
from ccf.models_grc import TrustProfile
from ccf.models_packages import AuthorizationPackage

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count(1)

#: Words that turn "the platform holds no record" into "we doubt you". §2.1
#: bans them by name; the rest are the near neighbours a later edit would
#: reach for. None of them may appear anywhere on the rendered page.
DOUBT_WORDS = (
    "unverified",
    "unconfirmed",
    "unsubstantiated",
    "unproven",
    "questionable",
    "dubious",
    "disputed",
    "doubt",
    "allegedly",
    "purported",
    "not verified",
    "cannot verify",
    "could not verify",
    "no evidence",
)


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _auth_enabled() -> Iterator[None]:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _today() -> datetime:
    return datetime.now(UTC)


async def _seed(
    *,
    tag: int,
    badges: list[dict[str, str]] | None = None,
    systems: tuple[tuple[str, int | None], ...] = (),
    packages: int = 0,
) -> tuple[int, str, int]:
    """One org + admin + trust profile + systems. Returns ``(org_id, token, profile_id)``.

    ``systems`` is ``(ato_status, days_until_expiry_or_None)`` per system;
    ``ato_expires_on`` is ``None`` when the offset is ``None``.
    """
    async with session_scope() as s:
        org = Organization(name=f"Corroboration Org {tag}")
        s.add(org)
        await s.flush()
        first_system: int | None = None
        for i, (status, offset) in enumerate(systems):
            row = System(
                organization_id=org.id,
                name=f"Corroboration Sys {tag}-{i}",
                ato_status=status,
                ato_expires_on=(
                    None if offset is None else (_today() + timedelta(days=offset)).date()
                ),
            )
            s.add(row)
            await s.flush()
            first_system = first_system or row.id
        for p in range(packages):
            s.add(
                AuthorizationPackage(
                    organization_id=org.id,
                    system_id=first_system,
                    label=f"Corroboration Pkg {tag}-{p}",
                )
            )
        profile = TrustProfile(organization_id=org.id, framework_badges=badges or [])
        s.add(profile)
        user = User(
            email=f"admin-corrob-{tag}@trust-corroboration.test",
            organization_id=org.id,
            role="admin",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        await s.flush()
        return org.id, user.api_token, profile.id


async def _cleanup(*org_ids: int) -> None:
    async with session_scope() as s:
        await s.execute(delete(Organization).where(Organization.id.in_(org_ids)))


async def _raw_badges(profile_id: int) -> str:
    """The stored JSONB exactly as Postgres holds it, as text.

    ``::text`` on a ``jsonb`` column renders the server's own normalized
    representation, so two reads differ if and only if the stored value
    changed -- which is the claim §6.5 makes.
    """
    async with session_scope() as s:
        return str(
            (
                await s.execute(
                    text("SELECT framework_badges::text FROM ccf.trust_profiles WHERE id = :i"),
                    {"i": profile_id},
                )
            ).scalar_one()
        )


def _esc(s: str) -> str:
    """Jinja autoescapes, so the apostrophe in "organization's" is ``&#39;``
    on the page. Compare against what a browser is actually served."""
    return str(escape(s))


# ── §6.1 the case the feature exists for ────────────────────────────────────


@pytest.mark.asyncio
async def test_authorized_badge_with_no_authorized_system_is_contradicted() -> None:
    """A badge claiming "Authorized" over systems Concord records as
    unauthorized is ``contradicted`` -- the one state an operator must act on.

    Seeded to match the measured platform: two systems, both ``ato_status='none'``,
    which is what all 14 systems on the dev catalog carry today.
    """
    tag = next(_SEQ)
    org, token, _pid = await _seed(
        tag=tag,
        badges=[{"framework": "FedRAMP Moderate", "status": "Authorized"}],
        systems=(("none", None), ("none", None)),
    )
    try:
        async with session_scope() as s:
            result = await corroborate_badges(
                s, [{"framework": "FedRAMP Moderate", "status": "Authorized"}], org_id=org
            )
        assert [b.state for b in result.badges] == [CONTRADICTED]
        assert result.badges[0].label == "does not match platform records"
        print("§6.1 state:", result.badges[0].state)
        print("§6.1 label:", result.badges[0].label)
        print("§6.1 detail:", result.badges[0].detail)

        async with _client() as c:
            page = await c.get("/trust", headers=_auth(token))
        assert page.status_code == 200, page.text
        # The operator's own words survive, unedited, beside the state.
        assert "FedRAMP Moderate" in page.text
        assert "Authorized" in page.text
        assert _esc(result.badges[0].detail) in page.text
    finally:
        await _cleanup(org)


# ── §6.2 unsupported is absence of record, not doubt ────────────────────────


@pytest.mark.asyncio
async def test_unsupported_reads_as_absence_of_record_not_doubt() -> None:
    """The common case, and the one that must not read as suspicion.

    The badge text is deliberately neutral ("CMMC L2" / "In progress", the
    real one on the dev catalog) so neither the phrasing being asserted nor
    any banned word can arrive from the fixture rather than from the code.
    """
    tag = next(_SEQ)
    org, token, _pid = await _seed(
        tag=tag,
        badges=[{"framework": "CMMC L2", "status": "In progress"}],
        systems=(("none", None),),
    )
    try:
        async with session_scope() as s:
            result = await corroborate_badges(
                s, [{"framework": "CMMC L2", "status": "In progress"}], org_id=org
            )
        assert [b.state for b in result.badges] == [UNSUPPORTED]
        assert result.badges[0].detail == UNSUPPORTED_DETAIL
        assert result.badges[0].label == "no record in Concord"

        async with _client() as c:
            page = await c.get("/trust", headers=_auth(token))
        assert page.status_code == 200, page.text

        # The exact phrasing, pinned. It names Concord's records as the
        # subject; it does not characterise the operator's claim.
        assert _esc(UNSUPPORTED_DETAIL) in page.text
        assert "Concord holds no authorization record" in page.text
        assert _esc(LOOSE_MATCH_NOTE) in page.text

        lowered = page.text.lower()
        for word in DOUBT_WORDS:
            assert word not in lowered, f"{word!r} renders absence of record as doubt"
        # and none of the authored strings contains one either
        for authored in (*STATE_LABELS.values(), UNSUPPORTED_DETAIL, LOOSE_MATCH_NOTE):
            for word in DOUBT_WORDS:
                assert word not in authored.lower(), f"{word!r} in {authored!r}"
    finally:
        await _cleanup(org)


@pytest.mark.asyncio
async def test_loose_framework_match_is_stated_not_implied() -> None:
    """§3: nothing stores a framework per system, so the match is on the org's
    systems as a whole -- and the rendered text has to say so rather than
    implying a precision the data does not have.

    The badge names a framework the platform has never heard of; the state is
    still produced, and the note that explains why is on the page.
    """
    tag = next(_SEQ)
    org, token, _pid = await _seed(
        tag=tag,
        badges=[{"framework": "ISO 27001", "status": "Certified"}],
        systems=(("authorized", 400),),
    )
    try:
        async with _client() as c:
            page = await c.get("/trust", headers=_auth(token))
        assert page.status_code == 200, page.text
        assert _esc(LOOSE_MATCH_NOTE) in page.text
        assert "not against the framework named on each badge" in page.text
    finally:
        await _cleanup(org)


# ── §6.3 corroborated ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_authorized_system_with_future_expiry_corroborates() -> None:
    tag = next(_SEQ)
    org, token, _pid = await _seed(
        tag=tag,
        badges=[{"framework": "FedRAMP Moderate", "status": "Authorized"}],
        systems=(("authorized", 365), ("none", None)),
    )
    try:
        async with session_scope() as s:
            result = await corroborate_badges(
                s, [{"framework": "FedRAMP Moderate", "status": "Authorized"}], org_id=org
            )
        assert [b.state for b in result.badges] == [CORROBORATED]
        assert result.badges[0].label == "supported by platform records"

        async with _client() as c:
            page = await c.get("/trust", headers=_auth(token))
        assert page.status_code == 200, page.text
        assert _esc(result.badges[0].detail) in page.text
    finally:
        await _cleanup(org)


@pytest.mark.asyncio
async def test_in_progress_is_corroborated_by_an_authorization_package() -> None:
    """§3's second corroborator: an ``AuthorizationPackage`` for a system in
    this org backs an "in progress" claim even with no system at
    ``ato_status='in_progress'``."""
    tag = next(_SEQ)
    org, _token, _pid = await _seed(
        tag=tag,
        badges=[{"framework": "FedRAMP Moderate", "status": "In progress"}],
        systems=(("none", None),),
        packages=1,
    )
    try:
        async with session_scope() as s:
            result = await corroborate_badges(
                s, [{"framework": "FedRAMP Moderate", "status": "In progress"}], org_id=org
            )
        assert [b.state for b in result.badges] == [CORROBORATED]
        assert "authorization package" in result.badges[0].detail
    finally:
        await _cleanup(org)


@pytest.mark.asyncio
async def test_in_progress_is_never_contradicted() -> None:
    """§2.2 makes the over-claim the only actionable state. An organization
    can be pursuing an authorization Concord has not been told about, so an
    "in progress" badge over unauthorized systems is silence, not disagreement
    -- this is why "nearly every badge will be unsupported" (§2.1) and not
    "nearly every badge will be contradicted"."""
    tag = next(_SEQ)
    org, _token, _pid = await _seed(tag=tag, systems=(("none", None), ("expired", -30)))
    try:
        async with session_scope() as s:
            result = await corroborate_badges(
                s, [{"framework": "CMMC L2", "status": "In progress"}], org_id=org
            )
        assert [b.state for b in result.badges] == [UNSUPPORTED]
    finally:
        await _cleanup(org)


@pytest.mark.asyncio
async def test_organization_with_no_systems_is_unsupported_not_contradicted() -> None:
    """The guard that keeps ``contradicted`` honest (§2.1).

    ``contradicted`` means "platform data says something different", which
    requires platform data. A tenant that has told Concord about no systems at
    all must read as ``unsupported``; reporting "does not match platform
    records" from an empty table is the same absence-as-evidence defect the
    ``unsupported`` wording exists to avoid, aimed at the strongest claim.
    """
    tag = next(_SEQ)
    org, _token, _pid = await _seed(tag=tag, systems=())
    try:
        async with session_scope() as s:
            result = await corroborate_badges(
                s, [{"framework": "FedRAMP High", "status": "Authorized"}], org_id=org
            )
        assert [b.state for b in result.badges] == [UNSUPPORTED]
        assert result.badges[0].detail == UNSUPPORTED_DETAIL
    finally:
        await _cleanup(org)


# ── §6.4 an expired ATO is reported with no badge at all ────────────────────


@pytest.mark.asyncio
async def test_expired_ato_is_reported_with_no_badge_present() -> None:
    """The single fact a trust page most needs to not omit, on the page where
    it would most easily be lost: one with no badges to attach it to."""
    tag = next(_SEQ)
    org, token, _pid = await _seed(tag=tag, badges=[], systems=(("expired", -45),))
    try:
        async with session_scope() as s:
            result = await corroborate_badges(s, [], org_id=org)
        assert result.badges == ()
        notice = result.expiry_notice
        assert notice is not None
        assert "lapsed authorization" in notice
        assert f"Corroboration Sys {tag}-0" in notice

        async with _client() as c:
            page = await c.get("/trust", headers=_auth(token))
        assert page.status_code == 200, page.text
        assert "No framework badges yet" in page.text  # genuinely badge-less
        assert _esc(notice) in page.text
    finally:
        await _cleanup(org)


@pytest.mark.asyncio
async def test_expired_badge_is_corroborated_by_a_lapsed_system() -> None:
    """The third row of §3's table: a badge that says the authorization has
    lapsed, over a system Concord records as lapsed, is supported."""
    tag = next(_SEQ)
    org, _token, _pid = await _seed(tag=tag, systems=(("expired", -30), ("none", None)))
    try:
        async with session_scope() as s:
            result = await corroborate_badges(
                s, [{"framework": "FedRAMP Moderate", "status": "Expired"}], org_id=org
            )
        assert [b.state for b in result.badges] == [CORROBORATED]
        assert "lapsed authorization" in result.badges[0].detail
    finally:
        await _cleanup(org)


@pytest.mark.asyncio
async def test_authorized_badge_over_a_lapsed_expiry_is_contradicted() -> None:
    """§3: the expiry is what decides it, not the status column alone."""
    tag = next(_SEQ)
    org, _token, _pid = await _seed(tag=tag, systems=(("authorized", -1),))
    try:
        async with session_scope() as s:
            result = await corroborate_badges(
                s, [{"framework": "FedRAMP Moderate", "status": "Authorized"}], org_id=org
            )
        assert [b.state for b in result.badges] == [CONTRADICTED]
        assert result.expiry_notice is not None
    finally:
        await _cleanup(org)


@pytest.mark.asyncio
async def test_authorized_with_no_expiry_on_file_is_not_a_lapse() -> None:
    """An authorization Concord records with no expiry date is still an
    authorization on file. §3 reads "expiry in the future"; taken literally
    that reports Concord's own record as disagreeing with the badge it
    supports, which is the one thing ``contradicted`` must never do."""
    tag = next(_SEQ)
    org, _token, _pid = await _seed(tag=tag, systems=(("authorized", None),))
    try:
        async with session_scope() as s:
            result = await corroborate_badges(
                s, [{"framework": "FedRAMP Moderate", "status": "Authorized"}], org_id=org
            )
        assert [b.state for b in result.badges] == [CORROBORATED]
        assert result.expiry_notice is None
    finally:
        await _cleanup(org)


# ── §6.5 the operator's claim is never touched ──────────────────────────────


@pytest.mark.asyncio
async def test_stored_badges_are_byte_identical_after_rendering() -> None:
    """No badge is dropped, edited, re-cased, re-keyed or reordered.

    The badges are deliberately awkward: mixed case, extra keys, a duplicate
    framework, and an entry whose status this module cannot classify. All of
    it must come back out of Postgres unchanged, and all of it must still be
    on the page in the order it was typed.
    """
    tag = next(_SEQ)
    badges = [
        {"framework": "CMMC L2", "status": "In progress", "note": f"typed by hand {tag}"},
        {"framework": "FedRAMP Moderate", "status": "AUTHORIZED"},
        {"framework": "CMMC L2", "status": "something the platform cannot read"},
        {"framework": "SOC 2 Type II", "status": "Attested"},
    ]
    org, token, pid = await _seed(tag=tag, badges=badges, systems=(("none", None),))
    try:
        before = await _raw_badges(pid)
        async with _client() as c:
            page = await c.get("/trust", headers=_auth(token))
            pkg = await c.get("/api/trust/package?fmt=json", headers=_auth(token))
        assert page.status_code == 200, page.text
        assert pkg.status_code == 200, pkg.text
        after = await _raw_badges(pid)
        assert after == before, "rendering mutated the operator's stored claim"

        # nothing dropped, nothing reordered
        rendered = pkg.json()["corroboration"]["badges"]
        assert [(b["framework"], b["status"]) for b in rendered] == [
            (b["framework"], b["status"]) for b in badges
        ]
        assert page.text.index("SOC 2 Type II") > page.text.index("FedRAMP Moderate")
        # the unreadable status is still shown, verbatim, and simply unsupported
        assert "something the platform cannot read" in page.text
        assert rendered[2]["state"] == UNSUPPORTED
    finally:
        await _cleanup(org)


# ── §6.6 the artifact cannot claim more than the screen ─────────────────────


@pytest.mark.asyncio
async def test_export_carries_the_same_states_as_the_page() -> None:
    """Compared both ways: the JSON export's states come from the same service
    the page renders, and every label and detail it carries is on the page."""
    tag = next(_SEQ)
    badges = [
        {"framework": "FedRAMP Moderate", "status": "Authorized"},
        {"framework": "CMMC L2", "status": "In progress"},
    ]
    org, token, _pid = await _seed(
        tag=tag, badges=badges, systems=(("none", None), ("expired", -10))
    )
    try:
        async with session_scope() as s:
            expected = await corroborate_badges(s, badges, org_id=org)

        async with _client() as c:
            page = await c.get("/trust", headers=_auth(token))
            js = await c.get("/api/trust/package?fmt=json", headers=_auth(token))
            md = await c.get("/api/trust/package?fmt=md", headers=_auth(token))
        assert page.status_code == 200, page.text
        assert js.status_code == 200, js.text
        assert md.status_code == 200, md.text

        exported = js.json()["corroboration"]
        assert exported == expected.as_export()
        assert [b["state"] for b in exported["badges"]] == [CONTRADICTED, UNSUPPORTED]

        # Every assertion below must be non-vacuous: ``"" in page.text`` is
        # true, so an export that quietly carried empty details would satisfy
        # a bare containment check *and* the equality above, since both sides
        # come from the same service. Mutating ``"detail": b.detail`` to
        # ``""`` survived until these emptiness and value pins were added.
        details = {b["state"]: b["detail"] for b in exported["badges"]}
        assert details[UNSUPPORTED] == UNSUPPORTED_DETAIL
        assert "Record the authorization, or correct the badge." in details[CONTRADICTED]
        for b in exported["badges"]:
            assert b["detail"], b
            assert b["label"] == STATE_LABELS[b["state"]], b
            assert _esc(b["label"]) in page.text, b
            assert _esc(b["detail"]) in page.text, b
            assert b["label"] in md.text, b
            assert b["detail"] in md.text, b
        assert exported["expiry_notice"] is not None
        assert _esc(exported["expiry_notice"]) in page.text
        assert exported["expiry_notice"] in md.text
        assert exported["note"] == LOOSE_MATCH_NOTE
        assert exported["note"] in md.text
    finally:
        await _cleanup(org)


# ── §6.7 tenant isolation, on an unscoped session ───────────────────────────


@pytest.mark.asyncio
async def test_another_tenants_authorized_system_never_corroborates() -> None:
    """Pinned on ``session_scope()``, which sets the RLS tenant to ``None``.

    Under ``get_session`` the RLS policy would hide the other tenant's rows
    whether or not this module carries an ``organization_id`` predicate, so
    the test would pass with the predicate deleted. The first assertion proves
    the other tenant's authorized system *is* reachable on this session; only
    then does the second assertion mean anything.
    """
    tag = next(_SEQ)
    other, _t2, _p2 = await _seed(
        tag=tag * 1000 + 1, systems=(("authorized", 365), ("in_progress", None)), packages=1
    )
    mine, _t1, _p1 = await _seed(tag=tag * 1000 + 2, systems=(("none", None),))
    badge = [{"framework": "FedRAMP Moderate", "status": "Authorized"}]
    try:
        async with session_scope() as s:
            visible = (
                (
                    await s.execute(
                        select(System.id).where(
                            System.organization_id == other, System.ato_status == "authorized"
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert visible, "unscoped session cannot see the other tenant — test proves nothing"

            mine_result = await corroborate_badges(s, badge, org_id=mine)
            other_result = await corroborate_badges(s, badge, org_id=other)

        assert [b.state for b in other_result.badges] == [CORROBORATED]
        assert [b.state for b in mine_result.badges] == [CONTRADICTED]
        # Every signal the module reads is scoped, not just ato_status: an
        # AuthorizationPackage belonging to another tenant must not back an
        # "in progress" claim here either.
        assert mine_result.facts.authorized_current == 0
        assert mine_result.facts.in_progress == 0
        assert mine_result.facts.packages == 0
        assert mine_result.facts.system_count == 1
        assert other_result.facts.packages == 1
    finally:
        await _cleanup(other, mine)


# ── the claim reader ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("status", "claim"),
    [
        ("Authorized", "authorized"),
        ("CERTIFIED", "authorized"),
        ("Accredited", "authorized"),
        ("In progress", "in_progress"),
        ("in-progress", "in_progress"),
        ("Expired", "expired"),
        ("Authorization expired", "expired"),  # expiry wins over "authoriz"
        ("", None),
        (None, None),
        ("Attested", None),
    ],
)
def test_classify_claim(status: str | None, claim: str | None) -> None:
    assert classify_claim(status) == claim


@pytest.mark.asyncio
async def test_a_non_dict_badge_row_is_skipped_not_raised() -> None:
    """``framework_badges`` is free JSONB an operator can put anything in, and
    a render is not the place to fail over it."""
    tag = next(_SEQ)
    badges = ["not a badge at all", {"framework": "CMMC L2", "status": "In progress"}]
    org, token, pid = await _seed(tag=tag, badges=badges, systems=(("none", None),))
    try:
        before = await _raw_badges(pid)
        async with _client() as c:
            page = await c.get("/trust", headers=_auth(token))
        assert page.status_code == 200, page.text
        assert await _raw_badges(pid) == before
        async with session_scope() as s:
            result = await corroborate_badges(s, badges, org_id=org)
        assert [b.framework for b in result.badges] == ["CMMC L2"]
    finally:
        await _cleanup(org)
