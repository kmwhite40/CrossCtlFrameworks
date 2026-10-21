"""Workstream H -- control effectiveness, evidence mapping, evidence expiration,
the integrations hub (spec 2026-10-20-grc-buildout-design.md, section H).

What is pinned, each the shape of a defect this platform has shipped:

* **Isolation is in the query.** Every page is driven over an RLS-bypass
  session (``_unscoped_session``), both ways round: Alpha never sees Bravo's
  records and sees its own, and the same for Bravo.
* **The rating rule.** Each of the three outcomes, from the pure rule and from
  the service over real rows; absence of data is never ``effective``.
* **Renewal is deduplicated** and the task stays in the caller's organization,
  assigned only to a user of that organization.
* **Webhooks** are created through the API's own writer, admin only, and the
  secret is never rendered.
"""

from __future__ import annotations

import itertools
import os
from datetime import UTC, date, datetime, timedelta

import pytest
from alembic import command
from alembic.config import Config
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select

from ccf.analytics import assurance_views as av
from ccf.api.deps import get_session
from ccf.api.main import create_app
from ccf.api.routes import events, ui_assure
from ccf.auth import SYSTEM_PRINCIPAL, hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import get_session_factory, session_scope, set_session_tenant
from ccf.models import (
    Control,
    ControlImplementation,
    Evidence,
    FrameworkMapping,
    Organization,
    System,
    Task,
    User,
    Webhook,
)
from ccf.models_evidence import EvidenceObject
from ccf.models_grc import (
    AuditEngagement,
    ConnectorConfig,
    ControlTest,
    ControlTestResult,
    ExternalIssueLink,
)
from ccf.models_identity import GroupRoleMapping, IdentityProvider
from ccf.models_program import AuditWorkpaper, CompensatingControl
from ccf.models_waivers import Waiver

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count(1)
ROLES = ("admin", "control_owner", "assessor", "viewer")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def _auth_enabled():
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


async def _unscoped_session():
    """RLS tenant cleared, so only the page's own org predicate can keep the
    other organization's rows off it."""
    factory = get_session_factory()
    async with factory() as session:
        await set_session_tenant(session, None)
        yield session


def _client() -> AsyncClient:
    app = create_app()
    app.dependency_overrides[get_session] = _unscoped_session
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://t")


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _test_and_result(org_id: int, system_id: int, control: str, name: str, status: str, **kw):
    t = ControlTest(
        organization_id=org_id,
        system_id=system_id,
        control_id=control,
        name=name,
        method=kw.pop("method", "connector"),
        source="generated",
        check_key=f"h.{name}",
        last_status=status,
        active=kw.pop("active", True),
    )
    r = ControlTestResult(
        status=status,
        run_at=datetime.now(UTC),
        evaluated=kw.pop("evaluated", 1),
        failing=int(status == "fail"),
    )
    t.results.append(r)
    return t


async def _org(label: str, tag: str, n: int) -> dict[str, object]:
    """One organization; every record named ``<label>-<kind>-<tag>``, and a
    soft-deleted system carrying records named ``<label>-DELETED-...``."""
    today = date.today()
    m = lambda kind: f"{label}-{kind}-{tag}"  # noqa: E731
    ctl = [f"QX-{n * 10 + k}" for k in range(1, 4)]
    async with session_scope() as s:
        org = Organization(name=m("org"))
        s.add(org)
        await s.flush()
        users = {}
        for role in ROLES:
            users[role] = User(
                email=f"{label.lower()}-{role}-{tag}@as.test",
                organization_id=org.id,
                role=role,
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
        live = System(organization_id=org.id, name=m("system"), baseline="moderate")
        gone = System(
            organization_id=org.id,
            name=f"{label}-DELETED-system-{tag}",
            baseline="moderate",
            deleted_at=datetime.now(UTC),
        )
        s.add_all([*users.values(), live, gone])
        await s.flush()
        s.add_all(
            [
                _test_and_result(org.id, live.id, ctl[0], m("test"), "pass"),
                _test_and_result(org.id, gone.id, ctl[0], f"{label}-DELETED-test-{tag}", "fail"),
                CompensatingControl(
                    organization_id=org.id,
                    system_id=live.id,
                    control_identifier=ctl[1],
                    measure=m("measure"),
                    rationale="r",
                    status="approved",
                    proposed_by="p@x",
                    decided_by="d@x",
                ),
            ]
        )
        eng = AuditEngagement(organization_id=org.id, name=m("audit"), status="fieldwork")
        s.add(eng)
        await s.flush()
        s.add(
            AuditWorkpaper(
                organization_id=org.id,
                engagement_id=eng.id,
                title=m("workpaper"),
                control_id=ctl[2],
                conclusion="effective",
                status="final",
                prepared_by="p@x",
                reviewed_by="r@x",
                reviewed_at=datetime.now(UTC),
            )
        )
        control = Control(identifier=ctl[0])
        s.add(control)
        await s.flush()
        impl = ControlImplementation(system_id=live.id, control_id=control.id, status="implemented")
        gone_impl = ControlImplementation(
            system_id=gone.id, control_id=control.id, status="implemented"
        )
        s.add_all([impl, gone_impl])
        await s.flush()
        expiring = EvidenceObject(
            organization_id=org.id,
            title=m("expiring"),
            system_id=live.id,
            control_id=ctl[0],
            owner=users["admin"].email,
            status="approved",
            expires_on=today + timedelta(days=10),
        )
        orgwide = EvidenceObject(
            organization_id=org.id,
            title=m("orgwide-expired"),
            status="approved",
            expires_on=today - timedelta(days=5),
        )
        on_gone = EvidenceObject(
            organization_id=org.id,
            title=f"{label}-DELETED-evidence-{tag}",
            system_id=gone.id,
            control_id=ctl[0],
            expires_on=today + timedelta(days=5),
        )
        s.add_all(
            [
                expiring,
                orgwide,
                on_gone,
                Evidence(implementation_id=impl.id, kind="document", title=m("legacy")),
                Evidence(
                    implementation_id=gone_impl.id,
                    kind="document",
                    title=f"{label}-DELETED-legacy-{tag}",
                ),
                Webhook(
                    organization_id=org.id,
                    url=f"https://{label}-hook-{tag}.example/x",
                    secret=f"SECRET-{label}-{tag}",
                    events=["created"],
                    active=True,
                ),
                ConnectorConfig(
                    organization_id=org.id,
                    name=m("connector"),
                    connector_type="aws",
                    status="configured",
                ),
                ExternalIssueLink(
                    organization_id=org.id,
                    entity_type="poam",
                    entity_id=n * 100 + len(label),
                    provider="jira" if label == "Alpha" else "emass",
                    external_id=m("ticket")[:64],
                    external_url="https://tracker.example/x",
                ),
            ]
        )
        if label == "Bravo":
            s.add_all(
                [
                    IdentityProvider(organization_id=org.id, name=m("idp"), issuer="https://i"),
                    GroupRoleMapping(organization_id=org.id, group=m("group"), role="viewer"),
                ]
            )
        await s.flush()
        return {
            "org_id": org.id,
            "label": label,
            "tag": tag,
            "system_id": live.id,
            "gone_id": gone.id,
            "controls": ctl,
            "tokens": {r: u.api_token for r, u in users.items()},
            "user_ids": {r: u.id for r, u in users.items()},
            "emails": {r: u.email for r, u in users.items()},
            "expiring_id": expiring.id,
            "orgwide_id": orgwide.id,
            "gone_evidence_id": on_gone.id,
        }


@pytest.fixture
async def two_orgs() -> tuple[dict[str, object], dict[str, object]]:
    n = next(_SEQ)
    tag = f"as{n}x{os.getpid()}{os.urandom(2).hex()}"
    return await _org("Alpha", tag, n), await _org("Bravo", tag, n + 50)


def _tok(org: dict[str, object], role: str = "admin") -> dict[str, str]:
    return _auth(org["tokens"][role])  # type: ignore[index]


# ── isolation, both ways, on the RLS-bypass session ──────────────────────────

OWN = {
    "/controls/effectiveness": ("test", "measure", "workpaper"),
    "/evidence/mapping": ("expiring", "legacy", "orgwide-expired"),
    "/evidence/expiration": ("expiring", "orgwide-expired"),
    "/integrations": ("connector",),
}


@pytest.mark.parametrize("path", sorted(OWN))
@pytest.mark.parametrize("caller", [0, 1])
async def test_each_page_shows_its_own_records_and_never_the_others(
    two_orgs, path: str, caller: int
) -> None:
    me, other = two_orgs[caller], two_orgs[1 - caller]
    async with _client() as c:
        resp = await c.get(path, headers=_tok(me, "viewer"))
    assert resp.status_code == 200, resp.text[:400]
    body = resp.text
    assert str(other["label"]) not in body, f"{path} shows {other['label']}'s records"
    assert "DELETED" not in body, f"{path} shows a soft-deleted system's records"
    for kind in OWN[path]:
        assert f"{me['label']}-{kind}-{me['tag']}" in body, f"{path} lacks own {kind}"
    if path == "/integrations":
        assert f"https://{me['label']}-hook-{me['tag']}.example/x" in body


async def test_the_integrations_counts_are_the_callers_own(two_orgs) -> None:
    a, b = two_orgs
    async with session_scope() as s:
        await set_session_tenant(s, None)
        hub_a = await av.integrations_hub(s, int(a["org_id"]))
        hub_b = await av.integrations_hub(s, int(b["org_id"]))
    assert [x["provider"] for x in hub_a["issue_links"]] == ["jira"]
    assert [x["provider"] for x in hub_b["issue_links"]] == ["emass"]
    assert (hub_a["sso"]["idp_records"], hub_a["sso"]["group_mappings"]) == (0, 0)
    assert (hub_b["sso"]["idp_records"], hub_b["sso"]["group_mappings"]) == (1, 1)
    assert len(hub_a["webhooks"]) == 1 and len(hub_a["connectors"]) == 1


async def test_no_organization_in_scope_is_an_empty_page_not_every_tenant() -> None:
    async with session_scope() as s:
        for view in (
            await av.control_effectiveness(s, None),
            await av.evidence_mapping(s, None),
            await av.evidence_expiration(s, None),
            await av.integrations_hub(s, None),
        ):
            assert view["scoped"] is False


async def test_the_effectiveness_route_is_not_swallowed_by_control_detail(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        body = (await c.get("/controls/effectiveness", headers=_tok(a))).text
    assert "The rating rule" in body


# ── the rating rule ──────────────────────────────────────────────────────────

P, F, W = "pass", "fail", "warn"


@pytest.mark.parametrize(
    ("outcomes", "conclusion", "expected"),
    [
        ([], None, av.NOT_DETERMINED),
        # An auditor's "effective" alone is not a latest passing test.
        ([], "effective", av.NOT_DETERMINED),
        ([av.Outcome(P)], None, av.EFFECTIVE),
        ([av.Outcome(P), av.Outcome(P)], "effective", av.EFFECTIVE),
        ([av.Outcome(P), av.Outcome(W)], None, av.NOT_DETERMINED),
        ([av.Outcome("manual_review_required")], None, av.NOT_DETERMINED),
        ([av.Outcome(F)], None, av.INEFFECTIVE),
        ([av.Outcome(P), av.Outcome(F)], None, av.INEFFECTIVE),
        ([av.Outcome(F, accepted=True)], None, av.NOT_DETERMINED),
        ([av.Outcome(P), av.Outcome(F, accepted=True)], None, av.NOT_DETERMINED),
        ([av.Outcome(P)], "ineffective", av.INEFFECTIVE),
        ([], "ineffective", av.INEFFECTIVE),
        ([av.Outcome(P)], "not_tested", av.EFFECTIVE),
    ],
)
def test_the_rating_rule(outcomes, conclusion, expected) -> None:
    assert av.rate(outcomes, conclusion) == expected


async def test_the_service_rates_each_outcome_from_real_rows(two_orgs) -> None:
    a, _ = two_orgs
    org, sid = int(a["org_id"]), int(a["system_id"])
    base = int(str(a["controls"][0]).split("-")[1]) + 3  # beyond the fixture's three
    c = {k: f"QX-{base + i}" for i, k in enumerate("abcdefghijkl")}
    async with session_scope() as s:
        s.add_all(
            [
                _test_and_result(org, sid, c["a"], f"t-a-{base}", "pass"),
                _test_and_result(org, sid, c["b"], f"t-b-{base}", "fail"),
                _test_and_result(org, sid, c["c"], f"t-c-{base}", "fail"),
                _test_and_result(org, sid, c["d"], f"t-d-{base}", "pass"),
                _test_and_result(org, sid, c["f"], f"t-f-{base}", "warn"),
                _test_and_result(org, sid, c["g"], f"t-g-{base}", "fail"),
                # An empty collection (nothing evaluated) is not a result.
                _test_and_result(org, sid, c["h"], f"t-h-{base}", "pass", evaluated=0),
                _test_and_result(org, sid, c["i"], f"t-i-{base}", "fail"),
                _test_and_result(org, sid, c["j"], f"t-j-{base}", "fail"),
                # A person's manual record and a retired test are not automated outcomes.
                _test_and_result(org, sid, c["k"], f"t-k-{base}", "pass", method="manual"),
                _test_and_result(org, sid, c["l"], f"t-l-{base}", "pass", active=False),
                # Neither a proposal nor a lapsed approval accepts a failure.
                CompensatingControl(
                    organization_id=org,
                    system_id=sid,
                    control_identifier=c["i"],
                    measure="m",
                    rationale="r",
                    status="proposed",
                ),
                CompensatingControl(
                    organization_id=org,
                    system_id=sid,
                    control_identifier=c["j"],
                    measure="m",
                    rationale="r",
                    status="approved",
                    expires_on=date.today() - timedelta(days=1),
                ),
                CompensatingControl(
                    organization_id=org,
                    system_id=sid,
                    control_identifier=c["c"],
                    measure="m",
                    rationale="r",
                    status="approved",
                ),
                Waiver(
                    organization_id=org,
                    system_id=sid,
                    control_id=c["g"],
                    rationale="accepted",
                    status="approved",
                ),
            ]
        )
        eng = AuditEngagement(organization_id=org, name=f"e-{base}", status="fieldwork")
        s.add(eng)
        await s.flush()
        for ctl, conclusion in ((c["d"], "ineffective"), (c["e"], "effective")):
            s.add(
                AuditWorkpaper(
                    organization_id=org,
                    engagement_id=eng.id,
                    title=f"wp-{ctl}",
                    control_id=ctl,
                    conclusion=conclusion,
                    status="final",
                    reviewed_at=datetime.now(UTC),
                )
            )
        # A draft ineffective conclusion is not a final one.
        s.add(
            AuditWorkpaper(
                organization_id=org,
                engagement_id=eng.id,
                title="draft",
                control_id=c["a"],
                conclusion="ineffective",
                status="draft",
            )
        )
        await s.flush()
    async with session_scope() as s:
        await set_session_tenant(s, None)
        view = await av.control_effectiveness(s, org)
    got = {r["control"]: r["rating"] for r in view["rows"]}
    assert got[c["a"]] == av.EFFECTIVE
    assert got[c["b"]] == av.INEFFECTIVE
    assert got[c["c"]] == av.NOT_DETERMINED  # accepted by compensating control
    assert got[c["d"]] == av.INEFFECTIVE  # passing test, ineffective final conclusion
    assert got[c["e"]] == av.NOT_DETERMINED  # a conclusion alone is not a test
    assert got[c["f"]] == av.NOT_DETERMINED
    assert got[c["g"]] == av.NOT_DETERMINED  # accepted by waiver
    assert c["h"] not in got
    assert got[c["i"]] == av.INEFFECTIVE  # proposed compensating control
    assert got[c["j"]] == av.INEFFECTIVE  # expired compensating control
    assert c["k"] not in got and c["l"] not in got
    assert sum(view["counts"].values()) == view["total"] == len(view["rows"])
    assert set(view["counts"]) == set(av.RATINGS)


async def test_the_page_states_the_rule_and_the_counts_sum(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        body = (await c.get("/controls/effectiveness", headers=_tok(a, "viewer"))).text
    for text in av.RATING_RULE.values():
        assert text in body
    assert "Absence of data is never rated effective" in body


async def test_the_system_and_family_filters_narrow_the_rows(two_orgs) -> None:
    a, _ = two_orgs
    async with session_scope() as s:
        await set_session_tenant(s, None)
        everything = await av.control_effectiveness(s, int(a["org_id"]))
        other_system = await av.control_effectiveness(
            s, int(a["org_id"]), system_id=int(a["gone_id"])
        )
        other_family = await av.control_effectiveness(s, int(a["org_id"]), family="ZZ")
    assert {r["control"] for r in everything["rows"]} >= set(a["controls"])  # type: ignore[arg-type]
    # A deleted system has no live tests; only the org-wide workpaper remains.
    assert [r["control"] for r in other_system["rows"]] == [a["controls"][2]]  # type: ignore[index]
    assert other_family["rows"] == []


# ── evidence mapping ─────────────────────────────────────────────────────────


async def test_baseline_controls_without_evidence_on_that_system_are_gaps(two_orgs) -> None:
    a, b = two_orgs
    n = next(_SEQ) + 900
    with_ev, without = f"QY-{n % 1000}", f"QW-{n % 1000}"
    async with session_scope() as s:
        for ident in (with_ev, without):
            ctl = Control(identifier=ident)
            s.add(ctl)
            await s.flush()
            s.add(FrameworkMapping(control_id=ctl.id, column_key="FedRAMP Moderate", value="X"))
        s.add_all(
            [
                EvidenceObject(
                    organization_id=int(a["org_id"]),
                    title="a-ev",
                    system_id=int(a["system_id"]),
                    control_id=with_ev,
                ),
                # Bravo's evidence does not close Alpha's gap.
                EvidenceObject(
                    organization_id=int(b["org_id"]),
                    title="b-ev",
                    system_id=int(b["system_id"]),
                    control_id=without,
                ),
            ]
        )
        await s.flush()
    async with session_scope() as s:
        await set_session_tenant(s, None)
        view = await av.evidence_mapping(s, int(a["org_id"]))
    (gap,) = [g for g in view["gaps"] if g["system_id"] == a["system_id"]]
    assert gap["baseline"] == "moderate"
    assert without in gap["missing"]
    assert with_ev not in gap["missing"]
    assert gap["size"] >= 2


# ── evidence expiration and renewal ──────────────────────────────────────────


async def _renewal_tasks(obj_id: int) -> list[Task]:
    async with session_scope() as s:
        return list(
            (await s.execute(select(Task).where(Task.dedupe_key == av.renewal_key(obj_id))))
            .scalars()
            .all()
        )


async def test_the_expiration_buckets(two_orgs) -> None:
    today = date(2026, 1, 1)
    assert av.bucket(today - timedelta(days=1), today) == "expired"
    assert av.bucket(today, today) == "within_30"
    assert av.bucket(today + timedelta(days=30), today) == "within_30"
    assert av.bucket(today + timedelta(days=31), today) == "within_60"
    assert av.bucket(today + timedelta(days=90), today) == "within_90"
    assert av.bucket(today + timedelta(days=91), today) is None
    a, _ = two_orgs
    async with session_scope() as s:
        await set_session_tenant(s, None)
        view = await av.evidence_expiration(s, int(a["org_id"]))
    assert view["counts"]["expired"] == 1 and view["counts"]["within_30"] == 1
    assert sum(view["counts"].values()) == len(view["rows"])


async def test_a_second_request_does_not_open_a_second_task(two_orgs) -> None:
    a, _ = two_orgs
    obj = int(a["expiring_id"])
    async with _client() as c:
        first = await c.post(f"/evidence/expiration/{obj}/renew", headers=_tok(a, "control_owner"))
        second = await c.post(f"/evidence/expiration/{obj}/renew", headers=_tok(a, "admin"))
        page = (await c.get("/evidence/expiration", headers=_tok(a, "viewer"))).text
    assert first.status_code == 303 and "requested=new" in first.headers["location"]
    assert second.status_code == 303 and "requested=open" in second.headers["location"]
    (task,) = await _renewal_tasks(obj)
    assert task.status == "open"
    assert task.organization_id == a["org_id"]
    assert task.assignee_user_id == a["user_ids"]["admin"]  # type: ignore[index]
    assert task.entity_type == "evidence_object" and task.entity_id == str(obj)
    assert f"task #{task.id}" in page


async def test_a_closed_request_is_reopened_not_duplicated(two_orgs) -> None:
    a, _ = two_orgs
    obj = int(a["expiring_id"])
    async with _client() as c:
        await c.post(f"/evidence/expiration/{obj}/renew", headers=_tok(a))
        async with session_scope() as s:
            (t,) = (
                (await s.execute(select(Task).where(Task.dedupe_key == av.renewal_key(obj))))
                .scalars()
                .all()
            )
            t.status = "done"
            t.closed_at = datetime.now(UTC)
        again = await c.post(f"/evidence/expiration/{obj}/renew", headers=_tok(a))
    assert "requested=new" in again.headers["location"]
    (task,) = await _renewal_tasks(obj)
    assert task.status == "open" and task.closed_at is None


async def test_an_owner_from_another_organization_is_never_assigned(two_orgs) -> None:
    """The owner field names Bravo's user; the task stays Alpha's, unassigned,
    and the page says the owner is not a user of this organization."""
    a, b = two_orgs
    async with session_scope() as s:
        obj = EvidenceObject(
            organization_id=int(a["org_id"]),
            title=f"Alpha-foreign-owner-{a['tag']}",
            owner=str(b["emails"]["admin"]),  # type: ignore[index]
            expires_on=date.today() + timedelta(days=3),
        )
        s.add(obj)
        await s.flush()
        obj_id = obj.id
    async with _client() as c:
        page = (await c.get("/evidence/expiration", headers=_tok(a))).text
        resp = await c.post(f"/evidence/expiration/{obj_id}/renew", headers=_tok(a))
    row = page.split(f'id="ev-{obj_id}"')[1].split("</tr>")[0]
    assert "not a user of this organization" in row
    assert resp.status_code == 303
    (task,) = await _renewal_tasks(obj_id)
    assert task.organization_id == a["org_id"]
    assert task.assignee_user_id is None


async def test_another_organizations_evidence_cannot_be_renewed(two_orgs) -> None:
    a, b = two_orgs
    async with _client() as c:
        resp = await c.post(f"/evidence/expiration/{b['expiring_id']}/renew", headers=_tok(a))
    assert resp.status_code == 404
    assert await _renewal_tasks(int(b["expiring_id"])) == []


async def test_evidence_on_a_deleted_system_cannot_be_renewed(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        resp = await c.post(f"/evidence/expiration/{a['gone_evidence_id']}/renew", headers=_tok(a))
    assert resp.status_code == 404
    assert await _renewal_tasks(int(a["gone_evidence_id"])) == []


async def test_another_organizations_task_is_neither_shown_nor_reused(two_orgs) -> None:
    """Bad data: Bravo holds a task carrying Alpha's renewal key. Alpha's page
    must not report it as Alpha's open request, and a request must not hand it
    back as though it were."""
    a, b = two_orgs
    obj = int(a["expiring_id"])
    async with session_scope() as s:
        s.add(
            Task(
                organization_id=int(b["org_id"]),
                title=f"Bravo-squatter-{b['tag']}",
                status="open",
                dedupe_key=av.renewal_key(obj),
            )
        )
        await s.flush()
    async with _client() as c:
        page = (await c.get("/evidence/expiration", headers=_tok(a))).text
        resp = await c.post(f"/evidence/expiration/{obj}/renew", headers=_tok(a))
    row = page.split(f'id="ev-{obj}"')[1].split("</tr>")[0]
    assert "Request renewal" in row and "task #" not in row
    assert resp.status_code == 404
    (task,) = await _renewal_tasks(obj)
    assert task.organization_id == b["org_id"]


@pytest.mark.parametrize("role", ["viewer", "assessor"])
async def test_renewal_is_refused_outside_admin_and_control_owner(two_orgs, role: str) -> None:
    a, _ = two_orgs
    async with _client() as c:
        resp = await c.post(f"/evidence/expiration/{a['expiring_id']}/renew", headers=_tok(a, role))
        page = (await c.get("/evidence/expiration", headers=_tok(a, role))).text
    assert resp.status_code == 403
    assert await _renewal_tasks(int(a["expiring_id"])) == []
    assert f"/evidence/expiration/{a['expiring_id']}/renew" not in page


# ── webhooks ─────────────────────────────────────────────────────────────────


async def _hooks(org_id: int) -> list[Webhook]:
    async with session_scope() as s:
        return list(
            (await s.execute(select(Webhook).where(Webhook.organization_id == org_id)))
            .scalars()
            .all()
        )


async def test_an_admin_creates_a_webhook_through_the_api_writer(two_orgs, monkeypatch) -> None:
    a, _ = two_orgs
    calls = []
    real = events.create_webhook

    async def spy(*args, **kwargs):
        calls.append(kwargs.get("principal"))
        return await real(*args, **kwargs)

    monkeypatch.setattr(events, "create_webhook", spy)
    secret = f"NEWSECRET-{a['tag']}"
    async with _client() as c:
        resp = await c.post(
            "/integrations/webhooks",
            headers=_tok(a),
            data={"url": "https://new.example/h", "secret": secret, "subscribed": "created, poam"},
        )
        page = (await c.get("/integrations", headers=_tok(a))).text
    assert resp.status_code == 303
    assert len(calls) == 1 and calls[0].org_id == a["org_id"]
    (new,) = [h for h in await _hooks(int(a["org_id"])) if h.url == "https://new.example/h"]
    assert new.secret == secret and new.events == ["created", "poam"] and new.active
    assert "https://new.example/h" in page
    assert secret not in page
    assert f"SECRET-Alpha-{a['tag']}" not in page


@pytest.mark.parametrize("role", ["control_owner", "assessor", "viewer"])
async def test_only_an_admin_may_create_or_disable_a_webhook(two_orgs, role: str) -> None:
    a, _ = two_orgs
    (hook,) = await _hooks(int(a["org_id"]))
    async with _client() as c:
        create = await c.post(
            "/integrations/webhooks", headers=_tok(a, role), data={"url": "https://x.example/"}
        )
        disable = await c.post(f"/integrations/webhooks/{hook.id}/disable", headers=_tok(a, role))
        page = (await c.get("/integrations", headers=_tok(a, role))).text
    assert create.status_code == 403 and disable.status_code == 403
    hooks = await _hooks(int(a["org_id"]))
    assert len(hooks) == 1 and hooks[0].active
    assert 'action="/integrations/webhooks' not in page
    assert f"SECRET-Alpha-{a['tag']}" not in page


async def test_an_admin_disables_only_their_own_organizations_webhook(two_orgs) -> None:
    a, b = two_orgs
    (mine,) = await _hooks(int(a["org_id"]))
    (theirs,) = await _hooks(int(b["org_id"]))
    async with _client() as c:
        cross = await c.post(f"/integrations/webhooks/{theirs.id}/disable", headers=_tok(a))
        own = await c.post(f"/integrations/webhooks/{mine.id}/disable", headers=_tok(a))
    assert cross.status_code == 404
    assert own.status_code == 303
    assert (await _hooks(int(b["org_id"])))[0].active is True
    assert (await _hooks(int(a["org_id"])))[0].active is False


async def test_the_secret_is_never_rendered_to_an_admin(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        page = (await c.get("/integrations", headers=_tok(a))).text
    assert f"SECRET-Alpha-{a['tag']}" not in page
    assert "Add webhook" in page


async def test_a_webhook_needs_an_organization() -> None:
    """A NULL-organization webhook receives every tenant's events, so the page
    refuses to create one for a global principal."""
    async with session_scope() as s:
        before = (await s.execute(select(func.count()).select_from(Webhook))).scalar_one()
        with pytest.raises(HTTPException) as err:
            await ui_assure.integrations_create_webhook(
                url="https://g.example/",
                secret="",
                subscribed="",
                session=s,
                principal=SYSTEM_PRINCIPAL,
            )
        after = (await s.execute(select(func.count()).select_from(Webhook))).scalar_one()
    assert err.value.status_code == 400
    assert before == after
