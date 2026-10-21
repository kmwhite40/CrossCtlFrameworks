"""Third parties, obligations and projects (workstream E of the GRC build-out).

Each property here is the shape of a defect this platform has shipped:

* **Tenant scope is in the query, and in every write.** Two organizations,
  each with one distinctively named record of every kind. Pages run on an
  RLS-bypass session (``_unscoped_session``) so only the route's own
  predicate can keep Bravo's rows off Alpha's page; every write and every
  link is driven with Bravo's ids as Alpha and must 404 -- and the same write
  on Alpha's own record must succeed, so the 404 is the org check and not a
  broken route.
* **Role gates are observable.** Each write refuses a viewer *and* a real role
  outside its gate, and admits the role inside it.
* **A number over nothing is ``—``.** A vendor with none of the score's inputs
  and a project with no POA&Ms show an em dash, never 0 or 100.
* **Mapped controls exist.** An identifier the catalog does not have is
  refused, not stored as coverage.
"""

from __future__ import annotations

import itertools
import os
from collections import Counter
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select
from sqlalchemy.exc import DBAPIError

from ccf.api.deps import get_session
from ccf.api.main import create_app
from ccf.api.routes.ui_tprmprog import progress
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import get_session_factory, session_scope, set_session_tenant
from ccf.governance import obligations as obl
from ccf.governance import third_party as tp
from ccf.models import (
    POAM,
    AuditLog,
    Control,
    Organization,
    Risk,
    System,
    Task,
    User,
    Vendor,
)
from ccf.models_program import (
    ComplianceObligation,
    ContractObligation,
    DueDiligenceItem,
    Project,
    ProjectLink,
    VendorContract,
    VendorFinding,
)
from ccf.models_tprm import QuestionnaireResponse, VendorQuestionnaire

pytestmark = pytest.mark.usefixtures("fresh_engine")

_SEQ = itertools.count()
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
    """RLS cleared, so a missing org predicate in a route is not masked."""
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


async def _org(label: str, tag: str) -> dict[str, Any]:
    """One organization with one record of every kind, named ``<label>-<kind>-<tag>``.

    Also a soft-deleted system carrying a POA&M, named ``<label>-DELETED-...``."""
    today = date.today()
    m = lambda kind: f"{label}-{kind}-{tag}"  # noqa: E731
    async with session_scope() as s:
        org = Organization(name=m("org"))
        s.add(org)
        await s.flush()
        users = {
            role: User(
                email=f"{label.lower()}-{role}-{tag}@tp.test",
                full_name=m(f"user-{role}"),
                organization_id=org.id,
                role=role,
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
            for role in ROLES
        }
        live = System(organization_id=org.id, name=m("system"), baseline="moderate")
        gone = System(
            organization_id=org.id,
            name=f"{label}-DELETED-system-{tag}",
            baseline="moderate",
            deleted_at=datetime.now(UTC),
        )
        vendor = Vendor(organization_id=org.id, name=m("vendor"), criticality="high")
        bare = Vendor(organization_id=org.id, name=m("bare-vendor"), criticality="critical")
        s.add_all([*users.values(), live, gone, vendor, bare])
        await s.flush()
        poam = POAM(system_id=live.id, title=m("poam"), severity="high", status="open")
        poam2 = POAM(system_id=live.id, title=m("poam-two"), severity="low", status="open")
        gone_poam = POAM(system_id=gone.id, title=f"{label}-DELETED-poam-{tag}", status="open")
        risk = Risk(system_id=live.id, title=m("risk"), status="open")
        gone_risk = Risk(system_id=gone.id, title=f"{label}-DELETED-risk-{tag}", status="open")
        # An enterprise risk (0100): no system, owned by the organization.
        ent_risk = Risk(
            organization_id=org.id,
            register="enterprise",
            title=m("enterprise-risk"),
            status="open",
            vendor_id=vendor.id,
        )
        task = Task(organization_id=org.id, title=m("task"), status="open")
        contract = VendorContract(
            organization_id=org.id,
            vendor_id=vendor.id,
            title=m("contract"),
            status="active",
            renewal_on=today + timedelta(days=30),
            annual_value=1000.0,
        )
        dd = DueDiligenceItem(
            organization_id=org.id,
            vendor_id=vendor.id,
            item=m("dd"),
            status="requested",
            due_on=today - timedelta(days=3),
        )
        finding = VendorFinding(
            organization_id=org.id,
            vendor_id=vendor.id,
            title=m("finding"),
            severity="high",
            status="open",
        )
        cob = ComplianceObligation(organization_id=org.id, source="regulation", title=m("oblig"))
        project = Project(organization_id=org.id, name=m("project"))
        q = VendorQuestionnaire(
            organization_id=org.id,
            vendor_id=vendor.id,
            name=m("questionnaire"),
            status="submitted",
            score=60.0,
        )
        s.add_all(
            [
                poam,
                poam2,
                gone_poam,
                gone_risk,
                risk,
                ent_risk,
                task,
                contract,
                dd,
                finding,
                cob,
                project,
                q,
            ]
        )
        await s.flush()
        ob = ContractObligation(
            organization_id=org.id,
            contract_id=contract.id,
            description=m("contract-obligation"),
            status="pending",
            due_on=today - timedelta(days=5),
        )
        link = ProjectLink(
            organization_id=org.id,
            project_id=project.id,
            entity_type="poam",
            entity_id=str(poam.id),
        )
        s.add_all(
            [
                ob,
                link,
                QuestionnaireResponse(
                    questionnaire_id=q.id,
                    question_id="GOV-02",
                    question_text=m("gap-question"),
                    weight=3,
                    answer="no",
                    sort_order=0,
                ),
                QuestionnaireResponse(
                    questionnaire_id=q.id,
                    question_id="GOV-01",
                    question_text=m("yes-question"),
                    weight=2,
                    answer="yes",
                    sort_order=1,
                ),
            ]
        )
        await s.flush()
        return {
            "label": label,
            "tag": tag,
            "org": org.id,
            "tokens": {r: u.api_token for r, u in users.items()},
            "users": {r: u.id for r, u in users.items()},
            "system": live.id,
            "gone_system": gone.id,
            "poam": poam.id,
            "poam2": poam2.id,
            "gone_poam": gone_poam.id,
            "risk": risk.id,
            "ent_risk": ent_risk.id,
            "gone_risk": gone_risk.id,
            "task": task.id,
            "vendor": vendor.id,
            "bare": bare.id,
            "contract": contract.id,
            "ob": ob.id,
            "dd": dd.id,
            "finding": finding.id,
            "cob": cob.id,
            "project": project.id,
            "link": link.id,
            "q": q.id,
        }


@pytest.fixture
async def two_orgs() -> tuple[dict[str, Any], dict[str, Any]]:
    tag = f"tp{next(_SEQ)}x{os.getpid()}"
    return await _org("Alpha", tag), await _org("Bravo", tag)


@pytest.fixture
async def catalog() -> list[str]:
    """Two catalog controls of this run's own, in the catalog's spelling."""
    tag = f"tp{next(_SEQ)}x{os.getpid()}"
    idents = [f"TP-{tag}-1", f"TP-{tag}-2"]
    async with session_scope() as s:
        s.add_all([Control(identifier=i, control_name=f"control {i}") for i in idents])
        await s.flush()
    return idents


# ── the pure rules ───────────────────────────────────────────────────────────


def test_a_vendor_with_no_inputs_has_no_score_whatever_its_criticality() -> None:
    for crit in ("low", "medium", "high", "critical", "unset"):
        assert tp.vendor_score(tp.VendorInputs(criticality=crit)) is None


def test_the_score_is_its_parts_and_the_parts_sum() -> None:
    sc = tp.vendor_score(
        tp.VendorInputs(
            criticality="high",
            questionnaire_score=60.0,
            findings_recorded=2,
            open_findings=Counter({"high": 1}),
            dd_items=3,
            dd_overdue=1,
        )
    )
    assert sc is not None
    assert (sc["q"], sc["f"], sc["d"]) == (20.0, 10.0, 5.0)
    assert sc["q"] + sc["f"] + sc["d"] == sc["subtotal"] == 35.0
    assert sc["weight"] == 1.25
    assert sc["score"] == 44  # 35 x 1.25 = 43.75
    assert sc["missing"] == [] and sc["partial"] is False


def test_each_part_is_capped_and_the_score_never_exceeds_100() -> None:
    sc = tp.vendor_score(
        tp.VendorInputs(
            criticality="critical",
            questionnaire_score=0.0,
            findings_recorded=9,
            open_findings=Counter({"critical": 9}),
            dd_items=9,
            dd_overdue=9,
        )
    )
    assert sc is not None
    assert (sc["q"], sc["f"], sc["d"]) == (50.0, 30.0, 20.0)
    assert sc["score"] == 100


def test_a_recorded_input_of_zero_is_a_measurement_not_an_absence() -> None:
    """Closed findings and non-overdue requests were measured: score 0, not —."""
    sc = tp.vendor_score(tp.VendorInputs(criticality="medium", findings_recorded=1, dd_items=1))
    assert sc is not None and sc["score"] == 0
    assert sc["missing"] == ["no scored questionnaire"] and sc["partial"] is True


def test_progress_over_no_poams_is_none() -> None:
    assert progress(0, 0) is None
    assert progress(1, 3) == 33
    assert progress(2, 2) == 100


def test_control_ids_parse_and_dedupe() -> None:
    assert obl.parse_control_ids(" ac-2, AC-2;IR-6  sc-7 ") == ["ac-2", "IR-6", "sc-7"]
    assert obl.parse_control_ids("") == []


# ── pages: the caller's records, never another tenant's ─────────────────────

PAGES = (
    ("/contracts", ("contract", "contract-obligation")),
    ("/due-diligence", ("dd", "vendor")),
    ("/vendor-findings", ("finding", "gap-question")),
    ("/obligations", ("oblig",)),
    ("/projects", ("project",)),
    ("/vendors", ("vendor", "bare-vendor")),
)


@pytest.mark.parametrize(("path", "kinds"), PAGES)
async def test_each_page_shows_its_own_records_and_never_another_orgs(
    two_orgs, path: str, kinds: tuple[str, ...]
) -> None:
    a, _ = two_orgs
    async with _client() as c:
        resp = await c.get(path, headers=_auth(a["tokens"]["viewer"]))
    assert resp.status_code == 200, resp.text[:400]
    body = resp.text
    for kind in kinds:
        assert f"Alpha-{kind}-{a['tag']}" in body, f"{path} does not show the caller's {kind}"
    assert "Bravo" not in body, f"{path} shows Bravo's records to Alpha"
    assert "DELETED" not in body


async def test_detail_pages_show_their_record_and_404_another_orgs(two_orgs) -> None:
    a, b = two_orgs
    h = _auth(a["tokens"]["viewer"])
    async with _client() as c:
        own_c = await c.get(f"/contracts/{a['contract']}", headers=h)
        own_p = await c.get(f"/projects/{a['project']}", headers=h)
        other_c = await c.get(f"/contracts/{b['contract']}", headers=h)
        other_p = await c.get(f"/projects/{b['project']}", headers=h)
    assert own_c.status_code == 200 and f"Alpha-contract-obligation-{a['tag']}" in own_c.text
    assert own_p.status_code == 200 and f"Alpha-poam-{a['tag']}" in own_p.text
    assert "Bravo" not in own_c.text and "Bravo" not in own_p.text
    # The add-link selects offer the project's organization only.
    assert "DELETED" not in own_p.text
    assert other_c.status_code == 404 and other_p.status_code == 404


# ── writes: another tenant's id is 404 on every write and every link ────────


def _writes(a: dict[str, Any], b: dict[str, Any]) -> list[tuple[str, str, dict[str, str]]]:
    """(name, path, form) for every write, each naming a record of Bravo's,
    driven as Alpha's admin (the role every gate admits)."""
    return [
        ("contract: Bravo vendor", "/contracts", {"vendor_id": str(b["vendor"]), "title": "x"}),
        (
            "contract: Bravo owner",
            "/contracts",
            {
                "vendor_id": str(a["vendor"]),
                "title": "x",
                "owner_user_id": str(b["users"]["admin"]),
            },
        ),
        ("contract update", f"/contracts/{b['contract']}", {"title": "x", "status": "active"}),
        (
            "contract obligation add",
            f"/contracts/{b['contract']}/obligations",
            {"description": "x"},
        ),
        (
            "contract obligation status",
            f"/contracts/{b['contract']}/obligations/{b['ob']}/status",
            {"status": "met"},
        ),
        (
            "contract obligation through own contract",
            f"/contracts/{a['contract']}/obligations/{b['ob']}/status",
            {"status": "met"},
        ),
        ("dd standard", f"/due-diligence/{b['vendor']}/standard", {}),
        ("dd add", f"/due-diligence/{b['vendor']}/items", {"item": "x"}),
        ("dd receive", f"/due-diligence/items/{b['dd']}/receive", {"evidence_ref": "x"}),
        ("dd review", f"/due-diligence/items/{b['dd']}/review", {"decision": "not_applicable"}),
        ("finding create", "/vendor-findings", {"vendor_id": str(b["vendor"]), "title": "x"}),
        (
            "finding from gap",
            "/vendor-findings/from-gap",
            {"questionnaire_id": str(b["q"]), "question_id": "GOV-02"},
        ),
        ("finding status", f"/vendor-findings/{b['finding']}/status", {"status": "closed"}),
        ("obligation update", f"/obligations/{b['cob']}", {"status": "met"}),
        (
            "obligation: Bravo owner",
            "/obligations",
            {"source": "statute", "title": "x", "owner_user_id": str(b["users"]["admin"])},
        ),
        (
            "obligation update: Bravo owner",
            f"/obligations/{a['cob']}",
            {"status": "met", "owner_user_id": str(b["users"]["admin"])},
        ),
        (
            "project: Bravo owner",
            "/projects",
            {"name": "x", "owner_user_id": str(b["users"]["admin"])},
        ),
        ("project update", f"/projects/{b['project']}", {"name": "x", "status": "active"}),
        (
            "link onto Bravo's project",
            f"/projects/{b['project']}/links",
            {"entity_type": "poam", "entity_id": str(a["poam"])},
        ),
        *[
            (
                f"link Bravo {key}",
                f"/projects/{a['project']}/links",
                {"entity_type": etype, "entity_id": str(b[key])},
            )
            for etype, key in (
                ("poam", "poam"),
                ("task", "task"),
                ("risk", "risk"),
                ("risk", "ent_risk"),
                ("system", "system"),
            )
        ],
        (
            "link own POA&M on a deleted system",
            f"/projects/{a['project']}/links",
            {"entity_type": "poam", "entity_id": str(a["gone_poam"])},
        ),
        (
            "link own risk on a deleted system",
            f"/projects/{a['project']}/links",
            {"entity_type": "risk", "entity_id": str(a["gone_risk"])},
        ),
        (
            "link own deleted system",
            f"/projects/{a['project']}/links",
            {"entity_type": "system", "entity_id": str(a["gone_system"])},
        ),
        ("unlink on Bravo's project", f"/projects/{b['project']}/links/{b['link']}/delete", {}),
        ("unlink Bravo's link", f"/projects/{a['project']}/links/{b['link']}/delete", {}),
    ]


def _own_writes(a: dict[str, Any], ctrl: str) -> list[tuple[str, str, dict[str, str]]]:
    """The same writes on Alpha's own records: each must succeed (303)."""
    return [
        ("contract create", "/contracts", {"vendor_id": str(a["vendor"]), "title": "own"}),
        (
            "contract create with own owner",
            "/contracts",
            {
                "vendor_id": str(a["vendor"]),
                "title": "own",
                "owner_user_id": str(a["users"]["admin"]),
            },
        ),
        ("contract update", f"/contracts/{a['contract']}", {"title": "own", "status": "active"}),
        (
            "contract obligation add",
            f"/contracts/{a['contract']}/obligations",
            {"description": "own", "control_id": ctrl},
        ),
        (
            "contract obligation status",
            f"/contracts/{a['contract']}/obligations/{a['ob']}/status",
            {"status": "met"},
        ),
        ("dd standard", f"/due-diligence/{a['vendor']}/standard", {}),
        ("dd add", f"/due-diligence/{a['vendor']}/items", {"item": "own"}),
        ("dd receive", f"/due-diligence/items/{a['dd']}/receive", {"evidence_ref": "s3://x"}),
        # One admin token receives and reviews here, so the decision is one
        # separation of duties does not govern (accepting is refused to the
        # receiver: test_the_receiver_of_an_item_cannot_review_it).
        ("dd review", f"/due-diligence/items/{a['dd']}/review", {"decision": "not_applicable"}),
        ("finding create", "/vendor-findings", {"vendor_id": str(a["vendor"]), "title": "own"}),
        (
            "finding from gap",
            "/vendor-findings/from-gap",
            {"questionnaire_id": str(a["q"]), "question_id": "GOV-02"},
        ),
        ("finding status", f"/vendor-findings/{a['finding']}/status", {"status": "remediating"}),
        (
            "obligation create",
            "/obligations",
            {"source": "statute", "title": "own", "owner_user_id": str(a["users"]["admin"])},
        ),
        ("obligation update", f"/obligations/{a['cob']}", {"status": "met", "control_ids": ctrl}),
        ("project create", "/projects", {"name": "own", "owner_user_id": str(a["users"]["admin"])}),
        ("project update", f"/projects/{a['project']}", {"name": "own", "status": "active"}),
        *[
            (
                f"link own {key}",
                f"/projects/{a['project']}/links",
                {"entity_type": etype, "entity_id": str(a[key])},
            )
            for etype, key in (
                ("poam", "poam2"),
                ("task", "task"),
                ("risk", "risk"),
                ("risk", "ent_risk"),
                ("system", "system"),
            )
        ],
        ("unlink own link", f"/projects/{a['project']}/links/{a['link']}/delete", {}),
    ]


async def test_every_write_and_link_naming_another_orgs_record_is_404(two_orgs) -> None:
    a, b = two_orgs
    failures = []
    async with _client() as c:
        for name, path, form in _writes(a, b):
            resp = await c.post(path, data=form, headers=_auth(a["tokens"]["admin"]))
            if resp.status_code != 404:
                failures.append(f"{name}: {path} -> {resp.status_code} {resp.text[:120]}")
    assert not failures, "\n".join(failures)
    # And nothing of Bravo's moved.
    async with session_scope() as s:
        assert (await s.get(VendorContract, b["contract"])).title == f"Bravo-contract-{b['tag']}"
        assert (await s.get(ContractObligation, b["ob"])).status == "pending"
        assert (await s.get(DueDiligenceItem, b["dd"])).status == "requested"
        assert (await s.get(VendorFinding, b["finding"])).status == "open"
        assert (await s.get(ComplianceObligation, b["cob"])).status == "open"
        assert (await s.get(Project, b["project"])).name == f"Bravo-project-{b['tag']}"
        assert await s.get(ProjectLink, b["link"]) is not None
        n_dd = (
            await s.execute(
                select(func.count())
                .select_from(DueDiligenceItem)
                .where(DueDiligenceItem.vendor_id == b["vendor"])
            )
        ).scalar_one()
        assert n_dd == 1
        alpha_links = (
            (
                await s.execute(
                    select(ProjectLink.entity_id).where(ProjectLink.project_id == a["project"])
                )
            )
            .scalars()
            .all()
        )
        assert alpha_links == [str(a["poam"])]


async def test_the_same_writes_on_the_callers_own_records_succeed(two_orgs, catalog) -> None:
    """Without this, the 404s above could be a broken route rather than the org check."""
    a, _ = two_orgs
    failures = []
    async with _client() as c:
        for name, path, form in _own_writes(a, catalog[0]):
            resp = await c.post(path, data=form, headers=_auth(a["tokens"]["admin"]))
            if resp.status_code != 303:
                failures.append(f"{name}: {path} -> {resp.status_code} {resp.text[:160]}")
    assert not failures, "\n".join(failures)
    async with session_scope() as s:
        links = Counter(
            (
                await s.execute(
                    select(ProjectLink.entity_type).where(ProjectLink.project_id == a["project"])
                )
            )
            .scalars()
            .all()
        )
        # poam2, task, both risks and system linked; the original POA&M link removed.
        assert links == Counter({"poam": 1, "task": 1, "risk": 2, "system": 1})
        events = (
            await s.execute(
                select(AuditLog.entity_type, AuditLog.organization_id).where(
                    AuditLog.actor == f"alpha-admin-{a['tag']}@tp.test"
                )
            )
        ).all()
    kinds = {e for e, _ in events}
    assert {
        "vendor_contract",
        "contract_obligation",
        "due_diligence_checklist",
        "due_diligence_item",
        "vendor_finding",
        "compliance_obligation",
        "project",
    } <= kinds
    assert {o for _, o in events} == {a["org"]}, "an event was recorded outside the caller's org"


# ── role gates ───────────────────────────────────────────────────────────────


def _gated(a: dict[str, Any], ctrl: str) -> list[tuple[str, dict[str, str], str, str]]:
    """(path, form, a role outside the gate, the role inside it)."""
    return [
        ("/contracts", {"vendor_id": str(a["vendor"]), "title": "g"}, "assessor", "control_owner"),
        (
            f"/contracts/{a['contract']}",
            {"title": "g", "status": "active"},
            "assessor",
            "control_owner",
        ),
        (
            f"/contracts/{a['contract']}/obligations",
            {"description": "g", "control_id": ctrl},
            "assessor",
            "control_owner",
        ),
        (
            f"/contracts/{a['contract']}/obligations/{a['ob']}/status",
            {"status": "missed"},
            "assessor",
            "control_owner",
        ),
        (f"/due-diligence/{a['vendor']}/standard", {}, "assessor", "control_owner"),
        (f"/due-diligence/{a['vendor']}/items", {"item": "g"}, "assessor", "control_owner"),
        (
            f"/due-diligence/items/{a['dd']}/receive",
            {"evidence_ref": "s3://g"},
            "assessor",
            "control_owner",
        ),
        (
            f"/due-diligence/items/{a['dd']}/review",
            {"decision": "accepted"},
            "control_owner",
            "assessor",
        ),
        (
            "/vendor-findings",
            {"vendor_id": str(a["vendor"]), "title": "g"},
            "control_owner",
            "assessor",
        ),
        (
            "/vendor-findings/from-gap",
            {"questionnaire_id": str(a["q"]), "question_id": "GOV-02"},
            "control_owner",
            "assessor",
        ),
        (
            f"/vendor-findings/{a['finding']}/status",
            {"status": "remediating"},
            "assessor",
            "control_owner",
        ),
        ("/obligations", {"source": "policy", "title": "g"}, "assessor", "control_owner"),
        (f"/obligations/{a['cob']}", {"status": "met"}, "assessor", "control_owner"),
        ("/projects", {"name": "g"}, "assessor", "control_owner"),
        (
            f"/projects/{a['project']}",
            {"name": "g", "status": "active"},
            "assessor",
            "control_owner",
        ),
        (
            f"/projects/{a['project']}/links",
            {"entity_type": "task", "entity_id": str(a["task"])},
            "assessor",
            "control_owner",
        ),
        (f"/projects/{a['project']}/links/{a['link']}/delete", {}, "assessor", "control_owner"),
    ]


async def test_each_write_refuses_a_viewer_and_a_role_outside_its_gate(two_orgs, catalog) -> None:
    a, _ = two_orgs
    failures = []
    async with _client() as c:
        # The receive must precede the review that needs it, so run in order.
        for path, form, outside, inside in _gated(a, catalog[0]):
            for role in ("viewer", outside):
                resp = await c.post(path, data=form, headers=_auth(a["tokens"][role]))
                if resp.status_code != 403:
                    failures.append(f"{role} {path} -> {resp.status_code}")
            resp = await c.post(path, data=form, headers=_auth(a["tokens"][inside]))
            if resp.status_code != 303:
                failures.append(f"{inside} {path} -> {resp.status_code} {resp.text[:160]}")
    assert not failures, "\n".join(failures)


async def test_waiving_an_obligation_and_accepting_a_finding_are_admin_decisions(
    two_orgs,
) -> None:
    a, _ = two_orgs
    waive = (f"/contracts/{a['contract']}/obligations/{a['ob']}/status", {"status": "waived"})
    accept = (f"/vendor-findings/{a['finding']}/status", {"status": "accepted"})
    async with _client() as c:
        for path, form in (waive, accept):
            refused = await c.post(path, data=form, headers=_auth(a["tokens"]["control_owner"]))
            assert refused.status_code == 403, path
            assert "only an admin" in refused.json()["detail"]
        async with session_scope() as s:
            assert (await s.get(ContractObligation, a["ob"])).status == "pending"
            assert (await s.get(VendorFinding, a["finding"])).status == "open"
        for path, form in (waive, accept):
            ok = await c.post(path, data=form, headers=_auth(a["tokens"]["admin"]))
            assert ok.status_code == 303, path
    async with session_scope() as s:
        assert (await s.get(ContractObligation, a["ob"])).status == "waived"
        f = await s.get(VendorFinding, a["finding"])
        assert f.status == "accepted" and f.closed_at is not None


# ── due diligence: requests, not data ────────────────────────────────────────


async def test_the_standard_checklist_creates_requests_once(two_orgs) -> None:
    a, _ = two_orgs
    h = _auth(a["tokens"]["control_owner"])
    async with _client() as c:
        for _ in range(2):
            resp = await c.post(
                f"/due-diligence/{a['bare']}/standard", data={"due_on": "2030-01-31"}, headers=h
            )
            assert resp.status_code == 303
        page = (await c.get(f"/due-diligence?vendor_id={a['bare']}", headers=h)).text
    async with session_scope() as s:
        items = (
            (
                await s.execute(
                    select(DueDiligenceItem).where(DueDiligenceItem.vendor_id == a["bare"])
                )
            )
            .scalars()
            .all()
        )
    assert sorted(i.item for i in items) == sorted(n for n, _ in tp.STANDARD_CHECKLIST)
    assert len(items) == 7
    for i in items:
        assert i.status == "requested" and i.evidence_ref is None and i.reviewed_by is None
        assert i.due_on == date(2030, 1, 31) and i.organization_id == a["org"]
    assert "SOC 2 report" in page and "Sub-processor list" in page
    assert "0 of 7 required items accepted" in page


async def test_the_receiver_of_an_item_cannot_review_it(two_orgs) -> None:
    """Receiving the vendor's document and judging it are separate duties."""
    a, _ = two_orgs
    item = f"/due-diligence/items/{a['dd']}"
    async with _client() as c:
        got = await c.post(
            f"{item}/receive",
            data={"evidence_ref": "vault://x"},
            headers=_auth(a["tokens"]["admin"]),
        )
        assert got.status_code == 303
        for decision in ("accepted", "rejected"):
            own = await c.post(
                f"{item}/review", data={"decision": decision}, headers=_auth(a["tokens"]["admin"])
            )
            assert own.status_code == 403, decision
        async with session_scope() as s:
            row = await s.get(DueDiligenceItem, a["dd"])
            assert row.status == "received" and row.reviewed_by is None
            assert row.received_by == f"alpha-admin-{a['tag']}@tp.test"
        other = await c.post(
            f"{item}/review", data={"decision": "accepted"}, headers=_auth(a["tokens"]["assessor"])
        )
        assert other.status_code == 303
        # Accepted evidence cannot then be declared not applicable.
        na = await c.post(
            f"{item}/review",
            data={"decision": "not_applicable"},
            headers=_auth(a["tokens"]["assessor"]),
        )
        assert na.status_code == 409
    async with session_scope() as s:
        assert (await s.get(DueDiligenceItem, a["dd"])).status == "accepted"


async def test_an_item_received_before_receivers_were_recorded_must_be_received_again(
    two_orgs,
) -> None:
    a, _ = two_orgs
    async with session_scope() as s:
        row = await s.get(DueDiligenceItem, a["dd"])
        row.status, row.evidence_ref, row.received_by = "received", "vault://legacy", None
    async with _client() as c:
        resp = await c.post(
            f"/due-diligence/items/{a['dd']}/review",
            data={"decision": "accepted"},
            headers=_auth(a["tokens"]["assessor"]),
        )
    assert resp.status_code == 409
    async with session_scope() as s:
        assert (await s.get(DueDiligenceItem, a["dd"])).status == "received"


async def test_an_item_nothing_answered_cannot_be_accepted(two_orgs) -> None:
    a, _ = two_orgs
    review = f"/due-diligence/items/{a['dd']}/review"
    async with _client() as c:
        early = await c.post(
            review, data={"decision": "accepted"}, headers=_auth(a["tokens"]["assessor"])
        )
        assert early.status_code == 409
        got = await c.post(
            f"/due-diligence/items/{a['dd']}/receive",
            data={"evidence_ref": "vault://soc2.pdf"},
            headers=_auth(a["tokens"]["control_owner"]),
        )
        assert got.status_code == 303
        async with session_scope() as s:
            item = await s.get(DueDiligenceItem, a["dd"])
            assert item.status == "received" and item.reviewed_by is None
        done = await c.post(
            review, data={"decision": "accepted"}, headers=_auth(a["tokens"]["assessor"])
        )
        assert done.status_code == 303
    async with session_scope() as s:
        item = await s.get(DueDiligenceItem, a["dd"])
    assert item.status == "accepted"
    assert item.reviewed_by == f"alpha-assessor-{a['tag']}@tp.test"
    assert item.reviewed_at is not None


# ── vendor findings from questionnaire gaps ─────────────────────────────────


async def test_a_questionnaire_gap_becomes_one_finding(two_orgs) -> None:
    a, _ = two_orgs
    h = _auth(a["tokens"]["assessor"])
    form = {"questionnaire_id": str(a["q"]), "question_id": "GOV-02"}
    async with _client() as c:
        before = (await c.get("/vendor-findings", headers=h)).text
        assert 'action="/vendor-findings/from-gap"' in before
        assert (await c.post("/vendor-findings/from-gap", data=form, headers=h)).status_code == 303
        again = await c.post("/vendor-findings/from-gap", data=form, headers=h)
        yes = await c.post(
            "/vendor-findings/from-gap",
            data={"questionnaire_id": str(a["q"]), "question_id": "GOV-01"},
            headers=h,
        )
        after = (await c.get("/vendor-findings", headers=h)).text
    assert again.status_code == 409
    assert yes.status_code == 409  # answered "yes": not a gap
    async with session_scope() as s:
        f = (
            await s.execute(select(VendorFinding).where(VendorFinding.questionnaire_id == a["q"]))
        ).scalar_one()
    assert f.severity == "high"  # weight 3
    assert f.vendor_id == a["vendor"] and f.organization_id == a["org"]
    assert f.title.startswith("GOV-02: ")
    # The gap is now recorded, so it is no longer offered.
    assert 'action="/vendor-findings/from-gap"' not in after


async def test_a_draft_questionnaire_has_no_gaps_yet(two_orgs) -> None:
    a, _ = two_orgs
    async with session_scope() as s:
        q = await s.get(VendorQuestionnaire, a["q"])
        q.status = "in_progress"
    async with _client() as c:
        resp = await c.post(
            "/vendor-findings/from-gap",
            data={"questionnaire_id": str(a["q"]), "question_id": "GOV-02"},
            headers=_auth(a["tokens"]["admin"]),
        )
    assert resp.status_code == 409


async def test_findings_filter_by_severity_and_status(two_orgs) -> None:
    a, _ = two_orgs
    h = _auth(a["tokens"]["viewer"])
    async with _client() as c:
        hit = (await c.get("/vendor-findings?severity=high&status=open", headers=h)).text
        miss = (await c.get("/vendor-findings?severity=low", headers=h)).text
    assert f"Alpha-finding-{a['tag']}" in hit
    assert f"Alpha-finding-{a['tag']}" not in miss


# ── the vendor risk score on /vendors ────────────────────────────────────────


async def test_the_vendor_score_shows_its_formula_and_a_dash_over_nothing(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        body = (await c.get("/vendors", headers=_auth(a["tokens"]["viewer"]))).text
    assert 'id="vendor-scores"' in body
    for line in tp.FORMULA:
        assert line.replace("'", "&#39;") in body
    rows = {
        name: body[body.index(f"<strong>{name}</strong>") :].split("</tr>", 1)[0]
        for name in (f"Alpha-vendor-{a['tag']}", f"Alpha-bare-vendor-{a['tag']}")
    }
    # Q (100-60)/2 = 20, F one open high = 10, D one overdue request = 5:
    # 35 x 1.25 (high) = 43.75 -> 44.
    scored = rows[f"Alpha-vendor-{a['tag']}"]
    assert 'data-score="44"' in scored
    assert "Q 20.0 + F 10.0 + D 5.0 = 35.0 \u00d7 1.25" in scored
    # Critical criticality, but nothing measured: no score.
    assert 'data-score="none"' in rows[f"Alpha-bare-vendor-{a['tag']}"]
    assert "—" in rows[f"Alpha-bare-vendor-{a['tag']}"]


async def test_a_child_row_from_another_org_never_scores_a_vendor(two_orgs) -> None:
    """A questionnaire carrying Bravo's organization but Alpha's vendor id (a
    bad import; ``vendor_questionnaires`` predates 0101's triggers) is not
    Alpha's evidence. Findings and due-diligence items cannot be written that
    way at all since 0101, which is asserted here so the score's own check is
    known to sit behind a database guard."""
    a, b = two_orgs
    async with session_scope() as s:
        s.add(
            VendorQuestionnaire(
                organization_id=b["org"],
                vendor_id=a["bare"],
                name="x",
                status="submitted",
                score=10.0,
            )
        )
        await s.flush()
        bare = await s.get(Vendor, a["bare"])
        scores = await tp.vendor_scores(s, [bare], date.today())
    assert scores == {a["bare"]: None}
    for row in (
        VendorFinding(
            organization_id=b["org"], vendor_id=a["bare"], title="x", severity="critical"
        ),
        DueDiligenceItem(
            organization_id=b["org"], vendor_id=a["bare"], item="x", status="requested"
        ),
        # The other child rows whose org predicates in the routes sit behind
        # the same trigger (reported as unreachable by the mutation check).
        ContractObligation(organization_id=a["org"], contract_id=b["contract"], description="x"),
        ProjectLink(
            organization_id=a["org"], project_id=b["project"], entity_type="task", entity_id="1"
        ),
        VendorFinding(
            organization_id=a["org"],
            vendor_id=a["vendor"],
            questionnaire_id=b["q"],
            title="x",
            severity="low",
        ),
    ):
        with pytest.raises(DBAPIError, match="same organization"):
            async with session_scope() as s:
                s.add(row)
                await s.flush()


# ── mapped controls are validated against the catalog ───────────────────────


async def test_an_unknown_control_is_refused_and_a_known_one_stored_canonically(
    two_orgs, catalog
) -> None:
    a, _ = two_orgs
    h = _auth(a["tokens"]["admin"])
    title = f"Alpha-mapped-{a['tag']}"
    async with _client() as c:
        bad = await c.post(
            "/obligations",
            data={"source": "statute", "title": title, "control_ids": f"{catalog[0]}, ZZ-NOPE-9"},
            headers=h,
        )
        good = await c.post(
            "/obligations",
            data={
                "source": "statute",
                "title": title,
                "control_ids": f"{catalog[0].lower()}, {catalog[1]}",
            },
            headers=h,
        )
        bad_update = await c.post(
            f"/obligations/{a['cob']}",
            data={"status": "met", "control_ids": "ZZ-NOPE-9"},
            headers=h,
        )
        bad_contract = await c.post(
            f"/contracts/{a['contract']}/obligations",
            data={"description": "x", "control_id": "ZZ-NOPE-9"},
            headers=h,
        )
    assert bad.status_code == 400 and "ZZ-NOPE-9" in bad.json()["detail"]
    assert good.status_code == 303
    assert bad_update.status_code == 400
    assert bad_contract.status_code == 400
    async with session_scope() as s:
        rows = (
            (
                await s.execute(
                    select(ComplianceObligation).where(ComplianceObligation.title == title)
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1
        assert rows[0].control_ids == catalog
        assert (await s.get(ComplianceObligation, a["cob"])).control_ids in ([], None)
        n = (
            await s.execute(
                select(func.count())
                .select_from(ContractObligation)
                .where(ContractObligation.contract_id == a["contract"])
            )
        ).scalar_one()
        assert n == 1


# ── projects ─────────────────────────────────────────────────────────────────


async def test_progress_is_closed_over_linked_poams_and_a_dash_over_none(two_orgs) -> None:
    a, _ = two_orgs
    h = _auth(a["tokens"]["control_owner"])
    async with _client() as c:
        await c.post(
            f"/projects/{a['project']}/links",
            data={"entity_type": "poam", "entity_id": str(a["poam2"])},
            headers=h,
        )
        async with session_scope() as s:
            (await s.get(POAM, a["poam2"])).status = "completed"
            # A link that predates its system's deletion: shown, not counted.
            s.add(
                ProjectLink(
                    organization_id=a["org"],
                    project_id=a["project"],
                    entity_type="poam",
                    entity_id=str(a["gone_poam"]),
                )
            )
        await c.post("/projects", data={"name": f"Alpha-empty-{a['tag']}"}, headers=h)
        detail = (await c.get(f"/projects/{a['project']}", headers=h)).text
        listing = (await c.get("/projects", headers=h)).text
    assert 'data-progress="50"' in detail
    assert "1 of 2 linked POA&amp;Ms closed" in detail
    assert "no longer available" in detail
    assert "DELETED" not in detail
    own = listing[listing.index(f"Alpha-project-{a['tag']}") :].split("</tr>", 1)[0]
    empty = listing[listing.index(f"Alpha-empty-{a['tag']}") :].split("</tr>", 1)[0]
    assert 'data-progress="50"' in own
    assert 'data-progress="none"' in empty and "—" in empty


# ── contracts: renewals and missed obligations surfaced ─────────────────────


async def test_renewals_within_90_days_and_overdue_obligations_are_surfaced(two_orgs) -> None:
    a, _ = two_orgs
    async with session_scope() as s:
        s.add(
            VendorContract(
                organization_id=a["org"],
                vendor_id=a["vendor"],
                title=f"Alpha-far-{a['tag']}",
                status="active",
                renewal_on=date.today() + timedelta(days=200),
            )
        )
    async with _client() as c:
        body = (await c.get("/contracts", headers=_auth(a["tokens"]["viewer"]))).text
    renewals = body[body.index('id="renewals"') :].split("</section>", 1)[0]
    attention = body[body.index('id="missed-obligations"') :].split("</section>", 1)[0]
    assert f"Alpha-contract-{a['tag']}" in renewals
    assert f"Alpha-far-{a['tag']}" not in renewals
    assert f"Alpha-contract-obligation-{a['tag']}" in attention and "overdue" in attention


async def test_an_obligation_from_another_contract_cannot_be_reached_through_this_one(
    two_orgs,
) -> None:
    """Same org, wrong parent: the child is looked up under its parent."""
    a, _ = two_orgs
    async with session_scope() as s:
        other = VendorContract(
            organization_id=a["org"], vendor_id=a["vendor"], title="other", status="draft"
        )
        s.add(other)
        await s.flush()
        other_id = other.id
    async with _client() as c:
        resp = await c.post(
            f"/contracts/{other_id}/obligations/{a['ob']}/status",
            data={"status": "met"},
            headers=_auth(a["tokens"]["admin"]),
        )
    assert resp.status_code == 404


async def test_link_candidates_and_project_scope_use_the_projects_org(two_orgs) -> None:
    """The add-link select lists the org's own live records only."""
    a, b = two_orgs
    async with _client() as c:
        body = (await c.get(f"/projects/{a['project']}", headers=_auth(a["tokens"]["admin"]))).text
    assert f"Alpha-task-{a['tag']}" in body and f"Alpha-risk-{a['tag']}" in body
    assert f"Alpha-system-{a['tag']}" in body
    assert "Bravo" not in body and "DELETED" not in body
    async with session_scope() as s:
        assert (await s.get(Task, b["task"])) is not None
        assert (await s.get(Risk, b["risk"])) is not None
        assert (await s.get(System, b["system"])) is not None


async def test_enterprise_risks_are_scoped_by_their_owning_org(two_orgs) -> None:
    """0100: a risk with no system is owned by ``organization_id``. Alpha's
    links and is offered; Bravo's is not; a risk on a deleted system is out
    even though its organization is Alpha's."""
    a, b = two_orgs
    h = _auth(a["tokens"]["admin"])
    async with session_scope() as s:
        gone = await s.get(Risk, a["gone_risk"])
        assert gone.organization_id == a["org"]  # filled by the 0100 trigger
        # A bad import: Bravo's system-less risk pointing at Alpha's vendor.
        s.add(
            Risk(
                organization_id=b["org"],
                register="enterprise",
                title=f"Bravo-stray-risk-{b['tag']}",
                status="open",
                vendor_id=a["vendor"],
            )
        )
    async with _client() as c:
        page = (await c.get(f"/projects/{a['project']}", headers=h)).text
        own = await c.post(
            f"/projects/{a['project']}/links",
            data={"entity_type": "risk", "entity_id": str(a["ent_risk"])},
            headers=h,
        )
        other = await c.post(
            f"/projects/{a['project']}/links",
            data={"entity_type": "risk", "entity_id": str(b["ent_risk"])},
            headers=h,
        )
        linked = (await c.get(f"/projects/{a['project']}", headers=h)).text
        vendors = (await c.get("/vendors", headers=h)).text
    assert f"Alpha-enterprise-risk-{a['tag']}" in page
    assert own.status_code == 303
    assert other.status_code == 404
    risks_card = linked[linked.index('id="links-risk"') :].split("</section>", 1)[0]
    assert f"Alpha-enterprise-risk-{a['tag']}" in risks_card
    # The vendor's open risks: its enterprise risk, not Bravo's stray one.
    row = vendors[vendors.index(f"<strong>Alpha-vendor-{a['tag']}</strong>") :].split("</tr>", 1)[0]
    assert 'data-open-risks="1"' in row
    assert "Bravo" not in vendors


# ── pinned by the mutation check ─────────────────────────────────────────────


async def _second(a: dict[str, Any]) -> dict[str, int]:
    """A second contract and project in Alpha, each with a child of its own."""
    async with session_scope() as s:
        c2 = VendorContract(
            organization_id=a["org"], vendor_id=a["vendor"], title="second", status="active"
        )
        p2 = Project(organization_id=a["org"], name=f"Alpha-second-project-{a['tag']}")
        s.add_all([c2, p2])
        await s.flush()
        ob2 = ContractObligation(
            organization_id=a["org"], contract_id=c2.id, description=f"Alpha-ob2-{a['tag']}"
        )
        ln2 = ProjectLink(
            organization_id=a["org"],
            project_id=p2.id,
            entity_type="poam",
            entity_id=str(a["poam2"]),
        )
        s.add_all([ob2, ln2])
        await s.flush()
        return {"contract": c2.id, "ob": ob2.id, "project": p2.id, "link": ln2.id}


async def test_a_child_shows_and_moves_only_under_its_own_parent(two_orgs) -> None:
    """Same organization, other parent: a contract page lists only its own
    obligations, a project only its own links; a link is removed only through
    its own project; linking a record another project already has still links it."""
    a, _ = two_orgs
    two = await _second(a)
    h = _auth(a["tokens"]["admin"])
    async with _client() as c:
        contract = (await c.get(f"/contracts/{a['contract']}", headers=h)).text
        project = (await c.get(f"/projects/{a['project']}", headers=h)).text
        cross_unlink = await c.post(
            f"/projects/{a['project']}/links/{two['link']}/delete", headers=h
        )
        relink = await c.post(
            f"/projects/{a['project']}/links",
            data={"entity_type": "poam", "entity_id": str(a["poam2"])},
            headers=h,
        )
    assert f"Alpha-ob2-{a['tag']}" not in contract
    assert f"Alpha-contract-obligation-{a['tag']}" in contract
    poams = project[project.index('id="links-poam"') :].split("</section>", 1)[0]
    assert f"Alpha-poam-two-{a['tag']}" not in poams.split("<tfoot>")[0].split("card__footer")[0]
    assert cross_unlink.status_code == 404
    assert relink.status_code == 303
    async with session_scope() as s:
        assert await s.get(ProjectLink, two["link"]) is not None
        mine = (
            (
                await s.execute(
                    select(ProjectLink.entity_id).where(ProjectLink.project_id == a["project"])
                )
            )
            .scalars()
            .all()
        )
    assert sorted(mine) == sorted([str(a["poam"]), str(a["poam2"])])


async def test_a_stored_link_to_another_orgs_record_never_renders_it(two_orgs) -> None:
    """``project_links.entity_id`` is a string the database cannot check; a
    row written around the API (an import) to Bravo's task or system shows as
    unavailable, never as Bravo's title."""
    a, b = two_orgs
    async with session_scope() as s:
        for etype, key in (("task", "task"), ("system", "system")):
            s.add(
                ProjectLink(
                    organization_id=a["org"],
                    project_id=a["project"],
                    entity_type=etype,
                    entity_id=str(b[key]),
                )
            )
    async with _client() as c:
        body = (await c.get(f"/projects/{a['project']}", headers=_auth(a["tokens"]["admin"]))).text
    assert "Bravo" not in body
    assert body.count("no longer available") >= 2


async def test_a_mis_owned_questionnaire_offers_no_gap(two_orgs) -> None:
    """``vendor_questionnaires`` has no parent trigger. A questionnaire owned
    by one organization about the other's vendor is offered to neither."""
    a, b = two_orgs
    async with session_scope() as s:
        for org, vendor, who in ((a["org"], b["vendor"], "x1"), (b["org"], a["vendor"], "x2")):
            q = VendorQuestionnaire(
                organization_id=org, vendor_id=vendor, name=f"Bravo-q-{who}", status="submitted"
            )
            s.add(q)
            await s.flush()
            s.add(
                QuestionnaireResponse(
                    questionnaire_id=q.id,
                    question_id="IR-01",
                    question_text=f"Bravo-misowned-{who}-{a['tag']}",
                    weight=1,
                    answer="no",
                )
            )
    async with _client() as c:
        body = (await c.get("/vendor-findings", headers=_auth(a["tokens"]["admin"]))).text
    assert f"Alpha-gap-question-{a['tag']}" in body
    assert "misowned" not in body


async def test_a_platform_session_cannot_raise_a_gap_across_organizations(two_orgs) -> None:
    """A global principal (auth off) skips the org filter on load; the gap
    route still refuses a questionnaire whose organization is not its
    vendor's, rather than handing the database a cross-org finding."""
    a, b = two_orgs
    async with session_scope() as s:
        q = VendorQuestionnaire(
            organization_id=b["org"], vendor_id=a["vendor"], name="misowned", status="submitted"
        )
        s.add(q)
        await s.flush()
        s.add(
            QuestionnaireResponse(
                questionnaire_id=q.id,
                question_id="IR-01",
                question_text="misowned",
                weight=1,
                answer="no",
            )
        )
        qid = q.id
    os.environ["CCF_AUTH_ENABLED"] = "false"
    get_settings.cache_clear()
    async with _client() as c:
        resp = await c.post(
            "/vendor-findings/from-gap", data={"questionnaire_id": str(qid), "question_id": "IR-01"}
        )
    assert resp.status_code == 404


async def test_a_risk_on_a_deleted_system_is_not_a_vendors_open_risk(two_orgs) -> None:
    a, _ = two_orgs
    async with session_scope() as s:
        (await s.get(Risk, a["gone_risk"])).vendor_id = a["vendor"]
    async with _client() as c:
        body = (await c.get("/vendors", headers=_auth(a["tokens"]["viewer"]))).text
    row = body[body.index(f"<strong>Alpha-vendor-{a['tag']}</strong>") :].split("</tr>", 1)[0]
    assert 'data-open-risks="1"' in row  # the enterprise risk only
