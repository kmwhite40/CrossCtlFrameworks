"""Crosswalk pages: the provider preview and a vendor's uploaded package.

Run on an RLS-cleared session, so only each route's own organization predicate
scopes it (a missing one would otherwise be masked; see
concord-rls-masks-tenant-tests). FedRAMP's sample package
(tests/fixtures/cr26_sample, CC0) is the input.
"""

from __future__ import annotations

import io
import itertools
import json
import os
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from markupsafe import escape
from openpyxl import load_workbook
from sqlalchemy import func, select
from sqlalchemy.exc import DBAPIError

from ccf.api.deps import get_session
from ccf.api.main import create_app
from ccf.api.routes import ui_crosswalk
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import get_session_factory, session_scope, set_session_tenant
from ccf.fedramp20x import crosswalk as xw
from ccf.models import AuditLog, Organization, System, User, Vendor
from ccf.models_cr26 import Cr26Document
from ccf.models_tprm import VendorCertDocument
from ccf.oscal.validation import validate_document

pytestmark = pytest.mark.usefixtures("fresh_engine")

SAMPLES = Path(__file__).parent / "fixtures" / "cr26_sample"
ROLES = ("admin", "control_owner", "assessor", "viewer")
_SEQ = itertools.count()


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


@pytest.fixture
def _auth_enabled():
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


async def _unscoped_session():
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


def _files() -> list[tuple[str, bytes]]:
    return [(f.name, f.read_bytes()) for f in sorted(SAMPLES.glob("*.json"))]


async def _org(label: str) -> dict[str, Any]:
    tag = f"xw{next(_SEQ)}x{os.getpid()}{os.urandom(2).hex()}"
    async with session_scope() as s:
        org = Organization(name=f"{label}-{tag}")
        s.add(org)
        await s.flush()
        users = {
            role: User(
                email=f"{label.lower()}-{role}-{tag}@xw.test",
                organization_id=org.id,
                role=role,
                active=True,
                password_hash=hash_password("pw"),
                api_token=new_api_token(),
            )
            for role in ROLES
        }
        vendor = Vendor(organization_id=org.id, name=f"{label}-VENDOR-{tag}")
        classed = System(organization_id=org.id, name=f"{label}-sys-{tag}", certification_class="C")
        unclassed = System(organization_id=org.id, name=f"{label}-noclass-{tag}")
        s.add_all([*users.values(), vendor, classed, unclassed])
        await s.flush()
        for sys_ in (classed, unclassed):
            for _name, data in _files():
                doc = json.loads(data)
                s.add(
                    Cr26Document(
                        organization_id=org.id,
                        system_id=sys_.id,
                        kind=xw.detect_kind(doc),
                        document=doc,
                        ruleset_version="2026-06-24",
                        is_valid=True,
                        validation_errors=[],
                    )
                )
        await s.flush()
        return {
            "org": org.id,
            "tag": tag,
            "vendor": vendor.id,
            "system": classed.id,
            "unclassed": unclassed.id,
            "tokens": {r: u.api_token for r, u in users.items()},
            "emails": {r: u.email for r, u in users.items()},
        }


@pytest.fixture
async def two_orgs(_auth_enabled) -> tuple[dict[str, Any], dict[str, Any]]:
    return await _org("Alpha"), await _org("Bravo")


async def _upload(c: AsyncClient, vid: int, token: str, files: list[tuple[str, bytes]]):
    return await c.post(
        f"/vendors/{vid}/fedramp-package",
        files=[("files", (n, d, "application/json")) for n, d in files],
        headers=_auth(token),
    )


async def _docs(vid: int) -> dict[str, VendorCertDocument]:
    async with session_scope() as s:
        await set_session_tenant(s, None)
        rows = (
            (await s.execute(select(VendorCertDocument).where(VendorCertDocument.vendor_id == vid)))
            .scalars()
            .all()
        )
    return {r.kind: r for r in rows}


# ── vendor packages ──────────────────────────────────────────────────────────


async def test_an_upload_is_recognised_validated_stored_and_audited(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        resp = await _upload(c, a["vendor"], a["tokens"]["control_owner"], _files())
    assert resp.status_code == 200 and "6 files stored." in resp.text
    docs = await _docs(a["vendor"])
    assert set(docs) == set(xw.PACKAGE_KINDS)
    assert all(d.is_valid and d.organization_id == a["org"] for d in docs.values())
    async with session_scope() as s:
        await set_session_tenant(s, None)
        events = (
            await s.execute(
                select(func.count()).where(
                    AuditLog.entity_type == "vendor_cert_document",
                    AuditLog.action == "create",
                    AuditLog.organization_id == a["org"],
                )
            )
        ).scalar_one()
    assert events == 6


async def test_a_second_upload_replaces_the_kind_and_says_so(two_orgs) -> None:
    a, _ = two_orgs
    sdr = next((n, d) for n, d in _files() if "security-decision" in n)
    async with _client() as c:
        await _upload(c, a["vendor"], a["tokens"]["admin"], [sdr])
        changed = json.loads(sdr[1])
        changed["securityControls"] = []
        await _upload(
            c, a["vendor"], a["tokens"]["admin"], [("sdr2.json", json.dumps(changed).encode())]
        )
    docs = await _docs(a["vendor"])
    assert list(docs) == ["sdr"] and docs["sdr"].filename == "sdr2.json"
    assert docs["sdr"].document["securityControls"] == []
    async with session_scope() as s:
        await set_session_tenant(s, None)
        actions = (
            (
                await s.execute(
                    select(AuditLog.action).where(
                        AuditLog.entity_type == "vendor_cert_document",
                        AuditLog.entity_id == str(docs["sdr"].id),
                    )
                )
            )
            .scalars()
            .all()
        )
    assert sorted(actions) == ["create", "update"]


async def test_a_schema_invalid_file_is_kept_with_its_verdict(two_orgs) -> None:
    a, _ = two_orgs
    sdr = json.loads(next(d for n, d in _files() if "security-decision" in n))
    sdr["keySecurityIndicators"][0]["ksiImplementationStatus"] = "Totally"
    async with _client() as c:
        await _upload(
            c, a["vendor"], a["tokens"]["admin"], [("bad.json", json.dumps(sdr).encode())]
        )
        page = (
            await c.get(
                f"/vendors/{a['vendor']}/fedramp-package", headers=_auth(a["tokens"]["admin"])
            )
        ).text
    doc = (await _docs(a["vendor"]))["sdr"]
    assert doc.is_valid is False and doc.validation_errors
    assert "schema error" in page


async def test_files_that_are_not_package_documents_are_refused_by_name(
    two_orgs, monkeypatch
) -> None:
    a, _ = two_orgs
    monkeypatch.setattr(ui_crosswalk, "MAX_FILE_BYTES", 2000)
    async with _client() as c:
        resp = await _upload(
            c,
            a["vendor"],
            a["tokens"]["admin"],
            [
                ("notes.txt", b"hello"),
                ("other.json", b'{"a": 1}'),
                ("huge.json", b"{" + b" " * 3000 + b"}"),
                ("nan.json", b'{"vulnerabilities": [], "reportPeriod": {"x": NaN}}'),
                ("nul.json", b'{"vulnerabilities": [], "reportPeriod": {"x": "a\\u0000b"}}'),
            ],
        )
    page = resp.text
    assert resp.status_code == 200 and "0 files stored." in page
    assert "notes.txt: not JSON" in page
    assert "other.json: not a FedRAMP certification package document" in page
    assert "huge.json: larger than" in page
    assert "nan.json: not JSON" in page
    assert "nul.json: contains a NUL character" in page
    assert await _docs(a["vendor"]) == {}


async def test_json_nested_too_deeply_is_refused_not_a_server_error(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        resp = await _upload(
            c, a["vendor"], a["tokens"]["admin"], [("deep.json", b"[" * 200000 + b"]" * 200000)]
        )
    assert resp.status_code == 200 and "deep.json: nested too deeply to read" in resp.text


async def test_one_bad_file_does_not_lose_the_good_ones(two_orgs) -> None:
    """A file jsonb would refuse used to fail the whole upload with a 500."""
    a, _ = two_orgs
    async with _client() as c:
        resp = await _upload(
            c,
            a["vendor"],
            a["tokens"]["admin"],
            [("nul.json", b'{"vulnerabilities": [], "reportPeriod": {"x": "\\u0000"}}'), *_files()],
        )
    assert resp.status_code == 200 and "6 files stored." in resp.text
    assert len(await _docs(a["vendor"])) == 6


async def test_a_second_file_of_the_same_kind_in_one_upload_is_refused(two_orgs) -> None:
    a, _ = two_orgs
    sdr = next((n, d) for n, d in _files() if "security-decision" in n)
    async with _client() as c:
        resp = await _upload(c, a["vendor"], a["tokens"]["admin"], [sdr, ("again.json", sdr[1])])
    assert "1 file stored." in resp.text
    assert "again.json: a second Security Decision Record in this upload" in resp.text
    assert (await _docs(a["vendor"]))["sdr"].filename == sdr[0]


async def test_the_upload_outcome_cannot_be_forged_by_a_link(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        page = (
            await c.get(
                f"/vendors/{a['vendor']}/fedramp-package?uploaded=6&refused=forged",
                headers=_auth(a["tokens"]["viewer"]),
            )
        ).text
    assert "files stored" not in page and "forged" not in page


@pytest.mark.parametrize("role", ["assessor", "viewer"])
async def test_only_the_third_party_write_roles_upload_or_remove(two_orgs, role: str) -> None:
    a, _ = two_orgs
    async with _client() as c:
        await _upload(c, a["vendor"], a["tokens"]["admin"], _files()[:1])
        kind = next(iter(await _docs(a["vendor"])))
        assert (await _upload(c, a["vendor"], a["tokens"][role], _files())).status_code == 403
        gone = await c.post(
            f"/vendors/{a['vendor']}/fedramp-package/{kind}/delete",
            headers=_auth(a["tokens"][role]),
        )
        assert gone.status_code == 403
        read = await c.get(
            f"/vendors/{a['vendor']}/fedramp-package", headers=_auth(a["tokens"][role])
        )
        assert read.status_code == 200
    assert len(await _docs(a["vendor"])) == 1


async def test_another_organizations_vendor_is_not_found_anywhere(two_orgs) -> None:
    a, b = two_orgs
    async with _client() as c:
        await _upload(c, b["vendor"], b["tokens"]["admin"], _files())
        h = _auth(a["tokens"]["admin"])
        assert (
            await c.get(f"/vendors/{b['vendor']}/fedramp-package", headers=h)
        ).status_code == 404
        assert (await _upload(c, b["vendor"], a["tokens"]["admin"], _files())).status_code == 404
        assert (
            await c.post(f"/vendors/{b['vendor']}/fedramp-package/sdr/delete", headers=h)
        ).status_code == 404
        assert (
            await c.get(
                f"/vendors/{b['vendor']}/fedramp-package/export/controls.csv?cls=C", headers=h
            )
        ).status_code == 404
        index = (await c.get("/vendors/fedramp-packages", headers=h)).text
    assert f"Bravo-VENDOR-{b['tag']}" not in index and f"Alpha-VENDOR-{a['tag']}" in index
    assert len(await _docs(b["vendor"])) == 6


async def test_a_row_cannot_point_at_another_organizations_vendor(two_orgs) -> None:
    a, b = two_orgs
    with pytest.raises(DBAPIError, match="same organization"):
        async with session_scope() as s:
            await set_session_tenant(s, None)
            s.add(
                VendorCertDocument(
                    organization_id=a["org"],
                    vendor_id=b["vendor"],
                    kind="sdr",
                    document={},
                    filename="x",
                    sha256="0" * 64,
                    size_bytes=2,
                    is_valid=False,
                    validation_errors=[],
                    uploaded_by="x",
                )
            )
            await s.flush()


async def test_nothing_is_computed_until_a_class_is_chosen(two_orgs) -> None:
    a, _ = two_orgs
    h = _auth(a["tokens"]["viewer"])
    async with _client() as c:
        await _upload(c, a["vendor"], a["tokens"]["admin"], _files())
        before = (await c.get(f"/vendors/{a['vendor']}/fedramp-package", headers=h)).text
        after = (await c.get(f"/vendors/{a['vendor']}/fedramp-package?cls=C", headers=h)).text
        refused = (await c.get(f"/vendors/{a['vendor']}/fedramp-package?cls=A", headers=h)).text
        csv_text = (
            await c.get(
                f"/vendors/{a['vendor']}/fedramp-package/export/determinations.csv?cls=C", headers=h
            )
        ).text
        no_class = await c.get(
            f"/vendors/{a['vendor']}/fedramp-package/export/controls.csv", headers=h
        )
    assert "Partly reported" not in before and "does not state its certification class" in before
    # Not choosing yet is not an error: no refusal is shown before a choice.
    assert "Rev5 control baseline for Class" not in before
    model = xw.build_model(
        {k: json.loads(d) for k, d in ((xw.detect_kind(json.loads(d)), d) for _, d in _files())},
        "C",
    )
    assert f"of {model.total} Class C controls" in after
    assert "Rev5 control baseline for Class" in refused
    assert csv_text.lstrip("﻿").startswith('"Control","Title","Coverage"')
    assert no_class.status_code == 409


async def test_removing_a_document_is_audited(two_orgs) -> None:
    a, _ = two_orgs
    async with _client() as c:
        await _upload(c, a["vendor"], a["tokens"]["admin"], _files())
        resp = await c.post(
            f"/vendors/{a['vendor']}/fedramp-package/sdr/delete",
            headers=_auth(a["tokens"]["control_owner"]),
        )
    assert resp.status_code == 303
    assert "sdr" not in await _docs(a["vendor"])  # removal still redirects (no outcome to show)
    async with session_scope() as s:
        await set_session_tenant(s, None)
        deleted = (
            await s.execute(
                select(func.count()).where(
                    AuditLog.entity_type == "vendor_cert_document",
                    AuditLog.action == "delete",
                    AuditLog.organization_id == a["org"],
                )
            )
        ).scalar_one()
    assert deleted == 1


# ── provider preview ─────────────────────────────────────────────────────────


async def test_the_preview_reads_the_systems_own_documents_at_its_recorded_class(two_orgs) -> None:
    a, _ = two_orgs
    h = _auth(a["tokens"]["viewer"])
    async with _client() as c:
        page = (await c.get(f"/systems/{a['system']}/agency-view?cls=D", headers=h)).text
        csv_resp = await c.get(f"/systems/{a['system']}/agency-view/export/register.csv", headers=h)
    assert "of 322 Class C controls" in page  # the recorded class wins over ?cls
    assert "assumed, not recorded" not in page
    assert csv_resp.status_code == 200 and "MOCP-VULN-2026-0131" in csv_resp.text


async def test_an_unclassed_system_is_previewed_only_as_a_stated_assumption(two_orgs) -> None:
    a, _ = two_orgs
    h = _auth(a["tokens"]["viewer"])
    async with _client() as c:
        bare = (await c.get(f"/systems/{a['unclassed']}/agency-view", headers=h)).text
        assumed = (await c.get(f"/systems/{a['unclassed']}/agency-view?cls=B", headers=h)).text
    assert "No certification class is recorded" in bare and "Class B controls" not in bare
    assert "of 155 Class B controls" in assumed and "assumed, not recorded" in assumed


async def test_another_organizations_system_is_not_previewed(two_orgs) -> None:
    a, b = two_orgs
    h = _auth(a["tokens"]["admin"])
    async with _client() as c:
        assert (await c.get(f"/systems/{b['system']}/agency-view", headers=h)).status_code == 404
        assert (
            await c.get(f"/systems/{b['system']}/agency-view/export/controls.csv", headers=h)
        ).status_code == 404
        index = (await c.get("/fedramp20x/agency-view", headers=h)).text
    assert f"Bravo-sys-{b['tag']}" not in index and f"Alpha-sys-{a['tag']}" in index


async def test_an_unscoped_session_is_told_rather_than_shown_every_tenant() -> None:
    await _org("Uns")
    async with _client() as c:  # auth off: no organization
        for path in ("/fedramp20x/agency-view", "/vendors/fedramp-packages"):
            resp = await c.get(path)
            assert resp.status_code == 200 and "No organization in scope" in resp.text, path


async def test_the_preview_applies_the_systems_recorded_path(two_orgs) -> None:
    a, _ = two_orgs
    async with session_scope() as s:
        await set_session_tenant(s, None)
        (await s.get(System, a["system"])).certification_path = "program"
    async with _client() as c:
        page = (
            await c.get(f"/systems/{a['system']}/agency-view", headers=_auth(a["tokens"]["viewer"]))
        ).text
    assert "Program path" in page
    assert "the certification path is not known" not in page


# ── overview, schema errors and exports ──────────────────────────────────────

EXPORT_TYPES = {
    "review.xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "report.html": "text/html",
    "controls.csv": "text/csv",
    "determinations.csv": "text/csv",
    "register.csv": "text/csv",
    "oscal-ssp.json": "application/json",
    "oscal-poam.json": "application/json",
}


def test_every_export_is_listed_here() -> None:
    assert set(EXPORT_TYPES) == set(ui_crosswalk.EXPORTS)


def _bases(a: dict[str, Any]) -> list[str]:
    return [
        f"/vendors/{a['vendor']}/fedramp-package/export",
        f"/systems/{a['system']}/agency-view/export",
    ]


async def test_a_viewer_downloads_every_export_on_both_pages_but_cannot_upload(two_orgs) -> None:
    a, _ = two_orgs
    h = _auth(a["tokens"]["viewer"])
    async with _client() as c:
        await _upload(c, a["vendor"], a["tokens"]["admin"], _files())
        for base in _bases(a):
            for name, ctype in EXPORT_TYPES.items():
                resp = await c.get(f"{base}/{name}?cls=C", headers=h)
                assert resp.status_code == 200, (base, name, resp.text[:200])
                assert resp.headers["content-type"].startswith(ctype), name
                disposition = resp.headers["content-disposition"]
                assert disposition.startswith("attachment;") and disposition.endswith(
                    f'-class-c.{name.rsplit(".", 1)[1]}"'
                )
        assert (await _upload(c, a["vendor"], a["tokens"]["viewer"], _files())).status_code == 403


async def test_the_exports_carry_the_notice_and_validate(two_orgs) -> None:
    a, _ = two_orgs
    h = _auth(a["tokens"]["viewer"])
    base = f"/vendors/{a['vendor']}/fedramp-package/export"
    async with _client() as c:
        await _upload(c, a["vendor"], a["tokens"]["admin"], _files())
        got = {n: await c.get(f"{base}/{n}?cls=C", headers=h) for n in EXPORT_TYPES}
    for name, kind in (("oscal-ssp.json", "ssp"), ("oscal-poam.json", "poam")):
        doc = got[name].json()
        report = validate_document(doc, kind)
        assert report.mode == "official" and report.ok, report.errors[:5]
        assert xw.NOTICE in json.dumps(doc)
    report = got["report.html"]
    notice = str(escape(xw.NOTICE))
    # At the head, before any control, and again at the end.
    assert report.text.count(notice) == 2 and "AC Access Control" in report.text
    assert report.text.index(notice) < report.text.index("<h2>")
    assert "default-src 'none'" in report.headers["content-security-policy"]
    assert "<script" not in report.text.lower() and "<link" not in report.text.lower()
    wb = load_workbook(io.BytesIO(got["review.xlsx"].content))
    assert wb.sheetnames[0] == "Summary"
    assert xw.NOTICE in [r[1] for r in wb["Summary"].iter_rows(values_only=True)]


async def test_package_text_in_the_report_is_escaped(two_orgs) -> None:
    a, _ = two_orgs
    cpo = json.loads(next(d for n, d in _files() if "overview" in n))
    cpo["serviceIdentification"]["serviceName"] = "<script>alert(1)</script>"
    async with _client() as c:
        await _upload(
            c, a["vendor"], a["tokens"]["admin"], [("cpo.json", json.dumps(cpo).encode())]
        )
        report = await c.get(
            f"/vendors/{a['vendor']}/fedramp-package/export/report.html?cls=C",
            headers=_auth(a["tokens"]["viewer"]),
        )
        page = await c.get(
            f"/vendors/{a['vendor']}/fedramp-package?cls=C", headers=_auth(a["tokens"]["viewer"])
        )
    assert "<script>alert(1)</script>" not in report.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in report.text
    assert "<script>alert(1)</script>" not in page.text


async def test_another_organizations_exports_are_not_found(two_orgs) -> None:
    a, b = two_orgs
    h = _auth(a["tokens"]["admin"])
    async with _client() as c:
        await _upload(c, b["vendor"], b["tokens"]["admin"], _files())
        for base in _bases(b):
            for name in EXPORT_TYPES:
                resp = await c.get(f"{base}/{name}?cls=C", headers=h)
                assert resp.status_code == 404, (base, name)
        # and a name that is not an export is not found either
        for own in _bases(a):
            assert (await c.get(f"{own}/secrets.txt?cls=C", headers=h)).status_code == 404


async def test_register_and_poam_exports_are_refused_without_vulnerability_files(two_orgs) -> None:
    a, _ = two_orgs
    h = _auth(a["tokens"]["viewer"])
    sdr = next((n, d) for n, d in _files() if "security-decision" in n)
    base = f"/vendors/{a['vendor']}/fedramp-package"
    async with _client() as c:
        await _upload(c, a["vendor"], a["tokens"]["admin"], [sdr])
        page = (await c.get(f"{base}?cls=C", headers=h)).text
        refused = {
            n: await c.get(f"{base}/export/{n}?cls=C", headers=h)
            for n in ("register.csv", "oscal-poam.json")
        }
        kept = await c.get(f"{base}/export/review.xlsx?cls=C", headers=h)
    for resp in refused.values():
        assert resp.status_code == 409 and "holds none" in resp.json()["detail"]
    assert kept.status_code == 200
    assert "not available" in page and "nothing to export" in page
    assert f'href="{base}/export/oscal-poam.json' not in page
    assert f'href="{base}/export/oscal-ssp.json?cls=C"' in page


async def test_a_poam_is_refused_when_the_files_list_no_vulnerabilities(two_orgs) -> None:
    a, _ = two_orgs
    h = _auth(a["tokens"]["viewer"])
    vdr = json.loads(next(d for n, d in _files() if "vulnerability-detail" in n))
    vdr["vulnerabilities"] = []
    base = f"/vendors/{a['vendor']}/fedramp-package"
    async with _client() as c:
        await _upload(
            c, a["vendor"], a["tokens"]["admin"], [("vdr.json", json.dumps(vdr).encode())]
        )
        page = (await c.get(f"{base}?cls=C", headers=h)).text
        poam = await c.get(f"{base}/export/oscal-poam.json?cls=C", headers=h)
        register = await c.get(f"{base}/export/register.csv?cls=C", headers=h)
    assert poam.status_code == 409 and "list no vulnerabilities" in poam.json()["detail"]
    assert register.status_code == 200  # a header-only register is true: none listed
    assert "vulnerability files list no vulnerabilities" in page


async def test_both_pages_show_the_overview_and_the_latest_ongoing_report(two_orgs) -> None:
    a, _ = two_orgs
    h = _auth(a["tokens"]["viewer"])
    async with _client() as c:
        await _upload(c, a["vendor"], a["tokens"]["admin"], _files())
        pages = [
            (await c.get(f"/vendors/{a['vendor']}/fedramp-package", headers=h)).text,
            (await c.get(f"/systems/{a['system']}/agency-view", headers=h)).text,
        ]
    for page in pages:
        for text in (
            "Government-Only Cloud",
            "Beacon Assurance Partners, LLC",
            "2026-10-15",
            'href="https://trust.meridianfed.com/mocp"',
            "F0009182736",
            "SendSecure Notifications",
            "Latest ongoing report",
            "2026-04-01 to 2026-06-30",
            "Changes planned through 2026-12-31",
            "credential-stuffing",
            "Reduced the automated account-lockout threshold",
            "Small Business Administration",
            "One accepted vulnerability remains open",
        ):
            assert text in page, text
        # Transformative changes: the report lists none, and the page says so.
        assert 'Transformative changes</dt><dd><span class="dim">none reported' in page


async def test_a_non_http_url_in_the_package_is_never_a_link(two_orgs) -> None:
    a, _ = two_orgs
    cpo = json.loads(next(d for n, d in _files() if "overview" in n))
    cpo["serviceProperties"]["trustCenter"]["url"] = "javascript:alert(document.cookie)"
    cpo["thirdPartyInformationResources"]["nonCertified"][0]["website"] = "data:text/html,x"
    async with _client() as c:
        await _upload(
            c, a["vendor"], a["tokens"]["admin"], [("cpo.json", json.dumps(cpo).encode())]
        )
        page = (
            await c.get(
                f"/vendors/{a['vendor']}/fedramp-package", headers=_auth(a["tokens"]["viewer"])
            )
        ).text
    assert "javascript:alert(document.cookie)" in page  # shown, as text
    assert 'href="javascript:' not in page and 'href="data:' not in page


async def test_each_schema_error_is_listed_with_its_path(two_orgs) -> None:
    a, _ = two_orgs
    sdr = json.loads(next(d for n, d in _files() if "security-decision" in n))
    sdr["keySecurityIndicators"] = [
        {**sdr["keySecurityIndicators"][0], "ksiImplementationStatus": "Totally"} for _ in range(30)
    ]
    async with _client() as c:
        await _upload(
            c, a["vendor"], a["tokens"]["admin"], [("bad.json", json.dumps(sdr).encode())]
        )
        page = (
            await c.get(
                f"/vendors/{a['vendor']}/fedramp-package", headers=_auth(a["tokens"]["viewer"])
            )
        ).text
    errors = (await _docs(a["vendor"]))["sdr"].validation_errors
    assert len(errors) > xw.SHOWN_ERRORS
    path, _, _message = errors[0].partition(": ")
    assert f'<span class="mono">{path}</span>' in page
    assert f"and {len(errors) - xw.SHOWN_ERRORS} more" in page
    if len(errors) == ui_crosswalk.KEPT_ERRORS:
        assert f"at least {len(errors)} schema errors" in page
    else:
        assert f"{len(errors)} schema errors" in page and "at least" not in page


async def test_a_capped_error_list_is_not_shown_as_an_exact_count(two_orgs) -> None:
    a, _ = two_orgs
    sdr = json.loads(next(d for n, d in _files() if "security-decision" in n))
    sdr["keySecurityIndicators"] = [
        {**sdr["keySecurityIndicators"][0], "ksiImplementationStatus": "Totally"} for _ in range(80)
    ]
    async with _client() as c:
        await _upload(
            c, a["vendor"], a["tokens"]["admin"], [("bad.json", json.dumps(sdr).encode())]
        )
        page = (
            await c.get(
                f"/vendors/{a['vendor']}/fedramp-package", headers=_auth(a["tokens"]["viewer"])
            )
        ).text
    assert len((await _docs(a["vendor"]))["sdr"].validation_errors) == ui_crosswalk.KEPT_ERRORS
    assert f"at least {ui_crosswalk.KEPT_ERRORS} schema errors" in page
