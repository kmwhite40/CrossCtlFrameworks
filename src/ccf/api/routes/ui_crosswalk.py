"""Crosswalk pages: a FedRAMP certification package read against the Rev5 baseline.

Two uses of one engine (:mod:`ccf.fedramp20x.crosswalk`):

* **Agency view preview** (``/fedramp20x/agency-view``, ``/systems/{id}/agency-view``):
  a system's own stored CR26 documents, as an agency reviewer will read them.
  Read-only.
* **Vendor packages** (``/vendors/fedramp-packages``, ``/vendors/{id}/fedramp-package``):
  a provider's package uploaded under Third-Party Risk, kept per vendor in
  ``vendor_cert_documents`` (migration 0121) and read the same way.

The class is never defaulted. The provider preview uses the system's recorded
Certification Class; without one, the page asks which class to preview *as*
and says it is an assumption. A vendor's package does not state its class, so
the reviewer chooses it and nothing is computed until they do.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...analytics.posture import org_system_subq
from ...auth import Principal
from ...cr26.validation import validate_document
from ...fedramp20x import crosswalk as xw
from ...models import System, Vendor
from ...models_cr26 import Cr26Document
from ...models_tprm import VendorCertDocument
from ..audit import record_event
from ..auth_deps import get_principal, require_role
from ..deps import get_session
from .systems import require_system_in_scope
from .ui import _principal_org, no_org_page, templates

router = APIRouter(include_in_schema=False)

PREVIEW_ACTIVE = "agency_view"
VENDOR_ACTIVE = "vendor_packages"

#: Who may upload or remove a vendor's package files: the third-party write roles.
UPLOAD_ROLES: tuple[str, ...] = ("admin", "control_owner")

#: Per file. A CR26 package file is a few hundred kilobytes; this is generous.
MAX_FILE_BYTES = 10 * 1024 * 1024

EXPORTS = {
    "controls": xw.control_rows,
    "determinations": xw.determination_rows,
    "register": xw.register_rows,
}


def _can(request: Request, *roles: str) -> bool:
    """Whether to offer a form; the route's own gate is what enforces it."""
    p = getattr(request.state, "principal", None)
    if p is None:
        return True
    return bool(getattr(p, "is_global", False) or getattr(p, "role", None) in roles)


def _class(raw: str | None) -> str | None:
    cls = (raw or "").strip().upper()
    return cls or None


def _model(
    pkg: dict[str, Any], cls: str | None, path: str | None = None
) -> tuple[xw.Model | None, str | None]:
    if cls is None or not any(pkg.get(k) for k in ("sdr", "cpo", "vdr", "avi", "ver_history")):
        return None, None
    try:
        return xw.build_model(pkg, cls, path=path), None
    except xw.CrosswalkError as exc:
        return None, str(exc)


def _csv(model: xw.Model, table: str, stem: str) -> Response:
    rows = EXPORTS[table](model)
    filename = f"{stem}-{table}-class-{model.cls.lower()}.csv"
    return Response(
        xw.to_csv(rows),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── provider preview ─────────────────────────────────────────────────────────


@router.get("/fedramp20x/agency-view", response_class=HTMLResponse)
async def agency_view_index(
    request: Request, session: AsyncSession = Depends(get_session)
) -> Response:
    org = _principal_org(request)
    if org is None:
        return no_org_page(request, PREVIEW_ACTIVE)
    systems = (
        (
            await session.execute(
                select(System).where(System.id.in_(org_system_subq(org))).order_by(System.name)
            )
        )
        .scalars()
        .all()
    )
    counts: dict[int, int] = {
        sid: n
        for sid, n in (
            await session.execute(
                select(Cr26Document.system_id, func.count())
                .where(
                    # The listed (already scoped) systems: one predicate, pinned there.
                    Cr26Document.system_id.in_([s.id for s in systems]),
                    Cr26Document.kind.in_(tuple(xw.PACKAGE_KINDS)),
                    Cr26Document.document_key.is_(None),
                )
                .group_by(Cr26Document.system_id)
            )
        ).all()
    }
    return templates.TemplateResponse(
        request,
        "agency_view_index.html",
        {"active": PREVIEW_ACTIVE, "systems": systems, "counts": counts, "notice": xw.NOTICE},
    )


async def _system_package(session: AsyncSession, system: System) -> dict[str, Any]:
    rows = (
        (
            await session.execute(
                select(Cr26Document).where(
                    Cr26Document.system_id == system.id,
                    Cr26Document.kind.in_(tuple(xw.PACKAGE_KINDS)),
                    Cr26Document.document_key.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    return {r.kind: r for r in rows}


@router.get("/systems/{sid}/agency-view", response_class=HTMLResponse)
async def agency_view_system(
    request: Request,
    sid: int,
    cls: str | None = Query(None, max_length=1),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> Response:
    system = await require_system_in_scope(session, sid, principal)
    docs = await _system_package(session, system)
    recorded = system.certification_class
    chosen = recorded or _class(cls)
    model, problem = _model(
        {k: r.document for k, r in docs.items()}, chosen, system.certification_path
    )
    return templates.TemplateResponse(
        request,
        "agency_view_system.html",
        {
            "active": PREVIEW_ACTIVE,
            "system": system,
            "docs": docs,
            "kinds": xw.PACKAGE_KINDS,
            "recorded_class": recorded,
            "assumed_class": None if recorded else chosen,
            "classes": xw.BASELINE_CLASSES,
            "model": model,
            "problem": problem,
            "states": xw.STATES,
            "notice": xw.NOTICE,
            "export_base": f"/systems/{system.id}/agency-view/export",
        },
    )


@router.get("/systems/{sid}/agency-view/export/{table}.csv")
async def agency_view_export(
    sid: int,
    table: str,
    cls: str | None = Query(None, max_length=1),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> Response:
    if table not in EXPORTS:
        raise HTTPException(404, "no such export")
    system = await require_system_in_scope(session, sid, principal)
    docs = await _system_package(session, system)
    model, problem = _model(
        {k: r.document for k, r in docs.items()},
        system.certification_class or _class(cls),
        system.certification_path,
    )
    if model is None:
        raise HTTPException(
            409, problem or "choose a certification class, and store package documents first"
        )
    return _csv(model, table, f"system-{system.id}")


# ── vendor packages ──────────────────────────────────────────────────────────


async def _vendor(session: AsyncSession, vid: int, org: int) -> Vendor:
    """The vendor iff it belongs to ``org``; a foreign and a missing one look alike."""
    vendor = (
        await session.execute(select(Vendor).where(Vendor.id == vid, Vendor.organization_id == org))
    ).scalar_one_or_none()
    if vendor is None:
        raise HTTPException(404, "vendor not found")
    return vendor


async def _vendor_docs(session: AsyncSession, vendor: Vendor) -> dict[str, VendorCertDocument]:
    rows = (
        (
            await session.execute(
                # ``vendor`` is already the caller's (``_vendor``); 0121's
                # parent-org trigger keeps every row in its vendor's organization.
                select(VendorCertDocument).where(VendorCertDocument.vendor_id == vendor.id)
            )
        )
        .scalars()
        .all()
    )
    return {r.kind: r for r in rows}


@router.get("/vendors/fedramp-packages", response_class=HTMLResponse)
async def vendor_packages_index(
    request: Request, session: AsyncSession = Depends(get_session)
) -> Response:
    org = _principal_org(request)
    if org is None:
        return no_org_page(request, VENDOR_ACTIVE)
    vendors = (
        (
            await session.execute(
                select(Vendor).where(Vendor.organization_id == org).order_by(Vendor.name)
            )
        )
        .scalars()
        .all()
    )
    rows = (
        await session.execute(
            select(
                VendorCertDocument.vendor_id, VendorCertDocument.kind, VendorCertDocument.is_valid
            ).where(VendorCertDocument.vendor_id.in_([v.id for v in vendors]))
        )
    ).all()
    held: dict[int, dict[str, bool]] = {}
    for vid, kind, ok in rows:
        held.setdefault(vid, {})[kind] = ok
    return templates.TemplateResponse(
        request,
        "vendor_packages_index.html",
        {
            "active": VENDOR_ACTIVE,
            "vendors": vendors,
            "held": held,
            "kinds": xw.PACKAGE_KINDS,
            "notice": xw.NOTICE,
        },
    )


@router.get("/vendors/{vid}/fedramp-package", response_class=HTMLResponse)
async def vendor_package(
    request: Request,
    vid: int,
    cls: str | None = Query(None, max_length=1),
    session: AsyncSession = Depends(get_session),
) -> Response:
    org = _principal_org(request)
    if org is None:
        return no_org_page(request, VENDOR_ACTIVE)
    vendor = await _vendor(session, vid, org)
    return await _vendor_page(request, session, vendor, _class(cls))


async def _vendor_page(
    request: Request,
    session: AsyncSession,
    vendor: Vendor,
    chosen: str | None,
    outcome: dict[str, Any] | None = None,
) -> Response:
    """The vendor's package page. ``outcome`` is an upload's result, rendered by
    the POST itself: a result read from the URL could be forged by a link."""
    docs = await _vendor_docs(session, vendor)
    model, problem = _model({k: r.document for k, r in docs.items()}, chosen)
    return templates.TemplateResponse(
        request,
        "vendor_package.html",
        {
            "active": VENDOR_ACTIVE,
            "vendor": vendor,
            "docs": docs,
            "kinds": xw.PACKAGE_KINDS,
            "chosen_class": chosen,
            "classes": xw.BASELINE_CLASSES,
            "model": model,
            "problem": problem,
            "states": xw.STATES,
            "notice": xw.NOTICE,
            "can_upload": _can(request, *UPLOAD_ROLES),
            "outcome": outcome,
            "export_base": f"/vendors/{vendor.id}/fedramp-package/export",
            "max_mb": MAX_FILE_BYTES // (1024 * 1024),
        },
    )


async def _read_limited(upload: UploadFile) -> bytes | None:
    """The file's bytes, or ``None`` when it is larger than :data:`MAX_FILE_BYTES`.

    Reads at most one byte past the limit, never the whole of an oversized file."""
    data = await upload.read(MAX_FILE_BYTES + 1)
    return None if len(data) > MAX_FILE_BYTES else data


@router.post("/vendors/{vid}/fedramp-package")
async def vendor_package_upload(
    request: Request,
    vid: int,
    files: list[UploadFile] = File(...),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*UPLOAD_ROLES)),
) -> Response:
    """Store each file under the kind its contents show, judged against FedRAMP's
    schema. An invalid file is kept with its verdict; a file that cannot be read
    as a package document, or a second file of a kind already in this upload,
    is refused and named back to the reviewer. The page is rendered here, with
    the outcome, rather than redirected to a URL that carries it."""
    org = principal.org_id
    if org is None:
        raise HTTPException(400, "this action needs an organization; sign in as a member of one")
    vendor = await _vendor(session, vid, org)
    docs = await _vendor_docs(session, vendor)
    stored: list[str] = []
    refused: list[str] = []
    seen: set[str] = set()
    for upload in files[:12]:
        name = (upload.filename or "file").replace("\n", " ")[:255]
        data = await _read_limited(upload)
        if data is None:
            refused.append(f"{name}: larger than {MAX_FILE_BYTES // (1024 * 1024)} MB")
            continue
        doc, why = _parse(data)
        if why is not None:
            refused.append(f"{name}: {why}")
            continue
        kind = xw.detect_kind(doc)
        if kind is None:
            refused.append(f"{name}: not a FedRAMP certification package document")
            continue
        if kind in seen:
            refused.append(
                f"{name}: a second {xw.PACKAGE_KINDS[kind]} in this upload; only the first is kept"
            )
            continue
        seen.add(kind)
        report = validate_document(doc, kind)
        row = docs.get(kind)
        before = row.sha256 if row is not None else None
        if row is None:
            row = VendorCertDocument(organization_id=org, vendor_id=vendor.id, kind=kind)
            session.add(row)
            docs[kind] = row
        row.document = doc
        row.filename = name
        row.sha256 = hashlib.sha256(data).hexdigest()
        row.size_bytes = len(data)
        row.is_valid = report.ok
        row.validation_errors = report.errors[:50]
        row.uploaded_by = principal.email
        await session.flush()
        await record_event(
            session,
            organization_id=org,
            actor=principal.email,
            action="create" if before is None else "update",
            entity_type="vendor_cert_document",
            entity_id=str(row.id),
            diff={
                "vendor_id": vendor.id,
                "kind": kind,
                "filename": name,
                "sha256": [before, row.sha256],
                "valid": report.ok,
            },
        )
        stored.append(f"{name}: {xw.PACKAGE_KINDS[kind]}")
    if files[12:]:
        refused.append(f"{len(files) - 12} more file(s): at most 12 per upload")
    await session.commit()
    return await _vendor_page(
        request, session, vendor, None, {"stored": stored, "refused": refused}
    )


def _refuse_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _parse(data: bytes) -> tuple[Any, str | None]:
    """(document, None), or (None, why) for a file that cannot be stored.

    Beyond "not JSON": NaN/Infinity (not JSON, and refused by jsonb), nesting
    deep enough to exhaust the parser, and a NUL character in any string
    (jsonb refuses ``\\u0000``). Each is refused here, by name, instead of
    failing the database write and losing every other file in the upload."""
    try:
        doc = json.loads(data.decode("utf-8-sig"), parse_constant=_refuse_constant)
    except (UnicodeDecodeError, ValueError):
        return None, "not JSON"
    except RecursionError:
        return None, "nested too deeply to read"
    stack: list[Any] = [doc]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                if "\x00" in key:
                    return None, "contains a NUL character, which cannot be stored"
                stack.append(value)
        elif isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, str) and "\x00" in node:
            return None, "contains a NUL character, which cannot be stored"
    return doc, None


@router.post("/vendors/{vid}/fedramp-package/{kind}/delete")
async def vendor_package_delete(
    vid: int,
    kind: str,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_role(*UPLOAD_ROLES)),
) -> RedirectResponse:
    org = principal.org_id
    if org is None:
        raise HTTPException(400, "this action needs an organization; sign in as a member of one")
    vendor = await _vendor(session, vid, org)
    row = (await _vendor_docs(session, vendor)).get(kind)
    if row is None:
        raise HTTPException(404, "document not found")
    await record_event(
        session,
        organization_id=org,
        actor=principal.email,
        action="delete",
        entity_type="vendor_cert_document",
        entity_id=str(row.id),
        diff={"vendor_id": vendor.id, "kind": kind, "filename": row.filename, "sha256": row.sha256},
    )
    await session.delete(row)
    await session.commit()
    return RedirectResponse(f"/vendors/{vendor.id}/fedramp-package", status_code=303)


@router.get("/vendors/{vid}/fedramp-package/export/{table}.csv")
async def vendor_package_export(
    request: Request,
    vid: int,
    table: str,
    cls: str | None = Query(None, max_length=1),
    session: AsyncSession = Depends(get_session),
) -> Response:
    if table not in EXPORTS:
        raise HTTPException(404, "no such export")
    org = _principal_org(request)
    if org is None:
        raise HTTPException(400, "this export needs an organization; sign in as a member of one")
    vendor = await _vendor(session, vid, org)
    docs = await _vendor_docs(session, vendor)
    model, problem = _model({k: r.document for k, r in docs.items()}, _class(cls))
    if model is None:
        raise HTTPException(
            409, problem or "choose a certification class, and upload package documents first"
        )
    return _csv(model, table, f"vendor-{vendor.id}")
