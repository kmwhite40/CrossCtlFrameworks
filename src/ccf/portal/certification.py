"""FedRAMP Certification Data through the portal (CDS-TRC-PAC, -HMR, -USH).

A grant can cover one or more systems' certification data: the CR26
deliverables :mod:`ccf.cr26.store` holds (SDR, CPO, OCR, VDR, AVI, VER
history, incident reports, significant change notifications). A token holder
lists and fetches them as JSON, or as Markdown generated from that same JSON.

Three rules:

* **Only schema-valid documents are shared.** A stored document can be a
  draft that fails FedRAMP's schema (``cr26.store`` keeps drafts on purpose).
  Handing one to an agency as certification data would present an
  incomplete record as a filed one, so it is withheld -- and the listing says
  how many were withheld, rather than implying there are none.
* **The two formats cannot disagree** (CDS-CSO-CBF). The Markdown is rendered
  by code from the JSON, never authored separately, and both carry the
  SHA-256 of the canonical JSON they came from, so a reader can check it.
* **Scope is the grant's, re-checked on every read.** A system not in the
  grant -- or one deleted since the grant was issued -- answers exactly as a
  missing document does, and the attempt is logged as ``denied``.

See docs/superpowers/specs/2026-11-05-trust-center-cds-design.md.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..cr26.store import DELIVERABLE_KINDS
from ..db import set_session_tenant
from ..models import System
from ..models_cr26 import CertificationSnapshotDocument, Cr26Document
from ..models_portal import ExternalAccessGrant

#: What each deliverable kind is called on the page and in the Markdown.
KIND_TITLES: dict[str, str] = {
    "cpo": "Certification Package Overview",
    "sdr": "Security Decision Record",
    "ocr": "Ongoing Certification Report",
    "vdr": "Vulnerability Detail Report",
    "avi": "Accepted Vulnerability Info",
    "ver_history": "Historical Vulnerability Evaluation and Reporting Activity",
    "incident": "Incident Report",
    "scn": "Significant Change Notification",
    "assessor": "Assessor Information",
    "advisor": "Advisor Information",
}


def shared_system_ids(grant: ExternalAccessGrant) -> list[int]:
    """The systems whose certification data ``grant`` covers."""
    raw = (grant.scope or {}).get("certification_system_ids") or []
    return [int(s) for s in raw]


def canonical_json(document: Any) -> bytes:
    """The bytes the digest is taken over: sorted keys, no whitespace."""
    return json.dumps(document, sort_keys=True, separators=(",", ":"), default=str).encode()


def digest(document: Any) -> str:
    return hashlib.sha256(canonical_json(document)).hexdigest()


@dataclass(frozen=True)
class Listing:
    documents: list[dict[str, Any]]
    #: Stored but failing FedRAMP's schema, so not shared.
    withheld_invalid: int


async def list_documents(session: AsyncSession, grant: ExternalAccessGrant) -> Listing:
    """Every valid certification document the grant covers, newest first."""
    await set_session_tenant(session, grant.organization_id)
    systems = shared_system_ids(grant)
    if not systems:
        return Listing([], 0)
    scope = (
        Cr26Document.system_id.in_(systems),
        Cr26Document.organization_id == grant.organization_id,
        Cr26Document.kind.in_(DELIVERABLE_KINDS),
    )
    rows = (
        await session.execute(
            select(Cr26Document, System.name)
            .join(System, System.id == Cr26Document.system_id)
            .where(System.deleted_at.is_(None))
            .where(*scope, Cr26Document.is_valid.is_(True))
            .order_by(Cr26Document.updated_at.desc(), Cr26Document.id.desc())
        )
    ).all()
    withheld = (
        await session.execute(
            select(func.count())
            .select_from(Cr26Document)
            .join(System, System.id == Cr26Document.system_id)
            .where(*scope, System.deleted_at.is_(None), Cr26Document.is_valid.is_(False))
        )
    ).scalar_one()
    return Listing([_summary(doc, name) for doc, name in rows], int(withheld))


def _summary(
    doc: Cr26Document | CertificationSnapshotDocument, system_name: str
) -> dict[str, Any]:
    path = f"/api/portal/certification-data/{doc.system_id}/{doc.kind}"
    if doc.document_key is not None:
        path += f"?key={doc.document_key}"
    sep = "&" if "?" in path else "?"
    return {
        "system_id": doc.system_id,
        "system": system_name,
        "kind": doc.kind,
        "title": KIND_TITLES.get(doc.kind, doc.kind),
        "document_key": doc.document_key,
        "schema_version": doc.schema_version,
        "ruleset_version": doc.ruleset_version,
        "updated_at": doc.updated_at,
        "sha256": digest(doc.document),
        "json_url": path,
        "markdown_url": f"{path}{sep}format=md",
    }


async def get_document(
    session: AsyncSession,
    grant: ExternalAccessGrant,
    *,
    system_id: int,
    kind: str,
    document_key: str | None,
) -> tuple[Cr26Document, str] | None:
    """One shared document and its system's name, or ``None`` if the grant
    cannot see it -- out of scope, missing, and invalid all answer the same."""
    await set_session_tenant(session, grant.organization_id)
    if system_id not in shared_system_ids(grant) or kind not in DELIVERABLE_KINDS:
        return None
    row = (
        await session.execute(
            select(Cr26Document, System.name)
            .join(System, System.id == Cr26Document.system_id)
            .where(System.deleted_at.is_(None))
            .where(
                Cr26Document.system_id == system_id,
                Cr26Document.organization_id == grant.organization_id,
                Cr26Document.kind == kind,
                Cr26Document.document_key.is_(None)
                if document_key is None
                else Cr26Document.document_key == document_key,
                Cr26Document.is_valid.is_(True),
            )
        )
    ).first()
    return None if row is None else (row[0], row[1])


def envelope(doc: Cr26Document, system_name: str) -> dict[str, Any]:
    """The JSON response: the document as stored, with what identifies it."""
    return {**_summary(doc, system_name), "document": doc.document}


# ── human-readable ───────────────────────────────────────────────────────


_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _label(key: str) -> str:
    words = _CAMEL.sub(" ", key).replace("_", " ").strip()
    return words[:1].upper() + words[1:]


def _scalar(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return str(value).replace("\n", " ")


def _is_scalar(value: Any) -> bool:
    return not isinstance(value, dict | list)


def _render(value: Any, label: str, depth: int, out: list[str]) -> None:
    heading = "#" * min(depth, 6)
    if isinstance(value, dict):
        out.append(f"\n{heading} {label}\n")
        scalars = [(k, v) for k, v in value.items() if _is_scalar(v)]
        nested = [(k, v) for k, v in value.items() if not _is_scalar(v)]
        out.extend(f"- **{_label(k)}:** {_scalar(v)}" for k, v in scalars)
        for k, v in nested:
            _render(v, _label(k), depth + 1, out)
    elif isinstance(value, list):
        out.append(f"\n{heading} {label}\n")
        if not value:
            out.append("_None._")
        elif all(_is_scalar(v) for v in value):
            out.extend(f"- {_scalar(v)}" for v in value)
        else:
            for i, item in enumerate(value, 1):
                _render(item, f"{label} {i}", depth + 1, out)
    else:
        out.append(f"- **{label}:** {_scalar(value)}")


def to_markdown(
    doc: Cr26Document | CertificationSnapshotDocument,
    system_name: str,
    *,
    context: list[str] | None = None,
) -> str:
    """The document as Markdown, generated from its JSON and nothing else.

    Every key and value in the JSON appears, in the JSON's own order; nothing
    is summarised or dropped, so the two formats say the same thing. A
    snapshot's document renders the same way; ``context`` adds lines saying
    which snapshot it is.
    """
    meta = _summary(doc, system_name)
    out = [
        f"# {meta['title']}: {system_name}",
        "",
        *(context or []),
        f"- **System ID:** {doc.system_id}",
        f"- **Kind:** {doc.kind}",
    ]
    if doc.document_key is not None:
        out.append(f"- **Document key:** {doc.document_key}")
    out += [
        f"- **Schema version:** {_scalar(doc.schema_version)}",
        f"- **FedRAMP rules version:** {doc.ruleset_version}",
        f"- **Updated:** {doc.updated_at.isoformat() if doc.updated_at else '—'}",
        f"- **SHA-256 of the JSON this was generated from:** `{meta['sha256']}`",
    ]
    body: list[str] = []
    for key, value in (doc.document or {}).items():
        _render(value, _label(key), 2, body)
    return "\n".join(out + body) + "\n"
