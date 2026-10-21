"""Generic import/export — registers to CSV / JSON / Markdown (item 13).

Extensible: register a dataset by adding a loader that returns a list of flat
dict rows. Rendering to csv/json/md is shared. Heavy DOCX/PDF stays in the SSP
and reports modules; this is the lightweight, scriptable path.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import date
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..constants import (
    POAM_ACTIVE_STATUSES,
    POAM_CLOSED_STATUSES,
    POAM_STATUSES,
    poam_leaves_risk_accepted,
)
from ..models import POAM, Policy, Risk, System, Vendor
from .risk import band, compute_scores, resolve_axis, risk_in_scope

FORMATS = ("csv", "json", "md")


def _org_systems(org_id: int | None) -> Any:
    q = select(System.id)
    return q if org_id is None else q.where(System.organization_id == org_id)


async def _poams(session: AsyncSession, org_id: int | None) -> list[dict[str, Any]]:
    stmt = select(POAM).order_by(POAM.id)
    if org_id is not None:
        stmt = stmt.where(POAM.system_id.in_(_org_systems(org_id)))
    return [
        {
            "id": p.id,
            "title": p.title,
            "severity": p.severity,
            "status": p.status,
            "source": p.source,
            "identified_on": p.identified_on,
            "due_on": p.due_on,
            "scheduled_completion": p.scheduled_completion,
            "point_of_contact": p.point_of_contact,
        }
        for p in (await session.execute(stmt)).scalars().all()
    ]


async def _risks(session: AsyncSession, org_id: int | None) -> list[dict[str, Any]]:
    stmt = select(Risk).order_by(Risk.id)
    if org_id is not None:
        # Enterprise risks (no system) are the organization's too; the one
        # scope definition is governance.risk.risk_in_scope.
        stmt = stmt.where(risk_in_scope(org_id))
    return [
        {
            "id": r.id,
            "title": r.title,
            "category": r.category,
            "likelihood": r.likelihood,
            "likelihood_score": r.likelihood_score,
            "impact": r.impact,
            "impact_score": r.impact_score,
            "treatment": r.treatment,
            "status": r.status,
            "inherent_score": r.inherent_score,
            "residual_score": r.residual_score,
            "residual_band": band(r.residual_score),
        }
        for r in (await session.execute(stmt)).scalars().all()
    ]


async def _vendors(session: AsyncSession, org_id: int | None) -> list[dict[str, Any]]:
    stmt = select(Vendor).order_by(Vendor.name)
    if org_id is not None:
        stmt = stmt.where(Vendor.organization_id == org_id)
    return [
        {
            "id": v.id,
            "name": v.name,
            "criticality": v.criticality,
            "status": v.status,
            "risk_rating": v.risk_rating,
            "authorization": v.authorization,
            "last_reviewed_on": v.last_reviewed_on,
            "next_review_on": v.next_review_on,
        }
        for v in (await session.execute(stmt)).scalars().all()
    ]


async def _policies(session: AsyncSession, org_id: int | None) -> list[dict[str, Any]]:
    stmt = select(Policy).order_by(Policy.name)
    if org_id is not None:
        stmt = stmt.where(Policy.organization_id == org_id)
    return [
        {
            "id": p.id,
            "name": p.name,
            "category": p.category,
            "status": p.status,
            "review_frequency": p.review_frequency,
            "next_review_on": p.next_review_on,
        }
        for p in (await session.execute(stmt)).scalars().all()
    ]


DATASETS = {
    "poams": _poams,
    "risks": _risks,
    "vendors": _vendors,
    "policies": _policies,
}


def _render(rows: list[dict[str, Any]], fmt: str, dataset: str) -> tuple[bytes, str]:
    if fmt == "json":
        return json.dumps(rows, indent=2, default=str).encode(), "application/json"
    cols = list(rows[0].keys()) if rows else ["id"]
    if fmt == "md":
        out = [
            f"# {dataset} register\n",
            "| " + " | ".join(cols) + " |",
            "| " + " | ".join(["---"] * len(cols)) + " |",
        ]
        for r in rows:
            out.append("| " + " | ".join(str(r.get(c, "")) for c in cols) + " |")
        return ("\n".join(out) + "\n").encode(), "text/markdown"
    # csv
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow(r)
    return buf.getvalue().encode(), "text/csv"


async def export(
    session: AsyncSession, *, dataset: str, fmt: str, org_id: int | None = None
) -> tuple[bytes, str, str]:
    """Return (bytes, media_type, filename) for a dataset in the requested format."""
    if dataset not in DATASETS:
        raise ValueError(f"unknown dataset: {dataset}")
    if fmt not in FORMATS:
        raise ValueError(f"format must be one of {', '.join(FORMATS)}")
    rows = await DATASETS[dataset](session, org_id)
    content, media = _render(rows, fmt, dataset)
    ext = {"json": "json", "md": "md", "csv": "csv"}[fmt]
    return content, media, f"{dataset}.{ext}"


# --- import (round-trip: same datasets can be re-ingested) -------------------

IMPORT_FORMATS = ("csv", "json")

# Per-dataset import spec: model, required field, writable str fields, date
# fields, and how a new row is linked to the tenant. Numeric/derived columns
# (scores, bands) are recomputed, never trusted from the payload.
_IMPORT_SPEC: dict[str, dict[str, Any]] = {
    "poams": {
        "model": POAM,
        "required": "title",
        "str_fields": ["title", "severity", "status", "source", "point_of_contact"],
        "date_fields": ["identified_on", "due_on", "scheduled_completion"],
        "link": "system",
    },
    "risks": {
        "model": Risk,
        "required": "title",
        "str_fields": ["title", "category", "likelihood", "impact", "treatment", "status"],
        "date_fields": [],
        "link": "system",
    },
    "vendors": {
        "model": Vendor,
        "required": "name",
        "str_fields": ["name", "criticality", "status", "risk_rating", "authorization"],
        "date_fields": ["last_reviewed_on", "next_review_on"],
        "link": "org",
    },
    "policies": {
        "model": Policy,
        "required": "name",
        "str_fields": ["name", "category", "status", "review_frequency"],
        "date_fields": ["next_review_on"],
        "link": "org",
    },
}


def _parse_rows(content: bytes, fmt: str) -> list[dict[str, Any]]:
    text_in = content.decode("utf-8-sig")
    if fmt == "json":
        data = json.loads(text_in)
        if isinstance(data, dict):
            data = data.get("rows", data.get("data", [data]))
        if not isinstance(data, list):
            raise ValueError("JSON import must be a list of objects.")
        return [dict(r) for r in data]
    if fmt == "csv":
        return [dict(r) for r in csv.DictReader(io.StringIO(text_in))]
    raise ValueError(f"import format must be one of {', '.join(IMPORT_FORMATS)}")


def _coerce_date(value: Any) -> date | None:
    if value in (None, "", "None"):
        return None
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value)[:10])


def _clean(value: Any) -> str | None:
    if value in (None, "", "None"):
        return None
    return str(value).strip()


async def _first_system_id(session: AsyncSession, org_id: int | None) -> int | None:
    stmt = select(System.id).order_by(System.id).limit(1)
    if org_id is not None:
        stmt = stmt.where(System.organization_id == org_id)
    return (await session.execute(stmt)).scalars().first()


#: The statuses each register accepts, as its API validates them.
_IMPORT_STATUSES: dict[type, tuple[str, ...]] = {
    Risk: ("open", "mitigated", "accepted", "closed"),
    POAM: POAM_STATUSES,
}


def _gated_status_change(model: type, old: str | None, new: str) -> str | None:
    """Why an import may not make this status change, or None.

    Accepting a risk, and closing a POA&M, accepting its risk or reopening an
    accepted one, are each a decision the API makes only against a spent
    approval (``risks._require_acceptance_gate``, ``poams`` + ``approvals.consume``).
    A bulk file is not that decision: the row is refused and the record keeps
    its status. Re-importing an unchanged status is not a change."""
    if new == old:
        return None
    if model is Risk and new == "accepted":
        return "accepting a risk needs an approved review; accept it on the risk itself"
    if model is POAM and (
        new in POAM_CLOSED_STATUSES
        or new == "risk_accepted"
        or poam_leaves_risk_accepted(old or "", new)
    ):
        return f"moving a POA&M to {new!r} needs an approved review; change it on the POA&M itself"
    return None


def _apply_fields(obj: Any, row: dict[str, Any], spec: dict[str, Any]) -> None:
    model = spec["model"]
    if model in _IMPORT_STATUSES and "status" in row:
        new = _clean(row["status"])
        if new is not None:
            if new not in _IMPORT_STATUSES[model]:
                allowed = ", ".join(_IMPORT_STATUSES[model])
                raise ValueError(f"status must be one of {allowed}, not {new!r}")
            refused = _gated_status_change(model, getattr(obj, "status", None), new)
            if refused:
                raise ValueError(refused)
    if model is POAM and getattr(obj, "status", None) == "risk_accepted" and "due_on" in row:
        # ``due_on`` is the acceptance's expiry (the scanner keeps an accepted
        # POA&M accepted until it passes). The API spends an approval on any
        # change but a shortening (``poams._require_expiry_extension_gate``).
        new_due, held = _coerce_date(row["due_on"]), obj.due_on
        if new_due != held and not (new_due is not None and held is not None and new_due <= held):
            raise ValueError(
                "extending a risk acceptance's expiry (due_on) needs an approved review; "
                "change it on the POA&M itself"
            )
    if model is POAM and getattr(obj, "status", None) in POAM_ACTIVE_STATUSES and "due_on" in row:
        # An open weakness's due date moving later -- or cleared, which is the
        # same without a limit -- is a deviation the API takes only as an
        # extension the ISSM or AO decides (``ccf.ato.extensions``).
        new_status = _clean(row.get("status")) or obj.status
        new_due, held = _coerce_date(row["due_on"]), obj.due_on
        if (
            new_status in POAM_ACTIVE_STATUSES
            and held is not None
            and (new_due is None or new_due > held)
        ):
            raise ValueError(
                "moving an open POA&M's due date later needs an approved extension; "
                "request one on the POA&M itself"
            )
    for f in spec["str_fields"]:
        if f in row:
            if f == "status" and model in _IMPORT_STATUSES and _clean(row[f]) is None:
                continue  # a blank cell leaves the status as it is
            setattr(obj, f, _clean(row[f]))
    for f in spec["date_fields"]:
        if f in row:
            setattr(obj, f, _coerce_date(row[f]))
    if spec["model"] is Risk:
        # The 1-5 score is the source of truth and the level follows it
        # (governance.risk.resolve_axis). An import that sets only the level
        # used to leave the score where it was, so the two could disagree and
        # the risk was placed by a score nobody had entered.
        for axis in ("likelihood", "impact"):
            raw = row.get(f"{axis}_score")
            try:
                score = int(raw) if raw is not None and raw != "" else None
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{axis}_score must be a whole number 1-5, not {raw!r}") from exc
            new_score, new_level = resolve_axis(
                axis=axis,
                score=score,
                level=getattr(obj, axis, None),
                current_score=getattr(obj, f"{axis}_score", None),
            )
            setattr(obj, f"{axis}_score", new_score)
            setattr(obj, axis, new_level)
        inherent, residual = compute_scores(
            obj.likelihood_score, obj.impact_score, getattr(obj, "treatment", None)
        )
        obj.inherent_score, obj.residual_score = inherent, residual


async def import_rows(
    session: AsyncSession, *, dataset: str, content: bytes, fmt: str, org_id: int | None = None
) -> dict[str, Any]:
    """Ingest CSV/JSON for a dataset. Upserts by ``id`` within the tenant scope.

    Returns a summary ``{created, updated, skipped, errors}``. Scores/bands are
    recomputed; the ``id`` column, if present, is used only to match an existing
    row (and ignored if it does not belong to the caller's org).
    """
    if dataset not in _IMPORT_SPEC:
        raise ValueError(f"dataset not importable: {dataset}")
    if fmt not in IMPORT_FORMATS:
        raise ValueError(f"import format must be one of {', '.join(IMPORT_FORMATS)}")
    spec = _IMPORT_SPEC[dataset]
    model, required, link = spec["model"], spec["required"], spec["link"]

    rows = _parse_rows(content, fmt)
    # Valid ids the caller may update (org-scoped).
    existing = await DATASETS[dataset](session, org_id)
    owned_ids = {r["id"] for r in existing}
    system_id = await _first_system_id(session, org_id) if link == "system" else None

    summary: dict[str, Any] = {"created": 0, "updated": 0, "skipped": 0, "errors": []}
    for i, row in enumerate(rows):
        try:
            if not _clean(row.get(required)):
                summary["skipped"] += 1
                summary["errors"].append(f"row {i + 1}: missing required '{required}'")
                continue
            raw_id = str(row.get("id") or "").strip()
            rid = int(raw_id) if raw_id.isdigit() else None
            if rid is not None and rid in owned_ids:
                obj = await session.get(model, rid)
                _apply_fields(obj, row, spec)
                summary["updated"] += 1
                continue
            obj = model()
            _apply_fields(obj, row, spec)
            if link == "system":
                if system_id is None:
                    summary["skipped"] += 1
                    summary["errors"].append(f"row {i + 1}: no system to attach to")
                    continue
                obj.system_id = system_id
            elif link == "org":
                obj.organization_id = org_id
            session.add(obj)
            summary["created"] += 1
        except (ValueError, TypeError) as exc:
            summary["skipped"] += 1
            summary["errors"].append(f"row {i + 1}: {exc}")

    await session.flush()
    summary["errors"] = summary["errors"][:20]  # cap noise
    return summary
