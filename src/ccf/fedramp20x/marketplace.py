"""The FedRAMP Marketplace as a reference for dependency status.

FedRAMP publishes its Marketplace daily at
``github.com/FedRAMP/marketplace-fedramp-gov-data`` (``data.json``, public
domain). Concord refreshes ``ccf.marketplace_products`` from it and, for a
dependency a person has linked to a product, shows the Marketplace record
beside the operator's recorded values and names every disagreement.

It never rewrites ``FedRAMPDependency.fedramp_status``: the recorded value may
be legitimately different (an agency ATO not yet listed), and replacing it
silently would erase that. See
docs/superpowers/specs/2026-10-15-fedramp-marketplace-design.md.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..logging import get_logger
from ..models import FedRAMPDependency, MarketplaceProduct

log = get_logger(__name__)

SOURCE_KEY = "fedramp_marketplace_data"
_DATA_DIR = Path(__file__).with_name("marketplace_data")
_SCHEMA_FILE = "data.schema.json"

#: Marketplace status -> the recorded vocabulary (DEPENDENCY_STATUSES).
#: "FedRAMP Ready" is a readiness assessment, not an authorization.
STATUS_MAP = {
    "FedRAMP Authorized": "authorized",
    "FedRAMP In Process": "in_process",
    "Agency In Process": "in_process",
    "FedRAMP Ready": "not_authorized",
}
IMPACT_MAP = {
    "Low": "low",
    "20x Low": "low",
    "LI-SaaS": "low",
    "Moderate": "moderate",
    "20x Moderate": "moderate",
    "High": "high",
}
#: "Program" (the 2026 program certification) has no recorded counterpart.
AUTH_TYPE_MAP = {"JAB": "jab", "Agency": "agency"}


class MarketplaceDataError(ValueError):
    """The fetched data is not what FedRAMP's schema says it is."""


def _schema() -> dict[str, Any]:
    manifest = json.loads((_DATA_DIR / "MANIFEST.json").read_text(encoding="utf-8"))
    body = (_DATA_DIR / _SCHEMA_FILE).read_bytes()
    want = manifest["files"][_SCHEMA_FILE]["sha256"]
    if hashlib.sha256(body).hexdigest() != want:
        raise MarketplaceDataError(f"vendored {_SCHEMA_FILE} does not match its MANIFEST pin")
    schema: dict[str, Any] = json.loads(body)
    return schema


def _date(raw: Any) -> date | None:
    if not isinstance(raw, str) or not raw[:4].isdigit():
        return None  # the data uses sentinels such as "Not Active"
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def parse(body: bytes) -> list[dict[str, Any]]:
    """Validate ``data.json`` against FedRAMP's schema and return product rows."""
    import jsonschema  # noqa: PLC0415

    try:
        doc = json.loads(body)
    except json.JSONDecodeError as exc:
        raise MarketplaceDataError(f"not JSON: {exc}") from exc
    errors = list(jsonschema.Draft7Validator(_schema()).iter_errors(doc))
    if errors:
        raise MarketplaceDataError(f"{len(errors)} schema violation(s); first: {errors[0].message}")
    products = doc["data"]["Products"]
    if not products:
        # An empty but schema-valid file would delist every product.
        raise MarketplaceDataError("the Marketplace lists no products; refusing to delist all")
    rows: list[dict[str, Any]] = []
    for p in products:
        rows.append(
            {
                "fedramp_id": str(p["id"]),
                "csp": str(p.get("csp") or ""),
                "cso": str(p.get("cso") or p.get("name") or ""),
                "status": str(p.get("status") or ""),
                "impact_level": p.get("impact_level") or None,
                "auth_type": p.get("auth_type") or None,
                "auth_date": _date(p.get("auth_date")),
                "independent_assessor": p.get("independent_assessor") or None,
                "service_model": list(p.get("service_model") or []),
                "deployment_model": p.get("deployment_model") or None,
                "leveraged_systems": list(p.get("leveraged_systems") or []),
            }
        )
    return rows


async def apply(
    session: AsyncSession, rows: list[dict[str, Any]], *, commit_sha: str | None
) -> dict[str, int]:
    """Upsert products; delist (never delete) what this refresh did not list."""
    now = datetime.now(UTC)
    existing = {
        p.fedramp_id: p for p in (await session.execute(select(MarketplaceProduct))).scalars()
    }
    created = updated = delisted = relisted = 0
    seen: set[str] = set()
    for row in rows:
        fid = row["fedramp_id"]
        seen.add(fid)
        product = existing.get(fid)
        if product is None:
            product = MarketplaceProduct(fedramp_id=fid)
            session.add(product)
            created += 1
        else:
            updated += 1
            if product.delisted_at is not None:
                relisted += 1
        for key, value in row.items():
            setattr(product, key, value)
        product.source_commit = commit_sha
        product.refreshed_at = now
        product.delisted_at = None
    for fid, product in existing.items():
        if fid not in seen and product.delisted_at is None:
            product.delisted_at = now
            delisted += 1
    await session.flush()
    return {
        "created": created,
        "updated": updated,
        "delisted": delisted,
        "relisted": relisted,
        "total": len(rows),
    }


async def refresh(session: AsyncSession) -> dict[str, Any]:
    """Poll the registered Marketplace source now (seeding it if absent).

    The same path the scheduler's ``poll_sources`` step takes daily -- one
    fetch, one ETag, one drift record -- so a manual refresh can never
    disagree with the automatic one about what was last applied.
    """
    from ..etl.sources import DEFAULT_SOURCES, check_source  # noqa: PLC0415
    from ..models import CatalogSource  # noqa: PLC0415

    source = (
        await session.execute(select(CatalogSource).where(CatalogSource.key == SOURCE_KEY))
    ).scalar_one_or_none()
    if source is None:
        spec = next(s for s in DEFAULT_SOURCES if s["key"] == SOURCE_KEY)
        source = CatalogSource(**spec)
        session.add(source)
        await session.flush()
    if not source.enabled:
        return {"status": "skipped", "reason": "source disabled"}
    check = await check_source(session, source)
    return {"status": check.status, **(check.detail or {})}


# --- comparing a dependency with its Marketplace record ---------------------


@dataclass(frozen=True)
class Finding:
    field: str
    recorded: str | None
    marketplace: str | None
    message: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "field": self.field,
            "recorded": self.recorded,
            "marketplace": self.marketplace,
            "message": self.message,
        }


def compare(dep: FedRAMPDependency, product: MarketplaceProduct | None) -> list[Finding]:
    """Every way the recorded values disagree with the linked Marketplace record."""
    if not dep.marketplace_id:
        return []
    if product is None:
        return [
            Finding(
                "marketplace_id",
                dep.marketplace_id,
                None,
                f"{dep.marketplace_id} is not a FedRAMP Marketplace product Concord holds.",
            )
        ]
    out: list[Finding] = []
    if product.delisted_at is not None:
        out.append(
            Finding(
                "listing",
                "listed",
                "delisted",
                f"FedRAMP no longer lists {product.cso} (since {product.delisted_at.date()}).",
            )
        )
    mapped = STATUS_MAP.get(product.status)
    recorded = dep.fedramp_status
    if recorded not in (None, "unknown") and mapped is not None and recorded != mapped:
        out.append(
            Finding(
                "fedramp_status",
                recorded,
                product.status,
                f"Recorded {recorded!r}; the Marketplace lists {product.status!r}.",
            )
        )
    impact = IMPACT_MAP.get(product.impact_level or "")
    if dep.impact_level and impact and dep.impact_level != impact:
        out.append(
            Finding(
                "impact_level",
                dep.impact_level,
                product.impact_level,
                f"Recorded impact {dep.impact_level!r}; the Marketplace lists "
                f"{product.impact_level!r}.",
            )
        )
    auth = AUTH_TYPE_MAP.get(product.auth_type or "")
    if (
        dep.authorization_level in AUTH_TYPE_MAP.values()
        and auth
        and auth != dep.authorization_level
    ):
        out.append(
            Finding(
                "authorization_level",
                dep.authorization_level,
                product.auth_type,
                f"Recorded {dep.authorization_level!r} authorization; the Marketplace lists "
                f"{product.auth_type!r}.",
            )
        )
    return out


def product_out(product: MarketplaceProduct) -> dict[str, Any]:
    return {
        "fedramp_id": product.fedramp_id,
        "csp": product.csp,
        "cso": product.cso,
        "status": product.status,
        "impact_level": product.impact_level,
        "auth_type": product.auth_type,
        "auth_date": product.auth_date.isoformat() if product.auth_date else None,
        "independent_assessor": product.independent_assessor,
        "service_model": list(product.service_model or []),
        "deployment_model": product.deployment_model,
        "leveraged_systems": list(product.leveraged_systems or []),
        "source_commit": product.source_commit,
        "refreshed_at": product.refreshed_at.isoformat() if product.refreshed_at else None,
        "delisted_at": product.delisted_at.isoformat() if product.delisted_at else None,
        "url": f"https://marketplace.fedramp.gov/products/{product.fedramp_id}",
    }


async def products_by_id(session: AsyncSession, ids: set[str]) -> dict[str, MarketplaceProduct]:
    if not ids:
        return {}
    rows = (
        await session.execute(
            select(MarketplaceProduct).where(MarketplaceProduct.fedramp_id.in_(ids))
        )
    ).scalars()
    return {p.fedramp_id: p for p in rows}


async def search(session: AsyncSession, q: str, *, limit: int = 20) -> list[MarketplaceProduct]:
    """Products whose ID, provider or offering matches ``q`` (case-insensitive)."""
    term = f"%{q.strip()}%"
    stmt = (
        select(MarketplaceProduct)
        .where(
            or_(
                MarketplaceProduct.fedramp_id.ilike(term),
                MarketplaceProduct.csp.ilike(term),
                MarketplaceProduct.cso.ilike(term),
            )
        )
        .order_by(MarketplaceProduct.delisted_at.is_not(None), MarketplaceProduct.cso)
        .limit(min(limit, 100))
    )
    return list((await session.execute(stmt)).scalars())


async def disagreements(session: AsyncSession, system_id: int) -> int:
    """How many of a system's linked dependencies disagree with the Marketplace."""
    deps = list(
        (
            await session.execute(
                select(FedRAMPDependency).where(
                    FedRAMPDependency.system_id == system_id,
                    FedRAMPDependency.marketplace_id.is_not(None),
                )
            )
        ).scalars()
    )
    found = await products_by_id(session, {d.marketplace_id for d in deps if d.marketplace_id})
    return sum(1 for d in deps if compare(d, found.get(d.marketplace_id or "")))
