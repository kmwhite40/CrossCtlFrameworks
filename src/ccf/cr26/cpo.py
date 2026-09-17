"""Seed a Certification Package Overview with what the platform actually knows.

**This is not a generator, and it must not become one.** The CPO has ten
required fields. Three have a source here:

===========================  ==========================
``providerName``             ``Organization.name``
``serviceName``              ``System.name``
``serviceDescription``       ``System.description``
===========================  ==========================

The rest -- ``serviceAcronym``, ``fedRampPackageId``, ``website``, ``logo``,
``certificationType``, ``serviceType`` and ``deploymentModel``, plus
``contactInformation`` -- are facts about the business that exist nowhere in
this platform. ``Vendor`` is third-party supply chain, and there is no party or
contact table at all. Inventing plausible values would produce a document that
validates and is wrong, which is worse than one that visibly does not validate.

So the seeded document is **invalid by design**, and a test asserts that. The
value this module adds is a starting point and a verdict, not a deliverable.

``certificationType`` is deliberately absent: it is a declaration the provider
makes, not a fact the platform can compute. Inferring it from
``certification_class`` is the same mistake as deriving Class from ``baseline``
-- see :mod:`tests.test_cr26_certification_type_not_derived`.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Organization, System
from ..models_cr26 import Cr26Document
from .store import put_document

#: The only ``serviceIdentification`` fields the platform can fill.
SEEDED_FIELDS: tuple[str, ...] = ("providerName", "serviceName", "serviceDescription")


async def seed_cpo(session: AsyncSession, *, system_id: int) -> Cr26Document:
    """Create or refresh this system's CPO skeleton, preserving authored fields."""
    system = await session.get(System, system_id)
    if system is None:
        raise ValueError(f"unknown system: {system_id!r}")
    org = await session.get(Organization, system.organization_id)

    seeded: dict[str, Any] = {
        "providerName": org.name if org is not None else "",
        "serviceName": system.name,
    }
    # Omit rather than seed "" when there is no description: an empty string
    # would satisfy the schema's `required` check and look filled-in, hiding
    # exactly the kind of gap this module exists to surface honestly. A
    # description explicitly authored as "" is left alone -- only a NULL
    # column (nothing recorded at all) is treated as absent.
    if system.description is not None:
        seeded["serviceDescription"] = system.description

    existing = await _current(session, system_id)
    document: dict[str, Any] = existing if existing is not None else {}
    identification = dict(document.get("serviceIdentification") or {})
    # Seeded values fill gaps; anything a human authored wins. Re-seeding must
    # never destroy the seven fields only a human can supply.
    for field, value in seeded.items():
        identification.setdefault(field, value)
    document["serviceIdentification"] = identification

    return await put_document(session, system_id=system_id, kind="cpo", document=document)


async def _current(session: AsyncSession, system_id: int) -> dict[str, Any] | None:
    from sqlalchemy import select  # noqa: PLC0415

    row = (
        await session.execute(
            select(Cr26Document).where(
                Cr26Document.system_id == system_id, Cr26Document.kind == "cpo"
            )
        )
    ).scalars().first()
    return dict(row.document) if row is not None else None
