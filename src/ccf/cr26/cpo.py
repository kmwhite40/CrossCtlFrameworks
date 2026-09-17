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
this platform. ``Vendor`` is third-party supply chain. There *is* a ``people``
table (:mod:`ccf.models_people`), but it models the **workforce** security
lifecycle -- PS-2 risk designation, PS-3 screening, AT training, AC-2 access --
while ``contactInformation`` is an array of *published CSP contacts* whose
items must include one with ``contactType`` ``const: "Security"`` and one
``const: "Sales"``. ``Person`` has ``position`` and ``department``; it has no
concept of a published contact type, so it cannot source this field.
Inventing plausible values would produce a document that validates and is
wrong, which is worse than one that visibly does not validate.

So the seeded document is **invalid by design**, and a test asserts that. The
value this module adds is a starting point and a verdict, not a deliverable.

``certificationType`` is deliberately absent: it is a declaration the provider
makes, not a fact the platform can compute. Inferring it from
``certification_class`` is the same mistake as deriving Class from ``baseline``
-- see :mod:`tests.test_cr26_certification_type_not_derived`.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Organization, System
from ..models_cr26 import Cr26Document
from .store import put_document

#: How each seedable ``serviceIdentification`` field is sourced. A source that
#: yields ``None`` -- no organization row, or a description never recorded --
#: means the field is **omitted**, never seeded as ``""``: the schema puts no
#: ``minLength`` on any of them, so an empty string satisfies ``required`` and
#: looks filled-in, hiding exactly the kind of gap this module exists to
#: surface honestly. A value explicitly authored as ``""`` is left alone --
#: only ``None`` (nothing recorded at all) is treated as absent.
_SOURCES: dict[str, Callable[[System, Organization | None], str | None]] = {
    "providerName": lambda system, org: org.name if org is not None else None,
    "serviceName": lambda system, org: system.name,
    "serviceDescription": lambda system, org: system.description,
}

#: The only ``serviceIdentification`` fields the platform can fill. Derived
#: from :data:`_SOURCES` rather than restated, so the declaration and the code
#: that builds the document cannot drift apart.
SEEDED_FIELDS: tuple[str, ...] = tuple(_SOURCES)


def _seed_values(system: System, org: Organization | None) -> dict[str, Any]:
    """Every :data:`SEEDED_FIELDS` entry this system can actually fill.

    An unsourced field is absent from the result, never present as ``""`` --
    see :data:`_SOURCES`.
    """
    return {
        field: value
        for field, source in _SOURCES.items()
        if (value := source(system, org)) is not None
    }


async def seed_cpo(session: AsyncSession, *, system_id: int) -> Cr26Document:
    """Create or refresh this system's CPO skeleton, preserving authored fields."""
    system = await session.get(System, system_id)
    # A soft-deleted system is not a writable system -- see ccf.cr26.store.
    if system is None or system.deleted_at is not None:
        raise ValueError(f"unknown system: {system_id!r}")
    org = await session.get(Organization, system.organization_id)

    seeded = _seed_values(system, org)

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
