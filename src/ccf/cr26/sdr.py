"""Seed a FedRAMP Security Decision Record from what the platform holds.

Unlike the CPO -- which is mostly facts about the business that live nowhere
here -- the SDR genuinely IS a second profile over content this platform
already produces. Ten of its eleven mapped fields have real sources.

The eleventh, ``ksiImplementation``, is the provider's narrative of how the
offering meets each indicator, and it exists nowhere per-system.
``KSI.description`` is the catalog's org-agnostic description of the
*requirement*, so rendering it there would describe the obligation while
claiming to describe the implementation.

That gap is more dangerous than the CPO's, because every required
``keySecurityIndicators`` field is an array of free text: ``[]`` satisfies the
schema. A seeder could emit a complete-looking indicator saying nothing at all,
and unlike the CPO the document would still validate. So an indicator with no
authored narrative is **omitted entirely** and named in the result.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import SSPControlEntry, SSPProject


def _parameter_values(odp_values: dict[str, Any] | None) -> list[dict[str, str]]:
    """Answered organization-defined parameters, as CR26 wants them.

    Unanswered parameters are DROPPED, not stringified. ``ssp/nist80053.py``
    scaffolds ``odp_values`` as ``{param.id: None}`` for every parameter in the
    control, and ``parameterValue`` is ``type: string`` -- so ``str(None)``
    would emit ``"None"`` as the provider's chosen value, a document that
    validates and is wrong.
    """
    return [
        {"parameterId": str(key), "parameterValue": str(value)}
        for key, value in (odp_values or {}).items()
        if value is not None
    ]


def render_controls(entries: Sequence[SSPControlEntry]) -> list[dict[str, Any]]:
    """The SSP's control content in the SDR's shape.

    The joins match ``ssp/nist80053_docx.py`` lines 170 and 173, which render
    these same two fields into the Word SSP. Two profiles over one body of
    content must not disagree about what a control says.
    """
    return [
        {
            "controlId": entry.control_id,
            "controlImplementationStatus": ", ".join(entry.implementation_status or []),
            "controlImplementationDescription": " ".join(
                str(part.get("text") or "") for part in (entry.part_narratives or [])
            ),
            "parameterValues": _parameter_values(entry.odp_values),
        }
        for entry in entries
    ]


async def latest_project_id(session: AsyncSession, system_id: int) -> int | None:
    """The SSP project this system's SDR renders from, or ``None``.

    ``SSPProject.system_id`` is nullable with no unique constraint, so a system
    may have several. Two precedents disagree -- ``api/routes/oscal.py`` orders
    by ``id.desc()``, ``api/routes/reports.py`` by ``updated_at.desc()``. This
    follows ``reports.py``: it is the closer analogue (rendering a document
    rather than assembling a package), and "most recently worked on" is the
    better answer to "which SSP describes this system today".

    The choice is reported in :class:`SdrSeedResult` rather than left implicit,
    because the ambiguity is real and an operator should never have to guess
    which SSP their SDR came from.
    """
    return (
        await session.execute(
            select(SSPProject.id)
            .where(SSPProject.system_id == system_id)
            .order_by(SSPProject.updated_at.desc())
            .limit(1)
        )
    ).scalars().first()
