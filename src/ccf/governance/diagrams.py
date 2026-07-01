"""Diagram generation — render compliance data as Mermaid diagrams.

Produces authorization-boundary, control-coverage, and system-landscape diagrams
as Mermaid source (text), which the UI renders client-side and documents embed.
No external renderer required; the same text can be piped to mermaid-cli / Kroki
for SVG/PNG in a pipeline.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import ControlImplementation, System, Vendor

_RESP_LABEL = {
    "customer": "Customer-managed",
    "provider": "Provider-managed",
    "shared": "Shared responsibility",
    "inherited": "Inherited",
}


def _san(text: str) -> str:
    """Sanitize a label for Mermaid (no quotes/brackets/newlines)."""
    return (text or "").replace('"', "'").replace("[", "(").replace("]", ")").replace("\n", " ")


async def authorization_boundary(session: AsyncSession, system_id: int) -> str:
    """Mermaid flowchart of a system's authorization boundary by responsibility."""
    system = (
        await session.execute(select(System).where(System.id == system_id))
    ).scalar_one_or_none()
    if system is None:
        raise ValueError("system not found")
    impls = (
        (
            await session.execute(
                select(ControlImplementation).where(ControlImplementation.system_id == system_id)
            )
        )
        .scalars()
        .all()
    )
    by_resp: dict[str, int] = Counter(i.responsibility or "customer" for i in impls)

    lines = [
        "flowchart TB",
        f'  subgraph BOUND["Authorization Boundary — {_san(system.name)}"]',
        "    direction TB",
    ]
    for resp, label in _RESP_LABEL.items():
        n = by_resp.get(resp, 0)
        if n:
            lines.append(f'    {resp}["{label}<br/>{n} controls"]')
    lines.append("  end")
    # Inherited responsibilities point at authorized providers (vendors).
    vendors = (
        (await session.execute(select(Vendor).where(Vendor.authorization.is_not(None))))
        .scalars()
        .all()
    )
    for v in vendors[:8]:
        vid = f"v{v.id}"
        lines.append(f'  {vid}[("{_san(v.name)}<br/>{_san(v.authorization or "")}")]')
        if by_resp.get("inherited"):
            lines.append(f"  inherited --> {vid}")
    return "\n".join(lines)


async def control_coverage(session: AsyncSession, system_id: int) -> str:
    """Mermaid pie chart of implementation status for a system."""
    impls = (
        (
            await session.execute(
                select(ControlImplementation).where(ControlImplementation.system_id == system_id)
            )
        )
        .scalars()
        .all()
    )
    counts = Counter(i.status for i in impls)
    lines = ["pie showData", "  title Control implementation coverage"]
    for status, n in counts.most_common():
        lines.append(f'  "{_san(status)}" : {n}')
    if not impls:
        lines.append('  "no implementations" : 1')
    return "\n".join(lines)


async def system_landscape(session: AsyncSession, org_id: int | None = None) -> str:
    """Mermaid flowchart of every system and its ATO status in an org."""
    stmt = select(System)
    if org_id is not None:
        stmt = stmt.where(System.organization_id == org_id)
    systems = (await session.execute(stmt)).scalars().all()
    lines = ["flowchart LR", '  ORG(["Organization"])']
    ato_class = {
        "authorized": ":::ok",
        "in_progress": ":::warn",
        "expired": ":::bad",
        "none": "",
    }
    for s in systems:
        sid = f"s{s.id}"
        cls = ato_class.get(s.ato_status or "none", "")
        lines.append(f'  ORG --> {sid}["{_san(s.name)}<br/>ATO: {s.ato_status or "none"}"]{cls}')
    lines.append("  classDef ok fill:#d1fae5,stroke:#059669;")
    lines.append("  classDef warn fill:#fef3c7,stroke:#d97706;")
    lines.append("  classDef bad fill:#fee2e2,stroke:#dc2626;")
    return "\n".join(lines)


DIAGRAMS: dict[str, Any] = {
    "authorization-boundary": authorization_boundary,
    "control-coverage": control_coverage,
}
