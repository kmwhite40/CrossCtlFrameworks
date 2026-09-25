"""The customer journey, as one ordered thing with a state per step.

Concord had every part of this and no path through it. A customer could
describe a system, connect a provider, run a scan, read findings and generate
an SSP -- from five unrelated pages, in any order, with nothing saying which
step they were on or what came next. The tools existed; the workflow did not.

The steps are the ones the work actually has:

1. describe the system, and say which baseline it is held to
2. connect the evidence sources
3. assess against that baseline
4. see posture *against the baseline*, not against what was checked
5. remediate what failed
6. document it in an SSP

Each step reports ``done`` / ``blocked`` / ``todo`` with the reason, so the
page can say what to do next rather than listing everything at once.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import POAM, SSPProject, System, Task
from ..models_grc import ConnectorConfig, ControlTest
from .framework_posture import framework_posture


def _step(key: str, title: str, state: str, detail: str, action: str, href: str) -> dict[str, Any]:
    return {
        "key": key,
        "title": title,
        "state": state,
        "detail": detail,
        "action": action,
        "href": href,
    }


async def customer_workspace(session: AsyncSession, org_id: int | None) -> dict[str, Any]:
    """Every step's state for this organization, and the one to do next."""
    if org_id is None:
        return {"steps": [], "system": None, "posture": None, "next": None}

    systems = (
        await session.execute(
            select(System)
            .where(System.organization_id == org_id, System.deleted_at.is_(None))
            .order_by(System.id)
        )
    ).scalars().all()

    # The system this workspace is about: the first with a baseline declared,
    # else the first at all. A workspace that silently picked a different
    # system each time the data changed would be worse than one that says it
    # is unset.
    system = next((s for s in systems if s.baseline), systems[0] if systems else None)

    steps: list[dict[str, Any]] = []

    # 1 -- describe
    if system is None:
        steps.append(_step(
            "describe", "Describe the system", "todo",
            "No system yet. The intake questionnaire derives a baseline and seeds an SSP.",
            "Start intake", "/intake"))
    elif not system.baseline:
        steps.append(_step(
            "describe", "Describe the system", "blocked",
            f"{system.name} has no FIPS-199 baseline, so there is nothing to measure against.",
            "Set a baseline", f"/systems/{system.id}"))
    else:
        baseline = system.baseline.value if hasattr(system.baseline, "value") else system.baseline
        steps.append(_step(
            "describe", "Describe the system", "done",
            f"{system.name} — FedRAMP {baseline.title()} baseline.",
            "Review", f"/systems/{system.id}"))

    # 2 -- connect
    connectors = (
        await session.execute(
            select(ConnectorConfig).where(ConnectorConfig.organization_id == org_id)
        )
    ).scalars().all()
    live = [c for c in connectors if c.encrypted_credential is not None]
    if not connectors:
        steps.append(_step(
            "connect", "Connect evidence sources", "todo",
            "No provider connected. Concord reads configuration from your own tenant.",
            "Connect a provider", "/connectors"))
    elif not live:
        steps.append(_step(
            "connect", "Connect evidence sources", "blocked",
            f"{len(connectors)} connector(s) registered, none holding a credential.",
            "Add a credential", f"/connectors/{connectors[0].id}"))
    else:
        working = [c for c in live if c.status == "configured"]
        state = "done" if working else "blocked"
        detail = (
            f"{len(working)} of {len(live)} credential(s) verified."
            if working
            else f"{len(live)} credential(s) stored, none verified — test the connection."
        )
        steps.append(_step(
            "connect", "Connect evidence sources", state, detail,
            "Manage connectors", "/connectors"))

    # 3 -- assess
    assessed = (
        await session.execute(
            select(func.count(ControlTest.id)).where(ControlTest.organization_id == org_id)
        )
    ).scalar_one()
    if not assessed:
        steps.append(_step(
            "assess", "Assess against the baseline", "todo" if live else "blocked",
            "No control has been assessed. Testing a connector's credential scans every system.",
            "Run a scan", "/connectors"))
    else:
        steps.append(_step(
            "assess", "Assess against the baseline", "done",
            f"{assessed} control test(s) recorded from live configuration.",
            "See results", "/control-tests"))

    # 4 -- posture, measured against the baseline
    posture = (
        await framework_posture(session, org_id=org_id, system_id=system.id)
        if system is not None
        else None
    )
    if posture and posture["total"]:
        covered = len(posture["passing"]) + len(posture["failing"])
        steps.append(_step(
            "posture", "Current posture", "done" if covered else "todo",
            (
                f"{len(posture['passing'])} satisfied, {len(posture['failing'])} failing, "
                f"{len(posture['unaddressed'])} not yet addressed of {posture['total']} "
                f"controls in the {posture['baseline']} baseline."
            ),
            "Open posture", "/posture"))
    else:
        steps.append(_step(
            "posture", "Current posture", "blocked",
            "No baseline declared, so coverage cannot be measured.",
            "Set a baseline", f"/systems/{system.id}" if system else "/intake"))

    # 5 -- remediate
    open_tasks = (
        await session.execute(
            select(func.count(Task.id)).where(
                Task.organization_id == org_id, Task.status == "open"
            )
        )
    ).scalar_one()
    failing = len(posture["failing"]) if posture else 0
    if failing or open_tasks:
        steps.append(_step(
            "remediate", "Remediate", "todo",
            f"{failing} control(s) failing, {open_tasks} open remediation task(s).",
            "Work the queue", "/dashboard"))
    else:
        steps.append(_step(
            "remediate", "Remediate", "done" if assessed else "blocked",
            "Nothing failing." if assessed else "Nothing assessed yet.",
            "Work the queue", "/dashboard"))

    # 6 -- document
    ssp = (
        await session.execute(
            select(func.count(SSPProject.id)).where(SSPProject.organization_id == org_id)
        )
    ).scalar_one() if system is not None else 0
    steps.append(_step(
        "document", "Document in an SSP", "done" if ssp else "todo",
        f"{ssp} SSP project(s)." if ssp else "No SSP yet — intake seeds one automatically.",
        "Open SSP builder", "/ssp"))

    nxt = next((s for s in steps if s["state"] != "done"), None)
    return {
        "steps": steps,
        "system": system,
        "posture": posture,
        "next": nxt,
        "open_poams": (
            await session.execute(
                select(func.count(POAM.id)).join(System, System.id == POAM.system_id).where(
                    System.organization_id == org_id, System.deleted_at.is_(None)
                )
            )
        ).scalar_one(),
    }


__all__ = ["customer_workspace"]
