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
from .framework_posture import resolve_applied_framework, system_framework_posture
from .gaps import compliance_gaps


def _step(  # noqa: PLR0917 -- one positional per column of a step row
    key: str, title: str, state: str, detail: str, action: str, href: str
) -> dict[str, Any]:
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

    # The system this workspace is about: the first whose framework Concord can
    # actually measure, else the first at all. A workspace that silently picked
    # a different system each time the data changed would be worse than one
    # that says it is unset.
    #
    # "Has a baseline" used to be the test, which skipped a system held to
    # 800-171 through its intake profile -- the shape the tenant this was found
    # on actually has. `resolve_applied_framework` answers the real question.
    applied_by_system = {
        s.id: await resolve_applied_framework(session, s) for s in systems
    }
    system = next(
        (s for s in systems if applied_by_system[s.id] is not None),
        systems[0] if systems else None,
    )

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

    # 4 -- posture, measured against the framework the system is held to
    posture = (
        await system_framework_posture(session, org_id=org_id, system_id=system.id)
        if system is not None
        else None
    )
    if posture and posture["total"]:
        covered = len(posture["passing"]) + len(posture["failing"])
        unit = posture["unit"] or "control"
        # Every bucket, because "of {total}" is an accounting claim.
        #
        # This named three of the five `framework_posture` partitions into --
        # satisfied, failing, not yet addressed -- while citing the whole
        # framework as the denominator, so a reader subtracting them got a
        # remainder belonging to nothing on the page. The two it dropped are the
        # two that most change what somebody does next: `documented` is a claim
        # owed evidence, and `manual_review` is work to schedule. Omitting them
        # from a sentence that says "of {total}" silently reassigns them to "not
        # yet addressed" in the reader's head, which is the opposite of what
        # either means.
        #
        # Built as a list of non-zero parts so the sentence stays readable on a
        # healthy system, and asserted to sum to the total by
        # tests/test_workspace_posture_sentence_adds_up.py -- parsed out of this
        # string, so a future edit that drops a bucket fails there.
        parts = [
            (len(posture["passing"]), "satisfied"),
            (len(posture["failing"]), "failing"),
            (len(posture["documented"]), "documented, awaiting evidence"),
            (len(posture["manual_review"]), "could not be judged"),
            (len(posture["unaddressed"]), "not yet addressed"),
        ]
        said = ", ".join(f"{n} {label}" for n, label in parts if n) or "0 assessed"
        steps.append(_step(
            "posture", "Current posture", "done" if covered else "todo",
            f"{said} of {posture['total']} {unit}s in {posture['framework_label']}.",
            "Open posture", "/posture"))
    else:
        # Say what is missing. "No baseline declared" was wrong for a system
        # that declares 800-171 and has no FIPS-199 categorization -- it named
        # the wrong remedy, and sent the customer to set a baseline they may not
        # need.
        steps.append(_step(
            "posture", "Current posture", "blocked",
            (posture or {}).get("reason")
            or "No framework declared, so coverage cannot be measured.",
            "Declare a framework", f"/systems/{system.id}" if system else "/intake"))

    # 5 -- remediate
    open_tasks = (
        await session.execute(
            select(func.count(Task.id)).where(
                Task.organization_id == org_id, Task.status == "open"
            )
        )
    ).scalar_one()
    # A formally accepted finding is not outstanding work, so the step that
    # asks "is there anything left to do" must not count it. It is still
    # failing -- the posture step above is right to include it -- so both
    # numbers are reported, rather than one quietly replacing the other.
    gaps = await compliance_gaps(session, org_id)
    accepted = gaps["accepted"]
    outstanding = gaps["open"]
    if outstanding or open_tasks:
        steps.append(_step(
            "remediate", "Correct and remediate", "todo",
            (
                f"{outstanding} of {gaps['failing']} failing control(s) unaccepted, "
                f"{open_tasks} open remediation task(s)"
                + (f", {accepted} risk-accepted." if accepted else ".")
            ),
            "Work the gaps", "/dashboard"))
    elif accepted:
        steps.append(_step(
            "remediate", "Correct and remediate", "done",
            f"Nothing outstanding — {accepted} finding(s) failing with the risk accepted.",
            "Review acceptances", "/dashboard"))
    else:
        steps.append(_step(
            "remediate", "Correct and remediate", "done" if assessed else "blocked",
            "Nothing failing." if assessed else "Nothing assessed yet.",
            "Work the gaps", "/dashboard"))

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
        # Named, so a page showing one system's posture does not read as the
        # organization's. Two systems here sit on different frameworks.
        "other_systems": [
            {
                "system_id": s.id,
                "name": s.name,
                "framework": (af.label if (af := applied_by_system[s.id]) else None),
            }
            for s in systems
            if system is None or s.id != system.id
        ],
        "open_poams": (
            await session.execute(
                select(func.count(POAM.id)).join(System, System.id == POAM.system_id).where(
                    System.organization_id == org_id, System.deleted_at.is_(None)
                )
            )
        ).scalar_one(),
    }


__all__ = ["customer_workspace"]
