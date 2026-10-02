"""Resolve a system's live-audit plan before executing provider scans."""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..analytics.framework_posture import resolve_applied_framework, system_framework_posture
from ..connectors.readiness import provider_readiness
from ..models import System
from .checks import known_providers
from .scope import provider_scope


async def live_audit_plan(
    session: AsyncSession,
    *,
    system: System,
    org_id: int | None,
    persist_readiness: bool = False,
) -> dict[str, Any]:
    """Provider/framework-aware plan for one live audit run.

    The plan is intentionally separate from execution. It is the surface an
    operator needs before pressing "scan": what framework denominator applies,
    which provider checks will run, and which checks/controls need manual review
    because the provider is unavailable or the shared-responsibility template
    says the control should be evidenced another way.
    """
    applied = await resolve_applied_framework(session, system)
    framework = (
        {
            "key": applied.key,
            "label": applied.label,
            "denominator": applied.denominator,
            "source": applied.source,
            "baseline": applied.baseline,
        }
        if applied
        else None
    )

    # Only the providers this system's environment is measured against. The plan
    # used to verify every registered provider, so an M365 system read "1 of 5
    # providers ready", was told to verify AWS for ever, and had its framework
    # items marked ``covered_by_automated_check`` by AWS checks that never run
    # against it. Out-of-scope providers are named with the reason rather than
    # dropped, so a reader can see what was excluded and why.
    scope = await provider_scope(session, system=system)
    providers = [
        await provider_readiness(
            session,
            organization_id=org_id,
            connector_key=key,
            persist=persist_readiness,
        )
        for key in sorted(known_providers())
        if key in scope and scope[key].in_scope
    ]
    out_of_scope = [
        {"connector": key, "reason": scope[key].reason}
        for key in sorted(known_providers())
        if key in scope and not scope[key].in_scope
    ]

    api_checks: list[dict[str, Any]] = []
    manual_review: list[dict[str, Any]] = []
    automated_control_ids: set[str] = set()
    for provider in providers:
        for check in provider["checks"]:
            if check["scan_applicability"] == "scan":
                if check.get("control_id"):
                    automated_control_ids.add(str(check["control_id"]))
                for control_id in check.get("control_ids") or []:
                    automated_control_ids.add(str(control_id))
            if not provider["ready"]:
                manual_review.append(
                    {
                        **check,
                        "connector": provider["connector"],
                        "reason": provider.get("reason") or provider["status"],
                        "status": "manual_review_required",
                    }
                )
            elif check["scan_applicability"] == "scan":
                api_checks.append({**check, "connector": provider["connector"]})
            else:
                manual_review.append(
                    {
                        **check,
                        "connector": provider["connector"],
                        "reason": check["scan_applicability"],
                        "status": "manual_review_required",
                    }
                )

    framework_posture = await system_framework_posture(
        session,
        org_id=org_id,
        system_id=system.id,
    )
    framework_items: list[dict[str, Any]] = []
    framework_manual_review: list[dict[str, Any]] = []
    if framework_posture.get("total"):
        unit = framework_posture.get("unit") or "control"
        practice_ids = framework_posture.get("practice_ids") or {}
        all_items = (
            set(framework_posture.get("passing") or [])
            | set(framework_posture.get("failing") or [])
            | set(framework_posture.get("documented") or [])
            | set(framework_posture.get("unaddressed") or [])
        )
        for item_id in sorted(all_items):
            mapped_control = practice_ids.get(item_id, item_id)
            automated = mapped_control in automated_control_ids or item_id in automated_control_ids
            if item_id in set(framework_posture.get("passing") or []):
                status = "automated_pass"
            elif item_id in set(framework_posture.get("failing") or []):
                status = "automated_fail"
            elif item_id in set(framework_posture.get("documented") or []):
                status = "documented"
            else:
                status = "manual_review_required"
            row = {
                "id": item_id,
                "unit": unit,
                "mapped_control_id": mapped_control,
                "automated": automated,
                "status": status,
                "reason": (
                    "covered_by_automated_check"
                    if automated
                    else "no_automated_provider_check_for_framework_item"
                ),
            }
            framework_items.append(row)
            if status == "manual_review_required":
                framework_manual_review.append(row)

    return {
        "system_id": system.id,
        "framework": framework,
        "framework_posture": framework_posture,
        "framework_controls": framework_items,
        "providers": providers,
        "providers_out_of_scope": out_of_scope,
        "api_checks": api_checks,
        "manual_review_required": manual_review,
        "framework_manual_review_required": framework_manual_review,
        "summary": {
            "providers": len(providers),
            "providers_ready": sum(1 for p in providers if p["ready"]),
            "api_checks": len(api_checks),
            "manual_review_required": len(manual_review),
            "framework_total": framework_posture.get("total") or 0,
            "framework_automated": sum(1 for row in framework_items if row["automated"]),
            "framework_manual_review_required": len(framework_manual_review),
            "framework_failing": len(framework_posture.get("failing") or []),
            "framework_passing": len(framework_posture.get("passing") or []),
            "framework_documented": len(framework_posture.get("documented") or []),
        },
    }
