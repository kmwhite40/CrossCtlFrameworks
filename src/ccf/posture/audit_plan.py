"""Resolve a system's live-audit plan before executing provider scans."""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..analytics.framework_posture import resolve_applied_framework
from ..connectors.readiness import provider_readiness
from ..models import System
from .checks import known_providers


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

    providers = [
        await provider_readiness(
            session,
            organization_id=org_id,
            connector_key=key,
            persist=persist_readiness,
        )
        for key in sorted(known_providers())
    ]

    api_checks: list[dict[str, Any]] = []
    manual_review: list[dict[str, Any]] = []
    for provider in providers:
        for check in provider["checks"]:
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

    return {
        "system_id": system.id,
        "framework": framework,
        "providers": providers,
        "api_checks": api_checks,
        "manual_review_required": manual_review,
        "summary": {
            "providers": len(providers),
            "providers_ready": sum(1 for p in providers if p["ready"]),
            "api_checks": len(api_checks),
            "manual_review_required": len(manual_review),
        },
    }
