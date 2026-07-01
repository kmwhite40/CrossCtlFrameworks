"""Canned implementation-statement library for the SSP builder.

Reusable statement templates the author can apply to a control instead of
writing from scratch. Each ``body`` may contain ``{{odp_key}}`` placeholders
(organization-defined parameters) and ``{{context}}`` tokens (``environment``,
``services``) that :func:`ccf.ssp.odp.render` fills in at apply time.

Scope precedence when matching a control: ``control`` > ``domain`` > ``global``.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import StatementTemplate

# key, scope, domain, body, tags. Bodies are DoD/CMMC-flavored starting points.
CANNED_TEMPLATES: list[dict[str, Any]] = [
    {
        "key": "global_customer_responsibility",
        "title": "Customer responsibility (Government cloud)",
        "scope": "global",
        "domain": None,
        "body": (
            "As a customer responsibility within {{environment}}, the organization configures "
            "and maintains {{services}} to satisfy this requirement. Configuration is performed "
            "by the System Owner and evidenced in the {{environment}} tenant/account."
        ),
        "tags": ["customer-responsibility", "govcloud"],
    },
    {
        "key": "global_inherited",
        "title": "Inherited from authorized cloud provider",
        "scope": "global",
        "domain": None,
        "body": (
            "This requirement is inherited from {{environment}}, which maintains a FedRAMP "
            "authorization. The organization relies on the provider's implementation and "
            "retains the provider's customer responsibility matrix as evidence."
        ),
        "tags": ["inherited"],
    },
    {
        "key": "ac_session_lock",
        "title": "AC — session/device lock after inactivity",
        "scope": "domain",
        "domain": "AC",
        "body": (
            "The organization enforces a session/device lock after {{inactivity_period}} of "
            "inactivity, implemented through {{services}} on {{environment}}, and requires "
            "re-authentication to resume the session."
        ),
        "tags": ["odp"],
    },
    {
        "key": "au_audit_retention",
        "title": "AU — audit generation & retention",
        "scope": "domain",
        "domain": "AU",
        "body": (
            "The organization generates and retains audit records for {{audit_retention_period}} "
            "using {{services}} on {{environment}}, protecting them from unauthorized access, "
            "modification, and deletion."
        ),
        "tags": ["odp"],
    },
    {
        "key": "ir_incident_reporting",
        "title": "IR — incident detection & reporting",
        "scope": "domain",
        "domain": "IR",
        "body": (
            "The organization detects and responds to incidents using {{services}} on "
            "{{environment}} and reports reportable cyber incidents {{incident_report_timeframe}} "
            "in accordance with DFARS 252.204-7012."
        ),
        "tags": ["odp", "dfars"],
    },
    {
        "key": "si_flaw_remediation",
        "title": "SI — flaw remediation timeframe",
        "scope": "domain",
        "domain": "SI",
        "body": (
            "The organization identifies and remediates system flaws "
            "{{flaw_remediation_timeframe}} using {{services}} on {{environment}}, "
            "tracking remediation to closure."
        ),
        "tags": ["odp"],
    },
]


async def seed_statement_templates(session: AsyncSession, *, overwrite: bool = False) -> int:
    """Upsert the canned template library by ``key``. Returns rows touched."""
    existing = {
        t.key: t for t in (await session.execute(select(StatementTemplate))).scalars().all()
    }
    touched = 0
    for order, spec in enumerate(CANNED_TEMPLATES):
        cur = existing.get(spec["key"])
        if cur is None:
            session.add(StatementTemplate(sort_order=order, **spec))
            touched += 1
        elif overwrite:
            cur.title = spec["title"]
            cur.scope = spec["scope"]
            cur.domain = spec["domain"]
            cur.body = spec["body"]
            cur.tags = spec["tags"]
            cur.sort_order = order
            touched += 1
    await session.flush()
    return touched
