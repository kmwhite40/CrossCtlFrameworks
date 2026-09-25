"""Push a Concord record into an external tracker, and record where it went.

The orchestration deliberately does three things in a fixed order, and the
order is the point:

1. **Resolve the caller's own organization's credential.** Never a fallback,
   never another tenant's -- ``resolve_credential`` returns ``None`` both for
   "no org" and "no credential", and both mean not configured.
2. **Prove the record belongs to that organization** with an explicit predicate,
   on top of RLS rather than relying on it. A POA&M reaches its tenant through
   ``systems.organization_id``, not a column of its own, and a test issued over
   HTTP cannot tell an app predicate from a database policy -- so the check is
   written here and pinned on an unscoped session.
3. **Push, then record.** Never the reverse: a link row written before the
   remote call would claim a ticket exists whenever the call then fails.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..connectors.credentials import resolve_credential
from ..models import POAM, System
from ..models_grc import ConnectorConfig, ExternalIssueLink
from .jira import CREDENTIAL_TYPE, PROVIDER, JiraTracker
from .types import (
    IntegrationError,
    IntegrationNotConfigured,
    IssueContent,
    IssueTracker,
    PushResult,
)

ENTITY_POAM = "poam"


def poam_content(poam: POAM) -> IssueContent:
    """Map a POA&M onto the provider-neutral ticket shape.

    The body is assembled from the fields an engineer needs to act, each
    labelled, and omits any that are unset rather than emitting "None" -- a
    ticket reading "Remediation plan: None" is worse than one that does not
    mention a plan, because it looks like a decision was recorded.
    """
    sections: list[str] = []
    if poam.weakness:
        sections.append(f"Weakness\n{poam.weakness}")
    if poam.remediation_plan:
        sections.append(f"Remediation plan\n{poam.remediation_plan}")
    if poam.resources_required:
        sections.append(f"Resources required\n{poam.resources_required}")
    if poam.point_of_contact:
        sections.append(f"Point of contact: {poam.point_of_contact}")
    sections.append(
        f"Filed from Concord POA&M #{poam.id}. "
        "Concord remains the record of truth for this item's compliance status; "
        "closing this ticket does not close the POA&M."
    )

    labels = ["concord", f"poam-{poam.id}"]
    if poam.severity:
        labels.append(f"severity-{poam.severity}")
    if poam.status:
        labels.append(f"status-{poam.status}")

    return IssueContent(
        key=f"{ENTITY_POAM}:{poam.id}",
        title=poam.title,
        body="\n\n".join(sections),
        due_on=poam.scheduled_completion or poam.due_on,
        labels=tuple(labels),
    )


async def _tracker_for(session: AsyncSession, org_id: int) -> IssueTracker:
    """Build this organization's Jira tracker, or say precisely what is missing."""
    secret = await resolve_credential(session, org_id, CREDENTIAL_TYPE)
    if not secret:
        raise IntegrationNotConfigured(
            "no Jira credential is stored for this organization"
        )
    cfg = (
        await session.execute(
            select(ConnectorConfig).where(
                ConnectorConfig.organization_id == org_id,
                ConnectorConfig.connector_type == CREDENTIAL_TYPE,
            )
        )
    ).scalars().first()
    config = dict(cfg.config or {}) if cfg is not None else {}
    project_key = str(config.get("project_key") or secret.get("project_key") or "")
    if not project_key:
        raise IntegrationNotConfigured(
            "no Jira project key is configured for this organization"
        )
    return JiraTracker(
        base_url=str(secret.get("base_url", "")),
        email=str(secret.get("email", "")),
        api_token=str(secret.get("api_token", "")),
        project_key=project_key,
        issue_type=str(config.get("issue_type") or "Task"),
        send_due_date=bool(config.get("send_due_date", False)),
    )


async def _owned_poam(session: AsyncSession, org_id: int, poam_id: int) -> POAM:
    """The POA&M, only if it belongs to ``org_id``.

    Explicit join to ``systems.organization_id``: a POA&M carries no
    organization of its own, and "the query returned nothing" must mean the
    same thing for another tenant's id as for one that does not exist.
    """
    poam = (
        await session.execute(
            select(POAM)
            .join(System, System.id == POAM.system_id)
            .where(POAM.id == poam_id, System.organization_id == org_id)
        )
    ).scalars().first()
    if poam is None:
        raise IntegrationNotConfigured(f"no POA&M {poam_id} in this organization")
    return poam


async def existing_link(
    session: AsyncSession, org_id: int, entity_type: str, entity_id: int, provider: str
) -> ExternalIssueLink | None:
    return (
        await session.execute(
            select(ExternalIssueLink).where(
                ExternalIssueLink.organization_id == org_id,
                ExternalIssueLink.provider == provider,
                ExternalIssueLink.entity_type == entity_type,
                ExternalIssueLink.entity_id == entity_id,
            )
        )
    ).scalars().first()


async def links_for_entities(
    session: AsyncSession,
    org_id: int,
    entity_type: str,
    entity_ids: list[int],
    provider: str,
) -> dict[int, ExternalIssueLink]:
    """This organization's links for the given records, keyed by entity id.

    Lives here rather than inline in the page route so the organization
    predicate can be pinned on an unscoped session. Over HTTP the session is
    tenant-bound and RLS refuses another tenant's row regardless, so a test
    issued that way passes whether or not this predicate exists -- it proves
    the policy, not the code.
    """
    if not entity_ids:
        return {}
    rows = (
        await session.execute(
            select(ExternalIssueLink).where(
                ExternalIssueLink.organization_id == org_id,
                ExternalIssueLink.entity_type == entity_type,
                ExternalIssueLink.provider == provider,
                ExternalIssueLink.entity_id.in_(entity_ids),
            )
        )
    ).scalars().all()
    return {row.entity_id: row for row in rows}


async def push_poam(
    session: AsyncSession,
    org_id: int | None,
    poam_id: int,
    *,
    tracker: IssueTracker | None = None,
) -> PushResult:
    """File or update this POA&M's ticket, and record where it now lives.

    ``tracker`` is injectable so tests drive a faithful fake rather than the
    network; production passes nothing and gets the organization's own Jira.
    """
    if org_id is None:
        raise IntegrationNotConfigured(
            "pushing to a tracker requires an organization context"
        )
    poam = await _owned_poam(session, org_id, poam_id)
    if tracker is None:
        tracker = await _tracker_for(session, org_id)

    link = await existing_link(session, org_id, ENTITY_POAM, poam_id, tracker.provider)
    content = poam_content(poam)

    try:
        if link is None:
            result = await tracker.create(content)
        else:
            result = await tracker.update(link.external_id, content)
    except IntegrationError as exc:
        # A failure is recorded only against a link that already exists. There
        # is nothing to record against otherwise: writing a row for a ticket
        # that was never created would claim an external record that does not
        # exist, and the next push would take the update path to a key Jira
        # has never heard of.
        if link is not None:
            link.last_status = "failed"
            link.last_error = str(exc)
            link.last_pushed_at = datetime.now(UTC)
            await session.flush()
        raise

    if link is None:
        link = ExternalIssueLink(
            organization_id=org_id,
            entity_type=ENTITY_POAM,
            entity_id=poam_id,
            provider=tracker.provider,
            external_id=result.external_id,
            external_url=result.url,
        )
        session.add(link)
    else:
        link.external_id = result.external_id
        link.external_url = result.url
    link.last_status = "ok"
    link.last_error = None
    link.last_pushed_at = datetime.now(UTC)
    await session.flush()
    return result


__all__ = [
    "ENTITY_POAM",
    "PROVIDER",
    "existing_link",
    "links_for_entities",
    "poam_content",
    "push_poam",
]
