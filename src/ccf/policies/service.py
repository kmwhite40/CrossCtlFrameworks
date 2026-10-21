"""Creating, rendering, activating and attesting policy documents.

A policy is created from a library template with the organization's own
parameter values; each render is a new immutable ``PolicyVersion`` with its
body hash and the parameters it still lacks. A version is put in force only by
**activation**, which (with authentication on) spends an approval of *that
version* -- not of the policy, or a version written after the review could be
activated on it -- and refuses a version that still reads
"[ORGANIZATION-DEFINED: x]". Attestation records the person signed in, never
an identity named in the request.
"""

from __future__ import annotations

import hashlib
import re
from datetime import date, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..api.audit import record_event
from ..auth import Principal
from ..config import get_settings
from ..governance import approvals, bus
from ..models import Organization, Policy, PolicyAttestation, PolicyVersion, User
from ..ssp.odp import render
from .library import BY_KEY
from .templates import CONTEXT_TOKENS, Template

#: Days until the next review after a version is put in force.
REVIEW_DAYS = {
    "monthly": 30, "quarterly": 91, "semiannual": 182, "annual": 365, "biennial": 730,
}


class PolicyError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def sha256(text: str | None) -> str | None:
    return hashlib.sha256(text.encode()).hexdigest() if text is not None else None


def render_template(
    template: Template, parameters: dict[str, Any], context: dict[str, Any]
) -> tuple[str, list[str]]:
    """The template as Markdown, and the parameters it still lacks (in order)."""
    parts = [f"# {template.title}"]
    for section in template.sections:
        parts.append(f"## {section.heading}")
        parts.append(section.body.strip())
    supports = []
    if template.controls:
        supports.append("NIST SP 800-53 Rev. 5: " + ", ".join(template.controls))
    if template.requirements_171:
        supports.append("NIST SP 800-171 Rev. 2: " + ", ".join(template.requirements_171))
    if supports:
        parts.append("## Related Requirements")
        parts.append(
            "This document addresses the following requirements. It states what "
            "{{organization}} requires; it is not evidence that any control is implemented.\n\n"
            + "\n".join(f"- {s}" for s in supports)
        )
    text, missing = render("\n\n".join(parts) + "\n", parameters, context)
    return text, list(dict.fromkeys(missing))


def clean_parameters(template: Template, raw: dict[str, Any]) -> dict[str, str]:
    """Only the template's declared keys (and the context tokens), trimmed;
    blanks dropped. A context token given here is used only where Concord
    cannot derive it -- an org-less single-operator policy, or no owner set."""
    declared = {p.key for p in template.parameters} | set(CONTEXT_TOKENS)
    out: dict[str, str] = {}
    for key, value in raw.items():
        if key in declared and value is not None and str(value).strip():
            out[key] = str(value).strip()
    return out


async def _context(session: AsyncSession, policy: Policy) -> dict[str, Any]:
    org_name = None
    if policy.organization_id is not None:
        org_name = (
            await session.execute(
                select(Organization.name).where(Organization.id == policy.organization_id)
            )
        ).scalar_one_or_none()
    owner = None
    if policy.owner_user_id is not None:
        u = await session.get(User, policy.owner_user_id)
        if u is not None:
            owner = u.full_name or u.email
    return {"organization": org_name, "policy_owner": owner}


def _next_version(existing: list[str]) -> str:
    best = (0, 0)
    for v in existing:
        m = re.fullmatch(r"(\d+)\.(\d+)", v.strip())
        if m:
            best = max(best, (int(m.group(1)), int(m.group(2))))
    if best == (0, 0):
        return "1.0"
    return f"{best[0]}.{best[1] + 1}"


async def _versions(session: AsyncSession, policy_id: int) -> list[PolicyVersion]:
    return list(
        (
            await session.execute(
                select(PolicyVersion)
                .where(PolicyVersion.policy_id == policy_id)
                .order_by(PolicyVersion.id.desc())
            )
        ).scalars()
    )


async def render_version(
    session: AsyncSession, policy: Policy, principal: Principal
) -> PolicyVersion:
    """Render the policy's template with its current parameters as a new version."""
    template = BY_KEY.get(policy.template_key or "")
    if template is None:
        raise PolicyError(409, "this policy was not created from a library template")
    params = dict(policy.parameters or {})
    ctx = await _context(session, policy)
    for token in CONTEXT_TOKENS:
        if ctx.get(token) is None:
            ctx[token] = params.get(token)
    text, missing = render_template(
        template, {k: v for k, v in params.items() if k not in CONTEXT_TOKENS}, ctx
    )
    existing = await _versions(session, policy.id)
    if existing and existing[0].body_sha256 == sha256(text):
        return existing[0]  # nothing changed; no new version
    v = PolicyVersion(
        policy_id=policy.id,
        version=_next_version([e.version for e in existing]),
        body=text,
        body_sha256=sha256(text),
        unresolved_parameters=missing,
        created_by=principal.email,
    )
    session.add(v)
    await session.flush()
    return v


async def create_from_template(
    session: AsyncSession,
    *,
    org_id: int | None,
    template_key: str,
    name: str | None,
    parameters: dict[str, Any],
    owner_user_id: int | None,
    principal: Principal,
) -> tuple[Policy, PolicyVersion]:
    template = BY_KEY.get(template_key)
    if template is None:
        raise PolicyError(404, f"no template {template_key!r}")
    title = (name or "").strip() or template.title
    clash = (
        await session.execute(
            select(Policy.id).where(Policy.organization_id == org_id, Policy.name == title)
        )
    ).scalar_one_or_none()
    if clash is not None:
        raise PolicyError(409, f"a policy named {title!r} already exists")
    if owner_user_id is not None:
        owner = await session.get(User, owner_user_id)
        if owner is None or (org_id is not None and owner.organization_id != org_id):
            raise PolicyError(404, "no such owner in this organization")
    policy = Policy(
        organization_id=org_id,
        name=title,
        description=template.summary,
        category=template.family,
        owner_user_id=owner_user_id,
        status="draft",
        review_frequency=template.review_frequency,
        linked_controls=list(template.controls),
        template_key=template.key,
        parameters=clean_parameters(template, parameters),
    )
    session.add(policy)
    await session.flush()
    version = await render_version(session, policy, principal)
    await record_event(
        session,
        actor=principal.email or "system",
        action="policy_created_from_template",
        entity_type="policy",
        entity_id=str(policy.id),
        diff={"template": template.key, "version": version.version,
              "unresolved": version.unresolved_parameters},
        organization_id=org_id,
    )
    return policy, version


async def set_parameters(
    session: AsyncSession, policy: Policy, raw: dict[str, Any], principal: Principal
) -> PolicyVersion:
    template = BY_KEY.get(policy.template_key or "")
    if template is None:
        raise PolicyError(409, "this policy was not created from a library template")
    policy.parameters = clean_parameters(template, raw)
    return await render_version(session, policy, principal)


async def activate(
    session: AsyncSession,
    *,
    policy: Policy,
    version: PolicyVersion,
    principal: Principal,
    today: date | None = None,
) -> Policy:
    """Put ``version`` in force. Gated on an approval of that exact version."""
    today = today or date.today()
    if version.policy_id != policy.id:
        raise PolicyError(404, "that version belongs to another policy")
    if policy.status == "retired":
        raise PolicyError(409, "a retired policy cannot be put back in force; create a new one")
    if not (version.body or version.uri):
        raise PolicyError(409, "this version has no text or document to put in force")
    if version.unresolved_parameters:
        raise PolicyError(
            409,
            "fill in the organization-defined values first: "
            + ", ".join(version.unresolved_parameters),
        )
    # The spend is the check: one conditional UPDATE, so two concurrent
    # requests cannot both put a version in force on one review.
    if get_settings().auth_enabled and not await approvals.consume(
        session, entity_type="policy_version", entity_id=version.id, actor=principal.email,
        org_id=policy.organization_id,
    ):
        raise PolicyError(
            409,
            "putting a policy in force needs an approved review of this version (submit "
            "it, then have a different administrator approve it)",
        )
    previous = policy.active_version_id
    policy.active_version_id = version.id
    policy.status = "active"
    if version.effective_on is None:
        version.effective_on = today
    days = REVIEW_DAYS.get((policy.review_frequency or "").lower())
    policy.next_review_on = today + timedelta(days=days) if days else policy.next_review_on
    await record_event(
        session,
        actor=principal.email or "system",
        action="policy_activated",
        entity_type="policy",
        entity_id=str(policy.id),
        diff={"version": version.version, "version_id": version.id,
              "body_sha256": version.body_sha256, "previous_version_id": previous},
        organization_id=policy.organization_id,
    )
    await bus.emit(
        session, verb="activated", entity_type="policy", entity_id=policy.id,
        summary=f"Policy '{policy.name}' v{version.version} in force",
        org_id=policy.organization_id, actor=principal.email,
    )
    return policy


async def retire(session: AsyncSession, *, policy: Policy, principal: Principal) -> Policy:
    if get_settings().auth_enabled and principal.role != "admin":
        raise PolicyError(403, "only an admin can retire a policy")
    policy.status = "retired"
    await record_event(
        session,
        actor=principal.email or "system",
        action="policy_retired",
        entity_type="policy",
        entity_id=str(policy.id),
        diff={"active_version_id": policy.active_version_id},
        organization_id=policy.organization_id,
    )
    return policy


async def attest(
    session: AsyncSession,
    *,
    policy: Policy,
    version: PolicyVersion,
    principal: Principal,
    attestor: str | None = None,
    note: str | None = None,
) -> PolicyAttestation:
    """Record that the signed-in person read and accepts the version in force.

    With authentication on, who attested is the principal and nothing else:
    the old route took ``user_id``/``attestor`` from the request body, so
    anyone could record anyone's acknowledgement. Single-operator mode has no
    users, so it may name the attestor (a recorded paper acknowledgement).
    """
    if policy.active_version_id != version.id:
        raise PolicyError(409, "only the version in force can be attested")
    if get_settings().auth_enabled:
        if principal.user_id is None:
            raise PolicyError(403, "attestation needs a signed-in person")
        user_id: int | None = principal.user_id
        who = principal.email
    else:
        user_id = None
        who = (attestor or "").strip() or principal.email
    existing = (
        await session.execute(
            select(PolicyAttestation).where(
                PolicyAttestation.policy_version_id == version.id,
                PolicyAttestation.user_id == user_id if user_id is not None
                else PolicyAttestation.attestor == who,
            )
        )
    ).scalars().first()
    if existing is not None:
        return existing
    a = PolicyAttestation(
        policy_version_id=version.id, user_id=user_id, attestor=who,
        note=(note or "").strip() or None,
    )
    session.add(a)
    await session.flush()
    await bus.emit(
        session, verb="attested", entity_type="policy_version", entity_id=version.id,
        summary=f"Policy '{policy.name}' v{version.version} attested by {who}",
        org_id=policy.organization_id, actor=principal.email,
    )
    return a
