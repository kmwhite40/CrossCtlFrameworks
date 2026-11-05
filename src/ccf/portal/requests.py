"""Agency self-service access requests (CDS-TRC-SSM) and denial notice (CDS-UTC-AAD).

A provider publishes a **request link** naming the systems agencies may ask
for. An agency submits a request through it and gets a one-time **receipt**.
The provider approves (choosing the expiry and, if narrower, the systems) or
denies (with a reason). On approval the agency **claims** access with its
receipt: that issues an ordinary ``agency`` grant and shows its token once --
the token cannot be made at approval and shown later, because only its hash
is ever stored. On denial, FedRAMP must be notified within the pinned rule's
window; Concord cannot file FedRAMP's form, so the provider records when it
did and under what reference, and until then the request reads as due or
overdue.

Business days count weekdays only, from the decision's calendar date in the
earliest US time zone (UTC-11). Federal holidays are not excluded and no US
zone reads the decision as an earlier date, so the due date is never later
than the true one -- at worst a day or two early. "Today", for overdue, is
read in the latest US zone (UTC+10), so the warning comes early, never late.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import hash_token
from ..fedramp20x.rules import load_rules
from ..models import System
from ..models_portal import (
    CertificationAccessRequest,
    CertificationRequestLink,
    ExternalAccessGrant,
)
from .service import create_grant

AAD_RULE = "CDS-UTC-AAD"
SSM_RULE = "CDS-TRC-SSM"
#: Pending requests one link may hold before it refuses more. A published link
#: is reachable by anyone who has it; this bounds what one leaked link costs.
MAX_PENDING_PER_LINK = 50
#: Pending requests one email address may hold across a link.
MAX_PENDING_PER_EMAIL = 3
MAX_TTL_DAYS = 366
#: An approval not collected within this lapses; otherwise a receipt approved
#: today could be exchanged for a fresh grant a year from now.
CLAIM_WITHIN = timedelta(days=14)
#: American Samoa and Guam: the earliest and latest calendar dates any US
#: zone gives an instant. See the module docstring.
US_EARLIEST = timezone(timedelta(hours=-11))
US_LATEST = timezone(timedelta(hours=10))


class RequestError(Exception):
    """A refusal the caller can act on, with the HTTP status that says why."""

    def __init__(self, message: str, status: int = 422) -> None:
        super().__init__(message)
        self.status = status


def _now() -> datetime:
    return datetime.now(UTC)


def _audit_actor(email: str) -> str:
    return f"external:{email}"


async def _audit(session: AsyncSession, org_id: int, **kw: Any) -> None:
    from ..api.audit import record_event  # noqa: PLC0415 — avoid import cycle

    await record_event(session, organization_id=org_id, **kw)


# ── the rule ───────────────────────────────────────────────────────────────


def _aad() -> dict[str, Any]:
    rule: dict[str, Any] = load_rules().data["FRR"]["CDS"]["data"]["all"]["UTC"][AAD_RULE]
    return rule


def notice_window() -> int:
    """CDS-UTC-AAD's window in business days, read from the pinned rules."""
    rule = _aad()
    if rule.get("timeframe_type") != "bizdays" or not isinstance(rule.get("timeframe_num"), int):
        # A unit this code does not count must fail, not become days.
        raise ValueError(
            f"{AAD_RULE}: cannot count {rule.get('timeframe_num')!r} {rule.get('timeframe_type')!r}"
        )
    return int(rule["timeframe_num"])


def notice_target() -> dict[str, str]:
    """Where FedRAMP says to send the notice, as pinned."""
    target = _aad()["notification"][0]
    return {
        "name": str(target["name"]),
        "url": str(target["target"]),
        "party": str(target["party"]),
    }


def decision_date(at: datetime) -> date:
    """The calendar date a decision counts from: its date in the earliest US zone."""
    return at.astimezone(US_EARLIEST).date()


def us_today(now: datetime | None = None) -> date:
    """The latest date it is anywhere in the US -- for "is it overdue yet"."""
    return (now or _now()).astimezone(US_LATEST).date()


def notice_due(decided_at: datetime) -> date:
    return add_business_days(decision_date(decided_at), notice_window())


def add_business_days(start: date, days: int) -> date:
    """``days`` weekdays after ``start`` (weekends skipped, holidays not)."""
    current = start
    remaining = days
    while remaining > 0:
        current += timedelta(days=1)
        if current.weekday() < 5:  # Mon..Fri
            remaining -= 1
    return current


@dataclass(frozen=True)
class Notice:
    state: str  # not_required | due | overdue | filed | filed_late
    due: date | None


def notice_state(req: CertificationAccessRequest, today: date) -> Notice:
    if req.status != "denied":
        return Notice("not_required", None)
    due = req.fedramp_notify_due
    if req.fedramp_notified_on is not None:
        late = due is not None and req.fedramp_notified_on > due
        return Notice("filed_late" if late else "filed", due)
    return Notice("overdue" if due is not None and today > due else "due", due)


# ── links ──────────────────────────────────────────────────────────────────


async def _live_system_ids(session: AsyncSession, org_id: int, ids: list[int]) -> set[int]:
    return set(
        (
            await session.execute(
                select(System.id).where(
                    System.id.in_(ids),
                    System.organization_id == org_id,
                    System.deleted_at.is_(None),
                )
            )
        ).scalars()
    )


async def create_link(
    session: AsyncSession,
    *,
    org_id: int,
    system_ids: list[int],
    label: str | None,
    actor: str,
) -> tuple[CertificationRequestLink, str]:
    """Create a request link. Returns it and its token, shown once."""
    ids = sorted({int(s) for s in system_ids})
    if not ids:
        raise RequestError("a request link must name at least one system")
    if missing := sorted(set(ids) - await _live_system_ids(session, org_id, ids)):
        raise RequestError(f"systems {missing} not found in organization {org_id}")
    token = secrets.token_urlsafe(32)
    link = CertificationRequestLink(
        organization_id=org_id,
        token_hash=hash_token(token),
        label=label,
        system_ids=ids,
        created_by=actor,
    )
    session.add(link)
    await session.flush()
    await _audit(
        session,
        org_id,
        actor=actor,
        action="create",
        entity_type="certification_request_link",
        entity_id=str(link.id),
        diff={"systems": ids, "label": label},
    )
    return link, token


async def list_links(session: AsyncSession, *, org_id: int) -> list[CertificationRequestLink]:
    return list(
        (
            await session.execute(
                select(CertificationRequestLink)
                .where(CertificationRequestLink.organization_id == org_id)
                .order_by(CertificationRequestLink.id.desc())
            )
        ).scalars()
    )


async def revoke_link(session: AsyncSession, link_id: int, *, org_id: int, actor: str) -> None:
    link = (
        await session.execute(
            select(CertificationRequestLink)
            .where(
                CertificationRequestLink.id == link_id,
                CertificationRequestLink.organization_id == org_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if link is None:
        raise RequestError("request link not found", 404)
    if link.revoked_at is not None:
        return  # the first revocation stands
    link.revoked_at = _now()
    link.revoked_by = actor
    await _audit(
        session,
        org_id,
        actor=actor,
        action="delete",
        entity_type="certification_request_link",
        entity_id=str(link.id),
        diff={"revoked_at": link.revoked_at.isoformat()},
    )


async def resolve_link(
    session: AsyncSession, token: str, *, lock: bool = False
) -> CertificationRequestLink | None:
    if not token:
        return None
    query = select(CertificationRequestLink).where(
        CertificationRequestLink.token_hash == hash_token(token),
        CertificationRequestLink.revoked_at.is_(None),
    )
    if lock:
        query = query.with_for_update()
    return (await session.execute(query)).scalar_one_or_none()


# ── the agency's side ──────────────────────────────────────────────────────


def _required(value: str | None, field: str) -> str:
    text = (value or "").strip()
    if not text:
        raise RequestError(f"{field} is required")
    return text


async def submit(
    session: AsyncSession,
    *,
    link_token: str,
    agency_name: str,
    requester_name: str,
    email: str,
    reason: str | None,
    system_ids: list[int],
) -> tuple[CertificationAccessRequest, str]:
    """Record an agency's request. Returns it and its receipt, shown once."""
    # Locked so concurrent submissions cannot all pass the caps below.
    link = await resolve_link(session, link_token, lock=True)
    if link is None:
        raise RequestError("this request link is not valid", 404)
    agency = _required(agency_name, "agency_name")
    requester = _required(requester_name, "requester_name")
    mail = _required(email, "email")
    if "@" not in mail:
        raise RequestError("email must be an email address")
    wanted = sorted({int(s) for s in system_ids}) or list(link.system_ids)
    if outside := sorted(set(wanted) - set(link.system_ids)):
        raise RequestError(f"systems {outside} cannot be requested through this link")
    pending = (
        await session.execute(
            select(func.count()).where(
                CertificationAccessRequest.link_id == link.id,
                CertificationAccessRequest.status == "pending",
            )
        )
    ).scalar_one()
    if pending >= MAX_PENDING_PER_LINK:
        raise RequestError("this link has too many requests awaiting a decision", 429)
    mine = (
        await session.execute(
            select(func.count()).where(
                CertificationAccessRequest.link_id == link.id,
                CertificationAccessRequest.status == "pending",
                func.lower(CertificationAccessRequest.email) == mail.lower(),
            )
        )
    ).scalar_one()
    if mine >= MAX_PENDING_PER_EMAIL:
        raise RequestError("this address already has requests awaiting a decision", 429)
    receipt = secrets.token_urlsafe(32)
    req = CertificationAccessRequest(
        organization_id=link.organization_id,
        link_id=link.id,
        receipt_hash=hash_token(receipt),
        agency_name=agency,
        requester_name=requester,
        email=mail,
        reason=(reason or "").strip() or None,
        system_ids=wanted,
        status="pending",
    )
    session.add(req)
    await session.flush()
    await _audit(
        session,
        link.organization_id,
        actor=_audit_actor(mail),
        action="create",
        entity_type="certification_access_request",
        entity_id=str(req.id),
        diff={"agency": agency, "systems": wanted, "link": link.id},
    )
    return req, receipt


async def by_receipt(
    session: AsyncSession, receipt: str, *, lock: bool = False
) -> CertificationAccessRequest | None:
    if not receipt:
        return None
    query = select(CertificationAccessRequest).where(
        CertificationAccessRequest.receipt_hash == hash_token(receipt)
    )
    if lock:
        query = query.with_for_update()
    return (await session.execute(query)).scalar_one_or_none()


def claim_by(req: CertificationAccessRequest) -> datetime | None:
    if req.status != "approved" or req.decided_at is None:
        return None
    return req.decided_at + CLAIM_WITHIN


def _claim_lapsed(req: CertificationAccessRequest) -> bool:
    deadline = claim_by(req)
    return deadline is not None and req.claimed_at is None and _now() > deadline


def receipt_view(req: CertificationAccessRequest) -> dict[str, Any]:
    """What the requester may see of their own request."""
    return {
        "status": req.status,
        "agency_name": req.agency_name,
        "systems": req.system_ids,
        "submitted_at": req.created_at,
        "decided_at": req.decided_at,
        # The reason is the requester's to know; who decided is not.
        "decision_reason": req.decision_reason if req.status == "denied" else None,
        "claimable": req.status == "approved" and req.claimed_at is None and not _claim_lapsed(req),
        "claim_by": claim_by(req),
        "claimed": req.claimed_at is not None,
    }


async def claim(session: AsyncSession, receipt: str) -> ExternalAccessGrant:
    """Issue the approved grant, once. The row is locked so two claims racing
    on one receipt cannot both issue a credential."""
    req = await by_receipt(session, receipt, lock=True)
    if req is None:
        raise RequestError("receipt not recognised", 404)
    if req.status != "approved":
        raise RequestError(f"this request is {req.status}, not approved", 409)
    if req.claimed_at is not None:
        raise RequestError("this approval has already been claimed", 409)
    if _claim_lapsed(req):
        raise RequestError("this approval was not collected in time and has lapsed", 409)
    if not req.ttl_days or req.approved_system_ids is None:
        # The CHECK forbids this; a direct write must not become a grant that
        # never expires.
        raise RequestError("this approval is incomplete and cannot be collected", 409)
    try:
        grant = await create_grant(
            session,
            org_id=req.organization_id,
            principal_name=req.requester_name,
            kind="agency",
            email=req.email,
            organization_name=req.agency_name,
            certification_system_ids=list(req.approved_system_ids),
            ttl_days=req.ttl_days,
            label=f"access request #{req.id}",
            # The grant's issuer is whoever approved it, not the claimant.
            actor=req.decided_by,
        )
    except ValueError as exc:  # a system deleted since approval
        raise RequestError(f"access can no longer be issued: {exc}", 409) from exc
    req.grant_id = grant.id
    req.claimed_at = _now()
    await _audit(
        session,
        req.organization_id,
        actor=_audit_actor(req.email),
        action="update",
        entity_type="certification_access_request",
        entity_id=str(req.id),
        diff={"claimed": True, "grant": grant.id},
    )
    return grant


# ── the provider's side ────────────────────────────────────────────────────


async def list_requests(session: AsyncSession, *, org_id: int) -> list[CertificationAccessRequest]:
    return list(
        (
            await session.execute(
                select(CertificationAccessRequest)
                .where(CertificationAccessRequest.organization_id == org_id)
                .order_by(CertificationAccessRequest.id.desc())
            )
        ).scalars()
    )


async def _pending_for_decision(
    session: AsyncSession, req_id: int, org_id: int
) -> CertificationAccessRequest:
    req = (
        await session.execute(
            select(CertificationAccessRequest)
            .where(
                CertificationAccessRequest.id == req_id,
                CertificationAccessRequest.organization_id == org_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if req is None:
        raise RequestError("access request not found", 404)
    if req.status != "pending":
        raise RequestError(f"this request is already {req.status}", 409)
    return req


async def approve(
    session: AsyncSession,
    req_id: int,
    *,
    org_id: int,
    actor: str,
    ttl_days: int,
    system_ids: list[int] | None = None,
) -> CertificationAccessRequest:
    req = await _pending_for_decision(session, req_id, org_id)
    if not 0 < ttl_days <= MAX_TTL_DAYS:
        raise RequestError(f"ttl_days must be between 1 and {MAX_TTL_DAYS}")
    granted = sorted({int(s) for s in system_ids}) if system_ids else list(req.system_ids)
    if outside := sorted(set(granted) - set(req.system_ids)):
        raise RequestError(f"systems {outside} were not requested")
    if missing := sorted(set(granted) - await _live_system_ids(session, org_id, granted)):
        raise RequestError(f"systems {missing} no longer exist")
    req.status = "approved"
    req.decided_by = actor
    req.decided_at = _now()
    req.ttl_days = ttl_days
    req.approved_system_ids = granted
    await _audit(
        session,
        org_id,
        actor=actor,
        action="update",
        entity_type="certification_access_request",
        entity_id=str(req.id),
        diff={"status": "approved", "systems": granted, "ttl_days": ttl_days},
    )
    return req


async def deny(
    session: AsyncSession, req_id: int, *, org_id: int, actor: str, reason: str
) -> CertificationAccessRequest:
    req = await _pending_for_decision(session, req_id, org_id)
    why = _required(reason, "reason")
    req.status = "denied"
    req.decided_by = actor
    req.decided_at = _now()
    req.decision_reason = why
    req.fedramp_notify_due = notice_due(req.decided_at)
    await _audit(
        session,
        org_id,
        actor=actor,
        action="update",
        entity_type="certification_access_request",
        entity_id=str(req.id),
        diff={"status": "denied", "fedramp_notify_due": req.fedramp_notify_due.isoformat()},
    )
    return req


async def record_notice(
    session: AsyncSession,
    req_id: int,
    *,
    org_id: int,
    actor: str,
    notified_on: date,
    reference: str,
) -> CertificationAccessRequest:
    """Record that FedRAMP was told of a denial. The first record stands."""
    req = (
        await session.execute(
            select(CertificationAccessRequest)
            .where(
                CertificationAccessRequest.id == req_id,
                CertificationAccessRequest.organization_id == org_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if req is None:
        raise RequestError("access request not found", 404)
    if req.status != "denied":
        raise RequestError("only a denial is reported to FedRAMP", 409)
    if req.fedramp_notified_on is not None:
        raise RequestError("the FedRAMP notice is already recorded", 409)
    ref = _required(reference, "reference")
    if req.decided_at is None:  # the CHECK forbids a decided state without it
        raise RequestError("this denial has no decision time", 409)
    if notified_on < decision_date(req.decided_at):
        raise RequestError("the notice cannot predate the denial")
    if notified_on > us_today():
        raise RequestError("the notice cannot be dated in the future")
    req.fedramp_notified_on = notified_on
    req.fedramp_notified_by = actor
    req.fedramp_reference = ref
    # When it was recorded, beside the date it is said to have been filed: the
    # filed date is the provider's word, this one is not.
    req.fedramp_notice_recorded_at = _now()
    await _audit(
        session,
        org_id,
        actor=actor,
        action="update",
        entity_type="certification_access_request",
        entity_id=str(req.id),
        diff={"fedramp_notified_on": notified_on.isoformat(), "reference": ref},
    )
    return req


def request_view(req: CertificationAccessRequest, today: date) -> dict[str, Any]:
    notice = notice_state(req, today)
    return {
        "id": req.id,
        "status": req.status,
        "agency_name": req.agency_name,
        "requester_name": req.requester_name,
        "email": req.email,
        "reason": req.reason,
        "system_ids": req.system_ids,
        "submitted_at": req.created_at,
        "decided_by": req.decided_by,
        "decided_at": req.decided_at,
        "decision_reason": req.decision_reason,
        "ttl_days": req.ttl_days,
        "approved_system_ids": req.approved_system_ids,
        "grant_id": req.grant_id,
        "claimed_at": req.claimed_at,
        "fedramp_notice": notice.state,
        "fedramp_notify_due": notice.due,
        "fedramp_notified_on": req.fedramp_notified_on,
        "fedramp_notified_by": req.fedramp_notified_by,
        "fedramp_reference": req.fedramp_reference,
        "fedramp_notice_recorded_at": req.fedramp_notice_recorded_at,
        "claim_by": claim_by(req),
    }
