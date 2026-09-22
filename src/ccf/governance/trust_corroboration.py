"""What the platform can back on the Trust Center — corroborate, never refuse.

Every field on ``/trust`` is operator-typed JSONB on one ``TrustProfile`` row.
``framework_badges`` is an arbitrary ``{framework, status}`` pair with no
vocabulary, no expiry and no link to an authorization record. Measured on the
dev catalog: all 14 systems carry ``ato_status='none'`` and the single existing
badge reads ``{"framework": "CMMC L2", "status": "In progress"}`` — so
*deriving* badges instead of accepting them would render an empty page, and an
empty Trust Center is honest and useless. This module therefore annotates the
operator's claim; it never becomes one.

Four properties this module must keep:

* **It never writes, edits, drops or reorders a badge.** Every function here
  is a ``SELECT``. :class:`BadgeCorroboration` holds a *reference* to the
  operator's badge dict, deliberately not a copy — nothing here may normalize,
  re-key or re-case what an operator typed, and
  ``test_stored_badges_are_byte_identical_after_rendering`` pins that the
  stored JSONB survives a render unchanged.

* **``unsupported`` is not doubt.** It is the common case (every system is
  ``none``) and it is a statement about *Concord's records*, not about the
  organization's compliance. :data:`UNSUPPORTED_DETAIL` says so in those
  words. "Unverified" and "unconfirmed" are banned phrasings, not stylistic
  preferences: on a page about an organization's security posture, rendering
  absence of evidence as evidence of absence is defamatory.

* **The framework match is loose, and it says so.** Badge frameworks are free
  text and nothing in the platform stores a compliance framework per system,
  so corroboration is matched against the organization's systems *as a whole*.
  :data:`LOOSE_MATCH_NOTE` is rendered beside the states so the text cannot
  imply a precision the data does not have.

* **Absence of systems is not contradiction.** An organization Concord holds
  no systems for is ``unsupported``, never ``contradicted`` — see
  :meth:`OrgAuthorizationFacts.holds_nothing`. ``contradicted`` requires the
  platform to hold a record that *says something different*: a system row
  whose own ``ato_status`` asserts it is not authorized. Collapsing the two
  would print "does not match platform records" for a brand-new tenant that
  has told Concord nothing, which is the exact defect the previous bullet
  names.

Pattern: :mod:`ccf.ssp.completeness_query` — a DB-backed read service that
lives beside its domain rather than in a route handler, so a second surface
(here: the ``/api/trust/package`` export) calls it instead of growing its own
copy. Shape: :mod:`ccf.capability.divergence`, the existing model for
surfacing a computed state beside an authored one without overwriting it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import System
from ..models_packages import AuthorizationPackage

# ── The three states (§2) ────────────────────────────────────────────────────
#: Platform data supports this claim.
CORROBORATED = "corroborated"
#: The platform holds nothing either way. The common case, and not doubt.
UNSUPPORTED = "unsupported"
#: Platform data says something different. The case the feature exists for.
CONTRADICTED = "contradicted"

# ── What a badge's free-text status is claiming ──────────────────────────────
CLAIM_AUTHORIZED = "authorized"
CLAIM_IN_PROGRESS = "in_progress"
CLAIM_EXPIRED = "expired"

#: Chip text per state. Deliberately phrased about *the platform's records*,
#: never about the claim: "no record in Concord" reports what Concord holds,
#: "unverified" would report a judgement of what the operator wrote.
STATE_LABELS = {
    CORROBORATED: "supported by platform records",
    UNSUPPORTED: "no record in Concord",
    CONTRADICTED: "does not match platform records",
}

#: The exact ``unsupported`` phrasing, pinned by
#: ``test_unsupported_reads_as_absence_of_record_not_doubt``. §2.1 of the
#: design makes this wording a requirement rather than copy: it must name
#: Concord's records as the subject of the sentence.
UNSUPPORTED_DETAIL = (
    "Concord holds no authorization record for this organization's systems. "
    "That is a statement about what the platform has been told, not about this claim."
)

#: Rendered once beside the badges. §3: the match is on the organization's
#: systems as a whole, and the text must not imply otherwise.
LOOSE_MATCH_NOTE = (
    "Concord does not record a compliance framework per system, so these checks are "
    "matched against all of this organization's systems as a whole, not against the "
    "framework named on each badge."
)


def _today() -> date:
    return datetime.now(UTC).date()


def classify_claim(status: str | None) -> str | None:
    """What a badge's free-text ``status`` is claiming, or ``None``.

    ``None`` means "this module has nothing to say about that claim", which
    resolves to :data:`UNSUPPORTED` — the safe state. Badge statuses are free
    text with no vocabulary (§5 keeps it that way), so this is a best-effort
    read of what an operator wrote, never a validation of it.

    ``expired`` is tested first on purpose: "Authorization expired" contains
    both "authoriz" and "expir", and it is claiming the lapse.
    """
    s = (status or "").strip().lower()
    if not s:
        return None
    if "expir" in s or "lapsed" in s:
        return CLAIM_EXPIRED
    if "progress" in s or "underway" in s or "pursuing" in s:
        return CLAIM_IN_PROGRESS
    if "authoriz" in s or "authoris" in s or "certifi" in s or "accredit" in s:
        return CLAIM_AUTHORIZED
    return None


@dataclass(frozen=True)
class ExpiredAuthorization:
    """One system whose authorization Concord records as lapsed."""

    system_id: int
    system_name: str
    ato_status: str | None
    expires_on: date | None

    @property
    def label(self) -> str:
        when = f" on {self.expires_on.isoformat()}" if self.expires_on else ""
        return f"{self.system_name}{when}"


@dataclass(frozen=True)
class OrgAuthorizationFacts:
    """Everything this module knows about one organization's authorizations.

    Only signals that already exist (§5): ``System.ato_status``,
    ``System.ato_expires_on`` and the existence of an
    :class:`~ccf.models_packages.AuthorizationPackage`. No new derivation and
    no new table.
    """

    system_count: int
    authorized_current: int
    in_progress: int
    packages: int
    expired: tuple[ExpiredAuthorization, ...] = ()

    @property
    def holds_nothing(self) -> bool:
        """Concord has been told nothing about this organization's systems.

        Distinct from "told, and what it was told disagrees". Nothing may be
        reported as :data:`CONTRADICTED` on the strength of an empty table.
        """
        return self.system_count == 0 and self.packages == 0


@dataclass(frozen=True)
class BadgeCorroboration:
    """One operator-typed badge, annotated — and never altered.

    ``badge`` is the operator's own dict by reference. Read it for display;
    do not write to it, and do not render a normalized substitute.
    """

    badge: dict[str, Any]
    claim: str | None
    state: str
    detail: str

    @property
    def framework(self) -> Any:
        return self.badge.get("framework")

    @property
    def status(self) -> Any:
        return self.badge.get("status")

    @property
    def label(self) -> str:
        return STATE_LABELS[self.state]


@dataclass(frozen=True)
class TrustCorroboration:
    """What the page and the export both render.

    ``expired`` is carried at this level rather than per badge because §3
    requires a lapsed authorization to be reported *even when no badge claims
    it* — an expired ATO is the single fact a trust page most needs to not
    omit, and a page with no badges at all is exactly where it would be lost.
    """

    badges: tuple[BadgeCorroboration, ...]
    facts: OrgAuthorizationFacts
    loose_match_note: str = LOOSE_MATCH_NOTE

    @property
    def expiry_notice(self) -> str | None:
        """The lapsed-authorization line, or ``None`` when nothing has lapsed."""
        if not self.facts.expired:
            return None
        names = "; ".join(e.label for e in self.facts.expired)
        noun = "authorization" if len(self.facts.expired) == 1 else "authorizations"
        return f"Concord's records show a lapsed {noun}: {names}."

    def as_export(self) -> dict[str, Any]:
        """The same states the page renders, for the downloaded artifact (§6.6).

        The export is compared against the page field-for-field by
        ``test_export_carries_the_same_states_as_the_page``: the artifact an
        organization hands a customer must not be able to claim more than the
        screen its operator looked at.
        """
        return {
            "note": self.loose_match_note,
            "expiry_notice": self.expiry_notice,
            "badges": [
                {
                    "framework": b.framework,
                    "status": b.status,
                    "state": b.state,
                    "label": b.label,
                    "detail": b.detail,
                }
                for b in self.badges
            ],
        }


def _org_systems(org_id: int | None) -> Any:
    """The systems in scope, mirroring ``capability.divergence._org_systems``.

    ``org_id is None`` means unscoped (auth disabled or a global principal),
    the same convention every caller in ``ui.py`` uses. The predicate is
    written here **explicitly** and not left to RLS: ``get_session`` binds the
    tenant, but this module is also called from ``session_scope()`` (CLI/ETL,
    which bypasses RLS), and a corroboration that silently widened to every
    tenant there would let one organization's ATO back another's badge.
    """
    q = select(System.id, System.name, System.ato_status, System.ato_expires_on)
    return q if org_id is None else q.where(System.organization_id == org_id)


async def authorization_facts(
    session: AsyncSession, *, org_id: int | None = None
) -> OrgAuthorizationFacts:
    """Read the organization's authorization signals. One SELECT, plus one
    for package existence."""
    today = _today()
    rows = (await session.execute(_org_systems(org_id).order_by(System.name, System.id))).all()

    authorized_current = 0
    in_progress = 0
    expired: list[ExpiredAuthorization] = []
    for sys_id, name, status, expires_on in rows:
        lapsed = status == "expired" or (expires_on is not None and expires_on < today)
        if lapsed:
            expired.append(
                ExpiredAuthorization(
                    system_id=sys_id,
                    system_name=name,
                    ato_status=status,
                    expires_on=expires_on,
                )
            )
        if status == "authorized" and not lapsed:
            # A missing ``ato_expires_on`` is not a lapse. §3 reads "expiry in
            # the future", but an authorization Concord records with no expiry
            # date on file is still an authorization on file, and calling it
            # contradicted would report Concord's own record as disagreeing
            # with the badge it supports.
            authorized_current += 1
        if status == "in_progress":
            in_progress += 1

    pkg_q = select(AuthorizationPackage.id).limit(1)
    if org_id is not None:
        pkg_q = pkg_q.where(AuthorizationPackage.organization_id == org_id)
    packages = len((await session.execute(pkg_q)).all())

    return OrgAuthorizationFacts(
        system_count=len(rows),
        authorized_current=authorized_current,
        in_progress=in_progress,
        packages=packages,
        expired=tuple(expired),
    )


def _authorized_state(facts: OrgAuthorizationFacts) -> tuple[str, str]:
    """The over-claim rule, and the only path to :data:`CONTRADICTED` (§2.2).

    A badge asserting an authorization while every system Concord holds for
    the organization records that it has none is the one case an operator
    must act on -- either by recording the authorization or by correcting the
    badge. Reached only when :meth:`OrgAuthorizationFacts.holds_nothing` is
    false, so ``system_count`` here is never zero: the sentence names records
    that exist.
    """
    if facts.authorized_current:
        return CORROBORATED, (
            f"Concord's records show {facts.authorized_current} system(s) in this "
            "organization with a current authorization."
        )
    return CONTRADICTED, (
        f"Concord holds {facts.system_count} system(s) for this organization and none "
        "of them records a current authorization. Record the authorization, or correct "
        "the badge."
    )


def _in_progress_state(facts: OrgAuthorizationFacts) -> tuple[str, str]:
    """Never contradicted: an organization can be pursuing an authorization
    Concord has not been told about, and a lapsed one is a reason to be
    pursuing another. Silence here is silence, not disagreement."""
    if facts.in_progress:
        return CORROBORATED, (
            f"Concord's records show {facts.in_progress} system(s) in this organization "
            "with an authorization in progress."
        )
    if facts.packages:
        return CORROBORATED, (
            "Concord holds an authorization package for a system in this organization."
        )
    return UNSUPPORTED, UNSUPPORTED_DETAIL


def _expired_state(facts: OrgAuthorizationFacts) -> tuple[str, str]:
    """Also never contradicted -- a badge that *under*claims is not an
    over-claim, and the loose framework match (§3) means a current
    authorization on one system says nothing about the framework this badge
    names."""
    if facts.expired:
        return CORROBORATED, (
            f"Concord's records show {len(facts.expired)} system(s) in this organization "
            "with a lapsed authorization."
        )
    return UNSUPPORTED, UNSUPPORTED_DETAIL


#: claim -> rule. A claim this module could not read has no entry, and an
#: unreadable claim resolves to ``unsupported`` -- the safe state.
_CLAIM_RULES = {
    CLAIM_AUTHORIZED: _authorized_state,
    CLAIM_IN_PROGRESS: _in_progress_state,
    CLAIM_EXPIRED: _expired_state,
}


def _state_for(claim: str | None, facts: OrgAuthorizationFacts) -> tuple[str, str]:
    """``(state, detail)`` for one claim against one organization's facts.

    ``holds_nothing`` short-circuits every rule: nothing may be reported as
    disagreeing with the platform on the strength of an empty table.
    """
    rule = _CLAIM_RULES.get(claim or "")
    if rule is None or facts.holds_nothing:
        return UNSUPPORTED, UNSUPPORTED_DETAIL
    return rule(facts)


async def corroborate_badges(
    session: AsyncSession,
    badges: list[Any] | None,
    *,
    org_id: int | None = None,
) -> TrustCorroboration:
    """Annotate every badge, in the operator's order, and report any lapse.

    ``badges`` is ``TrustProfile.framework_badges`` — free-text JSONB. Rows
    that are not dicts are skipped rather than raising: this feeds a render,
    and a render is not the place to fail over a column an operator can put
    anything in.
    """
    facts = await authorization_facts(session, org_id=org_id)
    out: list[BadgeCorroboration] = []
    for badge in badges or []:
        if not isinstance(badge, dict):
            continue
        claim = classify_claim(badge.get("status"))
        state, detail = _state_for(claim, facts)
        out.append(BadgeCorroboration(badge=badge, claim=claim, state=state, detail=detail))
    return TrustCorroboration(badges=tuple(out), facts=facts)


__all__ = [
    "CLAIM_AUTHORIZED",
    "CLAIM_EXPIRED",
    "CLAIM_IN_PROGRESS",
    "CONTRADICTED",
    "CORROBORATED",
    "LOOSE_MATCH_NOTE",
    "STATE_LABELS",
    "UNSUPPORTED",
    "UNSUPPORTED_DETAIL",
    "BadgeCorroboration",
    "ExpiredAuthorization",
    "OrgAuthorizationFacts",
    "TrustCorroboration",
    "authorization_facts",
    "classify_claim",
    "corroborate_badges",
]
