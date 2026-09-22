"""The guided onboarding path: six steps, per system, each with a state.

A customer-facing "where am I, what is next" answer, rendered on the system
detail page (see ``docs/superpowers/specs/2026-09-21-guided-onboarding-design.md``).

It lives here rather than in ``api/routes/ui.py`` for the reason
:mod:`ccf.ssp.completeness_query` lives outside ``api/routes/ssp.py``: where a
system stands is a property of the system, not of one HTTP endpoint, and a
second page needing it must call :func:`onboarding_state` rather than grow its
own copy of these joins.

**Every number here comes from the helper that already owns it.** Nothing in
this module re-derives a figure the product already computes -- POA&M counts
and the overdue rule come from :func:`ccf.analytics.posture.systems_scorecard`,
coverage from :func:`ccf.governance.automation.coverage`, SSP completeness from
:func:`ccf.ssp.completeness_query.project_completeness`, connector liveness from
:func:`ccf.governance.control_tests.organization_capture_is_live`, and
engagement currency from :func:`ccf.portal.service.current_engagement_ids`. A
dashboard and its source begin to disagree the first time one of them grows its
own second implementation.

Two figures are deliberately absent (spec §5.1):
``AuthorizationPackage.readiness_pct`` (a snapshot frozen at package-creation
time, wrong the moment anything changes) and anything from
``ccf.fedramp20x.readiness._derive_status`` (a second, KSI-only progress story
that would be free to disagree with these six steps on the same page).

The five states and the asymmetry between them
----------------------------------------------
``done`` is the only state this module is not entitled to guess at. **A step is
``done`` only on a row that exists, never on a query returning empty** -- "no
POA&Ms found" is not "no gaps", and "no connector errors" is not "a connector
works". Where the platform cannot see enough to say, the state is ``unknown``,
which must never be collapsed into ``done`` (an empty result read as the
favourable answer) nor into ``not_started`` (a guess rendered as a fact).

``not_available`` is derived, never stored: a system whose declared platform has
no connector in :data:`ccf.ssp.platforms.PLATFORM_CONNECTOR_KEYS` (Azure today),
or which declared no cloud at all, is not failing step 2 -- there is nothing
there to do. A *stored* not-applicable override is deliberately out of scope
(spec §4.1/§9); it needs an audit trail and a migration, and this page needs
neither.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .analytics.posture import systems_scorecard
from .governance import automation
from .governance.control_tests import organization_capture_is_live
from .models import KSIState, SSPProject, System, SystemProfile
from .models_cr26 import Cr26Document
from .models_grc import ConnectorConfig
from .models_packages import AuthorizationPackage
from .models_portal import AssessmentEngagement
from .portal.service import current_engagement_ids
from .ssp.completeness_query import project_completeness
from .ssp.platforms import PLATFORM_CONNECTOR_KEYS

#: Evidence exists. Only ever set from a row that exists.
DONE = "done"
#: Begun, with something measurable left -- and the remainder is *named*.
IN_PROGRESS = "in_progress"
#: The platform positively knows nothing exists.
NOT_STARTED = "not_started"
#: The platform cannot see enough to say. Never ``done``, never ``not_started``.
UNKNOWN = "unknown"
#: No connector exists for this system's declared platform (step 2 only).
NOT_AVAILABLE = "not_available"

#: Every state a :class:`Step` may carry. Rendering code maps each to a chip.
STATES: frozenset[str] = frozenset(
    {DONE, IN_PROGRESS, NOT_STARTED, UNKNOWN, NOT_AVAILABLE}
)

#: The intake ``cloud_platform`` answer meaning "this system uses no cloud".
#: Not an unrecognized code -- a deliberate answer, and exactly the customer
#: spec §4.1 refuses to show a permanently red step 2 to.
NO_CLOUD = "none"

#: How many named items a remainder sentence lists before it says "and N more".
#: A remainder must be named rather than counted, but a 300-item sentence names
#: nothing a reader can act on.
_NAMED_LIMIT = 3

#: KSI states that are not outstanding work. ``not_applicable`` is a recorded
#: decision, not an unanswered question; every other status (``fail``, ``warn``,
#: ``not_tested``, ``manual_review_required``) is something still to do.
_KSI_SETTLED = frozenset({"pass", "not_applicable"})


@dataclass(frozen=True)
class Step:
    """One step of the path: where the customer is, and what is next.

    ``detail`` is a whole sentence naming what remains -- not a count. "3 of 42
    controls have no narrative" tells a reader what to open; "39 remaining"
    does not.

    ``href`` is the page where the work actually happens, so the step is a door
    rather than a scoreboard. Nothing here gates anything (spec §7).
    """

    key: str
    number: int
    label: str
    state: str
    detail: str
    href: str

    def __post_init__(self) -> None:
        if self.state not in STATES:
            raise ValueError(f"unknown onboarding state: {self.state!r}")


def _named(items: Sequence[str], limit: int = _NAMED_LIMIT) -> str:
    """``"a, b, c and 4 more"`` -- the remainder named, then honestly truncated."""
    head = list(items[:limit])
    rest = len(items) - len(head)
    joined = ", ".join(head)
    if rest > 0:
        return f"{joined} and {rest} more"
    return joined


async def onboarding_state(session: AsyncSession, system: System) -> list[Step]:
    """The six steps for ``system``, in order.

    ``system`` must already be authorized for the caller: this function does no
    tenancy check of its own, exactly as
    :func:`ccf.ssp.completeness_query.project_completeness` does none. The route
    scopes the system with
    :func:`ccf.api.routes.systems.require_system_in_scope` before calling here.
    """
    profile = (
        await session.execute(
            select(SystemProfile).where(SystemProfile.system_id == system.id)
        )
    ).scalar_one_or_none()
    return [
        _step_intake(system, profile),
        await _step_connect_evidence(session, system, profile),
        await _step_ssp(session, system),
        await _step_close_gaps(session, system, profile),
        await _step_package(session, system),
        await _step_3pao(session, system),
    ]


# --- 1. Answer the intake questionnaire ------------------------------------


def _step_intake(system: System, profile: SystemProfile | None) -> Step:
    """``SystemProfile`` for this system, with ``derived_at`` set.

    ``derived_at`` rather than the row's mere existence is the done signal
    because the API already draws that line: ``api/routes/automation.py``
    answers "complete the questionnaire first" from the derivation, not from
    the profile row. Answers saved but never derived are work begun.

    This step never returns ``unknown``: ``system_profiles`` is a table the
    platform can always read, and a missing row positively means no answers
    exist. Inventing an ``unknown`` rung here to make the state set uniform
    would be the fabrication the spec's asymmetry exists to prevent.
    """
    href = "/intake"
    if profile is None:
        return Step(
            key="intake",
            number=1,
            label="Answer the intake questionnaire",
            state=NOT_STARTED,
            detail=(
                "No questionnaire answers have been recorded for this system. "
                "The answers are what decide which controls apply, so every "
                "later step reads from them."
            ),
            href=href,
        )
    if profile.derived_at is None:
        return Step(
            key="intake",
            number=1,
            label="Answer the intake questionnaire",
            state=IN_PROGRESS,
            detail=(
                "Answers are saved but applicability has never been derived "
                "from them, so no control has been marked as applying to this "
                "system yet. Re-submit the questionnaire to derive it."
            ),
            href=href,
        )
    return Step(
        key="intake",
        number=1,
        label="Answer the intake questionnaire",
        state=DONE,
        detail=(
            f"Answered, and applicability derived on "
            f"{profile.derived_at.date().isoformat()}."
        ),
        href=href,
    )


# --- 2. Connect your evidence sources --------------------------------------


def _declared_connector(declared: str) -> tuple[str | None, str, str, str]:
    """Resolve a declared intake platform to ``(connector_key, state, detail, href)``.

    ``connector_key`` is non-``None`` only when Concord ships a connector that
    could capture this platform; the other three fields then carry no meaning
    and the caller goes on to ask whether the tenant has actually captured
    anything. When it is ``None`` the platform alone settles the step, and the
    three fields are the settled answer.

    :data:`ccf.ssp.platforms.PLATFORM_CONNECTOR_KEYS` is read directly rather
    than through ``connector_key_for_platform``. That helper used to default an
    unrecognized code to Microsoft 365, turning "we cannot tell" into "go
    configure Microsoft Graph"; it no longer does, but it still answers ``None``
    for both "Concord ships no connector for this platform" and "Concord does
    not know what this platform is", and this function has to tell those two
    apart to say anything true to the customer.
    """
    if not declared:
        return None, UNKNOWN, (
            "This system has not declared a cloud platform, so Concord cannot "
            "tell which connector -- if any -- would capture its "
            "configuration. Answer the intake questionnaire first."
        ), "/intake"
    if declared == NO_CLOUD:
        return None, NOT_AVAILABLE, (
            "This system declared no cloud platform, so there is no capture "
            "connector to configure. Evidence for it is attached by hand."
        ), "/connectors"
    ssp_platform = automation.PLATFORM_TO_SSP.get(declared)
    if ssp_platform is None:
        return None, UNKNOWN, (
            f"Concord does not recognize the declared platform {declared!r}, "
            f"so it cannot say which connector would capture this system's "
            f"configuration."
        ), "/intake"
    connector_key = PLATFORM_CONNECTOR_KEYS.get(ssp_platform)
    if connector_key is None:
        return None, NOT_AVAILABLE, (
            "Concord ships no capture connector for this system's platform, so "
            "there is nothing to connect. Evidence for it must be attached by "
            "hand before a control counts as evidenced."
        ), "/connectors"
    return connector_key, "", "", "/connectors"


async def _step_connect_evidence(
    session: AsyncSession, system: System, profile: SystemProfile | None
) -> Step:
    """Has *this organization* actually captured configuration for its platform?

    The done signal is
    :func:`ccf.governance.control_tests.organization_capture_is_live` and
    nothing else. That function owns the whole rule -- no row, not
    ``configured``, never synced, a stale sync, a sync that discovered nothing,
    no recent ``CaptureSnapshot``, and a capture made under a host profile
    rather than this tenant's credential all mean *not* backed -- and restating
    any rung of it here would give the product two answers to "does this
    connector work".

    The now-removed ``has_capture_connector`` answered a different question
    (does Concord *ship* a connector for this platform), and a step built on it
    would report "connected" to a customer who has connected nothing. That is
    the defect ``fix/connector-backed-claim`` fixed; this step must not
    re-introduce it.

    The not-live case is split into ``not_started`` and ``in_progress`` by a
    plain existence check -- does a connector row of this type exist for the org
    at all -- which is deliberately *not* a restatement of the rungs: it never
    influences the ``done`` decision, only the wording of the sentence.

    ``not_available`` is derived (spec §4.1) from the declared platform alone,
    by :func:`_declared_connector`: ``"none"`` (no cloud), or an SSP platform
    with no entry in :data:`ccf.ssp.platforms.PLATFORM_CONNECTOR_KEYS` (Azure
    today).
    """
    key = "connect_evidence"
    number = 2
    label = "Connect your evidence sources"
    href = "/connectors"
    declared = (profile.cloud_platform or "") if profile is not None else ""

    connector_key, settled_state, settled_detail, settled_href = _declared_connector(declared)
    if connector_key is None:
        return Step(
            key=key, number=number, label=label,
            state=settled_state, detail=settled_detail, href=settled_href,
        )

    live = await organization_capture_is_live(
        session,
        organization_id=system.organization_id,
        connector_type=connector_key,
    )
    if live:
        return Step(
            key=key, number=number, label=label, state=DONE,
            detail=(
                f"The {connector_key} connector has completed a recent sync "
                f"that discovered configuration for your organization."
            ),
            href=href,
        )

    registered = (
        await session.execute(
            select(func.count(ConnectorConfig.id)).where(
                ConnectorConfig.organization_id == system.organization_id,
                ConnectorConfig.connector_type == connector_key,
            )
        )
    ).scalar_one()
    if registered:
        return Step(
            key=key, number=number, label=label, state=IN_PROGRESS,
            # Deliberately NOT an exhaustive list of the rungs: enumerating
            # them here is what let this sentence go stale and tell a customer
            # one of four things, all of them false, about a connector that had
            # synced fine but produced no capture artifact.
            detail=(
                f"A {connector_key} connector is registered but has not "
                f"recently captured your organization's own configuration: it "
                f"may not be finished being configured, may not have completed "
                f"a recent non-empty sync, may have produced no recent capture, "
                f"or may be authenticating as the host rather than as your "
                f"organization. Open it to see which."
            ),
            href=href,
        )
    return Step(
        key=key, number=number, label=label, state=NOT_STARTED,
        detail=(
            f"No {connector_key} connector is configured for your "
            f"organization, so nothing is capturing this system's "
            f"configuration automatically."
        ),
        href=href,
    )


# --- 3. Generate and refine the SSP ----------------------------------------


async def _step_ssp(session: AsyncSession, system: System) -> Step:
    """SSP completeness, from :func:`project_completeness` and nowhere else.

    **The rule for many projects.** ``SSPProject.system_id`` is nullable and
    carries no unique constraint, so a system may have zero, one, or many
    projects. With zero the step is ``not_started``. With exactly one, that
    project's completeness is this system's SSP completeness.

    **With more than one the step is ``unknown``**, and the sentence names the
    ambiguity. Concord has no field that marks one project as *the* plan for a
    system, so any tie-break -- newest, highest-scoring, lowest id -- would be
    this module inventing an answer and then rendering it as fact. Scoring the
    newest would be the worst of them: it is the one most likely to be a
    half-finished draft, so the step would move *backwards* the moment someone
    started a second plan. ``unknown`` says what is true: the platform cannot
    tell which plan to score. Picking one is a product decision with a column
    behind it, not a default this page gets to choose.
    """
    key = "ssp"
    number = 3
    label = "Generate and refine the SSP"
    projects = list(
        (
            await session.execute(
                select(SSPProject)
                .where(SSPProject.system_id == system.id)
                .order_by(SSPProject.id)
            )
        )
        .scalars()
        .all()
    )
    if not projects:
        return Step(
            key=key, number=number, label=label, state=NOT_STARTED,
            detail=(
                "No SSP project is linked to this system. Generating one seeds "
                "every applicable control with a draft statement to refine."
            ),
            href="/ssp",
        )
    if len(projects) > 1:
        return Step(
            key=key, number=number, label=label, state=UNKNOWN,
            detail=(
                f"{len(projects)} SSP projects are linked to this system "
                f"({_named([p.title for p in projects])}). Concord cannot tell "
                f"which one is this system's plan, so it will not report one "
                f"of their scores as the system's."
            ),
            href="/ssp",
        )

    project = projects[0]
    href = f"/ssp/{project.id}"
    report = await project_completeness(session, project)
    if report["ready"]:
        return Step(
            key=key, number=number, label=label, state=DONE,
            detail=(
                f"All {report['controls_total']} controls are complete and "
                f"every required section of the front matter is present."
            ),
            href=href,
        )

    remaining: list[str] = []
    gaps = report["control_gaps"]
    if gaps:
        remaining.append(
            f"{len(gaps)} controls still incomplete "
            f"({_named([str(g['control_id']) for g in gaps])})"
        )
    sections = report["missing_sections"]
    if sections:
        remaining.append(f"missing {_named([str(s) for s in sections])}")
    if not remaining:
        # A project with no entries at all: nothing is incomplete because
        # nothing is there. Naming that is more use than "0 gaps".
        remaining.append("the plan has no control entries yet")
    return Step(
        key=key, number=number, label=label, state=IN_PROGRESS,
        detail=f"Scored {report['score']}%. Remaining: {'; '.join(remaining)}.",
        href=href,
    )


# --- 4. Close the gaps ------------------------------------------------------


async def _step_close_gaps(
    session: AsyncSession, system: System, profile: SystemProfile | None
) -> Step:
    """Coverage, KSI states and POA&Ms -- each from its own owner.

    The POA&M counts come from :func:`systems_scorecard`, which is also where
    "overdue" is defined (``coalesce(due_on, scheduled_completion,
    original_due_on) < today`` over the active statuses). Re-deriving that here
    would put two overdue counts in one product (spec §5.2), and this page would
    be the one that is wrong.

    ``connector_backed`` is computed exactly as ``api/routes/automation.py``
    computes it -- ``PLATFORM_TO_SSP`` then
    :func:`ccf.governance.automation.platform_capture_is_live` -- so this step's
    coverage rollup is the same rollup that endpoint returns, down to the
    ``manual_evidence_required`` split. It is keyword-only and undefaulted for
    that reason: guessing ``True`` would count a platform default as captured
    evidence.

    Without a derivation there is nothing to measure against, so the step is
    ``unknown``: an un-derived system has no known set of applicable controls,
    and "0 gaps" would read as the favourable answer.
    """
    key = "close_gaps"
    number = 4
    label = "Close the gaps"
    href = f"/poams?system_id={system.id}"

    if profile is None or not profile.derivation:
        return Step(
            key=key, number=number, label=label, state=UNKNOWN,
            detail=(
                "Concord has not derived which controls apply to this system, "
                "so it cannot say what the gaps are. Answer the intake "
                "questionnaire first."
            ),
            href="/intake",
        )

    connector_backed = await automation.platform_capture_is_live(
        session,
        organization_id=system.organization_id,
        platform=automation.PLATFORM_TO_SSP.get(profile.cloud_platform or "", ""),
    )
    cov = automation.coverage(profile, connector_backed=connector_backed)

    ksi_rows = list(
        (
            await session.execute(select(KSIState).where(KSIState.system_id == system.id))
        )
        .scalars()
        .all()
    )
    ksi_outstanding = [k for k in ksi_rows if k.status not in _KSI_SETTLED]

    card = await _scorecard_row(session, system)
    open_poams = int(card["open_poams"]) if card else 0
    overdue_poams = int(card["overdue_poams"]) if card else 0

    uncovered = int(cov["total"]) - int(cov["covered"])
    manual = int(cov["manual_evidence_required"])

    remaining: list[str] = []
    if uncovered:
        remaining.append(f"{uncovered} of {cov['total']} applicable controls not yet covered")
    if manual:
        remaining.append(
            f"{manual} covered only by a platform default that nothing captured, "
            f"so a human must attach evidence"
        )
    if ksi_outstanding:
        remaining.append(
            f"{len(ksi_outstanding)} of {len(ksi_rows)} key security indicators not passing "
            f"({_named(sorted({k.status for k in ksi_outstanding}))})"
        )
    if open_poams:
        remaining.append(
            f"{open_poams} open POA&M(s)"
            + (f", {overdue_poams} of them overdue" if overdue_poams else "")
        )

    if not remaining:
        return Step(
            key=key, number=number, label=label, state=DONE,
            detail=(
                f"All {cov['total']} applicable controls are covered with "
                f"nothing awaiting manual evidence, and no weakness is open "
                f"against this system."
            ),
            href=href,
        )
    # Nothing covered, nothing tracked: the derivation exists and says nothing
    # has been done, which is positively knowing that no work has started --
    # not the same as not being able to see.
    if int(cov["covered"]) == 0 and not manual and not open_poams and not ksi_rows:
        return Step(
            key=key, number=number, label=label, state=NOT_STARTED,
            detail=(
                f"None of the {cov['total']} controls Concord derived as "
                f"applicable are covered yet, and no weakness has been "
                f"recorded against this system."
            ),
            href="/coverage",
        )
    return Step(
        key=key, number=number, label=label, state=IN_PROGRESS,
        detail=f"Remaining: {'; '.join(remaining)}.",
        href=href,
    )


async def _scorecard_row(session: AsyncSession, system: System) -> dict[str, Any] | None:
    """This system's row from :func:`systems_scorecard`, or ``None``.

    The whole org's scorecard is computed and one row taken from it, rather than
    counting POA&Ms here, precisely so the number on this page cannot differ
    from the number on ``/posture``. ``today`` is UTC, as every caller of
    ``systems_scorecard`` uses.
    """
    cards = await systems_scorecard(
        session, today=datetime.now(UTC).date(), org_id=system.organization_id
    )
    for card in cards:
        if card["system_id"] == system.id:
            return card
    return None


# --- 5. Produce the package -------------------------------------------------


async def _step_package(session: AsyncSession, system: System) -> Step:
    """Authorization packages and CR26 deliverables.

    ``is_valid`` is the done signal, not the existence of a row: a CR26
    document row means somebody authored a deliverable, and an authored
    deliverable that fails its schema is not a filed one.
    ``AuthorizationPackage.readiness_pct`` is deliberately not read here (spec
    §5.1) -- it is copied at package-creation time and is only ever correct as
    of ``created_at``.

    A system with no CR26 deliverables sits at ``in_progress``, never ``done``,
    even where CR26 is not its lane. That is the conservative direction: the
    cost is a step that says there is more to do, against a step that tells a
    customer their package is finished when it is not. Marking CR26 genuinely
    not-applicable for a Rev5 system is the stored override spec §4.1 defers,
    with the audit trail that decision deserves.
    """
    key = "package"
    number = 5
    label = "Produce the package"
    href = f"/fedramp20x?system_id={system.id}"

    packages = (
        await session.execute(
            select(func.count(AuthorizationPackage.id)).where(
                AuthorizationPackage.system_id == system.id
            )
        )
    ).scalar_one()
    docs = list(
        (
            await session.execute(
                select(Cr26Document)
                .where(Cr26Document.system_id == system.id)
                .order_by(Cr26Document.kind, Cr26Document.id)
            )
        )
        .scalars()
        .all()
    )

    if not packages and not docs:
        return Step(
            key=key, number=number, label=label, state=NOT_STARTED,
            detail=(
                "No authorization package has been produced and no CR26 "
                "deliverable has been authored for this system."
            ),
            href=href,
        )

    remaining: list[str] = []
    if not packages:
        remaining.append("no authorization package has been produced yet")
    if not docs:
        remaining.append("no CR26 deliverable has been authored yet")
    invalid = [d for d in docs if not d.is_valid]
    if invalid:
        remaining.append(
            f"{len(invalid)} CR26 deliverable(s) fail validation "
            f"({_named([d.kind for d in invalid])})"
        )
    if remaining:
        return Step(
            key=key, number=number, label=label, state=IN_PROGRESS,
            detail=f"Remaining: {'; '.join(remaining)}.",
            href=href,
        )
    return Step(
        key=key, number=number, label=label, state=DONE,
        detail=(
            f"{packages} authorization package(s) produced, and all "
            f"{len(docs)} CR26 deliverable(s) validate."
        ),
        href=href,
    )


# --- 6. Bring in your 3PAO --------------------------------------------------


async def _step_3pao(session: AsyncSession, system: System) -> Step:
    """A *current* engagement for this system.

    Currency is asked of :func:`ccf.portal.service.current_engagement_ids`
    rather than restated as ``revoked_at is None and period_to >= now``. That
    rule is what decides whether an assessor's token still resolves; a page that
    kept its own copy would eventually tell a customer their 3PAO is engaged
    after the engagement stopped authorizing anything.

    This is also why the step can move backwards: revoke the engagement or let
    its period elapse and the step stops being ``done`` on the next render. A
    path that only ratchets forward would be making a false claim the day an
    engagement expires (spec §7).
    """
    key = "3pao"
    number = 6
    label = "Bring in your 3PAO"
    href = "/admin/portal"

    engagements = list(
        (
            await session.execute(
                select(AssessmentEngagement)
                .where(AssessmentEngagement.system_id == system.id)
                .order_by(AssessmentEngagement.id)
            )
        )
        .scalars()
        .all()
    )
    if not engagements:
        return Step(
            key=key, number=number, label=label, state=NOT_STARTED,
            detail=(
                "No assessment engagement has been recorded for this system, "
                "so no 3PAO is authorized to assess it."
            ),
            href=href,
        )

    current = await current_engagement_ids(session, [e.id for e in engagements])
    if current:
        return Step(
            key=key, number=number, label=label, state=DONE,
            detail=(
                f"{len(current)} current assessment engagement(s) authorize a "
                f"3PAO to assess this system."
            ),
            href=href,
        )
    revoked = sum(1 for e in engagements if e.revoked_at is not None)
    elapsed = len(engagements) - revoked
    reasons = []
    if revoked:
        reasons.append(f"{revoked} revoked")
    if elapsed:
        reasons.append(f"{elapsed} whose assessment period has ended")
    return Step(
        key=key, number=number, label=label, state=IN_PROGRESS,
        detail=(
            f"This system has {len(engagements)} assessment engagement(s) but "
            f"none is current ({', '.join(reasons)}). Record a new one to "
            f"re-authorize a 3PAO."
        ),
        href=href,
    )
