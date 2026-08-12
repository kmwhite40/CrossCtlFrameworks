"""Objective-level assessment engine — proposal tables.

The engine evaluates individual 800-53A assessment objectives against evidence
retrieved from the preparation pipeline, then rolls the objective verdicts into a
*proposed* control finding. Proposals are inert: nothing here reaches
``AssessmentControlResult`` — and therefore nothing reaches the SAR or an
auto-created POA&M — until an assessor accepts it. A failed control creates real
remediation work, so the model never holds that authority.

The objectives themselves are not stored. They already exist as sub-clause rows in
``ccf.controls`` (``control_name IS NULL``); an objective proposal records the
objective's label and a SHA-256 of its text, so a catalog re-ingest that changes
wording makes a stale proposal detectable rather than silently wrong.

**These three tables carry a ``tenant_isolation`` RLS policy** (migration
``0060``, 2026-08-12 RLS-coverage design), matching the seven ``prep_*``
tables (see ``models_prep.py``'s identical note) and 121 of Concord's 135
``ccf`` tables overall. It is defence in depth, not the primary control:
every route and service function still filters by ``organization_id``
explicitly (derived from ``Assessment -> System -> Organization``, never from
a caller-supplied id -- see ``ccf.assessment.engine.service``), and those
checks are not removed or relaxed by the policy's addition.
``ccf.assessment.engine.jobs``'s job claim is **intentionally, still,
unscoped** by organization -- one worker drains every organization's queued
jobs by design -- which means the RLS policy above provides no protection on
that specific path: the claim runs through ``ccf.db.session_scope()``, which
leaves the tenant GUC unset and the bootstrap (table-owning) role in effect,
and an unset GUC is exactly what every policy in this schema treats as
bypass. The application-level guard on that path --
``ccf.assessment.engine.jobs.enqueue_reevaluation``'s ``result_org_id !=
organization_id`` check -- is what actually protects it, verified by
``tests/test_assessment_engine_api.py::test_create_proposal_app_check_rejects_cross_tenant_assessment_indep_of_rls``
and (for the GUC mechanism itself) ``tests/test_rls_worker_guc_bypass.py``.
See ``docs/ARCHITECTURE.md``'s "Objective-level assessment engine" section
for the same note alongside the rest of the engine's description.

**No governed-AI-action audit trail.** Objective evaluation
(``ccf.assessment.engine.evaluate``) calls ``ccf.ai.gateway.generate_structured_resolved``
directly (``ccf.prep.classify`` calls the plain ``generate_structured`` instead --
see that gateway function's docstring for why the two differ), neither routes through
``ccf.ai_actions.run_action``, so neither produces an ``ai_action_runs`` row, a
citation record in that subsystem, or a guardrail evaluation. An ``ActionDef``
is registered for prep classification in ``ccf.ai_actions.registry``, but
registration is not dispatch: nothing calls ``run_action`` with it, and there is
no equivalent ``ActionDef`` for objective evaluation at all. For a product whose
output becomes FedRAMP citations, wiring both through the typed AI-action layer
is the standing follow-up.

**Two proposals per control, distinguished by ``source_poam_id``.** The
original ``uq_control_proposal_assessment_control`` constraint was a flat
unique index on ``(assessment_id, control_identifier)`` (migration 0055). A
closure-triggered re-evaluation (migration 0058) needs a *second*,
distinct ``AssessmentControlProposal`` row for that same pair, alongside the
already-accepted first-pass row -- so the flat constraint was replaced by two
partial unique indexes: ``uq_control_proposal_first_pass`` scopes first-pass
idempotency to ``source_poam_id IS NULL`` rows only, and
``uq_control_proposal_source_poam`` caps re-evaluation at one proposal per
POA&M. ``open_control_proposal`` filters ``source_poam_id IS NULL``
explicitly for the same reason: once a re-evaluation row exists alongside a
first-pass row for the same control, an unfiltered lookup would see two rows.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

# Registers ccf.ai_action_runs — the AssessmentObjectiveProposal.ai_action_run_id
# FK target — before mapper configuration, matching models_prep.py's identical FK.
from . import models_ai_actions  # noqa: F401
from .models import Base

#: A model's verdict on one objective.
OBJECTIVE_VERDICTS = ("satisfied", "not_satisfied", "not_applicable", "insufficient_evidence")

#: What the rollup may propose for a control. ``insufficient_evidence`` is
#: proposal-only and is refused by the acceptance path — "the engine could not
#: tell" is not "the control fails", and conflating them manufactures POA&Ms out
#: of missing evidence.
CONTROL_PROPOSAL_FINDINGS = (
    "satisfied",
    "other_than_satisfied",
    "not_applicable",
    "insufficient_evidence",
)

#: Lifecycle of a proposal row. ``stale`` means the catalog objective text changed
#: after evaluation; ``failed`` means the model call could not be completed.
PROPOSAL_STATES = ("draft", "complete", "accepted", "rejected", "failed", "stale")

#: What an assessor may correct a proposed finding to. Deliberately excludes
#: ``insufficient_evidence``: that is a proposal-only state meaning the engine
#: could not tell, and an assessor overriding a verdict is asserting what is
#: true, not declining to say.
CORRECTED_FINDINGS = ("satisfied", "other_than_satisfied", "not_applicable")

ASSESSMENT_JOB_STATES = ("pending", "claimed", "done", "failed")


class AssessmentControlProposal(Base):
    """A proposed finding for one control within one assessment."""

    __tablename__ = "assessment_control_proposals"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    assessment_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.assessments.id", ondelete="CASCADE"), index=True
    )
    #: Canonical (unpadded) form, per ccf.prep.screen.normalize_control_identifier.
    control_identifier: Mapped[str] = mapped_column(String(64), index=True)

    state: Mapped[str] = mapped_column(String(16), default="draft", index=True)
    proposed_finding: Mapped[str | None] = mapped_column(String(32))
    rollup_rationale: Mapped[str | None] = mapped_column(Text)
    #: Thresholds in force when this proposal was evaluated, so a later settings
    #: change cannot retroactively reinterpret it.
    config_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    objectives_total: Mapped[int] = mapped_column(Integer, default=0)
    objectives_evaluated: Mapped[int] = mapped_column(Integer, default=0)
    #: How many of this control's objectives were contested by a challenger
    #: (AI dissent path, migration 0059) -- so a reviewer sees it without a
    #: join. Reset to 0 at the top of every evaluate_control_proposal rerun
    #: (ccf.assessment.engine.service), same as objectives_evaluated above,
    #: so a clean re-evaluation does not carry a prior run's dissent forward.
    dissent_count: Mapped[int] = mapped_column(Integer, default=0)

    accepted_by: Mapped[str | None] = mapped_column(String(255))
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)

    #: Set only on rejection: the finding the assessor believes is correct.
    corrected_finding: Mapped[str | None] = mapped_column(String(32))
    rejected_by: Mapped[str | None] = mapped_column(String(255))
    rejected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: Required on rejection. A rejection without a reason tells calibration the
    #: engine was wrong but not how, and "how" is what makes the metric useful.
    rejection_note: Mapped[str | None] = mapped_column(Text)

    #: Set only on a closure-triggered re-evaluation: the POA&M whose closure
    #: raised this proposal. NULL for every first-pass proposal. Nullable
    #: (not just "usually null"): every existing proposal has no source
    #: POA&M, and a re-evaluation proposal must stay usable if the POA&M is
    #: later deleted (ON DELETE SET NULL, not CASCADE -- the proposal is a
    #: record of what happened, not a detail owned by the POA&M).
    source_poam_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.poams.id", ondelete="SET NULL"), index=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    __table_args__ = (
        # First-pass idempotency (open_control_proposal's own reuse-or-create
        # logic) is scoped to source_poam_id IS NULL rows only -- see the
        # module docstring's note on why a flat (assessment_id,
        # control_identifier) constraint had to give way to this. A
        # closure-triggered re-evaluation for the same control is a second,
        # distinct row and must not collide with the accepted first-pass row
        # still sitting on that same pair.
        Index(
            "uq_control_proposal_first_pass",
            "assessment_id",
            "control_identifier",
            unique=True,
            postgresql_where=text("source_poam_id IS NULL"),
        ),
        # Caps re-evaluation at one proposal per POA&M -- belt-and-braces
        # alongside service.open_reevaluation_proposal's own
        # check-then-insert, which is what actually protects against a race
        # between two concurrent closures of the same POA&M.
        Index(
            "uq_control_proposal_source_poam",
            "source_poam_id",
            unique=True,
            postgresql_where=text("source_poam_id IS NOT NULL"),
        ),
        Index("ix_control_proposal_state", "organization_id", "state"),
    )


class AssessmentObjectiveProposal(Base):
    """A model's verdict on one assessment objective, with its citations."""

    __tablename__ = "assessment_objective_proposals"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    control_proposal_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.assessment_control_proposals.id", ondelete="CASCADE"), index=True
    )

    #: e.g. "AC-02a" from ap_acronym, or an ordinal-derived label when sparse.
    label: Mapped[str] = mapped_column(String(64))
    objective_text: Mapped[str] = mapped_column(Text)
    #: Detects a catalog re-ingest that reworded the objective under a stored verdict.
    objective_text_sha256: Mapped[str] = mapped_column(String(64))
    sort_order: Mapped[int] = mapped_column(Integer, default=0)

    state: Mapped[str] = mapped_column(String(16), default="complete")
    verdict: Mapped[str | None] = mapped_column(String(32))
    #: prep_units the model cited. Validated against what retrieval actually
    #: returned — a model cannot cite a passage it was never shown.
    cited_unit_ids: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    #: Ids retrieved and offered to the model, so a reviewer can see what it had.
    retrieved_unit_ids: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    gaps: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    contradictions: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    rationale: Mapped[str | None] = mapped_column(Text)
    model_name: Mapped[str | None] = mapped_column(String(128))
    model_confidence: Mapped[float | None] = mapped_column(Float)
    #: Provenance for the model call that produced this verdict. Nullable:
    #: historical rows predate provenance recording, and a recording failure
    #: must leave a usable NULL rather than block the verdict.
    ai_action_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.ai_action_runs.id", ondelete="SET NULL"), index=True
    )
    error: Mapped[str | None] = mapped_column(Text)

    #: AI dissent path (2026-08-11 design). The primary call's original
    #: verdict, preserved here because `verdict` above is deliberately
    #: overwritten to "insufficient_evidence" on a genuine disagreement --
    #: which is what lets ccf.assessment.engine.rollup work with this
    #: proposal with no change of its own. Recorded rather than inferred:
    #: under the current satisfied-only challenge policy a contested
    #: objective's primary verdict was always "satisfied" by construction and
    #: could in principle be inferred from the fact of a challenge, but that
    #: policy is expected to broaden (see the 2026-08-11 dissent-path
    #: design), and the moment it does, every previously contested row
    #: becomes unreadable without this column. NULL means "not challenged";
    #: populated whenever a challenge ran, agreement included.
    primary_verdict: Mapped[str | None] = mapped_column(String(32))
    #: All four of the columns in this block (primary_verdict above, and the
    #: three below) NULL together mean "not challenged" -- the primary
    #: verdict above was not satisfied, or CCF_ASSESSMENT_DISSENT_ENABLED was
    #: off -- and all four NULL can *also* mean "challenged, but the
    #: challenge call itself failed": those two cases are distinguishable
    #: only in the logs (assessment.challenger_failed), never from these
    #: columns alone. See ccf.assessment.engine.evaluate's module docstring
    #: for the full reasoning.
    #:
    #: The challenger's own verdict, retained separately from `verdict`
    #: above rather than overwriting it -- overwriting would destroy the
    #: record that a disagreement happened at all, which is what an assessor
    #: needs in order to adjudicate it. Populated whenever a challenge ran
    #: and succeeded, agreement included -- "challenged and agreed" must stay
    #: distinguishable from "not challenged".
    challenger_verdict: Mapped[str | None] = mapped_column(String(32))
    #: The challenger's own argument, shown to the assessor. Populated
    #: alongside challenger_verdict under the same rule.
    challenger_rationale: Mapped[str | None] = mapped_column(Text)
    #: Provenance for the challenger's own model call, recorded through
    #: ccf.ai_actions.provenance.record_ai_run under its own
    #: action_key="challenge_assessment_objective" -- a distinct row from the
    #: primary verdict's own ai_action_run_id above, so one query over
    #: ai_action_runs can separate a verdict from the argument made against
    #: it. ON DELETE SET NULL, not CASCADE: this row is a record of what
    #: happened and must survive its provenance row being cleaned up, exactly
    #: matching ai_action_run_id's own existing FK on this table (migration
    #: 0056).
    challenger_ai_action_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("ccf.ai_action_runs.id", ondelete="SET NULL"), index=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("control_proposal_id", "label", name="uq_objective_proposal_label"),
        Index("ix_objective_proposal_sort", "control_proposal_id", "sort_order"),
    )


class AssessmentJob(Base):
    """Queue entry driving evaluation of one control proposal."""

    __tablename__ = "assessment_jobs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    control_proposal_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.assessment_control_proposals.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    claimed_by: Mapped[str | None] = mapped_column(String(128))
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    __table_args__ = (Index("ix_assessment_jobs_claimable", "status", "created_at"),)


class CalibrationSnapshot(Base):
    """A point-in-time calibration measurement, tied to the configuration that produced it.

    The fingerprint is what makes drift meaningful. A metric is comparable to an
    earlier one only if what was measured did not change underneath, so two
    snapshots with different fingerprints are reported as *not comparable* rather
    than as drift -- which matters because ``prep_screen_threshold`` has a narrow
    empirical margin and will be re-derived.
    """

    __tablename__ = "calibration_snapshots"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("ccf.organizations.id", ondelete="CASCADE"), index=True
    )
    config_fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
