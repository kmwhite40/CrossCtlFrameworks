"""REST surface for the evidence preparation pipeline.

Preparation is asynchronous by nature, so the write endpoint enqueues and returns
identifiers rather than blocking on a run that may take minutes. Retrieval is
synchronous and read-only.

**Tenant scoping.** Every endpoint here derives its organization from the
authenticated principal, not from anything the caller supplies in the request:
a scoped (org-bound) principal's own organization always wins over an
``organization_id`` in the body/query, exactly as ``users.py::create_user``
already does for its own NOT-NULL ``organization_id`` column — a mismatch is
logged, not rejected, matching that same existing precedent rather than
inventing a new one. Only an *unscoped* principal's request uses the supplied
``organization_id`` as-is, which is an intended administrative capability
(consistent with the rest of the API), not a loophole for an ordinary user.

One case is worth stating plainly rather than leaving implicit: with
``CCF_AUTH_ENABLED=false`` (the default), every principal resolves to the
unscoped ``SYSTEM_PRINCIPAL`` — this is true of the whole app, not specific to
prep, and the app enforces no tenant isolation anywhere in that mode. In that
configuration the ``organization_id`` supplied to these endpoints is trusted
outright, the same as it is for every other endpoint. Do not run with auth
disabled against data from more than one real tenant.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth import Principal
from ...logging import get_logger
from ...models_prep import PREP_SOURCE_KINDS, PREP_STAGES
from ...prep import jobs as prep_jobs
from ...prep import pipeline
from ...prep.retriever import retrieve
from ...prep.sources import SourceMissing
from ..auth_deps import get_principal
from ..deps import get_session

log = get_logger(__name__)

router = APIRouter(prefix="/api/prep", tags=["prep"])


def _scoped_organization_id(requested: int, principal: Principal) -> int:
    """Resolve the organization a request actually runs against.

    A scoped principal's own organization always wins over ``requested`` —
    mirrors ``users.py::create_user``, the existing convention in this
    codebase for a NOT NULL ``organization_id`` that must resolve to one
    concrete value (unlike ``evidence_repo.py``'s nullable column, whose
    "pass principal.org_id through even if None" pattern cannot apply here: a
    None would violate PrepRun's NOT NULL constraint, and retrieval's vector
    half needs one concrete org to resolve AI-provider credentials for). A
    mismatch is logged rather than rejected, matching that same precedent
    exactly rather than inventing a third behavior. An unscoped principal
    (including SYSTEM_PRINCIPAL under CCF_AUTH_ENABLED=false) has no
    organization of its own to prefer, so ``requested`` is used as-is.
    """
    if principal.org_id is None:
        return requested
    if principal.org_id != requested:
        log.warning(
            "prep.organization_id_override",
            requested_organization_id=requested,
            principal_organization_id=principal.org_id,
        )
    return principal.org_id


class PrepRunRequest(BaseModel):
    organization_id: int
    source_kind: str
    source_id: int

    @field_validator("source_kind")
    @classmethod
    def _known_source_kind(cls, value: str) -> str:
        # Validated against models_prep.PREP_SOURCE_KINDS (the single source of
        # truth every prep stage already checks against) rather than a second,
        # hand-maintained literal here, so the two cannot drift — an unknown
        # kind is a 422 at the edge rather than a failed run discovered
        # minutes later by the worker.
        if value not in PREP_SOURCE_KINDS:
            raise ValueError(f"source_kind must be one of {PREP_SOURCE_KINDS}")
        return value


class PrepRunCreated(BaseModel):
    run_id: int
    job_id: int
    status: str


class PrepRunStatus(BaseModel):
    run_id: int
    status: str
    stages: dict[str, str]
    parser_name: str | None = None
    lines_parsed: int = 0
    lines_above_threshold: int = 0
    units_built: int = 0
    units_classified: int = 0
    units_embedded: int = 0
    error_stage: str | None = None
    error: str | None = None


class RetrievedUnitOut(BaseModel):
    unit_id: int
    content: str
    score: float
    page_numbers: list[int] = Field(default_factory=list)
    section_path: str | None = None
    table_coordinates: dict[str, Any] | None = None
    source_kind: str | None = None
    control_identifiers: list[str] = Field(default_factory=list)
    evidence_strength: str | None = None


class RetrieveResponse(BaseModel):
    control: str
    results: list[RetrievedUnitOut]


@router.post("/runs", response_model=PrepRunCreated, status_code=201)
async def create_prep_run(
    payload: PrepRunRequest,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> PrepRunCreated:
    """Queue a document for preparation, scoped to the caller's organization.

    See the module docstring for how ``organization_id`` is resolved from
    ``principal`` versus the request body.
    """
    organization_id = _scoped_organization_id(payload.organization_id, principal)
    try:
        job = await prep_jobs.enqueue(
            session,
            organization_id=organization_id,
            source_kind=payload.source_kind,
            source_id=payload.source_id,
        )
    except SourceMissing as exc:
        # Covers both a genuinely missing source and SourceOwnershipMismatch
        # (a real source belonging to a different organization) identically —
        # 404 either way, so this endpoint cannot be used to probe which ids
        # exist for another tenant.
        raise HTTPException(status_code=404, detail="prep source not found") from exc
    await session.commit()
    return PrepRunCreated(run_id=job.run_id, job_id=job.id, status=job.status)


@router.get("/runs/{run_id}", response_model=PrepRunStatus)
async def get_prep_run(
    run_id: int,
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> PrepRunStatus:
    """Report a run's status, stage by stage."""
    run = await pipeline.load_run(session, run_id)
    # 404 (not 403) for a cross-tenant run, matching evidence_repo.py's
    # _require_object: the response must not confirm that a run with this id
    # exists at all for a tenant the caller cannot see.
    if run is None or (
        principal.org_id is not None and run.organization_id != principal.org_id
    ):
        raise HTTPException(status_code=404, detail="prep run not found")
    return PrepRunStatus(
        run_id=run.id,
        status=run.status,
        stages={stage: getattr(run, f"stage_{stage}") for stage in PREP_STAGES},
        parser_name=run.parser_name,
        lines_parsed=run.lines_parsed,
        lines_above_threshold=run.lines_above_threshold,
        units_built=run.units_built,
        units_classified=run.units_classified,
        units_embedded=run.units_embedded,
        error_stage=run.error_stage,
        error=run.error,
    )


@router.get("/retrieve", response_model=RetrieveResponse)
async def retrieve_units(
    *,
    organization_id: int,
    control: str,
    query: str | None = None,
    system_id: int | None = None,
    limit: int | None = Query(default=None, ge=1, le=50),
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
) -> RetrieveResponse:
    """Retrieve prepared evidence supporting a control, scoped to the caller's
    organization.

    See the module docstring for how ``organization_id`` is resolved from
    ``principal`` versus the query parameter.
    """
    org_id = _scoped_organization_id(organization_id, principal)
    found = await retrieve(
        session,
        org_id=org_id,
        control_identifier=control,
        query_text=query,
        system_id=system_id,
        limit=limit,
    )
    return RetrieveResponse(
        control=control,
        results=[
            RetrievedUnitOut(
                unit_id=unit.unit_id,
                content=unit.content,
                score=unit.score,
                page_numbers=unit.page_numbers,
                section_path=unit.section_path,
                table_coordinates=unit.table_coordinates,
                source_kind=unit.source_kind,
                control_identifiers=unit.control_identifiers,
                evidence_strength=unit.evidence_strength,
            )
            for unit in found
        ],
    )
