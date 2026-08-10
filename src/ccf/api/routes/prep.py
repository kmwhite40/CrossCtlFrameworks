"""REST surface for the evidence preparation pipeline.

Preparation is asynchronous by nature, so the write endpoint enqueues and returns
identifiers rather than blocking on a run that may take minutes. Retrieval is
synchronous and read-only.
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ...models_prep import PREP_STAGES
from ...prep import jobs as prep_jobs
from ...prep import pipeline
from ...prep.retriever import retrieve
from ..deps import get_session

router = APIRouter(prefix="/api/prep", tags=["prep"])


class PrepRunRequest(BaseModel):
    organization_id: int
    # Constrained here so an unknown kind is a 422 at the edge rather than a
    # failed run discovered minutes later by the worker.
    source_kind: Literal["evidence_version", "policy_version"]
    source_id: int


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
    payload: PrepRunRequest, session: AsyncSession = Depends(get_session)
) -> PrepRunCreated:
    """Queue a document for preparation."""
    job = await prep_jobs.enqueue(
        session,
        organization_id=payload.organization_id,
        source_kind=payload.source_kind,
        source_id=payload.source_id,
    )
    await session.commit()
    return PrepRunCreated(run_id=job.run_id, job_id=job.id, status=job.status)


@router.get("/runs/{run_id}", response_model=PrepRunStatus)
async def get_prep_run(
    run_id: int, session: AsyncSession = Depends(get_session)
) -> PrepRunStatus:
    """Report a run's status, stage by stage."""
    run = await pipeline.load_run(session, run_id)
    if run is None:
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
) -> RetrieveResponse:
    """Retrieve prepared evidence supporting a control."""
    found = await retrieve(
        session,
        org_id=organization_id,
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
