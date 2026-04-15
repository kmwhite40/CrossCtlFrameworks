"""Pydantic v2 API schemas."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --- Reference layer ---------------------------------------------------------


class FrameworkOut(ORMModel):
    id: int
    code: str
    name: str
    family: str | None = None
    description: str | None = None


class ControlFamilyOut(ORMModel):
    id: int
    code: str
    name: str
    category: str | None = None


class FrameworkMappingOut(ORMModel):
    column_key: str
    value: str
    framework: FrameworkOut | None = None


class ControlSummary(ORMModel):
    id: int
    identifier: str
    sequence_control: str | None = None
    control_name: str | None = None
    family: ControlFamilyOut | None = None
    fisma_low: bool | None = None
    fisma_mod: bool | None = None
    fisma_high: bool | None = None


class ControlDetail(ControlSummary):
    description: str | None = None
    discussion: str | None = None
    related_controls: str | None = None
    assessment_objective: str | None = None
    examine: str | None = None
    interview: str | None = None
    test: str | None = None
    assurance_control: str | None = None
    implemented_by: str | None = None
    owner: str | None = None
    overall_control_type: str | None = None
    opd: bool | None = None
    ap_acronym: str | None = None
    mappings: list[FrameworkMappingOut] = Field(default_factory=list)
    source_row: int | None = None
    loaded_at: datetime | None = None


class ControlPage(ORMModel):
    total: int
    items: list[ControlSummary]


class WorksheetOut(ORMModel):
    id: int
    name: str
    slug: str
    headers: list[Any]
    row_count: int
    loaded_at: datetime


class WorksheetRowOut(ORMModel):
    row_index: int
    payload: dict[str, Any]


# --- Operational layer -------------------------------------------------------


class OrganizationOut(ORMModel):
    id: int
    name: str
    description: str | None = None
    created_at: datetime


class SystemOut(ORMModel):
    id: int
    organization_id: int
    name: str
    description: str | None = None
    baseline: str | None = None
    ato_status: str | None = None
    ato_expires_on: date | None = None


class SystemCreate(BaseModel):
    organization_id: int
    name: str
    description: str | None = None
    baseline: str | None = None
    fips199_confidentiality: str | None = None
    fips199_integrity: str | None = None
    fips199_availability: str | None = None


class ImplementationOut(ORMModel):
    id: int
    system_id: int
    control_id: int
    status: str
    responsibility: str | None = None
    narrative: str | None = None
    conmon_frequency: str | None = None
    last_assessed_on: date | None = None
    next_assessment_due: date | None = None


class ImplementationUpdate(BaseModel):
    status: str | None = None
    responsibility: str | None = None
    narrative: str | None = None
    conmon_frequency: str | None = None
    last_assessed_on: date | None = None
    next_assessment_due: date | None = None


class EvidenceOut(ORMModel):
    id: int
    implementation_id: int
    kind: str
    title: str
    uri: str | None = None
    collected_on: date | None = None
    expires_on: date | None = None


class POAMOut(ORMModel):
    id: int
    system_id: int
    control_id: int | None = None
    title: str
    severity: str
    status: str
    identified_on: date | None = None
    due_on: date | None = None
    closed_on: date | None = None


class ComplianceSummary(BaseModel):
    system_id: int
    total_controls: int
    implemented: int
    partial: int
    planned: int
    not_implemented: int
    inherited: int
    not_applicable: int
    coverage_pct: float
    open_poams: int
    overdue_poams: int
