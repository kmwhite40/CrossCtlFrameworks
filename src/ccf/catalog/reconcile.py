"""Advisory reconciliation of workbook control rows against the pinned OSCAL catalog.

Read-only: reconcilers here NEVER write to `controls` or `framework_mappings`.
They take plain `ControlRow` inputs (decoupled from the ORM so they stay pure
and unit-testable) and emit `CatalogFinding`s describing identity and
baseline mismatches, plus a raw-id -> canonical-id-or-None crosswalk.
"""
from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Any

from .canonical import canonicalize
from .csf import extract_ids, load_csf_catalog
from .oscal import OscalCatalog

_BASELINE_FIELDS = {"fisma_low": "low", "fisma_mod": "moderate", "fisma_high": "high"}
_TEXT_DRIFT_THRESHOLD = 0.6  # below this similarity -> text_drift (low)


@dataclass
class CatalogFinding:
    check: str
    severity: str
    canonical_id: str
    raw_id: str
    field: str | None
    workbook_value: str | None
    oscal_value: str | None
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "severity": self.severity,
            "canonical_id": self.canonical_id,
            "raw_id": self.raw_id,
            "field": self.field,
            "workbook_value": self.workbook_value,
            "oscal_value": self.oscal_value,
            "detail": self.detail,
        }


@dataclass
class ControlRow:
    control_number: str | None
    control_name: str | None
    description: str | None
    discussion: str | None
    fisma_low: bool | None
    fisma_mod: bool | None
    fisma_high: bool | None
    source_row: int | None


def check_identity(
    catalog: OscalCatalog, rows: list[ControlRow]
) -> tuple[list[CatalogFinding], dict[str, str | None], set[str]]:
    findings: list[CatalogFinding] = []
    crosswalk: dict[str, str | None] = {}
    failed: set[str] = set()
    for row in rows:
        raw = (row.control_number or "").strip()
        if not raw:
            continue
        cid = canonicalize(raw)
        if cid is None:
            crosswalk[raw] = None
            failed.add(raw)
            findings.append(
                CatalogFinding(
                    "identity",
                    "high",
                    raw,
                    raw,
                    "unparseable",
                    raw,
                    None,
                    f"unparseable control id '{raw}' — cannot be trusted in joins",
                )
            )
            continue
        crosswalk[raw] = cid.value
        oc = catalog.get(cid.value)
        if oc is None:
            failed.add(cid.value)
            findings.append(
                CatalogFinding(
                    "identity",
                    "high",
                    cid.value,
                    raw,
                    None,
                    raw,
                    None,
                    f"unknown_control_id: {cid.value} not in OSCAL 800-53r5 catalog",
                )
            )
        elif oc.withdrawn:
            succ = ", ".join(oc.incorporated_into) or "n/a"
            findings.append(
                CatalogFinding(
                    "identity",
                    "medium",
                    cid.value,
                    raw,
                    None,
                    raw,
                    succ,
                    f"withdrawn_control: {cid.value} is withdrawn (incorporated into {succ})",
                )
            )
    return findings, crosswalk, failed


def check_baseline(
    catalog: OscalCatalog, rows: list[ControlRow], failed: set[str]
) -> list[CatalogFinding]:
    findings: list[CatalogFinding] = []
    for row in rows:
        cid = canonicalize(row.control_number or "")
        if cid is None or cid.value in failed or not catalog.exists(cid.value):
            continue
        for field_name, level in _BASELINE_FIELDS.items():
            claimed = getattr(row, field_name)
            if claimed is None:
                continue
            authoritative = catalog.in_baseline(cid.value, level)
            if claimed and not authoritative:
                findings.append(
                    CatalogFinding(
                        "baseline",
                        "medium",
                        cid.value,
                        row.control_number or cid.value,
                        field_name,
                        "true",
                        "false",
                        f"baseline_overclaim: {cid.value} marked {level}"
                        f" but not in 800-53B {level}",
                    )
                )
            elif authoritative and not claimed:
                findings.append(
                    CatalogFinding(
                        "baseline",
                        "high",
                        cid.value,
                        row.control_number or cid.value,
                        field_name,
                        "false",
                        "true",
                        f"baseline_underclaim: {cid.value} in 800-53B {level} but not marked",
                    )
                )
    return findings


def _norm(s: str | None) -> str:
    return " ".join((s or "").split()).casefold()


def check_content_drift(
    catalog: OscalCatalog, rows: list[ControlRow], failed: set[str]
) -> list[CatalogFinding]:
    findings: list[CatalogFinding] = []
    for row in rows:
        cid = canonicalize(row.control_number or "")
        if cid is None or cid.value in failed:
            continue
        oc = catalog.get(cid.value)
        if oc is None or oc.withdrawn:
            continue
        if row.control_name and _norm(row.control_name) != _norm(oc.title):
            findings.append(
                CatalogFinding(
                    "content_drift",
                    "medium",
                    cid.value,
                    row.control_number or cid.value,
                    "control_name",
                    row.control_name,
                    oc.title,
                    f"title_drift: workbook '{row.control_name}' != OSCAL '{oc.title}'",
                )
            )
        wb_text = row.description or row.discussion
        if wb_text and oc.statement:
            ratio = SequenceMatcher(None, _norm(wb_text), _norm(oc.statement)).ratio()
            if ratio < _TEXT_DRIFT_THRESHOLD:
                field_name = "description" if row.description else "discussion"
                findings.append(
                    CatalogFinding(
                        "content_drift",
                        "low",
                        cid.value,
                        row.control_number or cid.value,
                        field_name,
                        (wb_text[:160] + "…") if len(wb_text) > 160 else wb_text,
                        (oc.statement[:160] + "…") if len(oc.statement) > 160 else oc.statement,
                        f"text_drift: similarity {ratio:.2f} < {_TEXT_DRIFT_THRESHOLD}",
                    )
                )
    return findings


@dataclass
class MappingRow:
    control_number: str | None
    column_key: str
    framework_code: str | None
    value: str | None


def _is_nist_target(m: MappingRow) -> bool:
    key = f"{m.column_key} {m.framework_code or ''}".lower()
    return "800-53" in key or "nist" in key


def check_mapping_endpoints(
    catalog: OscalCatalog, mappings: list[MappingRow]
) -> tuple[list[CatalogFinding], dict[str, int]]:
    findings: list[CatalogFinding] = []
    uncovered: dict[str, int] = {}
    for m in mappings:
        if _is_nist_target(m):
            cid = canonicalize(m.value or "")
            if cid is None or not catalog.exists(cid.value):
                shown = (m.value or "").strip() or "(empty)"
                findings.append(
                    CatalogFinding(
                        "mapping_endpoint",
                        "medium",
                        cid.value if cid else shown,
                        shown,
                        m.column_key,
                        shown,
                        None,
                        f"dangling_mapping_endpoint: '{shown}' not an 800-53r5 control",
                    )
                )
        else:
            code = m.framework_code or "OTHER"
            uncovered[code] = uncovered.get(code, 0) + 1
    return findings, uncovered


def check_csf_endpoints(mappings: list[MappingRow]) -> list[CatalogFinding]:
    """Resolve CSF 2.0 crosswalk values against NIST's published catalog.

    The workbook's CSF columns are free text and arrive in several shapes — a
    bare id, an id with a trailing colon, an id followed by prose, or a
    semicolon-joined list. ``extract_ids`` pulls the subcategory ids out; each
    one must exist in the OSCAL catalog.

    A value that names only a function or category ("Protect: Platform Security
    (PR.PS)") yields no subcategory ids and is NOT a finding — those columns
    legitimately carry coarser references.
    """
    csf = load_csf_catalog()
    findings: list[CatalogFinding] = []
    for m in mappings:
        if (m.framework_code or "") != "NIST_CSF_2_0":
            continue
        for cid in extract_ids(m.value):
            if csf.has(cid):
                continue
            shown = (m.value or "").strip() or "(empty)"
            findings.append(
                CatalogFinding(
                    "csf_endpoint",
                    "medium",
                    cid,
                    cid,
                    m.column_key,
                    shown,
                    None,
                    f"dangling_csf_endpoint: '{cid}' is not a CSF "
                    f"{csf.version} subcategory",
                )
            )
    return findings


@dataclass
class ReconcileResult:
    controls_checked: int
    not_evaluated: int
    findings: list[CatalogFinding]
    crosswalk: dict[str, str | None]
    summary: dict[str, Any]


def reconcile(
    catalog: OscalCatalog,
    control_rows: list[ControlRow],
    mapping_rows: list[MappingRow],
) -> ReconcileResult:
    id_findings, crosswalk, failed = check_identity(catalog, control_rows)
    base_findings = check_baseline(catalog, control_rows, failed)
    drift_findings = check_content_drift(catalog, control_rows, failed)
    map_findings, uncovered = check_mapping_endpoints(catalog, mapping_rows)
    csf_findings = check_csf_endpoints(mapping_rows)
    findings = id_findings + base_findings + drift_findings + map_findings + csf_findings

    # Partition distinct controls into evaluated vs not-evaluated on a CANONICAL
    # basis so the counts always reconcile even when several raw spellings
    # (e.g. "AC-2" and "AC-02") collapse to one canonical id — which is exactly
    # what canonicalize() exists to do. A control is "checked" once per distinct
    # canonical id; unparseable raws (no canonical id) are each their own unit.
    evaluated: set[str] = set()            # canonical ids that passed identity
    not_eval_canonical: set[str] = set()   # canonical ids unknown to OSCAL (in failed)
    not_eval_raw: set[str] = set()         # raws that don't canonicalize at all
    for row in control_rows:
        raw = (row.control_number or "").strip()
        if not raw:
            continue
        cid = crosswalk.get(raw)
        if cid is None:
            not_eval_raw.add(raw)
        elif cid in failed:
            not_eval_canonical.add(cid)
        else:
            evaluated.add(cid)
    evaluated_ids = sorted(evaluated)
    not_evaluated = len(not_eval_canonical) + len(not_eval_raw)
    # Invariant (guaranteed by construction): checked == evaluated + not_evaluated.
    controls_checked = len(evaluated_ids) + not_evaluated

    by_check: dict[str, int] = {
        "identity": 0,
        "baseline": 0,
        "content_drift": 0,
        "mapping_endpoint": 0,
        "csf_endpoint": 0,
    }
    by_sev: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        by_check[f.check] = by_check.get(f.check, 0) + 1
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    summary: dict[str, Any] = {
        "by_check": by_check,
        "by_severity": by_sev,
        "evaluated_ids": evaluated_ids,
        "mapping_endpoints_not_evaluated": uncovered,
        "oscal_version": catalog.version,
    }
    return ReconcileResult(controls_checked, not_evaluated, findings, crosswalk, summary)
