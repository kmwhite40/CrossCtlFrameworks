#!/usr/bin/env python3
"""Concord (ccf) schema-integrity validator.

Operationalizes the DATA-* findings from the 2026-07-21 consolidated register as
mechanical, repeatable checks against the SQLAlchemy ORM metadata. The core checks
are STATIC — they import the model modules and inspect ``Base.metadata`` with no
database connection — so they run anywhere (CI included) despite the flaky test DB.

Run:
    PYTHONPATH=src python docs/superpowers/assessments/integrity_checks.py
    PYTHONPATH=src python docs/superpowers/assessments/integrity_checks.py --strict

Exit code: 0 always, unless --strict (then non-zero if any finding is reported).
This lets the tool run as an informational baseline today and be flipped to a
CI gate once the DATA-* items are remediated.

Checks (map to register findings):
  1. fk_naming       — *_id columns with no ForeignKey            (DATA-02, -07, -11)
  2. unique_keys     — declared natural keys missing a UniqueConstraint (DATA-08, -10)
  3. cascade_audit   — ON DELETE CASCADE into authorization-record tables (DATA-04, -12)
  4. fk_width        — FK column integer width != referenced PK width (DATA-11)
  5. tenant_columns  — tenant-owned tables missing org/system scope (informational; DATA-03, -06)
"""
from __future__ import annotations

import argparse
import importlib
import sys
from dataclasses import dataclass

# Import every model module so all tables register on the shared Base.metadata.
_MODEL_MODULES = [
    "ccf.models",
    "ccf.models_grc",
    "ccf.models_evidence",
    "ccf.models_evidence_conf",
    "ccf.models_ai_actions",
    "ccf.models_ai_agents",
    "ccf.models_assurance",
    "ccf.models_identity",
    "ccf.models_packages",
    "ccf.models_packs",
    "ccf.models_people",
    "ccf.models_portal",
    "ccf.models_tprm",
    "ccf.models_self_assurance",
]

# ---- configuration derived from the assessment (edit as the schema evolves) ----

# Columns that end in _id but are deliberately generic discriminators, not FKs.
_GENERIC_ID_COLUMNS = {"entity_id", "source_id", "target_id", "external_id", "object_id"}

# Authorization-record tables whose rows are audit artifacts: a CASCADE delete into
# them destroys the authorization history (DATA-04). Flag inbound CASCADE FKs.
_AUTHORIZATION_TABLES = {
    "poams",
    "poam_milestones",
    "assessments",
    "assessment_results",
    "assessment_control_results",
    "evidence",
    "evidence_objects",
    "evidence_versions",
    "risks",
    "control_implementations",
    "audit_findings",
}

# Natural keys that should be unique (table -> tuple of columns). DATA-08 / DATA-10.
_NATURAL_KEYS = {
    "vendors": ("organization_id", "name"),
    "policies": ("organization_id", "name"),
    "fedramp_dependencies": ("system_id", "name"),
    "pack_mappings": ("pack_id", "control_id", "framework"),
    "people": ("organization_id", "email"),
}


@dataclass
class Finding:
    check: str
    ref: str  # register finding id
    severity: str
    table: str
    detail: str


def _load_metadata():
    for mod in _MODEL_MODULES:
        try:
            importlib.import_module(mod)
        except Exception as exc:  # pragma: no cover - defensive
            print(f"WARN: could not import {mod}: {exc}", file=sys.stderr)
    from ccf.models import Base  # noqa: PLC0415 — imported after modules register

    return Base.metadata


def _int_width(coltype) -> str | None:
    """Return 'big'/'small'/'int' for integer-family types, else None."""
    name = type(coltype).__name__.lower()
    if "big" in name:
        return "big"
    if "small" in name:
        return "small"
    if "integer" in name or name == "int":
        return "int"
    return None


def check_fk_naming(md) -> list[Finding]:
    out: list[Finding] = []
    for table in md.sorted_tables:
        for col in table.columns:
            if not col.name.endswith("_id"):
                continue
            if col.name in _GENERIC_ID_COLUMNS or col.primary_key:
                continue
            if not col.foreign_keys:
                out.append(
                    Finding(
                        "fk_naming",
                        "DATA-02/07/11",
                        "medium",
                        table.name,
                        f"column '{col.name}' looks like a reference but has no ForeignKey",
                    )
                )
    return out


def check_unique_keys(md) -> list[Finding]:
    from sqlalchemy import UniqueConstraint  # noqa: PLC0415

    out: list[Finding] = []
    tables = {t.name: t for t in md.sorted_tables}
    for tname, cols in _NATURAL_KEYS.items():
        table = tables.get(tname)
        if table is None:
            continue
        wanted = set(cols)
        # a covering unique constraint OR unique=True single column
        covered = any(
            isinstance(c, UniqueConstraint) and wanted.issubset({col.name for col in c.columns})
            for c in table.constraints
        )
        if not covered and len(cols) == 1:
            covered = any(col.unique for col in table.columns if col.name in wanted)
        if not covered:
            out.append(
                Finding(
                    "unique_keys",
                    "DATA-08/10",
                    "medium",
                    tname,
                    f"natural key {cols} has no UniqueConstraint (duplicates possible)",
                )
            )
    return out


def check_cascade_audit(md) -> list[Finding]:
    out: list[Finding] = []
    for table in md.sorted_tables:
        for fk in table.foreign_keys:
            target_table = fk.column.table.name
            ondelete = (fk.ondelete or "").upper()
            if ondelete == "CASCADE" and target_table in _AUTHORIZATION_TABLES:
                out.append(
                    Finding(
                        "cascade_audit",
                        "DATA-04",
                        "high",
                        table.name,
                        f"'{fk.parent.name}' -> {target_table} ON DELETE CASCADE "
                        f"(deletes destroy authorization records; prefer RESTRICT + soft-delete)",
                    )
                )
            # CASCADE from the tenant roots into authorization tables
            if ondelete == "CASCADE" and target_table in {"systems", "organizations"} and (
                table.name in _AUTHORIZATION_TABLES
            ):
                out.append(
                    Finding(
                        "cascade_audit",
                        "DATA-04",
                        "high",
                        table.name,
                        f"authorization table cascades on delete of {target_table} "
                        f"('{fk.parent.name}'); a single delete wipes history",
                    )
                )
    return out


def check_fk_width(md) -> list[Finding]:
    out: list[Finding] = []
    for table in md.sorted_tables:
        for fk in table.foreign_keys:
            child_w = _int_width(fk.parent.type)
            parent_w = _int_width(fk.column.type)
            if child_w and parent_w and child_w != parent_w:
                out.append(
                    Finding(
                        "fk_width",
                        "DATA-11",
                        "low",
                        table.name,
                        f"'{fk.parent.name}' ({child_w}int) references "
                        f"{fk.column.table.name}.{fk.column.name} ({parent_w}int) — width mismatch",
                    )
                )
    return out


def check_tenant_columns(md) -> list[Finding]:
    """Informational: tables carrying a tenant reference by naming but no FK on it,
    or tables that plausibly should be tenant-scoped. Heuristic only."""
    out: list[Finding] = []
    for table in md.sorted_tables:
        colnames = {c.name for c in table.columns}
        if "organization_id" in colnames:
            col = table.columns["organization_id"]
            if not col.foreign_keys:
                out.append(
                    Finding(
                        "tenant_columns",
                        "DATA-03/06",
                        "medium",
                        table.name,
                        "has organization_id but no ForeignKey to organizations",
                    )
                )
    return out


_CHECKS = [
    check_fk_naming,
    check_unique_keys,
    check_cascade_audit,
    check_fk_width,
    check_tenant_columns,
]


def main() -> int:
    ap = argparse.ArgumentParser(description="Concord schema-integrity validator")
    ap.add_argument("--strict", action="store_true", help="exit non-zero if any finding")
    args = ap.parse_args()

    md = _load_metadata()
    findings: list[Finding] = []
    for check in _CHECKS:
        findings.extend(check(md))

    by_check: dict[str, list[Finding]] = {}
    for f in findings:
        by_check.setdefault(f.check, []).append(f)

    print(f"Concord schema-integrity report — {len(md.sorted_tables)} tables inspected\n")
    if not findings:
        print("No findings. ✅")
    for check_name in sorted(by_check):
        items = by_check[check_name]
        print(f"## {check_name} — {len(items)} finding(s)")
        for f in items:
            print(f"  [{f.severity:6}] [{f.ref:12}] {f.table}: {f.detail}")
        print()

    print(f"TOTAL: {len(findings)} finding(s) across {len(by_check)} check(s).")
    if args.strict and findings:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
