"""Run and export assurance query templates.

``run_query`` coerces/validates the caller's params against the template's typed
schema, runs the deterministic runner tenant-scoped to ``org_id``, and returns a
uniform ``{key, title, columns, rows, count}`` envelope. ``export_csv`` renders that
envelope to CSV. Unknown keys raise ``KeyError`` (the API maps that to 404).
"""

from __future__ import annotations

import csv
import io
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from .registry import REGISTRY, TEMPLATES, QueryTemplate


def list_templates() -> list[dict[str, Any]]:
    """The registry as plain dicts — for API discovery and the UI picker."""
    return [
        {
            "key": t.key,
            "title": t.title,
            "description": t.description,
            "category": t.category,
            "columns": t.columns,
            "params": [
                {"name": p.name, "type": p.type, "label": p.label,
                 "required": p.required, "default": p.default}
                for p in t.params
            ],
        }
        for t in TEMPLATES
    ]


def _coerce(template: QueryTemplate, raw: dict[str, Any]) -> dict[str, Any]:
    """Validate + coerce the caller's params against the template's typed schema."""
    out: dict[str, Any] = {}
    for p in template.params:
        val = raw.get(p.name, p.default)
        if val in (None, "") and p.required:
            raise ValueError(f"missing required parameter: {p.name}")
        if val in (None, ""):
            out[p.name] = p.default
            continue
        if p.type == "int":
            try:
                out[p.name] = int(val)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"parameter {p.name} must be an integer") from exc
        else:
            out[p.name] = str(val)
    return out


async def run_query(
    session: AsyncSession, key: str, params: dict[str, Any], *, org_id: int | None
) -> dict[str, Any]:
    template = REGISTRY[key]  # KeyError → 404 at the API layer
    coerced = _coerce(template, params or {})
    rows = await template.run(session, coerced, org_id)
    return {
        "key": template.key,
        "title": template.title,
        "columns": template.columns,
        "rows": rows,
        "count": len(rows),
        "params": coerced,
    }


def export_csv(result: dict[str, Any]) -> str:
    buf = io.StringIO()
    columns = result["columns"]
    writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for row in result["rows"]:
        writer.writerow({c: row.get(c, "") for c in columns})
    return buf.getvalue()
