"""One resolver for an SSP project's organization-defined parameter prompts.

An ODP definition is *reference data* — what a fill-in-the-blank means, what
guidance NIST gives for it, what values it may take. It is not authored
content: the only thing an SSP owns is the value, in
``SSPControlEntry.odp_values``.

Where the reference comes from depends on the project's framework:

``cmmc-800-171``
    ``ScoringControl.odp_definitions``, seeded from the CMMC L2 scoring
    workbook plus the curated 800-171 overlay (``scoring/seed.py``,
    ``ssp/odp.py``). Unchanged by this module — it reads the same rows, with
    the same shape, as the four hand-copied joins it replaces.

``nist-800-53r5``
    Resolved from the parsed OSCAL catalog, at read time.

    ``ccf.scoring_controls`` is the CMMC L2 matrix: exactly 110 rows, every id
    of the shape ``AC.L2-3.1.1``. An 800-53 entry's ``control_id`` is ``AC-2``,
    so the join matched nothing and every parameter reached the human as a bare
    key with no label, guidance or choice list. Adding 800-53 rows to that
    table would put two control vocabularies in one column — the defect this
    codebase already carries in ``AssessmentControlResult.control_id`` — so the
    definitions are resolved rather than stored.

    Resolving beats persisting them on ``SSPControlEntry`` (which would need a
    migration) for the same reason: the catalog is the authority for what a
    parameter means, and a stored copy is a second source that goes stale the
    next time the catalog is revised. The seeder already derives ``odp_values``
    keys from the same catalog, so resolution and scaffolding cannot disagree.

Every surface that renders or scores ODPs calls this one function:
``api/routes/ssp.get_project``, ``api/routes/ui.ssp_detail``,
``api/routes/ui.ssp_save_entry`` and ``ssp/completeness_query``. Each of those
previously carried its own copy of the ``ScoringControl`` join, which is how
the 800-53 gap came to be silent in four places at once.
"""

from __future__ import annotations

from collections.abc import Iterable
from functools import lru_cache
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..catalog.oscal import OscalCatalog, load_oscal_catalog
from ..models import ScoringControl, SSPProject
from .nist80053 import odp_definitions_for

#: Mirrors ``api/routes/ssp.FRAMEWORKS``; the 800-53 seeder keys off the same
#: literal (``ssp.py:283``, ``ui.py:1239``).
FRAMEWORK_80053 = "nist-800-53r5"


@lru_cache(maxsize=1)
def _packaged_catalog() -> OscalCatalog:
    """The packaged 800-53r5 catalog, parsed once.

    ``load_oscal_catalog`` verifies and re-parses ~10 MB of JSON on every call
    (~50 ms), which is too much to pay per request on a page that renders a few
    hundred control entries. Cached like ``catalog.csf.load_csf_catalog``: the
    packaged document is immutable for the life of the process. This is a
    memoization of the authority, not a second copy of it — nothing here is
    written anywhere.

    Deliberately only the *packaged* directory. An adopted catalog revision is
    resolved through ``catalog/revisions.py`` and passed in explicitly; the
    800-53 seeder likewise seeds from the packaged catalog, so resolving from
    the same source keeps a project's prompts matching the keys it scaffolded.
    """
    return load_oscal_catalog()


async def odp_definitions_for_project(
    session: AsyncSession,
    project: SSPProject,
    control_ids: Iterable[str],
    *,
    catalog: OscalCatalog | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """``{control_id: [ODP definition dicts]}`` for the given controls.

    Controls with no parameters are simply absent from the mapping, so callers
    should use ``.get(cid) or []``. ``catalog`` is an injection point for tests
    and for a caller that has already loaded one; it is ignored for a CMMC
    project, which has no catalog-backed parameters.
    """
    ids = list(dict.fromkeys(control_ids))
    if not ids:
        return {}

    if project.framework == FRAMEWORK_80053:
        cat = catalog if catalog is not None else _packaged_catalog()
        out: dict[str, list[dict[str, Any]]] = {}
        for cid in ids:
            oc = cat.get(cid)
            if oc is None:
                # A control the entry names but this catalog revision lacks:
                # no prompts rather than a guess. Same posture as
                # capability/service.framework_reach on an absent control.
                continue
            defs = odp_definitions_for(oc)
            if defs:
                out[cid] = defs
        return out

    rows = (
        await session.execute(
            select(ScoringControl.control_id, ScoringControl.odp_definitions).where(
                ScoringControl.control_id.in_(ids)
            )
        )
    ).all()
    return {cid: list(defs or []) for cid, defs in rows if defs}
