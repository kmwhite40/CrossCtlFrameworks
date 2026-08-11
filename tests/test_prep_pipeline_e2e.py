"""End-to-end: a real source document driven through all five pipeline stages.

Every other prep test module verifies one stage against hand-built fixtures for
the *next* stage's input shape (e.g. ``test_prep_expand.py`` seeds ``PrepScreen``
rows directly, ``test_prep_embed_stage.py`` seeds ``PrepUnit`` rows directly).
That is deliberate and correct for pinning a single stage's own contract, but it
never proves the stages actually chain: that ``expand``'s persisted units are
consumable by ``classify``, that ``classify``'s output shape is what ``embed``
expects, that ``screen``'s ``candidate_controls`` reach ``classify`` intact.

This module seeds nothing but a real catalog control and a real evidence
document, calls ``pipeline.advance`` with every stage at its default ``pending``,
and only monkeypatches the two genuine external boundaries — the AI gateway's
``generate_structured`` and ``embed`` calls. Everything in between (parse,
screen, expand, the classify stage's own candidate-filtering, the embed stage's
dimension gate) runs unmodified, so this is the only place a broken handoff
between two stages would actually surface.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from sqlalchemy import delete, select, text

from ccf.ai import gateway
from ccf.ai.providers.base import EmbedResponse
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.evidence import storage
from ccf.models import Control, Organization
from ccf.models_evidence import EvidenceObject, EvidenceVersion
from ccf.models_prep import (
    PrepClassification,
    PrepEmbedding,
    PrepLine,
    PrepScreen,
    PrepUnit,
)
from ccf.prep import pipeline

pytestmark = pytest.mark.usefixtures("fresh_engine")

#: Same weighting the real ETL applies after every workbook ingest — copied
#: from ``tests/test_prep_screen.py`` rather than imported, so this module
#: seeds and cleans up its own catalog rows independently of that module's
#: fixtures (which reset the shared ``ccf_test`` schema only once per session).
_SEARCH_VECTOR_SQL = (
    "UPDATE ccf.controls SET search_vector = "
    "setweight(to_tsvector('english', coalesce(identifier,'')), 'A') || "
    "setweight(to_tsvector('english', coalesce(control_name,'')), 'A') || "
    "setweight(to_tsvector('english', coalesce(assessment_objective,'')), 'B') || "
    "setweight(to_tsvector('english', coalesce(description,'')), 'C') || "
    "setweight(to_tsvector('english', coalesce(discussion,'')), 'D')"
)


@pytest.fixture(autouse=True)
def _local_evidence_dir(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("CCF_EVIDENCE_BACKEND", "local")
    monkeypatch.setenv("CCF_EVIDENCE_LOCAL_DIR", str(tmp_path / "evidence"))
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
async def seeded_control() -> Any:
    """Seed one richly-worded catalog control, the same fixture text
    ``test_prep_screen.py`` uses, and remove it afterward so nothing leaks into
    the shared ``ccf_test`` schema.

    Seeded under the catalog's zero-padded spelling (``IA-02``), not
    Concord's own canonical unpadded tag (``IA-2``) -- deliberately, per
    Finding C1: the real ingested catalog is not consistently formatted, and
    this is the one place in the suite that drives a control identifier all
    the way from ``ccf.controls.identifier`` through screen, classify, and
    into ``PrepClassification.control_identifiers`` without any test fixture
    normalizing it along the way. If normalization regressed, this is where
    it would show up -- ``test_advance_drives_a_full_run_through_all_five_stages``
    asserts the *canonical* ``"IA-2"`` (not ``"IA-02"``) ends up on the
    persisted classification.
    """
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.identifier == "IA-02"))
        s.add(
            Control(
                identifier="IA-02",
                control_name="Identification and Authentication (Organizational Users)",
                description=(
                    "Uniquely identify and authenticate organizational users and associate "
                    "that unique identification with processes acting on behalf of those "
                    "users. Multifactor authentication is required for network access to "
                    "privileged and non-privileged accounts."
                ),
                assessment_objective=(
                    "multifactor authentication is implemented for network access to "
                    "privileged accounts; multifactor authentication is implemented for "
                    "network access to non-privileged accounts"
                ),
                discussion=(
                    "Organizational users include employees or individuals considered to "
                    "have equivalent status. Authentication of user identities is "
                    "accomplished through passwords, tokens, or multifactor authentication "
                    "mechanisms such as personal identity verification cards."
                ),
            )
        )
        await s.flush()
        await s.execute(text(_SEARCH_VECTOR_SQL))
    try:
        yield
    finally:
        async with session_scope() as s:
            await s.execute(delete(Control).where(Control.identifier == "IA-02"))


async def _org(name: str) -> int:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        return int(org.id)


async def _evidence_version(org_id: int, payload: bytes, filename: str) -> int:
    digest = hashlib.sha256(payload).hexdigest()
    ref = storage.get_backend().put(digest, payload, "text/plain")
    async with session_scope() as s:
        obj = EvidenceObject(organization_id=org_id, title=filename)
        s.add(obj)
        await s.flush()
        ver = EvidenceVersion(
            evidence_object_id=obj.id,
            version=1,
            sha256=digest,
            media_type="text/plain",
            size_bytes=len(payload),
            filename=filename,
            storage_backend="local",
            storage_ref=ref,
        )
        s.add(ver)
        await s.flush()
        return int(ver.id)


def _fake_embed(dim: int = 1024) -> Any:
    async def _embed(session: Any, org_id: int, *, texts: list[str], **kw: Any) -> EmbedResponse:
        return EmbedResponse(
            vectors=[[0.01] * dim for _ in texts],
            model="text-embedding-3-small",
            input_tokens=len(texts),
        )

    return _embed


async def _fake_generate_structured(
    session: Any,
    org_id: int,
    *,
    prompt: str,
    schema: dict[str, Any],
    purpose: str,
    system: str | None = None,
    **kw: Any,
) -> dict[str, Any]:
    """Echo back exactly the candidates ``classify.build_prompt`` offered.

    Deliberately does *not* hardcode "IA-2": it parses the same "Candidate
    controls: ..." line the real prompt carries, so the returned identifiers
    are whatever screening actually surfaced for this unit's trigger line —
    the thing this test exists to verify actually flows through, not a value
    this fake asserts on its own authority.
    """
    first_line = prompt.splitlines()[0]
    offered = first_line.removeprefix("Candidate controls:").strip()
    candidates = (
        [] if offered == "(none surfaced by screening)" else [c.strip() for c in offered.split(",")]
    )
    return {
        "control_identifiers": candidates,
        "artifact_type": "policy",
        "evidence_strength": "strong",
        "confidence": 0.9,
    }


async def test_advance_drives_a_full_run_through_all_five_stages(
    seeded_control: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    org_id = await _org("prep-e2e")
    payload = (
        b"Administrators must use multifactor authentication for network access.\n"
        b"The quick brown fox jumped over the lazy dog.\n"
    )
    version_id = await _evidence_version(org_id, payload, "access-control.txt")

    monkeypatch.setattr(gateway, "generate_structured", _fake_generate_structured)
    monkeypatch.setattr(gateway, "embed", _fake_embed())

    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="evidence_version", source_id=version_id
        )
        # Every stage starts at its model default of "pending" — nothing is
        # pre-marked complete, unlike test_prep_embed_stage.py's
        # `_run_with_units` fixture, which exists specifically to isolate the
        # embed stage and therefore hand-builds PrepUnit rows and marks the
        # four earlier stages complete without ever running them.
        assert run.stage_parse == "pending"
        assert run.stage_screen == "pending"
        assert run.stage_expand == "pending"
        assert run.stage_classify == "pending"
        assert run.stage_embed == "pending"

        await pipeline.advance(s, run)

        assert run.status == "complete", run.error
        assert run.stage_parse == "complete"
        assert run.stage_screen == "complete"
        assert run.stage_expand == "complete"
        assert run.stage_classify == "complete"
        assert run.stage_embed == "complete"
        assert pipeline.next_stage(run) is None

        run_id = run.id

    async with session_scope() as s:
        lines = (
            (await s.execute(select(PrepLine).where(PrepLine.run_id == run_id)))
            .scalars()
            .all()
        )
        screens = (
            (await s.execute(select(PrepScreen).where(PrepScreen.run_id == run_id)))
            .scalars()
            .all()
        )
        units = (
            (await s.execute(select(PrepUnit).where(PrepUnit.run_id == run_id)))
            .scalars()
            .all()
        )
        classifications = (
            (
                await s.execute(
                    select(PrepClassification).where(PrepClassification.run_id == run_id)
                )
            )
            .scalars()
            .all()
        )
        embeddings = (
            (await s.execute(select(PrepEmbedding).where(PrepEmbedding.run_id == run_id)))
            .scalars()
            .all()
        )

    # A row exists at every stage — the chain actually produced output at each
    # step, not just the last one.
    assert len(lines) == 2, "parse should have produced one PrepLine per non-blank input line"
    assert len(screens) == 2, "screen should score every parsed line, above or below threshold"
    assert len(units) == 1, "only the MFA line clears the default threshold and gets expanded"
    assert len(classifications) == 1
    assert len(embeddings) == 1

    for row in (*lines, *screens, *units, *classifications, *embeddings):
        assert row.organization_id == org_id

    line_ids = {line.id for line in lines}
    unit = units[0]

    # The contract that actually matters: expand's PrepUnit traces back to
    # real PrepLine rows parse produced, not dangling ids.
    assert unit.source_line_ids, "expand must record which lines it folded together"
    assert set(unit.source_line_ids) <= line_ids

    # classify's stored control_identifiers must be a subset of what screen
    # actually surfaced for this unit's own trigger line — proving screen's
    # candidate_controls reached classify's allow-list filtering intact,
    # rather than classify inventing or widening its own scope.
    trigger_screen = next(sc for sc in screens if sc.line_id == unit.trigger_line_id)
    classification = classifications[0]
    assert classification.unit_id == unit.id
    assert set(classification.control_identifiers) <= set(trigger_screen.candidate_controls)
    assert "IA-2" in classification.control_identifiers, (
        "the MFA line should have surfaced IA-2 as a real candidate and had it echoed "
        "back by classification — proving screen's output actually reached classify"
    )

    # embed's row traces back to the same unit and carries the fake provider's
    # model name, proving classify's output was consumable input to embed too
    # (embed only reads PrepUnit, but this confirms embed ran against the
    # exact unit expand and classify both operated on, not a stale one).
    embedding = embeddings[0]
    assert embedding.unit_id == unit.id
    assert embedding.model_name == "text-embedding-3-small"
