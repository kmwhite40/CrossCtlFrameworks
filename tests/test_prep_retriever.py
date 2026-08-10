"""Hybrid retrieval — RRF fusion, filtering, and citation fidelity."""

from __future__ import annotations

from typing import Any

import pytest

from ccf.ai import gateway
from ccf.ai.providers.base import EmbedResponse
from ccf.db import session_scope
from ccf.models import Organization, System
from ccf.models_prep import PrepClassification, PrepEmbedding, PrepLine, PrepUnit
from ccf.prep import pipeline
from ccf.prep.retriever import fuse, retrieve

pytestmark = pytest.mark.usefixtures("fresh_engine")


def test_fuse_ranks_a_unit_found_by_both_backends_above_either_alone() -> None:
    """The core claim of hybrid retrieval, asserted directly on the fusion."""
    fused = dict(fuse(lexical=[1, 2], vector=[3, 1]))
    assert fused[1] > fused[2]
    assert fused[1] > fused[3]


def test_fuse_returns_units_found_by_only_one_backend() -> None:
    ids = [unit_id for unit_id, _ in fuse(lexical=[1], vector=[2])]
    assert sorted(ids) == [1, 2]


def test_fuse_of_two_empty_rankings_is_empty() -> None:
    assert fuse(lexical=[], vector=[]) == []


async def _seed(org_name: str) -> tuple[int, int, dict[str, int]]:
    """Three units: one MFA policy, one backup policy, one unrelated."""
    async with session_scope() as s:
        org = Organization(name=org_name)
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name="Sys")
        s.add(system)
        await s.flush()
        run = await pipeline.create_run(
            s, organization_id=org.id, source_kind="evidence_version", source_id=1
        )
        ids: dict[str, int] = {}
        rows = [
            ("mfa", "Administrators authenticate with multifactor authentication.", "IA-2",
             [0.9] * 1024),
            ("backup", "Nightly backups are replicated offsite.", "CP-9", [0.1] * 1024),
            ("noise", "The cafeteria closes at five.", "AC-1", [0.0] * 1024),
        ]
        for key, content, control, vector in rows:
            line = PrepLine(run_id=run.id, organization_id=org.id, line_number=len(ids) + 1,
                            page_number=3, section_path="Access Control", content=content)
            s.add(line)
            await s.flush()
            unit = PrepUnit(run_id=run.id, organization_id=org.id, trigger_line_id=line.id,
                            source_line_ids=[line.id], content=content, page_numbers=[3],
                            section_path="Access Control", token_count=8,
                            system_id=system.id, source_kind="evidence_version")
            s.add(unit)
            await s.flush()
            ids[key] = int(unit.id)
            s.add(PrepClassification(unit_id=unit.id, run_id=run.id, organization_id=org.id,
                                     control_identifiers=[control], artifact_type="policy",
                                     evidence_strength="strong", model_confidence=0.8))
            s.add(PrepEmbedding(unit_id=unit.id, run_id=run.id, organization_id=org.id,
                                model_name="text-embedding-3-small", embedding=vector))
        await s.flush()
        return int(org.id), int(system.id), ids


def _fake_embed(vector: list[float]):
    async def _embed(session: Any, org_id: int, *, texts: list[str], **kw: Any) -> EmbedResponse:
        return EmbedResponse(vectors=[vector], model="text-embedding-3-small")

    return _embed


async def test_retrieve_returns_the_matching_unit_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id, _, ids = await _seed("retr-basic")
    monkeypatch.setattr(gateway, "embed", _fake_embed([0.9] * 1024))
    async with session_scope() as s:
        results = await retrieve(
            s, org_id=org_id, control_identifier="IA-2",
            query_text="multifactor authentication", limit=3,
        )
    assert results
    assert results[0].unit_id == ids["mfa"]


async def test_results_carry_the_citation_back_to_page_and_section(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id, _, _ = await _seed("retr-cite")
    monkeypatch.setattr(gateway, "embed", _fake_embed([0.9] * 1024))
    async with session_scope() as s:
        results = await retrieve(
            s, org_id=org_id, control_identifier="IA-2", query_text="mfa", limit=1
        )
    assert results[0].page_numbers == [3]
    assert results[0].section_path == "Access Control"
    assert "IA-2" in results[0].control_identifiers


async def test_retrieval_is_scoped_to_the_requesting_organization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_a, _, _ = await _seed("retr-tenant-a")
    org_b, _, _ = await _seed("retr-tenant-b")
    monkeypatch.setattr(gateway, "embed", _fake_embed([0.9] * 1024))
    async with session_scope() as s:
        results = await retrieve(
            s, org_id=org_a, control_identifier="IA-2", query_text="mfa", limit=10
        )
    async with session_scope() as s:
        b_units = {
            r.unit_id
            for r in await retrieve(
                s, org_id=org_b, control_identifier="IA-2", query_text="mfa", limit=10
            )
        }
    assert not ({r.unit_id for r in results} & b_units)


async def test_system_filter_excludes_other_systems(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id, system_id, _ = await _seed("retr-system")
    monkeypatch.setattr(gateway, "embed", _fake_embed([0.9] * 1024))
    async with session_scope() as s:
        matched = await retrieve(
            s, org_id=org_id, control_identifier="IA-2", query_text="mfa",
            system_id=system_id, limit=10,
        )
        missed = await retrieve(
            s, org_id=org_id, control_identifier="IA-2", query_text="mfa",
            system_id=system_id + 9_999, limit=10,
        )
    assert matched
    assert missed == []


async def test_retrieval_falls_back_to_lexical_when_embedding_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A provider outage must degrade retrieval, not break it."""
    org_id, _, ids = await _seed("retr-fallback")

    async def _boom(*args: Any, **kwargs: Any) -> EmbedResponse:
        raise gateway.GatewayError("provider unavailable")

    monkeypatch.setattr(gateway, "embed", _boom)
    async with session_scope() as s:
        results = await retrieve(
            s, org_id=org_id, control_identifier="IA-2",
            query_text="multifactor authentication", limit=3,
        )
    assert results
    assert results[0].unit_id == ids["mfa"]
    assert results[0].vector_rank is None


async def _add_unit(
    s: Any,
    *,
    run: Any,
    org_id: int,
    line_number: int,
    content: str,
    embedding: list[float],
    control_identifiers: list[str] | None = None,
) -> int:
    """One unit with full control over content, vector, and tagging."""
    line = PrepLine(run_id=run.id, organization_id=org_id, line_number=line_number,
                    page_number=1, section_path="Access Control", content=content)
    s.add(line)
    await s.flush()
    unit = PrepUnit(run_id=run.id, organization_id=org_id, trigger_line_id=line.id,
                    source_line_ids=[line.id], content=content, page_numbers=[1],
                    section_path="Access Control", token_count=len(content.split()),
                    source_kind="evidence_version")
    s.add(unit)
    await s.flush()
    if control_identifiers is not None:
        s.add(PrepClassification(unit_id=unit.id, run_id=run.id, organization_id=org_id,
                                 control_identifiers=control_identifiers, artifact_type="policy",
                                 evidence_strength="strong", model_confidence=0.8))
    s.add(PrepEmbedding(unit_id=unit.id, run_id=run.id, organization_id=org_id,
                        model_name="text-embedding-3-small", embedding=embedding))
    await s.flush()
    return int(unit.id)


async def test_retrieved_units_all_belong_to_the_requesting_org(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Defense in depth for the hydration query, not just the three candidate paths.

    Both orgs get byte-identical content and identical embedding vectors (via
    ``_seed``), so a hydration query missing its own organization_id guard
    would happily return the other org's units too.
    """
    org_a, _, ids_a = await _seed("retr-hydrate-a")
    _, _, ids_b = await _seed("retr-hydrate-b")
    monkeypatch.setattr(gateway, "embed", _fake_embed([0.9] * 1024))
    async with session_scope() as s:
        results = await retrieve(
            s, org_id=org_a, control_identifier="IA-2", query_text="mfa", limit=10
        )
    assert results
    own_ids = set(ids_a.values())
    other_ids = set(ids_b.values())
    for r in results:
        assert r.unit_id in own_ids
        assert r.unit_id not in other_ids


async def test_untagged_exact_match_outranks_tagged_but_irrelevant_units_under_a_tight_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A tagged-first sort tier previously let irrelevant tagged units bury the best match.

    Five units are tagged IA-2 but share no vocabulary or embedding direction with
    the query; one untagged unit is an exact lexical match with an identical
    embedding vector. With ``limit=3`` the untagged unit must still win rank 1 —
    the tagged boost should add to its score, not categorically outrank it.
    """
    query_text = "administrators authenticate with multifactor authentication"
    query_vector = [0.9] * 1024
    noise_vector = [1.0 if i % 2 == 0 else -1.0 for i in range(1024)]
    async with session_scope() as s:
        org = Organization(name="retr-starvation")
        s.add(org)
        await s.flush()
        run = await pipeline.create_run(
            s, organization_id=org.id, source_kind="evidence_version", source_id=1
        )
        org_id = int(org.id)
        target_id = await _add_unit(
            s, run=run, org_id=org_id, line_number=1, content=query_text,
            embedding=query_vector, control_identifiers=None,
        )
        for i in range(5):
            await _add_unit(
                s, run=run, org_id=org_id, line_number=2 + i,
                content=f"unrelated cafeteria hours notice number {i}",
                embedding=noise_vector, control_identifiers=["IA-2"],
            )
    monkeypatch.setattr(gateway, "embed", _fake_embed(query_vector))
    async with session_scope() as s:
        results = await retrieve(
            s, org_id=org_id, control_identifier="IA-2",
            query_text=query_text, limit=3,
        )
    assert results
    assert results[0].unit_id == target_id


async def test_retrieve_normalizes_an_enhancement_identifier_for_the_tagged_boost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-6(2) must still catch AC-6-classified evidence — screen only stores base ids."""
    query_text = "alpha bravo charlie access control policy"
    query_vector = [0.9] * 1024
    unrelated_vector = [1.0 if i % 2 == 0 else -1.0 for i in range(1024)]
    async with session_scope() as s:
        org = Organization(name="retr-enhancement")
        s.add(org)
        await s.flush()
        run = await pipeline.create_run(
            s, organization_id=org.id, source_kind="evidence_version", source_id=1
        )
        org_id = int(org.id)
        # "match": strong lexical + weaker vector match, untagged.
        await _add_unit(
            s, run=run, org_id=org_id, line_number=1, content=query_text,
            embedding=unrelated_vector, control_identifiers=None,
        )
        # "target": AC-6-tagged, no lexical overlap, identical vector to the query.
        target_id = await _add_unit(
            s, run=run, org_id=org_id, line_number=2,
            content="boundary enforcement device configuration review",
            embedding=query_vector, control_identifiers=["AC-6"],
        )
    monkeypatch.setattr(gateway, "embed", _fake_embed(query_vector))
    async with session_scope() as s:
        results = await retrieve(
            s, org_id=org_id, control_identifier="AC-6(2)",
            query_text=query_text, limit=1,
        )
    assert results
    assert results[0].unit_id == target_id
