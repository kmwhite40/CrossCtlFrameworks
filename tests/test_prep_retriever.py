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
from ccf.prep import retriever as retriever_module
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


async def test_system_scoped_retrieval_still_reaches_org_level_null_system_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """I4: a system_id-scoped query must still surface evidence with
    system_id IS NULL -- org-level documentation (e.g. a company-wide policy)
    that covers every system in the org, not one authorization boundary --
    or an org-level document could never be cited for any system-scoped
    query at all. A *different* system's evidence must still be excluded;
    the assessment engine passes the assessment's own real system_id here
    specifically so system B's evidence cannot be cited in system A's
    findings (see ccf.assessment.engine.service).
    """
    async with session_scope() as s:
        org = Organization(name="retr-null-system-org")
        s.add(org)
        await s.flush()
        system_a = System(organization_id=org.id, name="Sys A")
        system_b = System(organization_id=org.id, name="Sys B")
        s.add_all([system_a, system_b])
        await s.flush()
        run = await pipeline.create_run(
            s, organization_id=org.id, source_kind="evidence_version", source_id=1
        )

        org_line = PrepLine(run_id=run.id, organization_id=org.id, line_number=1,
                            page_number=1, section_path="Access Control",
                            content="Org-wide MFA policy applies to every system.")
        a_line = PrepLine(run_id=run.id, organization_id=org.id, line_number=2,
                          page_number=1, section_path="Access Control",
                          content="System A specific MFA configuration.")
        b_line = PrepLine(run_id=run.id, organization_id=org.id, line_number=3,
                          page_number=1, section_path="Access Control",
                          content="System B specific MFA configuration.")
        s.add_all([org_line, a_line, b_line])
        await s.flush()

        org_unit = PrepUnit(run_id=run.id, organization_id=org.id, trigger_line_id=org_line.id,
                            source_line_ids=[org_line.id], content=org_line.content,
                            page_numbers=[1], section_path="Access Control", token_count=8,
                            system_id=None, source_kind="evidence_version")
        a_unit = PrepUnit(run_id=run.id, organization_id=org.id, trigger_line_id=a_line.id,
                          source_line_ids=[a_line.id], content=a_line.content,
                          page_numbers=[1], section_path="Access Control", token_count=8,
                          system_id=system_a.id, source_kind="evidence_version")
        b_unit = PrepUnit(run_id=run.id, organization_id=org.id, trigger_line_id=b_line.id,
                          source_line_ids=[b_line.id], content=b_line.content,
                          page_numbers=[1], section_path="Access Control", token_count=8,
                          system_id=system_b.id, source_kind="evidence_version")
        s.add_all([org_unit, a_unit, b_unit])
        await s.flush()
        org_id, system_a_id = int(org.id), int(system_a.id)
        org_unit_id, a_unit_id, b_unit_id = int(org_unit.id), int(a_unit.id), int(b_unit.id)

    async def _boom(*args: Any, **kwargs: Any) -> Any:
        raise gateway.GatewayError("no embedding provider in this test -- lexical-only")

    monkeypatch.setattr(gateway, "embed", _boom)
    async with session_scope() as s:
        # A single term common to all three lines' content -- websearch_to_tsquery
        # ANDs multiple terms, so all three rows must match the lexical query on
        # their own merits; what distinguishes them here is purely the system
        # filter under test, not which terms happen to appear in which line.
        results = await retrieve(
            s, org_id=org_id, control_identifier="IA-2", query_text="MFA",
            system_id=system_a_id, limit=10,
        )
    found_ids = {r.unit_id for r in results}
    assert org_unit_id in found_ids, "org-level (system_id IS NULL) evidence must be reachable"
    assert a_unit_id in found_ids, "system A's own evidence must be reachable"
    assert b_unit_id not in found_ids, "system B's evidence must stay excluded"


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


# --- padded/unpadded control identifier reconciliation (Finding C1) --------
#
# The real ingested catalog is not consistently formatted: zero-padded
# ("AC-02"), unpadded ("CP-9"), and CMMC-style ("AC.L2-3.1.1") forms all
# coexist (confirmed live). Screening emits whatever the catalog row happens
# to be spelled, verbatim; before the fix, ``retrieve(control="AC-2")``
# returned zero results for a unit the classifier tagged "AC-02" -- the
# tagged-boost signal was dead for exactly the catalog's most common naming
# style. These two tests exercise both directions through the real
# ``retrieve()`` entrypoint, not just the normalization helper in isolation.


async def test_retrieve_finds_a_zero_padded_tagged_unit_from_an_unpadded_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    query_text = "delta echo foxtrot access control policy"
    query_vector = [0.9] * 1024
    unrelated_vector = [1.0 if i % 2 == 0 else -1.0 for i in range(1024)]
    async with session_scope() as s:
        org = Organization(name="retr-padded-catalog")
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
        # "target": tagged with the catalog's own zero-padded spelling
        # ("AC-02"), no lexical overlap, identical vector to the query --
        # reachable only via the tagged boost.
        target_id = await _add_unit(
            s, run=run, org_id=org_id, line_number=2,
            content="boundary enforcement device configuration review",
            embedding=query_vector, control_identifiers=["AC-02"],
        )
    monkeypatch.setattr(gateway, "embed", _fake_embed(query_vector))
    async with session_scope() as s:
        results = await retrieve(
            s, org_id=org_id, control_identifier="AC-2",
            query_text=query_text, limit=1,
        )
    assert results
    assert results[0].unit_id == target_id


async def test_retrieve_finds_an_unpadded_tagged_unit_from_a_zero_padded_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reverse direction: Concord's own canonical unpadded tag stored on
    the unit, queried with the catalog's zero-padded spelling."""
    query_text = "golf hotel india access control policy"
    query_vector = [0.9] * 1024
    unrelated_vector = [1.0 if i % 2 == 0 else -1.0 for i in range(1024)]
    async with session_scope() as s:
        org = Organization(name="retr-unpadded-tag")
        s.add(org)
        await s.flush()
        run = await pipeline.create_run(
            s, organization_id=org.id, source_kind="evidence_version", source_id=1
        )
        org_id = int(org.id)
        await _add_unit(
            s, run=run, org_id=org_id, line_number=1, content=query_text,
            embedding=unrelated_vector, control_identifiers=None,
        )
        target_id = await _add_unit(
            s, run=run, org_id=org_id, line_number=2,
            content="boundary enforcement device configuration review",
            embedding=query_vector, control_identifiers=["AC-2"],
        )
    monkeypatch.setattr(gateway, "embed", _fake_embed(query_vector))
    async with session_scope() as s:
        results = await retrieve(
            s, org_id=org_id, control_identifier="AC-02",
            query_text=query_text, limit=1,
        )
    assert results
    assert results[0].unit_id == target_id


# --- deterministic ranking (Finding I7) -------------------------------------


async def test_retrieve_ranking_is_deterministic_regardless_of_tagged_id_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two units tied on fused score (both tagged-only -- unreachable by
    lexical or vector, so both carry exactly ``tagged_boost`` and nothing
    else) must sort identically regardless of what order the tagged-unit
    query happens to return them in. Before the fix, the final sort was a
    stable sort over dict-insertion order, which followed whatever order the
    unbounded, unordered ``@>`` scan produced -- Postgres gives no guarantee
    that stays the same call to call.

    ``_lexical_ids``/``_vector_ids`` are stubbed to empty so the two units'
    scores come *only* from ``tagged_boost`` (real Postgres tie-order on
    those two backends is a separate, unrelated nondeterminism this test
    doesn't need and would otherwise contaminate the comparison). ``_tagged_ids``
    is stubbed to return the same two ids in opposite order on each call,
    standing in for Postgres's unspecified row order without depending on
    actually forcing two different physical scan orders.
    """
    async with session_scope() as s:
        org = Organization(name="retr-determinism")
        s.add(org)
        await s.flush()
        run = await pipeline.create_run(
            s, organization_id=org.id, source_kind="evidence_version", source_id=1
        )
        org_id = int(org.id)
        id_a = await _add_unit(
            s, run=run, org_id=org_id, line_number=1,
            content="unit alpha", embedding=[0.1] * 1024, control_identifiers=["IA-2"],
        )
        id_b = await _add_unit(
            s, run=run, org_id=org_id, line_number=2,
            content="unit bravo", embedding=[0.1] * 1024, control_identifiers=["IA-2"],
        )

    async def _empty(*args: Any, **kwargs: Any) -> list[int]:
        return []

    monkeypatch.setattr(retriever_module, "_lexical_ids", _empty)
    monkeypatch.setattr(retriever_module, "_vector_ids", _empty)

    orders = iter([[id_a, id_b], [id_b, id_a]])

    async def _fake_tagged_ids(*args: Any, **kwargs: Any) -> list[int]:
        return next(orders)

    monkeypatch.setattr(retriever_module, "_tagged_ids", _fake_tagged_ids)

    async with session_scope() as s:
        first = [
            r.unit_id
            for r in await retrieve(
                s, org_id=org_id, control_identifier="IA-2",
                query_text="completely unrelated query text zzz", limit=5,
            )
        ]
    async with session_scope() as s:
        second = [
            r.unit_id
            for r in await retrieve(
                s, org_id=org_id, control_identifier="IA-2",
                query_text="completely unrelated query text zzz", limit=5,
            )
        ]
    assert first == second == sorted([id_a, id_b])
