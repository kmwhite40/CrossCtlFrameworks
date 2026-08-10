"""Cross-tenant read/write isolation for the prep REST surface and pipeline.

Regression coverage for a review finding on Task 16: the prep endpoints
originally trusted a client-supplied ``organization_id`` outright (no
``Depends(get_principal)`` at all), which allowed two distinct attacks —

* **Read leak**: an authenticated org-A caller could pass ``organization_id``
  for any other org to ``GET /api/prep/retrieve`` and get that org's prepared
  evidence text back verbatim.
* **Laundering** (the more severe half, and it needs no knowledge of the
  victim org's identity — only an enumerable integer PK): an org-A caller
  could enqueue a run naming their *own* organization but another org's real
  ``EvidenceVersion``/``PolicyVersion`` PK as the source. ``resolve_source``
  has no org check, so the worker (which bypasses RLS) would fetch and
  prepare the victim's real bytes — and because every prep stage past parse
  tagged its output with the *caller's claimed* org rather than the source's
  *true* org, the attacker could then retrieve the victim's fully parsed,
  classified content under their own organization_id.

Three closes, exercised here:

1. The router derives organization from the authenticated principal, not a
   client-supplied field (``prep.py::_scoped_organization_id``).
2. ``jobs.enqueue`` refuses to open a run whose declared org does not own the
   named source (``sources.resolve_source_organization_id`` +
   ``SourceOwnershipMismatch``).
3. ``pipeline.run_stage_parse`` reconciles ``run.organization_id`` to the
   source's true org the moment it is resolved, so every stage's tagging is
   structurally single-sourced rather than merely coincidentally consistent.

Retrieval here runs through the real, authenticated HTTP path — bearer token
-> ``get_principal`` -> ``deps.get_session`` -> ``set_session_tenant`` ->
``SET ROLE ccf_app`` — not the unscoped bootstrap-role path every other prep
test uses via ``session_scope()``. That distinction matters on its own: a
separate review finding (Finding 2) was a pgvector operator that resolved
under the bootstrap role only by coincidence and 500'd for every real,
RLS-scoped tenant. Retrieval tests below would silently stop exercising that
code path — and stop catching a regression of it — if they used
``session_scope()`` instead of a real authenticated request.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.ai import gateway
from ccf.ai.providers.base import EmbedResponse
from ccf.api.main import create_app
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.evidence import storage
from ccf.models import Organization, System, User
from ccf.models_evidence import EvidenceObject, EvidenceVersion
from ccf.models_prep import (
    PrepClassification,
    PrepEmbedding,
    PrepLine,
    PrepRun,
    PrepScreen,
    PrepUnit,
)
from ccf.prep import pipeline

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(autouse=True)
def _auth_enabled() -> Any:
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _local_evidence_dir(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("CCF_EVIDENCE_BACKEND", "local")
    monkeypatch.setenv("CCF_EVIDENCE_LOCAL_DIR", str(tmp_path / "evidence"))
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _mk_user(email: str, org_name: str) -> tuple[str, int]:
    """Create an org + a real (viewer-role, non-admin) user in it; return
    (bearer token, org id). Deliberately not an admin: these tests are about
    what an *ordinary* org-scoped caller can and cannot reach.
    """
    async with session_scope() as s:
        org = Organization(name=org_name)
        s.add(org)
        await s.flush()
        user = User(
            email=email,
            organization_id=org.id,
            role="viewer",
            active=True,
            password_hash=hash_password("pw"),
            api_token=new_api_token(),
        )
        s.add(user)
        await s.flush()
        return user.api_token, org.id


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


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


async def _seed_prepared_unit(org_id: int, content: str, control: str, vector: list[float]) -> None:
    """Directly seed one fully-prepared unit (line/unit/classification/embedding)
    for org_id, bypassing the pipeline — mirrors test_prep_retriever.py's
    ``_seed`` helper, since this module is about retrieval's tenant scoping,
    not the pipeline mechanics test_prep_pipeline_e2e.py already covers.
    """
    async with session_scope() as s:
        system = System(organization_id=org_id, name="Sys")
        s.add(system)
        await s.flush()
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="evidence_version", source_id=1
        )
        line = PrepLine(
            run_id=run.id, organization_id=org_id, line_number=1,
            page_number=1, section_path="Access Control", content=content,
        )
        s.add(line)
        await s.flush()
        unit = PrepUnit(
            run_id=run.id, organization_id=org_id, trigger_line_id=line.id,
            source_line_ids=[line.id], content=content, page_numbers=[1],
            section_path="Access Control", token_count=8,
            system_id=system.id, source_kind="evidence_version",
        )
        s.add(unit)
        await s.flush()
        s.add(PrepClassification(
            unit_id=unit.id, run_id=run.id, organization_id=org_id,
            control_identifiers=[control], artifact_type="policy",
            evidence_strength="strong", model_confidence=0.8,
        ))
        s.add(PrepEmbedding(
            unit_id=unit.id, run_id=run.id, organization_id=org_id,
            model_name="text-embedding-3-small", embedding=vector,
        ))
        await s.flush()


def _fake_embed(vector: list[float]) -> Any:
    async def _embed(session: Any, org_id: int, *, texts: list[str], **kw: Any) -> EmbedResponse:
        return EmbedResponse(vectors=[vector], model="text-embedding-3-small")

    return _embed


# --- Read leak: retrieve.organization_id is overridden, not trusted --------


async def test_retrieve_ignores_a_scoped_principals_claimed_cross_tenant_organization_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An org-A caller naming org B's organization_id must never see org B's
    prepared evidence -- the caller's own organization always wins, silently
    (logged, not rejected -- see prep.py's _scoped_organization_id).

    Exercised through the real authenticated HTTP path (bearer token ->
    SET ROLE ccf_app), not session_scope(), so this also stands as the
    Finding-2 regression guard for the pgvector operator/search_path fix.
    """
    token_a, _org_a = await _mk_user("leak-a@prep-tenant.test", "Prep Tenant Org A")
    _token_b, org_b = await _mk_user("leak-b@prep-tenant.test", "Prep Tenant Org B")

    victim_text = "Administrators authenticate with multifactor authentication for IA-2."
    await _seed_prepared_unit(org_b, victim_text, "IA-2", [0.9] * 1024)
    monkeypatch.setattr(gateway, "embed", _fake_embed([0.9] * 1024))

    async with _client() as client:
        response = await client.get(
            "/api/prep/retrieve",
            params={"organization_id": org_b, "control": "IA-2"},
            headers=_auth(token_a),
        )
    assert response.status_code == 200
    results = response.json()["results"]
    assert results == [], "org A must not see org B's prepared evidence"
    assert not any(victim_text in str(r) for r in results)


async def test_retrieve_still_returns_the_callers_own_organizations_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The override is a redirect to the caller's real org, not a black hole:
    org A's own prepared evidence is still reachable (proving the endpoint
    stays useful for the case that matters -- a caller retrieving their own
    data -- rather than only "provably closed for attackers").
    """
    token_a, org_a = await _mk_user("own-a@prep-tenant.test", "Prep Tenant Own Org A")
    own_text = "Administrators authenticate with multifactor authentication for IA-2."
    await _seed_prepared_unit(org_a, own_text, "IA-2", [0.9] * 1024)
    monkeypatch.setattr(gateway, "embed", _fake_embed([0.9] * 1024))

    async with _client() as client:
        # Even naming a bogus/foreign organization_id in the query -- the
        # caller's own org still wins.
        response = await client.get(
            "/api/prep/retrieve",
            params={"organization_id": 999_999, "control": "IA-2"},
            headers=_auth(token_a),
        )
    assert response.status_code == 200
    results = response.json()["results"]
    assert len(results) == 1
    assert results[0]["content"] == own_text


# --- Laundering: enqueue refuses a cross-tenant source ----------------------


async def test_enqueue_refuses_a_cross_tenant_evidence_version_source_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Org A must not be able to enqueue a run against org B's real
    EvidenceVersion PK by claiming their own organization_id in the request
    -- this is the "no knowledge of the victim needed" laundering path:
    source_id is just an enumerable integer.
    """
    token_a, org_a = await _mk_user("launder-a@prep-tenant.test", "Prep Tenant Launder A")
    _token_b, org_b = await _mk_user("launder-b@prep-tenant.test", "Prep Tenant Launder B")
    victim_source_id = await _evidence_version(org_b, b"Org B's real secret evidence.", "s.txt")

    async with _client() as client:
        response = await client.post(
            "/api/prep/runs",
            json={
                "organization_id": org_a,
                "source_kind": "evidence_version",
                "source_id": victim_source_id,
            },
            headers=_auth(token_a),
        )
    assert response.status_code == 404

    async with session_scope() as s:
        # Scoped to org_a specifically (not a bare source_id match): other
        # tests in this module seed their own placeholder runs against a
        # hardcoded source_id=1 (mirroring test_prep_retriever.py's _seed
        # helper), and victim_source_id can coincidentally equal that same
        # integer depending on table-wide id allocation order -- scoping by
        # organization_id=org_a is what actually distinguishes "the
        # laundering attempt succeeded" from an unrelated fixture row.
        leaked = (
            await s.execute(
                select(PrepRun).where(
                    PrepRun.organization_id == org_a,
                    PrepRun.source_kind == "evidence_version",
                    PrepRun.source_id == victim_source_id,
                )
            )
        ).scalars().all()
        assert leaked == [], "no run should have been opened against the victim's source at all"


# --- Consistency: every prep_* row for a run shares one organization_id ----


async def test_prep_run_rows_share_one_organization_id_even_with_a_mismatched_create_run_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Defense-in-depth guard for pipeline.run_stage_parse's org reconciliation.

    jobs.enqueue() already refuses a mismatched claim before a run is even
    opened (see test_enqueue_refuses_a_cross_tenant_evidence_version_source_id
    above), so this deliberately bypasses that gate by calling
    pipeline.create_run directly -- exactly as every other prep stage-test
    module already does for its own internal setup (test_prep_screen.py,
    test_prep_classify.py, etc. all call create_run directly, never
    jobs.enqueue) -- to prove the *second*, independent safeguard: even if a
    run is somehow opened with the wrong organization_id, parsing corrects it
    to the source's true org, and every stage after it inherits that
    corrected value. Without pipeline.py's reconciliation, this is exactly
    the split the review found live: PrepLine.organization_id == victim_org
    while PrepUnit/PrepClassification/PrepEmbedding.organization_id ==
    attacker_org, all under the same run.
    """
    _, victim_org = await _mk_user("consist-victim@prep-tenant.test", "Prep Tenant Consist Victim")
    _, attacker_org = await _mk_user(
        "consist-attacker@prep-tenant.test", "Prep Tenant Consist Attacker"
    )
    version_id = await _evidence_version(
        victim_org,
        b"Administrators must use multifactor authentication for network access.\n",
        "victim.txt",
    )

    monkeypatch.setattr(gateway, "embed", _fake_embed([0.01] * 1024))

    async def _fake_generate_structured(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "control_identifiers": [],
            "artifact_type": "policy",
            "evidence_strength": "weak",
            "confidence": 0.5,
        }

    monkeypatch.setattr(gateway, "generate_structured", _fake_generate_structured)

    async with session_scope() as s:
        # Deliberately mismatched: claims attacker_org for a source that
        # belongs to victim_org. jobs.enqueue() would refuse this; create_run
        # itself (an internal primitive, not the untrusted boundary) does not.
        run = await pipeline.create_run(
            s, organization_id=attacker_org, source_kind="evidence_version",
            source_id=version_id,
        )
        run_id = int(run.id)
        await pipeline.advance(s, run)
        assert run.status in ("complete", "failed", "unsupported", "orphaned"), run.error
        # The reconciliation happens the moment parse resolves the real
        # source -- so the run itself is already corrected.
        assert run.organization_id == victim_org

    async with session_scope() as s:
        reloaded = await pipeline.load_run(s, run_id)
        assert reloaded is not None
        assert reloaded.organization_id == victim_org

        lines = (await s.execute(select(PrepLine).where(PrepLine.run_id == run_id))).scalars().all()
        screens = (
            await s.execute(select(PrepScreen).where(PrepScreen.run_id == run_id))
        ).scalars().all()
        units = (await s.execute(select(PrepUnit).where(PrepUnit.run_id == run_id))).scalars().all()
        classifications = (
            await s.execute(select(PrepClassification).where(PrepClassification.run_id == run_id))
        ).scalars().all()
        embeddings = (
            await s.execute(select(PrepEmbedding).where(PrepEmbedding.run_id == run_id))
        ).scalars().all()

    assert lines, "parse should have produced at least one line"
    all_rows = (*lines, *screens, *units, *classifications, *embeddings)
    assert all_rows, "the run should have produced output past parse"
    for row in all_rows:
        assert row.organization_id == victim_org, (
            f"{type(row).__name__} {row.id} carries organization_id={row.organization_id}, "
            f"not the source's true org ({victim_org}) -- the tagging split is back"
        )
