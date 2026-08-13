"""Task 5: the auditor's question, answered in one query.

Tasks 1-4 taught every AI-generated classification and objective verdict to
record its own provenance (``ccf.ai_actions.provenance.record_ai_run``) and
taught acceptance to stamp the accepting assessor onto every linked run
(``ccf.assessment.engine.service.accept_control_proposal``). None of that
matters if an auditor asking "which model produced this verdict, from what
evidence, and who accepted it" cannot get an answer without touching the
pipeline's own working tables (``assessment_objective_proposals``,
``prep_units``) -- reaching into those to *assemble* the answer would prove
only that the pipeline can explain itself to itself, not to an auditor sitting
outside it with nothing but ``ai_action_runs`` and ``ai_action_citations``.

This module drives the real chain the same way ``test_assessment_engine_e2e.py``
does -- a genuine ``EvidenceVersion`` through all five prep stages, then real
objective evaluation, then real acceptance -- monkeypatching only the two
external AI-gateway boundaries both stages actually call:
``gateway.generate_structured_resolved`` (both ``ccf.prep.classify`` and
``ccf.assessment.engine.evaluate`` call this one function, not the plain
``generate_structured`` -- see ``ccf.ai.gateway.StructuredResult``'s docstring)
and ``gateway.embed``. Everything else -- screening, classification, retrieval,
verdicts, provenance recording, acceptance stamping -- runs for real.
"""

from __future__ import annotations

import hashlib
import os
import re
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select, text

from ccf.ai import gateway
from ccf.ai.providers.base import EmbedResponse
from ccf.ai_actions.provenance import PIPELINE_RUN_STATUS, record_ai_run
from ccf.api.main import create_app
from ccf.assessment.engine import jobs
from ccf.assessment.engine.evaluate import ACTION_KEY as EVALUATE_ACTION_KEY
from ccf.assessment.engine.evaluate import PURPOSE as EVALUATE_PURPOSE
from ccf.assessment.engine.service import accept_control_proposal
from ccf.auth import hash_password, new_api_token
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.evidence import storage
from ccf.models import Assessment, Control, Organization, System, User
from ccf.models_ai_actions import AiActionCitation, AiActionRun
from ccf.models_assessment_engine import AssessmentControlProposal
from ccf.models_evidence import EvidenceObject, EvidenceVersion
from ccf.models_prep import PrepUnit
from ccf.prep import pipeline
from ccf.prep.classify import ACTION_KEY as CLASSIFY_ACTION_KEY

pytestmark = pytest.mark.usefixtures("fresh_engine")

#: A prefix no other test module uses -- see test_assessment_engine_e2e.py's
#: identical note for ZAE-70, test_assessment_acceptance.py's for ZQ-90/91,
#: test_assessment_engine_api.py's for ZQ-91 (different module, safe).
_SEQ = "ZPV-95"

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


@pytest.fixture(autouse=True)
async def _catalog_rows() -> Any:
    """One addressable control plus two real sub-clause objective rows --
    same MFA-phrased fixture shape as test_assessment_engine_e2e.py's ZAE-70,
    under this module's own ZPV-95 prefix.
    """
    async with session_scope() as s:
        await s.execute(delete(Control).where(Control.sequence_control == _SEQ))
        s.add(
            Control(
                identifier=_SEQ,
                sequence_control=_SEQ,
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
                source_row=1,
            )
        )
        s.add(
            Control(
                identifier=f"{_SEQ}-ao1",
                sequence_control=_SEQ,
                assessment_objective=(
                    "multifactor authentication is implemented for network access to "
                    "privileged accounts;"
                ),
                source_row=2,
            )
        )
        s.add(
            Control(
                identifier=f"{_SEQ}-ao2",
                sequence_control=_SEQ,
                assessment_objective=(
                    "multifactor authentication is implemented for network access to "
                    "non-privileged accounts;"
                ),
                source_row=3,
            )
        )
        await s.flush()
        await s.execute(text(_SEARCH_VECTOR_SQL))
    try:
        yield
    finally:
        async with session_scope() as s:
            await s.execute(delete(Control).where(Control.sequence_control == _SEQ))


@pytest.fixture(autouse=True)
async def _isolate_job_queue() -> Any:
    """``assessment_jobs`` is a genuinely global queue -- see
    test_assessment_engine_e2e.py's identical fixture for why this must be
    wiped unconditionally before and after.
    """

    async def _wipe() -> None:
        async with session_scope() as s:
            await s.execute(delete(jobs.AssessmentJob))

    await _wipe()
    yield
    await _wipe()


@pytest.fixture(autouse=True)
def _auth_enabled() -> Any:
    """Only tests 3-4 (the listing endpoint) go through real HTTP auth; tests
    1-2 drive the pipeline via ``session_scope()`` directly and are unaffected
    by this being on. Matches test_assessment_engine_api.py's convention.
    """
    os.environ["CCF_AUTH_ENABLED"] = "true"
    os.environ["CCF_AUTH_SESSION_SECRET"] = "test-secret"
    get_settings.cache_clear()
    yield
    os.environ.pop("CCF_AUTH_ENABLED", None)
    os.environ.pop("CCF_AUTH_SESSION_SECRET", None)
    get_settings.cache_clear()


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
    """Serve the prep pipeline's own embed stage; simulate an outage at
    retrieval time -- identical reasoning to test_assessment_engine_e2e.py's
    fixture of the same name: a constant vector would make this test's single
    ``PrepUnit`` trivially "found" for any query, masking a broken classify
    stage. Forcing retrieval onto ``retriever._tagged_ids`` instead means the
    citations asserted below are proof classification's output actually
    reached retrieval.
    """

    async def _embed(session: Any, org_id: int, *, texts: list[str], **kw: Any) -> EmbedResponse:
        if kw.get("purpose") == "prep.retrieve":
            raise gateway.GatewayError("simulated embedding provider outage at retrieval time")
        return EmbedResponse(
            vectors=[[0.01] * dim for _ in texts],
            model="text-embedding-3-small",
            input_tokens=len(texts),
        )

    return _embed


#: The model name the fake gateway reports resolving -- asserted below via the
#: one-query result, proving it came from a real resolved model, not NULL.
_FAKE_MODEL_NAME = "audit-e2e-fake-model-v1"


def _compute_fake_response(prompt: str, purpose: str) -> dict[str, Any]:
    """Shared logic behind the one gateway monkeypatch target both the prep
    pipeline's classify stage and the assessment engine's objective evaluation
    call through -- both call ``generate_structured_resolved`` now (see this
    module's docstring), distinguished only by ``purpose``.
    """
    if purpose == CLASSIFY_ACTION_KEY:
        first_line = prompt.splitlines()[0]
        offered = first_line.removeprefix("Candidate controls:").strip()
        candidates = (
            []
            if offered == "(none surfaced by screening)"
            else [c.strip() for c in offered.split(",")]
        )
        return {
            "control_identifiers": candidates,
            "artifact_type": "policy",
            "evidence_strength": "strong",
            "confidence": 0.9,
        }
    if purpose == EVALUATE_PURPOSE:
        offered_ids = [int(m) for m in re.findall(r"\[(\d+)\]", prompt)]
        return {
            "verdict": "satisfied",
            "cited_unit_ids": offered_ids,
            "gaps": [],
            "contradictions": [],
            "rationale": "The cited passage demonstrates multifactor authentication is used.",
            "confidence": 0.85,
        }
    raise AssertionError(f"unexpected generate_structured_resolved purpose: {purpose!r}")


async def _fake_generate_structured_resolved(
    session: Any,
    org_id: int,
    *,
    prompt: str,
    schema: dict[str, Any],
    purpose: str,
    system: str | None = None,
    **kw: Any,
) -> gateway.StructuredResult:
    data = _compute_fake_response(prompt, purpose)
    return gateway.StructuredResult(data=data, model=_FAKE_MODEL_NAME, provider="anthropic")


async def _prepared_and_accepted(monkeypatch: pytest.MonkeyPatch, org_name: str) -> tuple[
    int, set[int], str
]:
    """Real prep pipeline -> real objective evaluation -> real acceptance.

    Returns ``(org_id, unit_ids, accepted_by)``: ``unit_ids`` is the set of
    genuine ``prep_units`` ids the pipeline produced, kept only so callers can
    cross-check the audit trail's citations against real rows -- never to
    assemble the audit answer itself.
    """
    org_id = await _org(org_name)
    payload = (
        b"Administrators must use multifactor authentication for network access.\n"
        b"The quick brown fox jumped over the lazy dog.\n"
    )
    version_id = await _evidence_version(org_id, payload, "access-control.txt")

    monkeypatch.setattr(gateway, "generate_structured_resolved", _fake_generate_structured_resolved)
    monkeypatch.setattr(gateway, "embed", _fake_embed())

    async with session_scope() as s:
        run = await pipeline.create_run(
            s, organization_id=org_id, source_kind="evidence_version", source_id=version_id
        )
        await pipeline.advance(s, run)
        assert run.status == "complete", run.error

    async with session_scope() as s:
        units = (
            (await s.execute(select(PrepUnit).where(PrepUnit.organization_id == org_id)))
            .scalars()
            .all()
        )
    unit_ids = {int(u.id) for u in units}
    assert unit_ids, "the pipeline must have produced at least one genuine prep_units row"

    async with session_scope() as s:
        system = System(organization_id=org_id, name=f"{org_name}-system")
        s.add(system)
        await s.flush()
        assessment = Assessment(system_id=system.id, name=f"{org_name}-assessment", kind="self")
        s.add(assessment)
        await s.flush()
        assessment_id = int(assessment.id)

    async with session_scope() as s:
        await jobs.enqueue_control(s, assessment_id=assessment_id, control_identifier=_SEQ)
    async with session_scope() as s:
        stats = await jobs.run_once(s, worker=org_name, limit=5)
    assert stats == {"claimed": 1, "finished": 1, "failed": 0}, stats

    async with session_scope() as s:
        proposal = (
            await s.execute(
                select(AssessmentControlProposal).where(
                    AssessmentControlProposal.assessment_id == assessment_id
                )
            )
        ).scalar_one()
        assert proposal.state == "complete"
        proposal_id = int(proposal.id)

    accepted_by = f"{org_name}-assessor@example.com"
    async with session_scope() as s:
        await accept_control_proposal(s, proposal_id, accepted_by=accepted_by)

    return org_id, unit_ids, accepted_by


# --- Test 1: the acceptance criterion itself ---------------------------------


async def test_one_query_answers_model_evidence_and_reviewer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The whole point of the slice.

    Run slice 2's end-to-end flow, accept, then issue ONE query over
    ai_action_runs joined to ai_action_citations and assert it yields, per
    objective: the model name, every cited prep_unit id with its label, the
    accepting reviewer, and decided_at. Assert on the joined result, not by
    reading the pipeline tables.
    """
    org_id, unit_ids, accepted_by = await _prepared_and_accepted(monkeypatch, "audit-one-query")

    # --- THE auditor's query: one statement, one join, nothing else touched. ---
    async with session_scope() as s:
        stmt = (
            select(AiActionRun, AiActionCitation)
            .join(AiActionCitation, AiActionCitation.run_id == AiActionRun.id)
            .where(AiActionRun.organization_id == org_id)
            .where(AiActionRun.action_key == EVALUATE_ACTION_KEY)
            .order_by(AiActionRun.entity_id, AiActionCitation.id)
        )
        rows = (await s.execute(stmt)).all()

    assert rows, "the one query must return at least one citation row"

    # AiActionRun.entity_id already carries the objective label (set by
    # evaluate_objective) -- grouping on it answers "per objective" from the
    # joined result alone, with no lookup into assessment_objective_proposals.
    by_objective: dict[str, dict[str, Any]] = {}
    for run, citation in rows:
        entry = by_objective.setdefault(
            run.entity_id,
            {
                "model": run.summary.get("model"),
                "reviewer": run.reviewer,
                "decided_at": run.decided_at,
                "citations": [],
            },
        )
        entry["citations"].append((citation.source_id, citation.label))

    assert set(by_objective) == {f"{_SEQ}a", f"{_SEQ}b"}, (
        "the query must answer for both catalog objectives, keyed by the label "
        "carried on the run itself"
    )
    for label, entry in by_objective.items():
        assert entry["model"] == _FAKE_MODEL_NAME, f"{label}: model name missing from the query"
        assert entry["reviewer"] == accepted_by, f"{label}: accepting reviewer missing"
        assert entry["decided_at"] is not None, f"{label}: decided_at missing"
        assert entry["citations"], f"{label}: no cited prep_unit in the joined result"
        for source_id, citation_label in entry["citations"]:
            assert int(source_id) in unit_ids, (
                f"{label}: citation {source_id} is not a prep_unit this run actually produced"
            )
            assert citation_label, f"{label}: citation carries no label (page numbers/section path)"


# --- Test 2: citations must resolve --------------------------------------


async def test_every_citation_source_id_resolves_to_a_real_prep_unit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A citation pointing at nothing is worse than no citation."""
    org_id, unit_ids, _accepted_by = await _prepared_and_accepted(monkeypatch, "audit-citation-fk")

    async with session_scope() as s:
        citations = (
            (
                await s.execute(
                    select(AiActionCitation)
                    .join(AiActionRun, AiActionRun.id == AiActionCitation.run_id)
                    .where(AiActionRun.organization_id == org_id)
                    .where(AiActionRun.action_key == EVALUATE_ACTION_KEY)
                    .where(AiActionCitation.source_type == "prep_unit")
                )
            )
            .scalars()
            .all()
        )
    assert citations, "no prep_unit citations were recorded for this run"
    source_ids = {int(c.source_id) for c in citations}

    async with session_scope() as s:
        resolved = (
            (
                await s.execute(
                    select(PrepUnit.id).where(
                        PrepUnit.id.in_(source_ids), PrepUnit.organization_id == org_id
                    )
                )
            )
            .scalars()
            .all()
        )
    assert set(resolved) == source_ids, (
        "every AiActionCitation.source_id must resolve to a live prep_units row"
    )
    assert source_ids <= unit_ids


# --- Tests 3-4: the listing endpoint ------------------------------------


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _mk_user(email: str, org_name: str) -> tuple[str, int]:
    """Create an org + a real (viewer-role, non-admin) user in it; return
    (bearer token, org id) -- same shape as test_assessment_engine_api.py's
    identical helper.
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


async def test_the_listing_endpoint_returns_pipeline_runs() -> None:
    token, org_id = await _mk_user("list-a@ai-audit.test", "AI Audit List Org")
    async with session_scope() as s:
        run = await record_ai_run(
            s,
            action_key=EVALUATE_ACTION_KEY,
            entity_type="assessment_objective",
            entity_id="LIST-01a",
            organization_id=org_id,
            provider="anthropic",
            model="listing-fake-model",
            prompt="evaluate LIST-01a",
            output={"verdict": "satisfied"},
            citations=[],
        )
    assert run is not None
    run_id = run.id

    async with _client() as client:
        response = await client.get(
            "/api/ai-actions", params={"status": PIPELINE_RUN_STATUS}, headers=_auth(token)
        )
    assert response.status_code == 200
    body = response.json()
    ids = {r["id"] for r in body}
    assert run_id in ids, "the recorded pipeline run must appear in the listing"
    matched = next(r for r in body if r["id"] == run_id)
    assert matched["action_key"] == EVALUATE_ACTION_KEY
    assert matched["status"] == PIPELINE_RUN_STATUS


async def test_an_org_a_principal_cannot_list_org_b_runs() -> None:
    """Tenant scoping on the listing, asserted as an attack: org B's runs must
    not appear in org A's response body.
    """
    token_a, _org_a = await _mk_user("tenant-a@ai-audit.test", "AI Audit Tenant A")
    _token_b, org_b = await _mk_user("tenant-b@ai-audit.test", "AI Audit Tenant B")

    secret_entity_id = "victim-only-objective-ZZTOP"
    async with session_scope() as s:
        run_b = await record_ai_run(
            s,
            action_key=EVALUATE_ACTION_KEY,
            entity_type="assessment_objective",
            entity_id=secret_entity_id,
            organization_id=org_b,
            provider="anthropic",
            model="victim-only-model",
            prompt="evaluate the victim objective",
            output={"verdict": "satisfied"},
            citations=[],
        )
    assert run_b is not None
    run_b_id = run_b.id

    async with _client() as client:
        response = await client.get(
            "/api/ai-actions", params={"status": PIPELINE_RUN_STATUS}, headers=_auth(token_a)
        )
    assert response.status_code == 200
    body = response.json()
    ids = {r["id"] for r in body}
    assert run_b_id not in ids, "org A's response must not contain org B's run id"
    assert secret_entity_id not in response.text, (
        "org B's data must not leak into org A's response body at all"
    )
