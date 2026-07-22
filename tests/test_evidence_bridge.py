"""Bridge between the legacy control-linked evidence store and the versioned
evidence repository (DATA-09): ``evidence_objects.implementation_id`` ->
``control_implementations.id``.

Asserts a control implementation can be joined all the way through to a
confidence score via the new FK, and that an unlinked evidence object
resolves to NULL rather than fabricating a linkage.
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select

from ccf.config import get_settings
from ccf.db import session_scope
from ccf.evidence import confidence, service
from ccf.models import Control, ControlImplementation, Organization, System
from ccf.models_evidence import EvidenceObject
from ccf.models_evidence_conf import EvidenceConfidenceScore

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


async def _make_implementation(session, name: str) -> ControlImplementation:
    org = Organization(name=name)
    session.add(org)
    await session.flush()
    sysm = System(organization_id=org.id, name=f"{name} system")
    session.add(sysm)
    await session.flush()
    ctrl = Control(identifier=f"AC-{name}", control_name="Test control")
    session.add(ctrl)
    await session.flush()
    impl = ControlImplementation(system_id=sysm.id, control_id=ctrl.id, status="implemented")
    session.add(impl)
    await session.flush()
    return impl


@pytest.mark.asyncio
async def test_linked_evidence_object_joins_to_confidence_score() -> None:
    async with session_scope() as s:
        impl = await _make_implementation(s, "Bridge")
        obj = await service.create_object(
            s,
            org_id=None,
            title="access review export",
            control_id="AC-2",
            implementation_id=impl.id,
            source_type="connector",
        )
        await service.add_version(s, obj, data=b"evidence-bytes", filename="review.csv")
        score_row = await confidence.score_object(s, obj)
        await s.flush()

        # The join a control-authorization view would run: control implementation
        # -> its linked evidence object -> that object's confidence score.
        joined = (
            await s.execute(
                select(ControlImplementation, EvidenceObject, EvidenceConfidenceScore)
                .join(
                    EvidenceObject,
                    EvidenceObject.implementation_id == ControlImplementation.id,
                )
                .join(
                    EvidenceConfidenceScore,
                    EvidenceConfidenceScore.evidence_object_id == EvidenceObject.id,
                )
                .where(ControlImplementation.id == impl.id)
            )
        ).one()
        joined_impl, joined_obj, joined_score = joined
        assert joined_impl.id == impl.id
        assert joined_obj.id == obj.id
        assert joined_score.id == score_row.id
        assert joined_score.score > 0


@pytest.mark.asyncio
async def test_unlinked_evidence_object_has_null_implementation_id() -> None:
    async with session_scope() as s:
        obj = await service.create_object(
            s,
            org_id=None,
            title="ad-hoc screenshot",
            control_id="AC-2",  # free-text tag only — no real implementation link
            source_type="screenshot",
        )
        await s.flush()

        refreshed = (
            await s.execute(select(EvidenceObject).where(EvidenceObject.id == obj.id))
        ).scalar_one()
        assert refreshed.implementation_id is None
