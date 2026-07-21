"""Integration test for the SSP completeness route's evidence gate.

``ssp.completeness.assess`` gates "Implemented"/"Partially Implemented"
controls on linked evidence via ``_has_linked_evidence``, which reads
``entry["evidence_ref"]`` / ``entry["control_implementation"]["evidence"]``.
But the production row builder (``ssp.seed.entry_to_dict``) never emits those
keys, and the completeness route (``api/routes/ssp.py``) never populated them
either — so in production every "Implemented" control was unconditionally
flagged "implemented without evidence" and no SSP could ever be ready.

This test exercises the REAL route end to end — a real ``System``, a real
``ControlImplementation`` + linked ``Evidence`` row, a real SSP project/entry —
with no injected ``evidence_ref``/``control_implementation`` keys anywhere in
the test. It proves the production wiring, not just the pure ``assess()``
function (already covered by ``tests/test_ssp_completeness.py``).
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Control, ControlImplementation, Evidence, Organization, System

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


_FULL_META = {
    "system_type": "Cloud",
    "fips199": {"overall": "moderate"},
    "authorization_boundary": "the tenant",
    "roles": {
        "system_owner": {"name": "A"},
        "isso": {"name": "B"},
        "authorizing_official": {"name": "C"},
    },
}

_WITH_EVIDENCE = "AC.L2-3.1.1"
_WITHOUT_EVIDENCE = "AC.L2-3.1.2"


async def _make_system_with_evidence(name: str) -> int:
    """A real System with a real ControlImplementation + linked Evidence row
    for ``_WITH_EVIDENCE``, and a bare (no-evidence) ControlImplementation for
    ``_WITHOUT_EVIDENCE`` — the exact real join the completeness route must
    walk: SSPControlEntry.control_id -> Control.identifier -> ControlImplementation
    (by system) -> Evidence."""
    async with session_scope() as s:
        org = Organization(name=f"{name} Org")
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name=name)
        s.add(sysm)
        await s.flush()

        ctrl_with = Control(identifier=_WITH_EVIDENCE, control_name="With evidence")
        ctrl_without = Control(identifier=_WITHOUT_EVIDENCE, control_name="Without evidence")
        s.add_all([ctrl_with, ctrl_without])
        await s.flush()

        impl_with = ControlImplementation(
            system_id=sysm.id, control_id=ctrl_with.id, status="implemented"
        )
        impl_without = ControlImplementation(
            system_id=sysm.id, control_id=ctrl_without.id, status="implemented"
        )
        s.add_all([impl_with, impl_without])
        await s.flush()

        s.add(
            Evidence(
                implementation_id=impl_with.id,
                kind="config_export",
                title="MFA config export",
            )
        )
        await s.flush()
        return sysm.id


@pytest.mark.asyncio
async def test_completeness_route_reflects_real_evidence_linkage() -> None:
    async with _client() as c:
        await c.post("/api/scoring/seed")
        sys_id = await _make_system_with_evidence("EvidenceGateSys")

        pid = (
            await c.post(
                "/api/ssp/projects",
                json={
                    "customer_name": "EvidenceGate Co",
                    "system_id": sys_id,
                    "system_name": "EvidenceGateSys",
                },
            )
        ).json()["id"]

        meta_resp = await c.put(
            f"/api/ssp/projects/{pid}/metadata",
            json={"metadata_json": _FULL_META, "autofill": False},
        )
        assert meta_resp.status_code == 200, meta_resp.text

        for control_id in (_WITH_EVIDENCE, _WITHOUT_EVIDENCE):
            upd = await c.put(
                f"/api/ssp/projects/{pid}/entries/{control_id}",
                json={
                    "responsible_role": "System Owner",
                    "implementation_status": ["Implemented"],
                    "control_origination": ["Inherited"],
                    "part_narratives": [
                        {"text": "The organization enforces MFA for all remote access."}
                    ],
                },
            )
            assert upd.status_code == 200, upd.text

        report = (await c.get(f"/api/ssp/projects/{pid}/completeness")).json()
        gap_map = {g["control_id"]: g["gaps"] for g in report["control_gaps"]}

        # The control whose ControlImplementation has linked Evidence must NOT
        # be flagged for missing evidence.
        assert "implemented without evidence" not in gap_map.get(_WITH_EVIDENCE, [])
        # The control with a ControlImplementation but no Evidence must be.
        assert "implemented without evidence" in gap_map.get(_WITHOUT_EVIDENCE, [])
