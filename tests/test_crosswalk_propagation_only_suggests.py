"""Setting a control's implementation status never writes its crosswalk peers.

``reactions.propagate_implementation`` treated any two controls sharing one
``FrameworkMapping`` value as equivalent. On every status change it created
rows for missing peers with ``responsibility="inherited"`` and overwrote the
status a person had set on existing ones. So one PATCH could mark up to 60
controls implemented, claim each was inherited from a provider, and raise the
coverage percentage, with nobody having assessed any of them.

A shared mapping value means the controls are related, not that one satisfies
the other. Propagation now returns the peers as suggestions and writes nothing.
Cross-framework reach belongs to the capability layer, which traverses the
crosswalk at read time instead of copying statuses.
"""

from __future__ import annotations

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from ccf.api.main import create_app
from ccf.config import get_settings
from ccf.db import session_scope
from ccf.models import Control, ControlImplementation, FrameworkMapping, Organization, System

pytestmark = pytest.mark.usefixtures("fresh_engine")


@pytest.fixture(scope="module", autouse=True)
def _migrate() -> None:
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", str(get_settings().database_url_sync))
    command.upgrade(cfg, "head")


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


async def _fixture() -> tuple[int, int, int, int]:
    """A system, a source control, a peer a person set, and a peer nobody touched."""
    async with session_scope() as s:
        org = Organization(name="CrosswalkSuggestOrg")
        s.add(org)
        await s.flush()
        sysm = System(organization_id=org.id, name="CrosswalkSuggest system")
        s.add(sysm)
        source, set_peer, blank_peer = (Control(identifier=f"XWALK-SUGGEST-{i}") for i in range(3))
        s.add_all([source, set_peer, blank_peer])
        await s.flush()
        for c in (source, set_peer, blank_peer):
            s.add(FrameworkMapping(control_id=c.id, column_key="xwalk_suggest", value="QX.9.9"))
        s.add(
            ControlImplementation(
                system_id=sysm.id,
                control_id=set_peer.id,
                status="not_implemented",
                responsibility="customer",
            )
        )
        await s.flush()
        return sysm.id, source.id, set_peer.id, blank_peer.id


@pytest.mark.asyncio
async def test_status_change_writes_no_peer_and_returns_suggestions() -> None:
    sys_id, source_id, set_peer_id, blank_peer_id = await _fixture()
    async with _client() as c:
        r = await c.patch(
            f"/api/systems/{sys_id}/implementations/{source_id}",
            json={"status": "implemented"},
        )
        assert r.status_code == 200, r.text
        propagation = r.json()["propagation"]

    assert propagation["updated"] == 0
    assert sorted(propagation["suggested"]) == sorted([set_peer_id, blank_peer_id])

    async with session_scope() as s:
        rows = {
            i.control_id: i
            for i in (
                await s.execute(
                    select(ControlImplementation).where(ControlImplementation.system_id == sys_id)
                )
            ).scalars()
        }
    # The person's assessment of the peer stands.
    assert rows[set_peer_id].status == "not_implemented"
    assert rows[set_peer_id].responsibility == "customer"
    # Nobody claimed the untouched peer, so no row asserts anything about it.
    assert blank_peer_id not in rows
