"""AWS Organizations -> a system's boundary inventory.

The organization becomes one ``SystemComponent`` (type ``service``) and each
account an ``InventoryItem`` under it, written through ``ccf.boundary.service``
-- the seam that module was left with "so a future connector mapper can call
the same functions". Same discipline as ``connectors.puppetdb.sync_inventory``:
**additive and idempotent, never deletes** (an account missing from one read
may be truncation or a permission gap, not a closure -- its ``last_seen_at``
goes cold instead), machine-observed facts refresh, a human's description and
extra ``props`` keys survive.

Which system the accounts belong to is an operator's decision recorded on the
connector (``ConnectorConfig.config["system_id"]``), never inferred: the
binding PuppetDB's sync was left unwired for lack of.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..boundary import service as boundary
from ..logging import get_logger
from ..models import InventoryItem, SystemComponent
from .aws import AwsGovCloudConnector

log = get_logger(__name__)

SOURCE = "aws_govcloud"


async def sync_organization_inventory(
    session: AsyncSession, connector: AwsGovCloudConnector, *, system_id: int, org_id: int
) -> dict[str, Any]:
    """Reconcile the AWS organization into ``system_id``'s inventory."""
    result: dict[str, Any] = {
        "seen": 0, "created": 0, "updated": 0, "indeterminate": [], "truncated": False,
    }
    if not connector.is_configured():
        result["indeterminate"].append("connector not configured")
        return result
    inv = await asyncio.to_thread(connector.organization_inventory)
    result["indeterminate"] = list(inv["indeterminate"])
    result["truncated"] = bool(inv["truncated"])
    org = inv["organization"]
    if org is None:
        # Not an empty organization: one this identity cannot read. Writing
        # nothing is the only honest answer.
        return result
    now = datetime.now(UTC)

    component = None
    for c in (
        await session.execute(
            select(SystemComponent).where(
                SystemComponent.system_id == system_id, SystemComponent.source == SOURCE
            )
        )
    ).scalars():
        if (c.props or {}).get("aws_organization_id") == org["id"]:
            component = c
            break
    org_props = {
        "aws_organization_id": org["id"],
        "management_account_id": org["management_account_id"],
        "feature_set": org["feature_set"],
        "partition": org["partition"],
    }
    if component is None:
        component = await boundary.create_component(
            session, system_id=system_id, org_id=org_id,
            data={"type": "service", "title": f"AWS Organization {org['id']}",
                  "source": SOURCE, "props": org_props, "last_seen_at": now},
        )
    else:
        await boundary.update_component(
            session, component_id=component.id,
            data={"props": {**(component.props or {}), **org_props}, "last_seen_at": now},
        )

    existing = {
        row.asset_id: row
        for row in (
            await session.execute(
                select(InventoryItem).where(
                    InventoryItem.system_id == system_id, InventoryItem.source == SOURCE
                )
            )
        ).scalars()
    }
    for acct in inv["accounts"]:
        account_id = str(acct.get("id") or "")
        if not account_id:
            continue
        result["seen"] += 1
        props = {
            "account_id": account_id,
            "name": acct.get("name"),
            "status": acct.get("status"),
            "ou_path": acct.get("ou_path"),
            "parent_id": acct.get("parent_id"),
            "joined_at": acct.get("joined_at"),
            "partition": acct.get("partition"),
            "email_domain": acct.get("email_domain"),
            # Flagged, not hidden: an account outside the organization's
            # partition is an anomaly someone should look at.
            "partition_mismatch": bool(acct.get("partition"))
            and acct.get("partition") != org["partition"],
        }
        row = existing.get(account_id)
        if row is None:
            await boundary.create_inventory_item(
                session, system_id=system_id, org_id=org_id,
                data={"asset_id": account_id, "asset_type": "other", "source": SOURCE,
                      "component_id": component.id, "props": props, "last_seen_at": now,
                      "description": f"AWS account {acct.get('name') or account_id}"},
            )
            result["created"] += 1
        else:
            await boundary.update_inventory_item(
                session, item_id=row.id,
                data={"component_id": component.id,
                      "props": {**(row.props or {}), **props}, "last_seen_at": now},
            )
            result["updated"] += 1
    log.info("connector.aws.inventory_synced", system_id=system_id,
             seen=result["seen"], created=result["created"], updated=result["updated"])
    return result
