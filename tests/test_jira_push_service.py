"""Pushing a POA&M: tenancy, link bookkeeping, and what a failure must not write.

Every tenancy assertion runs on an unscoped ``session_scope()`` session -- RLS
is permissive when ``ccf.current_tenant()`` is NULL, so a refusal observed
there is provably the service's own predicate and not the row being
unreachable. A POA&M carries no ``organization_id``: it reaches its tenant
through ``systems``, which is exactly the join a missing check would skip.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from ccf.db import session_scope
from ccf.integrations.service import (
    ENTITY_POAM,
    existing_link,
    poam_content,
    push_poam,
)
from ccf.integrations.types import (
    IntegrationNotConfigured,
    IntegrationRefused,
    IssueContent,
    PushResult,
)
from ccf.models import POAM, Organization, System
from ccf.models_grc import ExternalIssueLink

pytestmark = pytest.mark.usefixtures("fresh_engine")


def _tag() -> str:
    return uuid.uuid4().hex[:8]


class _RecordingTracker:
    """A tracker that answers, and remembers what it was asked."""

    provider = "jira"
    credential_type = "jira"

    def __init__(self, *, fail: Exception | None = None) -> None:
        self.created: list[IssueContent] = []
        self.updated: list[tuple[str, IssueContent]] = []
        self._fail = fail

    async def create(self, content: IssueContent) -> PushResult:
        if self._fail:
            raise self._fail
        self.created.append(content)
        return PushResult(
            external_id="SEC-7", url="https://acme.atlassian.net/browse/SEC-7", created=True
        )

    async def update(self, external_id: str, content: IssueContent) -> PushResult:
        if self._fail:
            raise self._fail
        self.updated.append((external_id, content))
        return PushResult(
            external_id=external_id,
            url=f"https://acme.atlassian.net/browse/{external_id}",
            created=False,
        )


async def _org_with_poam(name: str, **poam_fields) -> tuple[int, int]:
    async with session_scope() as s:
        org = Organization(name=name)
        s.add(org)
        await s.flush()
        system = System(organization_id=org.id, name=f"{name} System")
        s.add(system)
        await s.flush()
        poam = POAM(
            system_id=system.id,
            title=poam_fields.pop("title", "Weak spot"),
            severity=poam_fields.pop("severity", "high"),
            status=poam_fields.pop("status", "open"),
            **poam_fields,
        )
        s.add(poam)
        await s.flush()
        return org.id, poam.id


# --- tenancy -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_another_organization_cannot_push_this_organizations_poam() -> None:
    """The owning org is asserted first, so a check that refused everything fails too."""
    tag = _tag()
    owner_id, poam_id = await _org_with_poam(f"Jira Owner {tag}")
    async with session_scope() as s:
        outsider = Organization(name=f"Jira Outsider {tag}")
        s.add(outsider)
        await s.flush()
        outsider_id = outsider.id

    tracker = _RecordingTracker()
    async with session_scope() as s:
        result = await push_poam(s, owner_id, poam_id, tracker=tracker)
        assert result.external_id == "SEC-7"

    async with session_scope() as s:
        with pytest.raises(IntegrationNotConfigured):
            await push_poam(s, outsider_id, poam_id, tracker=_RecordingTracker())

    # Nothing was filed on the outsider's behalf.
    async with session_scope() as s:
        rows = (
            await s.execute(
                select(ExternalIssueLink).where(
                    ExternalIssueLink.organization_id == outsider_id
                )
            )
        ).scalars().all()
        assert rows == []


@pytest.mark.asyncio
async def test_an_unscoped_principal_cannot_push_at_all() -> None:
    """`org_id is None` is the system principal -- global read, never a tenant write.

    Without this it would resolve no credential and, worse, write a link row
    with a null organization.

    The message is asserted, not merely the exception type: `_owned_poam`
    raises the same type for a POA&M in another tenant, so a test that checked
    only the type would pass with this guard deleted -- the refusal would just
    come from the org lookup failing to match instead. Removing the guard has
    to fail here, and with the type alone it did not.
    """
    tag = _tag()
    _owner, poam_id = await _org_with_poam(f"Jira Unscoped {tag}")
    async with session_scope() as s:
        with pytest.raises(IntegrationNotConfigured) as caught:
            await push_poam(s, None, poam_id, tracker=_RecordingTracker())
    assert "requires an organization context" in str(caught.value)


# --- link bookkeeping --------------------------------------------------------


@pytest.mark.asyncio
async def test_pushing_twice_updates_the_ticket_instead_of_filing_a_second() -> None:
    tag = _tag()
    org_id, poam_id = await _org_with_poam(f"Jira Twice {tag}")
    tracker = _RecordingTracker()

    async with session_scope() as s:
        first = await push_poam(s, org_id, poam_id, tracker=tracker)
    async with session_scope() as s:
        second = await push_poam(s, org_id, poam_id, tracker=tracker)

    assert first.created is True
    assert second.created is False
    assert len(tracker.created) == 1
    assert tracker.updated == [("SEC-7", tracker.updated[0][1])]

    async with session_scope() as s:
        rows = (
            await s.execute(
                select(ExternalIssueLink).where(ExternalIssueLink.entity_id == poam_id)
            )
        ).scalars().all()
        assert len(rows) == 1
        assert rows[0].external_id == "SEC-7"
        assert rows[0].last_status == "ok"
        assert rows[0].last_error is None
        assert rows[0].last_pushed_at is not None


@pytest.mark.asyncio
async def test_a_failed_first_push_records_no_link_at_all() -> None:
    """A link row written before the call would claim a ticket that never existed.

    The next push would then take the update path against a key Jira has never
    heard of, and the POA&M would show a link that goes nowhere.
    """
    tag = _tag()
    org_id, poam_id = await _org_with_poam(f"Jira Fail {tag}")
    tracker = _RecordingTracker(fail=IntegrationRefused("Jira returned 400", status=400))

    async with session_scope() as s:
        with pytest.raises(IntegrationRefused):
            await push_poam(s, org_id, poam_id, tracker=tracker)

    async with session_scope() as s:
        assert await existing_link(s, org_id, ENTITY_POAM, poam_id, "jira") is None


@pytest.mark.asyncio
async def test_a_failed_later_push_keeps_the_link_and_records_why() -> None:
    """The ticket still exists, so the link must survive -- carrying the reason."""
    tag = _tag()
    org_id, poam_id = await _org_with_poam(f"Jira Later {tag}")

    async with session_scope() as s:
        await push_poam(s, org_id, poam_id, tracker=_RecordingTracker())

    failing = _RecordingTracker(
        fail=IntegrationRefused("Jira returned 400 -- summary: too long", status=400)
    )
    async with session_scope() as s:
        with pytest.raises(IntegrationRefused):
            await push_poam(s, org_id, poam_id, tracker=failing)

    async with session_scope() as s:
        link = await existing_link(s, org_id, ENTITY_POAM, poam_id, "jira")
        assert link is not None
        assert link.external_id == "SEC-7", "the existing ticket must not be forgotten"
        assert link.last_status == "failed"
        assert "summary: too long" in (link.last_error or "")


# --- mapping -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_unset_field_is_omitted_rather_than_rendered_as_none() -> None:
    """"Remediation plan: None" reads as a recorded decision. Omission does not."""
    tag = _tag()
    org_id, poam_id = await _org_with_poam(
        f"Jira Map {tag}", title="No plan yet", weakness="Tokens are unbounded"
    )
    async with session_scope() as s:
        poam = (await s.execute(select(POAM).where(POAM.id == poam_id))).scalars().one()
        content = poam_content(poam)

    assert "None" not in content.body
    assert "Remediation plan" not in content.body
    assert "Weakness" in content.body


@pytest.mark.asyncio
async def test_the_ticket_says_concord_still_owns_the_compliance_status() -> None:
    """Push-only is a boundary users must see, not just one the code keeps.

    Someone will close the Jira issue and believe the POA&M closed with it.
    """
    tag = _tag()
    org_id, poam_id = await _org_with_poam(f"Jira Truth {tag}")
    async with session_scope() as s:
        poam = (await s.execute(select(POAM).where(POAM.id == poam_id))).scalars().one()
        body = poam_content(poam).body
    assert "closing this ticket does not close the poa&m" in body.lower()


@pytest.mark.asyncio
async def test_the_link_lookup_refuses_another_tenants_row_on_its_own() -> None:
    """Pinned on an unscoped session, where RLS is permissive.

    Over HTTP the session is tenant-bound and the policy refuses the row
    whether or not the query carries an organization predicate -- so the page
    test passes either way and proves the database, not this code. Run with
    ``ccf.current_tenant()`` NULL, only the predicate is left to do the work.

    The owning org is asserted first, so a lookup that returned nothing at all
    would fail here too.
    """
    from ccf.integrations.service import links_for_entities

    tag = _tag()
    mine_id, mine_poam = await _org_with_poam(f"Jira Lookup Mine {tag}")
    theirs_id, theirs_poam = await _org_with_poam(f"Jira Lookup Theirs {tag}")

    async with session_scope() as s:
        for org_id, poam_id, key in (
            (mine_id, mine_poam, "SEC-1"),
            (theirs_id, theirs_poam, "OTHER-1"),
        ):
            s.add(
                ExternalIssueLink(
                    organization_id=org_id,
                    entity_type=ENTITY_POAM,
                    entity_id=poam_id,
                    provider="jira",
                    external_id=key,
                    external_url=f"https://acme.atlassian.net/browse/{key}",
                )
            )

    both = [mine_poam, theirs_poam]
    async with session_scope() as s:
        mine = await links_for_entities(s, mine_id, ENTITY_POAM, both, "jira")

    assert set(mine) == {mine_poam}, "another tenant's link came back"
    assert mine[mine_poam].external_id == "SEC-1"


@pytest.mark.asyncio
async def test_the_link_lookup_issues_no_query_for_an_empty_page() -> None:
    """`IN ()` is not valid SQL everywhere and is never worth emitting."""
    from ccf.integrations.service import links_for_entities

    async with session_scope() as s:
        assert await links_for_entities(s, 1, ENTITY_POAM, [], "jira") == {}
