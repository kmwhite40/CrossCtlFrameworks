"""Resolution: the platform's checks plus this tenant's declared ones."""

from __future__ import annotations

import itertools

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ccf.db import session_scope
from ccf.models import Organization
from ccf.models_packs import PackRule
from ccf.packs.service import install_pack
from ccf.posture.checks import ENDPOINT_REGISTRY, checks_for
from ccf.posture.providers import m365
from ccf.posture.resolve import resolve_checks

_SEQ = itertools.count()

FORM_A = {
    "key": "org.stale_accounts.60d",
    "kind": "posture",
    "definition": {
        "evaluator": m365.STALE_ACCOUNTS.key,
        "parameters": {"threshold_days": 60},
    },
}

FORM_B = {
    "key": "org.no_guest_accounts",
    "kind": "posture",
    "definition": {
        "provider": "msgraph",
        "resource_type": "entra_user",
        "endpoint": "/v1.0/users?$select=id,userPrincipalName,userType",
        "expected": "no guest account exists in the directory",
        "control_ids": ["AC-2", "AC-6"],
        "mode": "per_resource",
        "resource_id_field": "userPrincipalName",
        "predicate": {"op": "not_equals", "path": "userType", "value": "Guest"},
        "required_permissions": ["User.Read.All"],
    },
}


def _manifest(*rules: dict, pack_id: str = "posture-test") -> dict:
    return {
        "id": pack_id,
        "name": "Posture Test",
        "version": "1.0.0",
        "schema_version": "1",
        "controls": [{"control_id": "AC-2", "title": "Account Management"}],
        "rules": list(rules),
    }


async def _org(session) -> Organization:
    org = Organization(name=f"ResolveOrg-{next(_SEQ)}")
    session.add(org)
    await session.flush()
    return org


async def test_an_org_with_no_packs_gets_exactly_the_platform_checks() -> None:
    async with session_scope() as session:
        org = await _org(session)
        resolved = await resolve_checks(session, provider="msgraph", org_id=org.id)
        assert [r.check.key for r in resolved] == [c.key for c in checks_for("msgraph")]
        assert {r.source for r in resolved} == {"platform"}


async def test_every_platform_check_resolves_with_an_endpoint() -> None:
    """A check with no endpoint cannot be scanned, so it must not resolve silently.

    Asserting ``r.endpoint`` on the resolved output cannot fail: ``_platform()``
    already drops any check whose ``endpoint_for`` is falsy before it can reach
    the output, so the loop only ever sees checks that already have one. The
    real claim -- every registered msgraph check has an endpoint registered for
    it -- is checked directly against the registry instead.
    """
    assert set(ENDPOINT_REGISTRY["msgraph"]) >= {c.key for c in m365.CHECKS}


async def test_a_form_a_rule_resolves_with_its_parameters_applied() -> None:
    async with session_scope() as session:
        org = await _org(session)
        await install_pack(session, org_id=org.id, manifest=_manifest(FORM_A))
        resolved = await resolve_checks(session, provider="msgraph", org_id=org.id)
        declared = [r for r in resolved if r.check.key == FORM_A["key"]]
        assert len(declared) == 1
        r = declared[0]
        assert r.evaluator_key == m365.STALE_ACCOUNTS.key
        assert r.parameters == {"threshold_days": 60}
        assert "60 days" in r.check.expected
        assert r.source == "pack:posture-test"
        # Inherited from the platform check rather than restated in the manifest.
        assert r.check.control_ids == m365.STALE_ACCOUNTS.control_ids
        assert r.check.required_permissions == m365.STALE_ACCOUNTS.required_permissions
        assert r.endpoint == m365.ENDPOINTS[m365.STALE_ACCOUNTS.key]


async def test_a_form_b_rule_resolves_with_its_spec() -> None:
    async with session_scope() as session:
        org = await _org(session)
        await install_pack(session, org_id=org.id, manifest=_manifest(FORM_B))
        resolved = await resolve_checks(session, provider="msgraph", org_id=org.id)
        declared = [r for r in resolved if r.check.key == FORM_B["key"]]
        assert len(declared) == 1
        r = declared[0]
        assert r.evaluator_key is None
        assert r.spec is not None
        assert r.spec.mode == "per_resource"
        assert r.spec.predicate["path"] == "userType"
        assert r.check.control_ids == ("AC-2", "AC-6")
        assert r.check.required_permissions == ("User.Read.All",)
        assert r.endpoint == FORM_B["definition"]["endpoint"]


async def test_the_platform_checks_are_still_present_alongside_declared_ones() -> None:
    """Declared checks are additive; they never displace the platform's."""
    async with session_scope() as session:
        org = await _org(session)
        await install_pack(session, org_id=org.id, manifest=_manifest(FORM_A, FORM_B))
        resolved = await resolve_checks(session, provider="msgraph", org_id=org.id)
        keys = {r.check.key for r in resolved}
        for check in checks_for("msgraph"):
            assert check.key in keys
        assert FORM_A["key"] in keys
        assert FORM_B["key"] in keys


async def test_another_tenants_declared_check_never_appears() -> None:
    async with session_scope() as session:
        org_a = await _org(session)
        org_b = await _org(session)
        await install_pack(session, org_id=org_a.id, manifest=_manifest(FORM_B))
        for_b = await resolve_checks(session, provider="msgraph", org_id=org_b.id)
        assert FORM_B["key"] not in {r.check.key for r in for_b}
        for_a = await resolve_checks(session, provider="msgraph", org_id=org_a.id)
        assert FORM_B["key"] in {r.check.key for r in for_a}


async def test_a_rule_for_another_provider_is_excluded() -> None:
    async with session_scope() as session:
        org = await _org(session)
        other = {
            **FORM_B,
            "key": "org.aws_thing",
            "definition": {**FORM_B["definition"], "provider": "aws_govcloud"},
        }
        await install_pack(session, org_id=org.id, manifest=_manifest(other))
        resolved = await resolve_checks(session, provider="msgraph", org_id=org.id)
        keys = {r.check.key for r in resolved}
        assert "org.aws_thing" not in keys
        aws = await resolve_checks(session, provider="aws_govcloud", org_id=org.id)
        assert [r.check.key for r in aws] == ["org.aws_thing"]


async def test_a_non_posture_rule_is_ignored() -> None:
    async with session_scope() as session:
        org = await _org(session)
        rule = {"key": "some_metric", "kind": "assert", "definition": {"metric": "x"}}
        await install_pack(session, org_id=org.id, manifest=_manifest(rule))
        resolved = await resolve_checks(session, provider="msgraph", org_id=org.id)
        keys = {r.check.key for r in resolved}
        assert "some_metric" not in keys


async def test_a_non_posture_rule_that_looks_posture_shaped_is_still_excluded() -> None:
    """The kind filter has to do the work, not the provider filter.

    A rule of another kind can carry a definition that names a provider -- an
    'assert' rule is free-form JSON -- so excluding non-posture rules cannot be
    left to _targets() happening to reject them.
    """
    async with session_scope() as session:
        org = await _org(session)
        disguised = {
            "key": "org.disguised",
            "kind": "assert",
            "definition": dict(FORM_B["definition"]),
        }
        await install_pack(session, org_id=org.id, manifest=_manifest(disguised))
        resolved = await resolve_checks(session, provider="msgraph", org_id=org.id)
        assert "org.disguised" not in {r.check.key for r in resolved}


async def test_declared_checks_come_back_in_key_order() -> None:
    """Asserted absolutely, not by comparing two runs: two resolutions of the
    same rows agree whatever order the database returns them in, so only the
    order itself pins it."""
    async with session_scope() as session:
        org = await _org(session)
        zulu = {**FORM_B, "key": "org.zulu"}
        alpha = {**FORM_B, "key": "org.alpha"}
        mike = {**FORM_B, "key": "org.mike"}
        # Installed in a deliberately unsorted order.
        await install_pack(session, org_id=org.id, manifest=_manifest(zulu, mike, alpha))
        resolved = await resolve_checks(session, provider="msgraph", org_id=org.id)
        declared = [r.check.key for r in resolved if r.source.startswith("pack:")]
        assert declared == ["org.alpha", "org.mike", "org.zulu"]


async def test_an_unevaluable_stored_rule_is_skipped_not_returned() -> None:
    """Validation should have caught it, so a row reaching here predates
    validation. Dropping it is safer than scanning a tenant with a rule whose
    behaviour is undefined -- and it must not take the other checks down."""
    async with session_scope() as session:
        org = await _org(session)
        pack = await install_pack(session, org_id=org.id, manifest=_manifest(FORM_B))
        # Corrupt the stored rule the way a pre-validation row would be. Scoped
        # to this pack: tests share one database and session_scope commits, so
        # matching on rule_key alone would find earlier tests' rows too.
        rule = (
            await session.execute(
                select(PackRule).where(
                    PackRule.pack_id == pack.id, PackRule.rule_key == FORM_B["key"]
                )
            )
        ).scalar_one()
        rule.definition = {"provider": "msgraph", "predicate": {"op": "regex", "path": "x"}}
        await session.flush()

        resolved = await resolve_checks(session, provider="msgraph", org_id=org.id)
        keys = {r.check.key for r in resolved}
        assert FORM_B["key"] not in keys
        for check in checks_for("msgraph"):
            assert check.key in keys, "a bad rule must not discard the platform checks"


async def test_resolution_is_deterministically_ordered() -> None:
    """Two resolutions must agree, or scan output churns between runs."""
    async with session_scope() as session:
        org = await _org(session)
        await install_pack(session, org_id=org.id, manifest=_manifest(FORM_A, FORM_B))
        one = await resolve_checks(session, provider="msgraph", org_id=org.id)
        two = await resolve_checks(session, provider="msgraph", org_id=org.id)
        first = [r.check.key for r in one]
        second = [r.check.key for r in two]
        assert first == second


# ── endpoint re-validation at resolve (CRITICAL 1, PR #13 review) ────────────
# packs.catalog validates a hostile endpoint at install; these cover a row
# that predates that validation (or reached the database by any other path)
# by writing the hostile value directly, the same technique
# test_an_unevaluable_stored_rule_is_skipped_not_returned already uses.


async def _install_then_corrupt_endpoint(session: AsyncSession, hostile_endpoint: str) -> None:
    org = await _org(session)
    pack = await install_pack(session, org_id=org.id, manifest=_manifest(FORM_B))
    rule = (
        await session.execute(
            select(PackRule).where(
                PackRule.pack_id == pack.id, PackRule.rule_key == FORM_B["key"]
            )
        )
    ).scalar_one()
    rule.definition = {**rule.definition, "endpoint": hostile_endpoint}
    await session.flush()

    resolved = await resolve_checks(session, provider="msgraph", org_id=org.id)
    keys = {r.check.key for r in resolved}
    assert FORM_B["key"] not in keys, (
        f"a rule with hostile endpoint {hostile_endpoint!r} must not resolve"
    )
    for check in checks_for("msgraph"):
        assert check.key in keys, "a bad rule must not discard the platform checks"


async def test_a_host_suffix_trick_endpoint_stored_directly_is_skipped_at_resolve() -> None:
    async with session_scope() as session:
        await _install_then_corrupt_endpoint(session, ".attacker.example/v1.0/users")


async def test_a_userinfo_trick_endpoint_stored_directly_is_skipped_at_resolve() -> None:
    async with session_scope() as session:
        await _install_then_corrupt_endpoint(session, "@attacker.example/x")


# ── mistyped provider: skipped and logged, not silently never-run ───────────


async def test_a_mistyped_provider_stored_directly_is_skipped_at_resolve() -> None:
    async with session_scope() as session:
        org = await _org(session)
        pack = await install_pack(session, org_id=org.id, manifest=_manifest(FORM_B))
        rule = (
            await session.execute(
                select(PackRule).where(
                    PackRule.pack_id == pack.id, PackRule.rule_key == FORM_B["key"]
                )
            )
        ).scalar_one()
        rule.definition = {**rule.definition, "provider": "msgrap"}  # typo of "msgraph"
        await session.flush()

        resolved = await resolve_checks(session, provider="msgraph", org_id=org.id)
        keys = {r.check.key for r in resolved}
        assert FORM_B["key"] not in keys
        for check in checks_for("msgraph"):
            assert check.key in keys


# ── control ids are stored canonicalized (resolve.py:107,129) ───────────────


async def test_form_b_control_ids_resolve_to_their_canonical_form() -> None:
    async with session_scope() as session:
        org = await _org(session)
        non_canonical = {
            **FORM_B,
            "definition": {**FORM_B["definition"], "control_ids": ["ac-02", "AC-6 (1)"]},
        }
        await install_pack(session, org_id=org.id, manifest=_manifest(non_canonical))
        resolved = await resolve_checks(session, provider="msgraph", org_id=org.id)
        r = next(r for r in resolved if r.check.key == FORM_B["key"])
        assert r.check.control_ids == ("AC-2", "AC-6(1)")


async def test_form_a_control_ids_resolve_to_their_canonical_form() -> None:
    async with session_scope() as session:
        org = await _org(session)
        non_canonical = {
            **FORM_A,
            "definition": {**FORM_A["definition"], "control_ids": ["ac-02"]},
        }
        await install_pack(session, org_id=org.id, manifest=_manifest(non_canonical))
        resolved = await resolve_checks(session, provider="msgraph", org_id=org.id)
        r = next(r for r in resolved if r.check.key == FORM_A["key"])
        assert r.check.control_ids == ("AC-2",)
