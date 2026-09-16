"""Which checks run for one tenant: the platform's, plus the ones it declared.

A scan needs more than a :class:`PostureCheck`: it needs the collection to
read and the means of judging it. :class:`ResolvedCheck` carries all three, so
a connector iterates one uniform sequence whether a check came from the
platform registry or a pack.

Tenant scoping is inherited rather than reinvented -- declared checks come from
``CompliancePack`` rows, which are already ``organization_id``-scoped with RLS
behind them, so a resolution for org A cannot surface org B's rules even if the
filter here were wrong.

Declared checks are strictly **additive**: they never displace or override a
platform check. ``packs.catalog`` refuses a colliding key at install, so by the
time a rule reaches this module the two key spaces are disjoint.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..catalog.canonical import canonicalize
from ..logging import get_logger
from ..models_packs import CompliancePack, PackRule
from .checks import checks_for, endpoint_for, known_providers
from .declared import DeclaredSpec, validate_predicate
from .parameters import parameterize
from .types import PostureCheck

log = get_logger(__name__)

#: A Form B endpoint must be a same-host, relative Graph path. This is a
#: security control, not a format nicety: ``connectors.msgraph`` builds the
#: request URL from this value, and it carries the org's Graph bearer token.
#: An endpoint that is not a plain relative path can redirect that token to
#: an attacker-controlled host --
#: ``".attacker.example/v1.0/users"`` exploits the missing trailing slash on
#: ``graph_base_url`` under naive string concatenation, and
#: ``"@attacker.example/x"`` exploits URL userinfo syntax the same way.
#: Checked here (at resolve, so a row written before this existed -- or
#: written by any path that bypassed install validation -- cannot be used),
#: again in ``packs.catalog`` (at install, so the author sees the error
#: immediately), and again in ``connectors.msgraph`` (at the request
#: boundary, which must hold even if both of the above are bypassed).
_ENDPOINT_PREFIXES = ("/v1.0/", "/beta/")
_ENDPOINT_MAX_LEN = 512


def validate_endpoint(raw: Any) -> list[str]:
    """Errors in a declared (Form B) endpoint; empty means it is safe to use."""
    if not isinstance(raw, str) or not raw:
        return ["'endpoint' must be a non-empty string"]
    if len(raw) > _ENDPOINT_MAX_LEN:
        return [f"'endpoint' exceeds {_ENDPOINT_MAX_LEN} characters"]
    if not raw.startswith(_ENDPOINT_PREFIXES):
        return ["'endpoint' must start with '/v1.0/' or '/beta/'"]
    if "//" in raw or "@" in raw or "\\" in raw or ".." in raw:
        return [
            "'endpoint' must be a plain relative Graph path "
            "(no '//', '@', '\\', or '..')"
        ]
    return []


def _canonical_control_ids(raw: Any) -> tuple[str, ...]:
    """Control ids in their canonical 800-53 form, dropping anything that isn't.

    Storing the id exactly as an author typed it (``"ac-02"``, ``"AC-2 (1)"``)
    orphans findings from the ``CapabilityControl``/``SSPControlEntry`` key
    space, which only ever holds the canonical spelling. ``packs.catalog``
    already refuses a non-canonical id at install, so silently dropping one
    here only matters for a row that predates that validation -- the same
    defense-in-depth posture as :func:`validate_endpoint`.
    """
    out: list[str] = []
    for v in _tuple_of_str(raw):
        c = canonicalize(v)
        if c is not None:
            out.append(c.value)
    return tuple(out)


class ResolutionError(ValueError):
    """A stored rule that cannot be turned into an executable check."""


@dataclass(frozen=True)
class ResolvedCheck:
    """One executable check: what to assess, where to read it, how to judge it.

    Exactly one of ``evaluator_key`` (Form A -- a platform evaluator, possibly
    parameterized) and ``spec`` (Form B -- a declarative predicate) is set.
    ``source`` records where the expectation came from (``"platform"`` or
    ``"pack:<key>"``) so a finding can say why it was assessed at all.
    """

    check: PostureCheck
    endpoint: str
    source: str
    evaluator_key: str | None = None
    parameters: dict[str, Any] | None = None
    spec: DeclaredSpec | None = None


def _platform(provider: str) -> list[ResolvedCheck]:
    out: list[ResolvedCheck] = []
    for check in checks_for(provider):
        endpoint = endpoint_for(provider, check.key)
        if not endpoint:
            # Registered as a check but with nowhere to read from: scanning it
            # would fetch the provider root or crash, so it is dropped loudly
            # rather than resolved into a scan.
            log.warning("posture.resolve.no_endpoint", provider=provider, check=check.key)
            continue
        out.append(
            ResolvedCheck(
                check=check,
                endpoint=endpoint,
                source="platform",
                evaluator_key=check.key,
                parameters=None,
            )
        )
    return out


def _tuple_of_str(raw: Any) -> tuple[str, ...]:
    if not isinstance(raw, list):
        return ()
    return tuple(str(v) for v in raw if isinstance(v, str) and v)


def _build_form_a(rule_key: str, definition: dict[str, Any], provider: str) -> ResolvedCheck:
    evaluator_key = str(definition.get("evaluator") or "")
    platform = next((c for c in checks_for(provider) if c.key == evaluator_key), None)
    if platform is None:
        raise ResolutionError(f"unknown evaluator {evaluator_key!r} for provider {provider!r}")
    endpoint = endpoint_for(provider, evaluator_key)
    if not endpoint:
        raise ResolutionError(f"no endpoint registered for {evaluator_key!r}")
    parameters = definition.get("parameters") or {}
    if not isinstance(parameters, dict):
        raise ResolutionError("'parameters' must be an object")
    # parameterize() re-renders the expected text and refuses anything
    # validation would have refused, so a pre-validation row cannot apply an
    # unchecked parameter here.
    check = parameterize(platform, parameters)
    # The declared check is its own check, under the pack's key, inheriting
    # everything it did not restate -- control ids and permissions included,
    # since a parameterized threshold does not change what it evidences.
    overrides: dict[str, Any] = {"key": rule_key}
    if definition.get("title"):
        overrides["title"] = str(definition["title"])
    control_ids = _canonical_control_ids(definition.get("control_ids"))
    if control_ids:
        overrides["control_ids"] = control_ids
    if definition.get("capability_key"):
        overrides["capability_key"] = str(definition["capability_key"])
    return ResolvedCheck(
        check=replace(check, **overrides),
        endpoint=endpoint,
        source="",  # filled in by the caller, which knows the pack key
        evaluator_key=evaluator_key,
        parameters=dict(parameters),
    )


def _build_form_b(rule_key: str, definition: dict[str, Any], provider: str) -> ResolvedCheck:
    endpoint = definition.get("endpoint")
    endpoint_problems = validate_endpoint(endpoint)
    if endpoint_problems:
        raise ResolutionError("; ".join(endpoint_problems))
    assert isinstance(endpoint, str)  # validate_endpoint() guarantees this
    predicate = definition.get("predicate")
    problems = validate_predicate(predicate)
    if problems:
        raise ResolutionError("; ".join(problems))
    control_ids = _canonical_control_ids(definition.get("control_ids"))
    if not control_ids:
        raise ResolutionError("a declarative check requires 'control_ids'")
    resource_type = str(definition.get("resource_type") or "")
    expected = str(definition.get("expected") or "")
    if not resource_type or not expected:
        raise ResolutionError("a declarative check requires 'resource_type' and 'expected'")
    mode = str(definition.get("mode") or "per_resource")
    spec = DeclaredSpec(
        mode=mode,
        resource_type=resource_type,
        predicate=dict(predicate) if isinstance(predicate, dict) else {},
        expected=expected,
        resource_id_field=(
            str(definition["resource_id_field"])
            if definition.get("resource_id_field")
            else None
        ),
        pass_observed=(
            str(definition["pass_observed"]) if definition.get("pass_observed") else None
        ),
        fail_observed=(
            str(definition["fail_observed"]) if definition.get("fail_observed") else None
        ),
    )
    check = PostureCheck(
        key=rule_key,
        title=str(definition.get("title") or rule_key),
        provider=provider,
        resource_type=resource_type,
        expected=expected,
        control_ids=control_ids,
        capability_key=(
            str(definition["capability_key"]) if definition.get("capability_key") else None
        ),
        required_permissions=_tuple_of_str(definition.get("required_permissions")),
    )
    return ResolvedCheck(check=check, endpoint=endpoint, source="", spec=spec)


def _targets(definition: dict[str, Any], provider: str) -> bool:
    """Is this rule for this provider?

    Form B names its provider explicitly. Form A does not need to -- the
    platform evaluator it names belongs to exactly one provider, so the
    evaluator implies it.
    """
    declared = definition.get("provider")
    if isinstance(declared, str) and declared:
        return declared == provider
    evaluator = definition.get("evaluator")
    if isinstance(evaluator, str):
        return any(c.key == evaluator for c in checks_for(provider))
    return False


def _build(rule_key: str, definition: Any, provider: str) -> ResolvedCheck:
    if not isinstance(definition, dict):
        raise ResolutionError("'definition' must be an object")
    has_evaluator = "evaluator" in definition
    has_predicate = "predicate" in definition
    if has_evaluator == has_predicate:
        raise ResolutionError("exactly one of 'evaluator' or 'predicate' is required")
    if has_evaluator:
        return _build_form_a(rule_key, definition, provider)
    return _build_form_b(rule_key, definition, provider)


def resolve_checks_from_registry(provider: str) -> tuple[ResolvedCheck, ...]:
    """The platform's checks for one provider, with no database.

    What a connector falls back to when its caller passed no checks -- keeping
    ``scan()`` usable from a context that has no session, which is how the
    existing connector tests drive it.
    """
    return tuple(_platform(provider))


async def resolve_checks(
    session: AsyncSession, *, provider: str, org_id: int | None
) -> tuple[ResolvedCheck, ...]:
    """Executable checks for one provider and one tenant.

    Platform checks first, then declared ones ordered by key, so two
    resolutions of the same state agree -- scan output that churns between runs
    is indistinguishable from drift.
    """
    rows = (
        await session.execute(
            select(PackRule.rule_key, PackRule.definition, CompliancePack.pack_key)
            .join(CompliancePack, CompliancePack.id == PackRule.pack_id)
            .where(
                CompliancePack.organization_id == org_id,
                CompliancePack.status == "installed",
                PackRule.kind == "posture",
            )
            .order_by(PackRule.rule_key)
        )
    ).all()

    declared: list[ResolvedCheck] = []
    for rule_key, definition, pack_key in rows:
        if not isinstance(definition, dict):
            log.warning("posture.resolve.definition_not_an_object", rule=str(rule_key))
            continue
        declared_provider = definition.get("provider")
        if (
            isinstance(declared_provider, str)
            and declared_provider
            and declared_provider not in known_providers()
        ):
            # A mistyped provider ('msgrap') is not "a rule for another
            # provider" -- _targets() below would just compare it unequal to
            # every real provider key forever, so the rule shows installed
            # and never runs, silently, on every resolution. install-time
            # validation (packs.catalog) should have caught this; a row
            # reaching here predates that check or bypassed it, so it is
            # skipped -- loudly, unlike the ordinary cross-provider case.
            log.warning(
                "posture.resolve.unknown_provider",
                rule=str(rule_key),
                pack=str(pack_key),
                provider=declared_provider,
            )
            continue
        if not _targets(definition, provider):
            continue  # a rule for another provider is not this scan's business
        try:
            resolved = _build(str(rule_key), definition, provider)
        except (ResolutionError, ValueError) as e:
            # Validation refuses these at install, so a row reaching here
            # predates validation or was written directly. Skipping it is safer
            # than scanning with a rule whose behaviour is undefined, and it
            # must not discard the checks that are fine.
            log.warning(
                "posture.resolve.rule_unusable",
                rule=str(rule_key),
                pack=str(pack_key),
                error=str(e)[:200],
            )
            continue
        declared.append(
            ResolvedCheck(
                check=resolved.check,
                endpoint=resolved.endpoint,
                source=f"pack:{pack_key}",
                evaluator_key=resolved.evaluator_key,
                parameters=resolved.parameters,
                spec=resolved.spec,
            )
        )
    return (*_platform(provider), *declared)
