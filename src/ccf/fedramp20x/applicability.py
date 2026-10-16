"""Which KSIs a system owes, by its CR26 Certification Class and Path.

Derived from FedRAMP's Consolidated Rules, never authored here:

* The KSI rules are **20x, Program-path** rules. ``IVV-CSX-AIA`` ("MUST
  include all Key Security Indicators", Classes B-D) and ``FRC-CSX-VVK`` live
  in subsets whose ``applicability`` is ``types: [20x], paths: [Program]``;
  ``FRC-CLA`` (Class A) is the same. A Rev5 certification owes a control list
  (``IVV-CSF-AIA``), not KSIs.
* **Class A** addresses exactly the KSIs ``FRC-CLA-MFR`` lists in its
  machine-readable ``related`` field.
* **Classes B, C and D** on 20x include all KSIs; a KSI whose class-B
  statement begins ``**Optional:**`` is **optional** for Class B.

Concord records Class and Path (``System.certification_class`` /
``certification_path``) but deliberately not certification *type* -- that is
a declaration the provider makes. So:

* path **Agency** -> no 20x subset applies (every one is Program-only), so the
  system is Rev5 by elimination and owes no KSI;
* path **Program** or unrecorded -> the KSI rules apply *if* the system is
  certified under 20x, and every sentence that reports the scope says so;
* a Class/Path pair the rules make impossible (Class A on the Agency path) is
  reported, not resolved;
* no Class -> **unscoped**: every current KSI, labelled as such.

Nothing here reads ``baseline`` (see ``ccf.constants.CERTIFICATION_CLASSES``).
The upstream wording parsed here is pinned by tests, so a re-vendored dataset
that moves it fails a test; at runtime a dataset that no longer parses
degrades to unscoped with the reason attached, rather than a 500.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..logging import get_logger
from ..models import KSI, System
from .rules import ConsolidatedRules, ksi_ids, load_rules

log = get_logger(__name__)

REQUIRED = "required"
OPTIONAL = "optional"
NOT_REQUIRED = "not_required"
UNSCOPED = "unscoped"

#: In front of the provider: counted (required, unscoped) or at least owed a
#: narrative (optional).
OWED = frozenset({REQUIRED, OPTIONAL, UNSCOPED})
#: What readiness counts.
COUNTED = frozenset({REQUIRED, UNSCOPED})

_CLASS_A_RULE = "FRC-CLA-MFR"
_ALL_KSIS_RULE = "IVV-CSX-AIA"
_REV5_RULE = "IVV-CSF-AIA"
_AUTOMATION_RULE = "FRC-CSX-VVK"
_OPTIONAL_PREFIX = "**Optional:**"
_MIN_METHODS_WORDS = {"1": 1, "2": 2, "4": 4}

#: Validation-rule kinds that are an automated check of the system itself.
#: ``control_state``, ``evidence_present``, ``profile_field`` and
#: ``dependency_authorized`` read records an operator entered: evaluating them
#: is automatic, but they do not "persistently verify and validate" anything.
_AUTOMATED_KINDS = frozenset({"connector_capture"})


class ApplicabilityError(RuntimeError):
    """The dataset no longer says what this module reads from it."""


@dataclass(frozen=True)
class Applicability:
    status: str
    #: The rule that decided it, or ``None`` for unscoped.
    rule: str | None
    note: str | None = None


@dataclass(frozen=True)
class AutomationRequirement:
    """FRC-CSX-VVK for one class: how many automated methods each KSI needs."""

    certification_class: str
    force: str
    min_methods: int
    statement: str


@dataclass(frozen=True)
class ClassScope:
    """Everything one Class/Path pair implies, plus the sentence that says so."""

    by_identifier: dict[str, Applicability]
    #: How the scope was decided, in words a reader can check against the rules.
    basis: str
    #: True when the KSI requirement holds only if the system is 20x.
    conditional_on_20x: bool = False
    automation: AutomationRequirement | None = None
    #: Set when the Class/Path pair is impossible or the rules would not parse.
    problem: str | None = None


def _frr(rules: ConsolidatedRules, process: str, bucket: str, subset: str, rid: str) -> Any:
    try:
        return rules.data["FRR"][process]["data"][bucket][subset][rid]
    except KeyError as exc:
        raise ApplicabilityError(f"{rid} is not where it was: {exc}") from exc


def _subset_paths(rules: ConsolidatedRules, process: str, bucket: str, subset: str) -> set[str]:
    info = rules.data["FRR"][process]["info"]
    holder = info if bucket == "all" else info.get(bucket, {})
    try:
        return set(holder["subsets"][subset]["applicability"]["paths"])
    except KeyError as exc:
        raise ApplicabilityError(f"{process} {subset} applicability moved: {exc}") from exc


def class_a_ksis(rules: ConsolidatedRules) -> frozenset[str]:
    rule = _frr(rules, "FRC", "all", "CLA", _CLASS_A_RULE)
    listed = frozenset(r for r in rule.get("related", []) if str(r).startswith("KSI-"))
    if not listed:
        raise ApplicabilityError(f"{_CLASS_A_RULE} lists no KSIs")
    unknown = listed - ksi_ids(rules)
    if unknown:
        raise ApplicabilityError(f"{_CLASS_A_RULE} lists undefined KSIs: {sorted(unknown)}")
    return listed


def _all_ksis_classes(rules: ConsolidatedRules) -> frozenset[str]:
    """Classes for which IVV-CSX-AIA says "all Key Security Indicators"."""
    rule = _frr(rules, "IVV", "20x", "CSX", _ALL_KSIS_RULE)
    return frozenset(
        cls.upper()
        for cls, variant in (rule.get("varies_by_class") or {}).items()
        if "all Key Security Indicators" in str(variant.get("statement", ""))
    )


def _class_variants(rules: ConsolidatedRules) -> dict[str, dict[str, str]]:
    return {
        ident: {c: str(v.get("statement", "")) for c, v in ind["varies_by_class"].items()}
        for theme in rules.data["KSI"].values()
        for ident, ind in theme["indicators"].items()
        if ind.get("varies_by_class")
    }


def automation_requirement(
    rules: ConsolidatedRules, certification_class: str | None
) -> AutomationRequirement | None:
    if certification_class is None:
        return None
    rule = _frr(rules, "FRC", "20x", "CSX", _AUTOMATION_RULE)
    variant = (rule.get("varies_by_class") or {}).get(certification_class.lower())
    if variant is None:
        return None
    statement = str(variant["statement"])
    force = next((f for f in ("MUST", "SHOULD", "MAY") if f" {f} " in f" {statement} "), None)
    if force is None:
        raise ApplicabilityError(f"{_AUTOMATION_RULE} class {certification_class}: no force")
    count = 0
    marker = "with at least "
    if marker in statement:
        word = statement.split(marker, 1)[1].split(" ", 1)[0]
        if word not in _MIN_METHODS_WORDS:
            raise ApplicabilityError(f"{_AUTOMATION_RULE}: unrecognised count {word!r}")
        count = _MIN_METHODS_WORDS[word]
    return AutomationRequirement(certification_class.upper(), force, count, statement)


def _uniform(ids: frozenset[str], status: str, rule: str | None) -> dict[str, Applicability]:
    return {k: Applicability(status, rule) for k in ids}


def for_class(
    rules: ConsolidatedRules,
    certification_class: str | None,
    certification_path: str | None = None,
) -> ClassScope:
    """The scope for one Class/Path pair (either may be ``None``)."""
    ids = ksi_ids(rules)
    path = certification_path.capitalize() if certification_path else None
    twentyx_paths = _subset_paths(rules, "IVV", "20x", "CSX") | _subset_paths(
        rules, "FRC", "all", "CLA"
    )
    allowed = "/".join(sorted(twentyx_paths))
    if certification_class is None:
        if path is not None and path not in twentyx_paths:
            # The path alone settles it: no KSI rule applies off the 20x paths.
            return ClassScope(
                _uniform(ids, NOT_REQUIRED, _REV5_RULE),
                f"The {path} path is Rev5 only: FedRAMP's KSI rules apply to 20x "
                f"{allowed} certifications.",
            )
        return ClassScope(
            _uniform(ids, UNSCOPED, None),
            "No Certification Class is recorded, so every current KSI is scored.",
        )
    cls = certification_class.upper()

    if path is not None and path not in twentyx_paths:
        if cls == "A":
            return ClassScope(
                _uniform(ids, UNSCOPED, None),
                "Every current KSI is scored, unscoped.",
                problem=(
                    f"Class A is a 20x certification on the {allowed} path only (FRC-CLA); "
                    f"this system records the {path} path. Correct one of them."
                ),
            )
        return ClassScope(
            _uniform(ids, NOT_REQUIRED, _REV5_RULE),
            f"The {path} path is Rev5 only: FedRAMP's KSI rules apply to 20x {allowed} "
            f"certifications, and a Rev5 Class {cls} certification owes the control list "
            f"in {_REV5_RULE} instead.",
        )

    if cls == "A":
        required = class_a_ksis(rules)
        by_id = {
            k: Applicability(REQUIRED if k in required else NOT_REQUIRED, _CLASS_A_RULE)
            for k in ids
        }
    else:
        if cls not in _all_ksis_classes(rules):
            raise ApplicabilityError(f"no rule in the dataset says what Class {cls} owes")
        by_id = {}
        by_class = _class_variants(rules)
        for k in ids:
            variants = by_class.get(k)
            if variants is None:
                by_id[k] = Applicability(REQUIRED, _ALL_KSIS_RULE)
            elif cls.lower() not in variants:
                by_id[k] = Applicability(
                    REQUIRED,
                    _ALL_KSIS_RULE,
                    note=f"FedRAMP publishes no Class {cls} wording for this indicator",
                )
            elif variants[cls.lower()].startswith(_OPTIONAL_PREFIX):
                by_id[k] = Applicability(OPTIONAL, k)
            else:
                by_id[k] = Applicability(REQUIRED, _ALL_KSIS_RULE)

    path_words = f"on the {path} path" if path else "with no Certification Path recorded"
    if cls == "A":
        # Class A exists only as a 20x certification (no Rev5 subset lists it),
        # so the class alone settles the type.
        return ClassScope(
            by_id,
            f"FedRAMP's KSI rules for a Class A certification (20x only), applied to a "
            f"system {path_words}.",
            automation=automation_requirement(rules, cls),
        )
    return ClassScope(
        by_id,
        f"FedRAMP's KSI rules for a 20x Class {cls} certification, applied to a system "
        f"{path_words}. Concord does not record certification type: if this system is "
        "certified under Rev5, these KSIs are not what it owes.",
        conditional_on_20x=True,
        automation=automation_requirement(rules, cls),
    )


def automated_methods(rule: dict[str, Any] | None) -> int:
    """Automated checks of the system itself in a Concord validation rule."""
    if not rule:
        return 0
    kind = rule.get("kind", "manual")
    if kind == "any_of":
        return sum(automated_methods(r) for r in rule.get("rules", []))
    return 1 if kind in _AUTOMATED_KINDS else 0


def automated_method_count(ksi: KSI, check_status: dict[str, str] | None) -> int:
    """Automated methods for one KSI on one system: capture leaves in its rule
    plus curated posture-check methods that have actually run there."""
    from .methods import methods_run  # noqa: PLC0415

    ran = methods_run(list(ksi.methods or []), check_status) if check_status else 0
    return automated_methods(ksi.rule) + ran


@dataclass(frozen=True)
class SystemScope:
    """A :class:`ClassScope` resolved against the catalog rows a system is scored on."""

    certification_class: str | None
    certification_path: str | None
    scope: ClassScope

    @property
    def by_identifier(self) -> dict[str, Applicability]:
        return self.scope.by_identifier

    def status(self, identifier: str) -> str:
        # A current row the pinned dataset does not define (catalog not yet
        # re-seeded) -- or any row when the rules would not parse -- has no
        # class determination to apply: unscoped.
        found = self.scope.by_identifier.get(identifier)
        return found.status if found is not None else UNSCOPED

    def counted(self, ksis: list[KSI]) -> list[KSI]:
        return [k for k in ksis if self.status(k.identifier) in COUNTED]

    def owed(self, ksis: list[KSI]) -> list[KSI]:
        return [k for k in ksis if self.status(k.identifier) in OWED]

    def summary(
        self, ksis: list[KSI], check_status: dict[str, str] | None = None
    ) -> dict[str, Any]:
        """Scope counts and FRC-CSX-VVK. ``check_status`` is the system's tier-0
        posture results: a curated method counts only once it has run there."""
        counts = {s: 0 for s in (REQUIRED, OPTIONAL, NOT_REQUIRED, UNSCOPED)}
        for k in ksis:
            counts[self.status(k.identifier)] += 1
        out: dict[str, Any] = {
            "certification_class": self.certification_class,
            "certification_path": self.certification_path,
            "ksi_scope": counts,
            "ksi_scope_basis": self.scope.basis,
            "ksi_scope_conditional_on_20x": self.scope.conditional_on_20x,
            "ksi_scope_problem": self.scope.problem,
            "automation_requirement": None,
        }
        auto = self.scope.automation
        if auto is not None:
            owed = self.owed(ksis)
            out["automation_requirement"] = {
                "rule": _AUTOMATION_RULE,
                "force": auto.force,
                "min_automated_methods_per_ksi": auto.min_methods,
                # With no minimum (Class A: MAY) "meeting" is vacuous -- every
                # KSI would meet zero -- so report how many have ANY instead.
                "ksis_meeting": sum(
                    1
                    for k in owed
                    if automated_method_count(k, check_status) >= max(auto.min_methods, 1)
                ),
                "ksis_owed": len(owed),
            }
        return out


async def system_scope(session: AsyncSession, system_id: int) -> SystemScope:
    system = await session.get(System, system_id)
    cls = system.certification_class if system is not None else None
    path = system.certification_path if system is not None else None
    return scope_for(cls, path)


def scope_for(cls: str | None, path: str | None) -> SystemScope:
    """The scope for a Class/Path pair; never raises (see the module docstring)."""
    try:
        return SystemScope(cls, path, for_class(load_rules(), cls, path))
    except ApplicabilityError as exc:
        log.error("fedramp20x.applicability_unreadable", cls=cls, path=path, error=str(exc))
        return SystemScope(
            cls,
            path,
            ClassScope(
                {},
                "Every current KSI is scored, unscoped.",
                problem=f"FedRAMP's rules could not be read for scoping: {exc}",
            ),
        )


async def counted_ksi_ids(session: AsyncSession, system_id: int) -> set[int]:
    """Primary keys of the current KSIs this system's readiness counts.

    The one answer every per-system consumer -- gaps, onboarding, package
    facts, drift alerts -- must give, so none of them disagrees with
    :func:`ccf.fedramp20x.readiness.score_system` about what the system owes.
    """
    from .catalog import current_ksis  # noqa: PLC0415 -- catalog imports models only

    scope = await system_scope(session, system_id)
    ksis = list((await session.execute(current_ksis())).scalars().all())
    return {k.id for k in scope.counted(ksis)}
