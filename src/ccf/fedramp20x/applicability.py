"""Which KSIs a system owes, by its CR26 Certification Class.

Derived from FedRAMP's Consolidated Rules, never authored here:

* **Class A** addresses exactly the KSIs ``FRC-CLA-MFR`` lists in its
  machine-readable ``related`` field ("Providers seeking a Class A FedRAMP
  Certification MUST address ... the following additional FedRAMP Class A
  rules").
* **Classes B, C and D** include all KSIs: ``IVV-CSX-AIA`` -- "MUST include all
  Key Security Indicators in a FedRAMP independent assessment at least once
  per year" -- per class.
* A KSI that varies by class and whose class-B statement begins
  ``**Optional:**`` is **optional** for Class B.
* A system with no recorded class is **unscoped**: every current KSI, as before
  classes existed, labelled so nobody reads it as a class determination.

``System.certification_class`` is independent of ``baseline`` (see
``ccf.constants.CERTIFICATION_CLASSES``); nothing here reads ``baseline``.

Each decision carries the rule ID that produced it. The parsing this relies on
is pinned by tests against the exact upstream wording, so a re-vendored
dataset that moves it fails a test rather than silently re-scoping systems.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..models import KSI, System
from .rules import ConsolidatedRules, ksi_ids, load_rules

REQUIRED = "required"
OPTIONAL = "optional"
NOT_REQUIRED = "not_required"
UNSCOPED = "unscoped"

#: Statuses that put a KSI in front of the provider: counted toward readiness
#: (required, unscoped) or at least due a narrative (optional).
OWED = frozenset({REQUIRED, OPTIONAL, UNSCOPED})
#: Statuses readiness counts.
COUNTED = frozenset({REQUIRED, UNSCOPED})

_CLASS_A_RULE = "FRC-CLA-MFR"
_ALL_KSIS_RULE = "IVV-CSX-AIA"
_AUTOMATION_RULE = "FRC-CSX-VVK"
_OPTIONAL_PREFIX = "**Optional:**"

#: FRC-CSX-VVK, per class: the force and the minimum number of automated
#: validation methods per KSI. Parsed from the statement; pinned by tests.
_MIN_METHODS_WORDS = {"1": 1, "2": 2, "4": 4}


class ApplicabilityError(RuntimeError):
    """The dataset no longer says what this module reads from it."""


@dataclass(frozen=True)
class Applicability:
    status: str
    #: The rule that decided it, or ``None`` for unscoped.
    rule: str | None
    #: Present when the class has no published wording for a KSI that varies
    #: by class, so a reader is told rather than shown another class's text.
    note: str | None = None


def _frr(rules: ConsolidatedRules, process: str, bucket: str, subset: str, rid: str) -> Any:
    try:
        return rules.data["FRR"][process]["data"][bucket][subset][rid]
    except KeyError as exc:
        raise ApplicabilityError(f"{rid} is not where it was: {exc}") from exc


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


def for_class(
    rules: ConsolidatedRules, certification_class: str | None
) -> dict[str, Applicability]:
    """Every current KSI's applicability for one class (``None`` = unscoped)."""
    ids = ksi_ids(rules)
    if certification_class is None:
        return {k: Applicability(UNSCOPED, None) for k in ids}
    cls = certification_class.upper()
    if cls == "A":
        required = class_a_ksis(rules)
        return {
            k: Applicability(REQUIRED if k in required else NOT_REQUIRED, _CLASS_A_RULE)
            for k in ids
        }
    if cls not in _all_ksis_classes(rules):
        raise ApplicabilityError(f"no rule in the dataset says what Class {cls} owes")
    out: dict[str, Applicability] = {}
    by_class = _class_variants(rules)
    for k in ids:
        variants = by_class.get(k)
        if variants is None:
            out[k] = Applicability(REQUIRED, _ALL_KSIS_RULE)
        elif cls.lower() not in variants:
            out[k] = Applicability(
                REQUIRED,
                _ALL_KSIS_RULE,
                note=f"FedRAMP publishes no Class {cls} wording for this indicator",
            )
        elif variants[cls.lower()].startswith(_OPTIONAL_PREFIX):
            out[k] = Applicability(OPTIONAL, k)
        else:
            out[k] = Applicability(REQUIRED, _ALL_KSIS_RULE)
    return out


def _class_variants(rules: ConsolidatedRules) -> dict[str, dict[str, str]]:
    return {
        ident: {c: str(v.get("statement", "")) for c, v in ind["varies_by_class"].items()}
        for theme in rules.data["KSI"].values()
        for ident, ind in theme["indicators"].items()
        if ind.get("varies_by_class")
    }


@dataclass(frozen=True)
class AutomationRequirement:
    """FRC-CSX-VVK for one class: how many automated methods each KSI needs."""

    certification_class: str
    force: str
    min_methods: int
    statement: str


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
    force = next(
        (f for f in ("MUST", "SHOULD", "MAY") if f" {f} " in f" {statement} "), None
    )
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


def automated_methods(rule: dict[str, Any] | None) -> int:
    """Automated leaf checks in a Concord validation rule (``manual`` counts 0)."""
    if not rule:
        return 0
    kind = rule.get("kind", "manual")
    if kind == "manual":
        return 0
    if kind == "any_of":
        return sum(automated_methods(r) for r in rule.get("rules", []))
    return 1


@dataclass(frozen=True)
class SystemScope:
    """What one system owes, resolved against the catalog rows it is scored on."""

    certification_class: str | None
    by_identifier: dict[str, Applicability]
    automation: AutomationRequirement | None

    def status(self, identifier: str) -> str:
        # A current row the pinned dataset does not define (a catalog not yet
        # re-seeded) has no class determination to apply: unscoped.
        found = self.by_identifier.get(identifier)
        return found.status if found is not None else UNSCOPED

    def counted(self, ksis: list[KSI]) -> list[KSI]:
        return [k for k in ksis if self.status(k.identifier) in COUNTED]

    def summary(self, ksis: list[KSI]) -> dict[str, Any]:
        counts = {s: 0 for s in (REQUIRED, OPTIONAL, NOT_REQUIRED, UNSCOPED)}
        for k in ksis:
            counts[self.status(k.identifier)] += 1
        out: dict[str, Any] = {
            "certification_class": self.certification_class,
            "ksi_scope": counts,
            "automation_requirement": None,
        }
        if self.automation is not None:
            owed = [k for k in ksis if self.status(k.identifier) in OWED]
            meeting = sum(
                1 for k in owed if automated_methods(k.rule) >= self.automation.min_methods
            )
            out["automation_requirement"] = {
                "rule": _AUTOMATION_RULE,
                "force": self.automation.force,
                "min_automated_methods_per_ksi": self.automation.min_methods,
                "ksis_meeting": meeting,
                "ksis_owed": len(owed),
            }
        return out


async def system_scope(session: AsyncSession, system_id: int) -> SystemScope:
    system = await session.get(System, system_id)
    cls = system.certification_class if system is not None else None
    rules = load_rules()
    return SystemScope(cls, for_class(rules, cls), automation_requirement(rules, cls))
