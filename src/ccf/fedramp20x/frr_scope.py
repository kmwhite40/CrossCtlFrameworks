"""Which FedRAMP process requirements (FRR) a provider owes, from the rules alone.

Spec: docs/superpowers/specs/2026-10-14-fedramp-consolidated-rules-design.md §7.

A requirement is owed in a *scenario* -- a certification type (20x or Rev5)
and path (Program or Agency) -- when its subset's ``applicability`` lists the
system's Class, that type and that path, and the requirement (or its subset)
``affects`` Providers. Concord records Class and Path but deliberately not
type, so the answer is never one list:

* ``owed``        -- owed in every scenario still possible for this system;
* ``conditional`` -- owed in some scenarios only, each naming which.

Class A also owes what ``FRC-CLA-MFR`` (MUST), ``FRC-CLA-RFR`` (SHOULD) and
``FRC-CLA-OFR`` (MAY) name: subset applicability alone undercounts it. Force
is the requirement's ``force`` or its class variant's; a class with no
variant is reported as ``None`` -- never borrowed from another class.
Processes FedRAMP marks ``placeholder`` or ``empty`` are left out.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .rules import ConsolidatedRules

_INACTIVE = frozenset({"placeholder", "empty"})
_CLASS_A_LISTS = (("FRC-CLA-MFR", "MUST"), ("FRC-CLA-RFR", "SHOULD"), ("FRC-CLA-OFR", "MAY"))
#: Forces that make a requirement a hard obligation.
HARD = frozenset({"MUST", "MUST NOT"})


@dataclass(frozen=True)
class Requirement:
    id: str
    name: str
    process: str
    force: str | None
    #: The (type, path) scenarios in which it is owed.
    scenarios: frozenset[tuple[str, str]] = field(default_factory=frozenset)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "process": self.process,
            "force": self.force,
            "scenarios": sorted(f"{t}/{p}" for t, p in self.scenarios),
        }


def _subsets(info: dict[str, Any], bucket: str) -> dict[str, Any]:
    if bucket == "all":
        out: dict[str, Any] = info.get("subsets") or {}
        return out
    nested = info.get(bucket) or {}
    out = nested.get("subsets") or {}
    return out


def _force(req: dict[str, Any], cls: str) -> str | None:
    if req.get("force"):
        return str(req["force"])
    variant = (req.get("varies_by_class") or {}).get(cls.lower())
    return str(variant["force"]) if variant and variant.get("force") else None


def _all_subsets(info: dict[str, Any]) -> dict[str, Any]:
    out = dict(_subsets(info, "all"))
    for bucket in ("20x", "rev5"):
        out.update(_subsets(info, bucket))
    return out


def certification_scenarios(
    rules: ConsolidatedRules, certification_class: str, certification_path: str | None
) -> list[tuple[str, str]]:
    """The (type, path) pairs FedRAMP's rules allow for this Class and Path.

    Read from the subsets that name a single type -- the only place the rules
    pair a type with its paths and classes. Today: 20x is Program-only; Rev5 is
    Program or Agency; Class A exists only under 20x. A subset listing both
    types and both paths is a cross product, not evidence that 20x/Agency
    exists, so it is not used here.
    """
    pairs: set[tuple[str, str]] = set()
    class_types: set[str] = set()
    cls = certification_class.upper()
    for process in rules.data["FRR"].values():
        for sub in _all_subsets(process["info"]).values():
            app = sub.get("applicability") or {}
            types = app.get("types") or []
            if len(types) != 1:
                continue
            pairs |= {(types[0], path) for path in app.get("paths") or []}
            if cls in (app.get("classes") or []):
                class_types.add(types[0])
    path = certification_path.capitalize() if certification_path else None
    return sorted((t, p) for t, p in pairs if t in class_types and (path is None or p == path))


def scope(
    rules: ConsolidatedRules, certification_class: str | None, certification_path: str | None
) -> dict[str, Any]:
    """``{"owed": [...], "conditional": [...], "basis": str}`` for one Class/Path."""
    if certification_class is None:
        return {
            "owed": [],
            "conditional": [],
            "basis": "No Certification Class is recorded, so no FRR scope can be derived.",
        }
    cls = certification_class.upper()
    possible = certification_scenarios(rules, cls, certification_path)
    if not possible:
        return {
            "owed": [],
            "conditional": [],
            "basis": (
                f"FedRAMP's rules allow no certification for Class {cls} on the "
                f"{(certification_path or '').capitalize()} path; correct the Class or Path."
            ),
        }
    hits: dict[str, dict[str, Any]] = {}

    for process_key, process in rules.data["FRR"].items():
        info = process["info"]
        if info.get("status") in _INACTIVE:
            continue
        for bucket, subsets in process["data"].items():
            declared = _subsets(info, bucket)
            for subset_key, requirements in subsets.items():
                subset = declared.get(subset_key) or _subsets(info, "all").get(subset_key) or {}
                app = subset.get("applicability") or {}
                if cls not in app.get("classes", []):
                    continue
                for rid, req in requirements.items():
                    affects = req.get("affects") or app.get("affects") or []
                    if "Providers" not in affects:
                        continue
                    matched = {
                        (t, p)
                        for t, p in possible
                        if t in app.get("types", []) and p in app.get("paths", [])
                    }
                    if not matched:
                        continue
                    entry = hits.setdefault(
                        rid,
                        {
                            "name": req.get("name", ""),
                            "process": process_key,
                            "force": _force(req, cls),
                            "scenarios": set(),
                        },
                    )
                    entry["scenarios"] |= matched

    if cls == "A":
        # FRC-CLA applies to 20x Program only; its lists name more rules than
        # subset applicability alone gives Class A.
        cla_scenarios = {(t, p) for t, p in possible if (t, p) == ("20x", "Program")}
        cla = rules.data["FRR"]["FRC"]["data"]["all"]["CLA"]
        names = _names(rules)
        for list_id, force in _CLASS_A_LISTS:
            for rid in cla[list_id].get("related", []):
                if rid.startswith("KSI-") or not cla_scenarios:
                    continue
                entry = hits.setdefault(
                    rid,
                    {
                        "name": names.get(rid, ""),
                        "process": rid.split("-")[0],
                        "force": force,
                        "scenarios": set(),
                    },
                )
                entry["scenarios"] |= cla_scenarios

    all_possible = frozenset(possible)
    owed: list[Requirement] = []
    conditional: list[Requirement] = []
    for rid in sorted(hits):
        h = hits[rid]
        req = Requirement(rid, h["name"], h["process"], h["force"], frozenset(h["scenarios"]))
        (owed if req.scenarios == all_possible else conditional).append(req)
    path_words = (
        f"the {certification_path.capitalize()} path"
        if certification_path
        else "an unrecorded path"
    )
    return {
        "owed": [r.as_dict() for r in owed],
        "conditional": [r.as_dict() for r in conditional],
        "basis": (
            f"FedRAMP Consolidated Rules {rules.version}, Class {cls} on {path_words}. "
            "Concord does not record certification type, so requirements that "
            "differ between 20x and Rev5 are listed as conditional."
        ),
    }


def _names(rules: ConsolidatedRules) -> dict[str, str]:
    out: dict[str, str] = {}
    for process in rules.data["FRR"].values():
        for subsets in process["data"].values():
            for requirements in subsets.values():
                for rid, req in requirements.items():
                    out[rid] = str(req.get("name", ""))
    return out
