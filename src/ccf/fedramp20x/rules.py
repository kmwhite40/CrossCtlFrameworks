"""FedRAMP's Consolidated Rules for 2026, vendored and verified.

``rules_data/fedramp-consolidated-rules.json`` is FedRAMP's own machine-readable
ruleset (``github.com/FedRAMP/rules``, public domain): definitions (FRD), process
rules (FRR), Key Security Indicators (KSI) and control guidance (CTL). It is
pinned by ``MANIFEST.json`` -- sha256, upstream commit, dataset version -- and
validated against FedRAMP's own JSON Schema on load, as the dataset's
``AGENTS.md`` asks before any automated reliance. The poller watches upstream
for drift (``etl.sources``, key ``fedramp_consolidated_rules``); adopting a new
revision is re-vendoring these files, never a silent fetch.

Found by way of myctrl.tools, whose KSI data names this repository as its
source -- and taken from FedRAMP, not from the aggregator, which was serving a
copy three months older than upstream.

This module only reads the dataset. What Concord derives from it -- the KSI
catalog rows -- is :mod:`ccf.fedramp20x.catalog`'s concern.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from ..catalog.canonical import canonicalize

DATA_DIR = Path(__file__).with_name("rules_data")
DATASET_FILE = "fedramp-consolidated-rules.json"
SCHEMA_FILE = "fedramp-consolidated-rules.schema.json"
RULES_OVERLAY_FILE = "ksi_rules.json"


class RulesDatasetError(RuntimeError):
    """The vendored dataset is missing, altered, or does not match its schema."""


@dataclass(frozen=True)
class ConsolidatedRules:
    version: str
    last_updated: str
    upstream_commit_sha: str | None
    data: dict[str, Any]

    @property
    def source_label(self) -> str:
        """What ``KSI.source`` records: the authority and the exact revision."""
        return f"fedramp-rules:{self.version}"


def _verify(d: Path) -> dict[str, Any]:
    manifest: dict[str, Any] = json.loads((d / "MANIFEST.json").read_text(encoding="utf-8"))
    files: dict[str, Any] = manifest.get("files", {})
    # Both FedRAMP files MUST be pinned: a manifest that drops an entry would
    # otherwise let that file load unverified. (``ksi_rules.json`` is Concord's
    # own authored overlay, reviewed like code, and is not pinned here.)
    unlisted = sorted({DATASET_FILE, SCHEMA_FILE} - files.keys())
    if unlisted:
        raise RulesDatasetError(f"MANIFEST.json does not pin: {unlisted}")
    for name, meta in files.items():
        p = d / name
        if not p.is_file():
            raise RulesDatasetError(f"missing vendored file {name}")
        got = hashlib.sha256(p.read_bytes()).hexdigest()
        if got != meta["sha256"]:
            raise RulesDatasetError(f"sha256 mismatch for {name}: {got} != {meta['sha256']}")
    return manifest


def _validate(data: Any, schema: dict[str, Any]) -> None:
    import jsonschema  # noqa: PLC0415 -- a hard dependency; imported where used

    validator = jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER
    )
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    if errors:
        first = errors[0]
        where = "/".join(str(p) for p in first.path) or "<root>"
        raise RulesDatasetError(
            f"{len(errors)} schema violation(s); first at {where}: {first.message}"
        )


def load_rules(directory: str | Path | None = None) -> ConsolidatedRules:
    """Verify, schema-validate and return the vendored dataset."""
    if directory is None:
        return _load_default()
    return _load(Path(directory))


@lru_cache(maxsize=1)
def _load_default() -> ConsolidatedRules:
    return _load(DATA_DIR)


def _load(d: Path) -> ConsolidatedRules:
    manifest = _verify(d)
    data = json.loads((d / DATASET_FILE).read_text(encoding="utf-8"))
    _validate(data, json.loads((d / SCHEMA_FILE).read_text(encoding="utf-8")))
    info = data["info"]
    if info["version"] != manifest.get("dataset_version"):
        raise RulesDatasetError(
            f"dataset says {info['version']!r}, MANIFEST pins {manifest.get('dataset_version')!r}"
        )
    return ConsolidatedRules(
        version=str(info["version"]),
        last_updated=str(info["last_updated"]),
        upstream_commit_sha=manifest.get("upstream_commit_sha"),
        data=data,
    )


def _control_id(raw: str) -> str:
    """FedRAMP writes ``at-2.2``; Concord's canonical form is ``AT-2(2)``."""
    head, _, enh = raw.strip().partition(".")
    candidate = f"{head}({enh})" if enh else head
    canon = canonicalize(candidate)
    if canon is None:
        raise RulesDatasetError(f"unrecognised control id in KSI mapping: {raw!r}")
    return canon.value


#: Theme statuses FedRAMP uses for a theme that defines nothing yet. Its
#: indicators, if any, are not requirements, so the catalog does not carry them.
_INACTIVE_THEME = frozenset({"placeholder", "empty"})


def _active_themes(rules: ConsolidatedRules) -> list[tuple[str, dict[str, Any]]]:
    return [
        (key, theme)
        for key, theme in rules.data["KSI"].items()
        if theme.get("status") not in _INACTIVE_THEME
    ]


def ksi_records(rules: ConsolidatedRules) -> list[dict[str, Any]]:
    """One catalog record per indicator, in the dataset's own order.

    Only fields FedRAMP publishes are filled. ``description`` is the statement
    verbatim; where FedRAMP states the indicator per class instead, the class
    statements are kept verbatim in ``statement_by_class`` and the description
    labels each one -- no class's text is chosen or copied onto another.
    """
    records: list[dict[str, Any]] = []
    for theme_key, theme in _active_themes(rules):
        for ident, ind in theme["indicators"].items():
            by_class = {
                str(cls): str(variant["statement"])
                for cls, variant in (ind.get("varies_by_class") or {}).items()
                if variant.get("statement")
            }
            statement = ind.get("statement")
            if statement:
                description = str(statement)
            elif by_class:
                description = "\n\n".join(
                    f"Class {cls.upper()}: {text}" for cls, text in sorted(by_class.items())
                )
            else:
                raise RulesDatasetError(f"{ident} has neither a statement nor class statements")
            records.append(
                {
                    "identifier": ident,
                    "category": theme_key,
                    "category_name": theme["name"],
                    "name": ind["name"],
                    "description": description,
                    "expected_outcome": description,
                    "statement_by_class": by_class,
                    "nist_refs": [_control_id(c) for c in ind.get("controls", [])],
                    # FedRAMP publishes no CMMC mapping; the phase-one catalog's
                    # was Concord's interpretation and is not carried over.
                    "cmmc_refs": [],
                    "provider_services": [],
                    "source": rules.source_label,
                }
            )
    return records


def frr_ids(rules: ConsolidatedRules) -> frozenset[str]:
    """Every FedRAMP process-rule requirement ID the dataset defines."""
    ids: set[str] = set()
    for process in rules.data["FRR"].values():
        for subsets in process["data"].values():
            for requirements in subsets.values():
                ids.update(requirements)
    return frozenset(ids)


def ksi_ids(rules: ConsolidatedRules) -> frozenset[str]:
    return frozenset(
        ident for _key, theme in _active_themes(rules) for ident in theme["indicators"]
    )


def load_rule_overlay(path: str | Path | None = None) -> dict[str, dict[str, Any]]:
    """Concord's authored validation rules, keyed by 2026 indicator ID."""
    p = Path(path) if path is not None else DATA_DIR / RULES_OVERLAY_FILE
    doc = json.loads(p.read_text(encoding="utf-8"))
    rules: dict[str, dict[str, Any]] = doc.get("rules", {})
    return rules


def ksi_definitions(rules: ConsolidatedRules) -> dict[str, list[dict[str, Any]]]:
    """For each KSI, the FedRAMP definitions (FRD) of the terms its statement uses.

    FedRAMP's AGENTS.md: "Use the FRD meaning whenever a defined term appears
    in a rule or indicator." A term with no FRD entry is returned with
    ``definition`` None rather than an invented meaning.
    """
    by_term: dict[str, tuple[str, dict[str, Any]]] = {}
    for bucket in rules.data["FRD"]["data"].values():
        for fid, entry in bucket.items():
            for name in [entry.get("term"), *(entry.get("alts") or [])]:
                if name:
                    by_term[str(name)] = (fid, entry)
    out: dict[str, list[dict[str, Any]]] = {}
    for theme in rules.data["KSI"].values():
        for ident, ind in theme["indicators"].items():
            rows = []
            for term in ind.get("terms") or []:
                found = by_term.get(term)
                rows.append(
                    {
                        "term": term,
                        "id": found[0] if found else None,
                        "definition": found[1].get("definition") if found else None,
                    }
                )
            out[ident] = rows
    return out
