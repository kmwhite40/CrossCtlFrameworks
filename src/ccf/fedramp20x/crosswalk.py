"""Lay a FedRAMP certification package against the Rev5 control baseline.

The agency's question about a CR26 package is "what does this package tell me
about each control I am responsible for deciding?". FedRAMP publishes, for
every Key Security Indicator (KSI) and FedRAMP rule (FRR), the 800-53
controls it relates to. This module turns that around: for each control in
the Rev5 Class B, C or D baseline (FRC-CSF-BSL) it lists the mapped indicators
and rules, what the package's Security Decision Record reports for each, and
gives the control exactly one coverage state. It also merges the vulnerability
reports into one register.

A link is where a reviewer looks, never evidence that a control is satisfied.
The package stays the source of record.

Two callers use it: the provider preview (Concord's own stored documents for a
system, "what will an agency see") and the agency view (a vendor's package
uploaded under Third-Party Risk). Everything here is pure: no session, no
clock except the one passed in.

Provenance. The crosswalk and register are a Python port of Crosswalk 20x
(Mycroft-io/crosswalk-rev5-to-20x v1.0.0, Apache-2.0, Copyright 2026 Mycroft
Technologies Inc.; see NOTICE), changed in the places the design records
(docs/superpowers/specs/2026-11-11-crosswalk-20x-design.md):

* **Traced is narrowed and Partly reported added.** Upstream counts a control
  as traced when every *reported* mapped entry is Implemented, even when
  other mapped entries are absent: about half its Traced controls on
  FedRAMP's own sample package. Here Traced needs every mapped entry reported.
* **The register is ordered by each document's own date**, not by the order
  the files were read, so an older snapshot cannot overwrite newer detail and
  an acceptance is only what the newest observation says.
* **The OSCAL exports assert no more than the package.** No ``planned`` for
  "Not Implemented", no ``implemented`` for a Partly reported control, no
  ``deviation-approved`` for a provider's acceptance, no export time standing
  in for a missing detection time (see "OSCAL 1.1.2 exports" below).

The reference data is Concord's own: the pinned consolidated rules
(:mod:`ccf.fedramp20x.rules`), which KSIs a class owes
(:mod:`ccf.fedramp20x.applicability`), NIST's OSCAL catalog for titles, and
FedRAMP's agency control guidance (``guidance_data/``, pinned by SHA-256).
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from ..catalog.canonical import canonical_to_oscal_id, canonicalize
from ..catalog.oscal import load_oscal_catalog, oscal_id_to_canonical
from . import applicability
from .rules import ConsolidatedRules, load_rules

GUIDANCE_DIR = Path(__file__).parent / "guidance_data"
GUIDANCE_FILE = "agency-control-guidance.json"

#: The classes FedRAMP publishes a Rev5 control baseline for (FRC-CSF-BSL).
BASELINE_CLASSES: tuple[str, ...] = ("B", "C", "D")

#: The package documents the crosswalk reads, as ``ccf.cr26`` names them.
PACKAGE_KINDS: dict[str, str] = {
    "cpo": "Certification Package Overview",
    "sdr": "Security Decision Record",
    "ocr": "Ongoing Certification Report",
    "vdr": "Vulnerability Detail Report",
    "avi": "Accepted Vulnerability Info",
    "ver_history": "Historical Vulnerability Activity",
}

IMPLEMENTED = "Implemented"

#: Coverage states in display order. Exactly one per baseline control.
STATES: dict[str, tuple[str, str]] = {
    "documented": (
        "Documented",
        "The provider documents this control directly in its Security Decision Record, as "
        "Implemented.",
    ),
    "traced": (
        "Traced",
        "Every indicator and rule FedRAMP maps to this control is reported, all as Implemented.",
    ),
    "partly_reported": (
        "Partly reported",
        "Some mapped indicators or rules are reported, all as Implemented; the others are not "
        "in the package.",
    ),
    "needs_review": (
        "Needs review",
        "A mapped indicator or rule, or the provider's own entry for this control, is reported "
        "with a status other than Implemented (or none).",
    ),
    "not_reported": (
        "Not reported",
        "FedRAMP maps indicators or rules to this control, but the package reports none of them.",
    ),
    "no_mapping": (
        "No mapping",
        "FedRAMP maps no indicator or rule to this control. The package gives no evidence; the "
        "agency decides.",
    ),
}

NOTICE = (
    "A derived reading aid, not a FedRAMP artifact, not a System Security Plan and not a "
    "POA&M. Control links are the related controls FedRAMP publishes for each Key Security "
    "Indicator and rule: a link shows where to look, not that a control is satisfied. The "
    "certification package remains the source of record."
)


class CrosswalkError(ValueError):
    """The request cannot be answered as asked (an unknown class, for one)."""


# ── reference data ───────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Mapped:
    """One KSI or FRR as the crosswalk needs it."""

    id: str
    name: str
    group: str
    #: ``{"*": text}`` for one statement, else ``{"b": ..., "c": ...}``.
    statements: Mapping[str, str]
    controls: tuple[str, ...]
    #: FRR only: where the rule applies.
    bucket: str = "all"
    affects: tuple[str, ...] = ()
    types: tuple[str, ...] = ()
    classes: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()

    def statement(self, cls: str) -> str:
        return self.statements.get("*") or self.statements.get(cls.lower(), "")


@dataclass(frozen=True)
class GuidancePart:
    part: str
    agency_actions: str
    fedramp_guidance: str
    notes: str


@dataclass(frozen=True)
class Reference:
    rules_version: str
    ksi: Mapping[str, Mapped]
    frr: Mapping[str, Mapped]
    baselines: Mapping[str, tuple[str, ...]]
    titles: Mapping[str, str]
    guidance: Mapping[str, tuple[GuidancePart, ...]]
    guidance_commit: str
    #: control -> (mapped KSI ids, mapped FRR ids), in the rules file's order.
    by_control: Mapping[str, tuple[tuple[str, ...], tuple[str, ...]]]


def to_control(raw: Any) -> str | None:
    """Concord's canonical control id from any spelling FedRAMP uses.

    ``"AC-02 (01)"``, ``"ac-2.1"`` and ``"AC-2(1)"`` all give ``"AC-2(1)"``;
    anything that is not a control id gives ``None``."""
    text = str(raw or "").strip()
    if not text:
        return None
    canon = canonicalize(text)
    if canon is None and "." in text:
        try:
            canon = canonicalize(oscal_id_to_canonical(text.lower()))
        except (ValueError, IndexError):
            canon = None
    return canon.value if canon else None


def _statements(v: Mapping[str, Any]) -> dict[str, str]:
    if "statement" in v:
        return {"*": str(v.get("statement") or "")}
    return {
        c: str((x or {}).get("statement") or "")
        for c, x in (v.get("varies_by_class") or {}).items()
    }


def _controls(v: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(sorted({c for c in (to_control(x) for x in v.get("controls") or []) if c}))


def _load_guidance() -> tuple[dict[str, tuple[GuidancePart, ...]], str]:
    manifest = json.loads((GUIDANCE_DIR / "MANIFEST.json").read_text(encoding="utf-8"))
    pinned = manifest["files"][GUIDANCE_FILE]["sha256"]
    raw = (GUIDANCE_DIR / GUIDANCE_FILE).read_bytes()
    got = hashlib.sha256(raw).hexdigest()
    if got != pinned:
        raise CrosswalkError(f"sha256 mismatch for {GUIDANCE_FILE}: {got} != {pinned}")
    data = json.loads(raw)
    out: dict[str, tuple[GuidancePart, ...]] = {}
    for controls in (data.get("controls") or {}).values():
        for cid, c in controls.items():
            key = to_control(cid)
            if key is None:
                continue
            parts = tuple(
                GuidancePart(
                    str(pk),
                    str(p.get("agency_actions") or ""),
                    str(p.get("fedramp_guidance") or ""),
                    str(p.get("notes") or ""),
                )
                for pk, p in (c.get("parts") or {}).items()
                if p and (p.get("agency_actions") or p.get("fedramp_guidance") or p.get("notes"))
            )
            if parts:
                out[key] = parts
    return out, str(manifest.get("upstream_commit_sha", ""))


def build_reference(rules: ConsolidatedRules) -> Reference:
    data = rules.data
    ksi: dict[str, Mapped] = {}
    for theme in data["KSI"].values():
        for iid, v in theme["indicators"].items():
            ksi[iid.upper()] = Mapped(
                iid.upper(),
                str(v.get("name", "")),
                str(theme.get("name", "")),
                _statements(v),
                _controls(v),
            )
    frr: dict[str, Mapped] = {}
    for process in data["FRR"].values():
        info = process["info"]
        for bucket, subsets in process["data"].items():
            for sk, reqs in subsets.items():
                sub = (
                    (info.get("subsets") or {}).get(sk)
                    or ((info.get(bucket) or {}).get("subsets") or {}).get(sk)
                    or {}
                )
                app = sub.get("applicability") or {}
                for rid, v in reqs.items():
                    frr[rid.upper()] = Mapped(
                        rid.upper(),
                        str(v.get("name", "")),
                        str(info.get("name", "")),
                        _statements(v),
                        _controls(v),
                        bucket=bucket,
                        affects=tuple(v.get("affects") or app.get("affects") or ()),
                        types=tuple(app.get("types") or ()),
                        classes=tuple(str(c).upper() for c in app.get("classes") or ()),
                        paths=tuple(str(x).capitalize() for x in app.get("paths") or ()),
                    )
    bsl = data["FRR"]["FRC"]["data"]["rev5"]["CSF"]["FRC-CSF-BSL"]["varies_by_class"]
    baselines: dict[str, tuple[str, ...]] = {}
    for cls, v in bsl.items():
        ids = {to_control(c) for group in v["rev5_controls_list"].values() for c in group}
        baselines[cls.upper()] = tuple(sorted((c for c in ids if c), key=_control_sort))
    by_control: dict[str, tuple[list[str], list[str]]] = {}
    for k in ksi.values():
        for c in k.controls:
            by_control.setdefault(c, ([], []))[0].append(k.id)
    for r in frr.values():
        for c in r.controls:
            by_control.setdefault(c, ([], []))[1].append(r.id)
    catalog = load_oscal_catalog()
    titles: dict[str, str] = {}
    for cid in {c for b in baselines.values() for c in b}:
        ctl = catalog.get(cid)
        if ctl is not None and ctl.title:
            titles[cid] = ctl.title
    guidance, commit = _load_guidance()
    return Reference(
        rules_version=rules.version,
        ksi=ksi,
        frr=frr,
        baselines=baselines,
        titles=titles,
        guidance=guidance,
        guidance_commit=commit,
        by_control={c: (tuple(k), tuple(f)) for c, (k, f) in by_control.items()},
    )


@lru_cache(maxsize=1)
def reference() -> Reference:
    """The reference for Concord's pinned rules (verified on first use)."""
    return build_reference(load_rules())


def _control_sort(cid: str) -> tuple[str, int, tuple[int, ...]]:
    canon = canonicalize(cid)
    if canon is None:
        return (cid, 0, ())
    return (canon.family, canon.number, canon.enhancements)


def control_title(ref: Reference, cid: str) -> str:
    own = ref.titles.get(cid, "")
    base = cid.split("(", 1)[0]
    if base != cid and own and ref.titles.get(base):
        return f"{ref.titles[base]} | {own}"
    return own


# ── reading a package ────────────────────────────────────────────────────────


def detect_kind(doc: Any) -> str | None:  # noqa: PLR0911 -- one return per kind
    """Which package document this is, from its top-level keys only."""
    if not isinstance(doc, dict):
        return None
    if doc.get("serviceIdentification") and doc.get("serviceProperties"):
        return "cpo"
    if any(
        isinstance(doc.get(k), list)
        for k in ("fedRampRequirements", "keySecurityIndicators", "securityControls")
    ):
        return "sdr"
    if isinstance(doc.get("activeVulnerabilities"), list) and "generatedAt" in doc:
        return "ver_history"
    if isinstance(doc.get("vulnerabilities"), list) and doc.get("reportPeriod"):
        return "vdr"
    if isinstance(doc.get("acceptedVulnerabilities"), list) and doc.get("reportPeriod"):
        return "avi"
    if isinstance(doc.get("certificationDataChanges"), list) or doc.get(
        "plannedCertificationDataChanges"
    ):
        return "ocr"
    return None


def _arr(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


def _str(v: Any) -> str:
    return v if isinstance(v, str) else "" if v is None else str(v)


def _obj(v: Mapping[str, Any], key: str) -> dict[str, Any]:
    """``v[key]`` when it is an object, else an empty one: package text is untrusted."""
    found = v.get(key)
    return found if isinstance(found, dict) else {}


def _strs(v: Any) -> list[str]:
    return [s for s in (_str(x) for x in _arr(v)) if s.strip()]


@dataclass
class Entry:
    """What the package reports for one KSI, FRR or control."""

    id: str
    status: str
    implementation: list[str] = field(default_factory=list)
    validation: list[str] = field(default_factory=list)
    assessment: list[str] = field(default_factory=list)
    evidence: list[dict[str, str]] = field(default_factory=list)
    parameters: list[dict[str, str]] = field(default_factory=list)

    @property
    def implemented(self) -> bool:
        # A missing or unrecognised status is never read as Implemented.
        return self.status == IMPLEMENTED


def _sdr_entries(
    sdr: Mapping[str, Any],
) -> tuple[dict[str, Entry], dict[str, Entry], dict[str, Entry], dict[str, list[str]]]:
    ksi: dict[str, Entry] = {}
    frr: dict[str, Entry] = {}
    ctl: dict[str, Entry] = {}
    unreadable: dict[str, list[str]] = {"controls": []}
    for k in _arr(sdr.get("keySecurityIndicators")):
        if not isinstance(k, dict):
            continue
        iid = _str(k.get("ksiId")).strip().upper()
        if iid:
            ksi[iid] = Entry(
                iid,
                _str(k.get("ksiImplementationStatus")),
                _strs(k.get("ksiImplementation")),
                _strs(k.get("ksiValidation")),
                _strs(k.get("ksiAssessment")),
                [
                    {
                        "type": _str(e.get("evidenceType")),
                        "description": _str(e.get("evidenceDescription")),
                        "location": _str(e.get("evidenceLocation")),
                        "updated": _str(e.get("lastUpdated")),
                    }
                    for e in _arr(k.get("ksiEvidence"))
                    if isinstance(e, dict)
                ],
            )
    for r in _arr(sdr.get("fedRampRequirements")):
        if not isinstance(r, dict):
            continue
        rid = _str(r.get("frrID")).strip().upper()
        if rid:
            frr[rid] = Entry(
                rid,
                _str(r.get("frrImplementationStatus")),
                _strs(r.get("frrImplementation")),
                _strs(r.get("frrValidation")),
                _strs(r.get("frrAssessment")),
            )
    for c in _arr(sdr.get("securityControls")):
        if not isinstance(c, dict):
            continue
        raw = c.get("controlId")
        cid = to_control(raw)
        if cid is None:
            if _str(raw).strip():
                unreadable["controls"].append(_str(raw))
            continue
        ctl[cid] = Entry(
            cid,
            _str(c.get("controlImplementationStatus")),
            _strs([c.get("controlImplementationDescription")]),
            parameters=[
                {"id": _str(p.get("parameterId")), "value": _str(p.get("parameterValue"))}
                for p in _arr(c.get("parameterValues"))
                if isinstance(p, dict)
            ],
        )
    return ksi, frr, ctl, unreadable


@dataclass
class Link:
    id: str
    name: str
    group: str
    statement: str
    entry: Entry | None


@dataclass
class ControlRow:
    id: str
    family: str
    title: str
    state: str
    ksi: list[Link]
    frr: list[Link]
    direct: Entry | None
    guidance: tuple[GuidancePart, ...]

    @property
    def mapped(self) -> int:
        return len(self.ksi) + len(self.frr)

    @property
    def reported(self) -> list[Link]:
        return [x for x in (*self.ksi, *self.frr) if x.entry is not None]

    @property
    def missing(self) -> list[str]:
        return [x.id for x in (*self.ksi, *self.frr) if x.entry is None]

    @property
    def weak(self) -> list[str]:
        out = [
            f"{x.id}: {x.entry.status or 'no status given'}"
            for x in self.reported
            if x.entry and not x.entry.implemented
        ]
        if self.direct is not None and not self.direct.implemented:
            out.append(f"{self.id}: {self.direct.status or 'no status given'}")
        return out


def coverage_state(direct: Entry | None, links: Sequence[Link]) -> str:
    """The one state for a control. See :data:`STATES` and the module docstring."""
    reported = [x for x in links if x.entry is not None]
    if any(not x.entry.implemented for x in reported if x.entry) or (
        direct is not None and not direct.implemented
    ):
        return "needs_review"
    if direct is not None:
        return "documented"
    if links and len(reported) == len(links):
        return "traced"
    if reported:
        return "partly_reported"
    if links:
        return "not_reported"
    return "no_mapping"


@dataclass
class Model:
    cls: str
    #: ``"Rev5"`` or ``"20x"`` as the package states it; ``None`` when it does not.
    certification_type: str | None
    #: ``"Program"`` or ``"Agency"`` when known (the provider preview); else ``None``.
    certification_path: str | None
    rules_version: str
    controls: list[ControlRow]
    counts: dict[str, int]
    completeness: dict[str, Any]
    unknown: dict[str, list[str]]
    outside_baseline: list[str]
    register: list[dict[str, Any]]
    identity: dict[str, str]
    #: The vulnerability documents (VDR, AVI, history) the package holds, by kind.
    #: Empty means there is no register to export, not an empty one.
    vulnerability_files: list[str] = field(default_factory=list)
    overview: dict[str, Any] | None = None
    ongoing: dict[str, Any] | None = None

    @property
    def total(self) -> int:
        return len(self.controls)

    @property
    def has_vulnerability_files(self) -> bool:
        return bool(self.vulnerability_files)


def identity(cpo: Mapping[str, Any] | None) -> dict[str, str]:
    s = (cpo or {}).get("serviceIdentification") or {}
    if not isinstance(s, dict):
        s = {}
    return {
        "package_id": _str(s.get("fedRampPackageId")),
        "provider": _str(s.get("providerName")),
        "service": _str(s.get("serviceName")),
        "acronym": _str(s.get("serviceAcronym")),
        "type": _str(s.get("certificationType")),
        "description": _str(s.get("serviceDescription")),
    }


def applicable_rules(
    ref: Reference, certification_type: str | None, cls: str, path: str | None = None
) -> list[str] | None:
    """The FedRAMP rules a provider of this type, class and path is expected to
    address, or ``None`` when the type is not known.

    From the type, class, path and affected-party metadata in the rules file. A
    path is applied only when known. Effective dates are not checked."""
    if certification_type is None:
        return None
    bucket = "rev5" if certification_type == "Rev5" else "20x"
    out = []
    for rid, r in ref.frr.items():
        if r.bucket not in ("all", bucket) or "Providers" not in r.affects:
            continue
        if r.types and certification_type not in r.types:
            continue
        if r.classes and cls.upper() not in r.classes:
            continue
        if path and r.paths and path not in r.paths:
            continue
        if "*" not in r.statements and cls.lower() not in r.statements:
            continue
        out.append(rid)
    return sorted(out)


def expected_ksis(
    certification_type: str | None, cls: str, path: str | None = None
) -> tuple[list[str] | None, list[str], str]:
    """(required, optional, basis) KSIs, from Concord's applicability.

    ``required`` is ``None`` when it cannot be known: the package does not
    state its type and no path is recorded. A Rev5 certification owes the
    control list (IVV-CSF-AIA), not indicators; so does any certification on
    a Rev5-only path, which :func:`applicability.for_class` decides."""
    if certification_type == "Rev5":
        return (
            [],
            [],
            (
                "A Rev5 certification owes the Rev5 control list (IVV-CSF-AIA), not Key Security "
                "Indicators; no indicator is expected."
            ),
        )
    if certification_type is None and path is None:
        return (
            None,
            [],
            (
                "The package does not state its certification type (it has no Certification "
                "Package Overview saying Rev5 or 20x), so which indicators it owes is not known. "
                "A Rev5 certification owes none."
            ),
        )
    scope = applicability.for_class(load_rules(), cls, path)
    required = sorted(
        k for k, a in scope.by_identifier.items() if a.status == applicability.REQUIRED
    )
    optional = sorted(
        k for k, a in scope.by_identifier.items() if a.status == applicability.OPTIONAL
    )
    return required, optional, scope.basis


def build_model(
    pkg: Mapping[str, Any],
    cls: str,
    *,
    path: str | None = None,
    ref: Reference | None = None,
) -> Model:
    """The whole derived view. ``pkg`` maps a kind of :data:`PACKAGE_KINDS` to its
    document; any may be missing. ``cls`` is B, C or D. ``path`` (program or
    agency) is passed when known -- the provider preview knows the system's."""
    ref = ref or reference()
    cls = (cls or "").strip().upper()
    if cls not in ref.baselines:
        raise CrosswalkError(
            f"FedRAMP publishes a Rev5 control baseline for Class {', '.join(ref.baselines)} only; "
            f"not for {cls or 'no class'}."
        )
    sdr = pkg.get("sdr") if isinstance(pkg.get("sdr"), dict) else {}
    cpo = pkg.get("cpo") if isinstance(pkg.get("cpo"), dict) else {}
    ident = identity(cpo)
    # Only what the package states: no CPO, or a type it does not name, is unknown.
    ctype = ident["type"] if ident["type"] in ("Rev5", "20x") else None
    path = path.strip().capitalize() if path and path.strip() else None
    ksi_in, frr_in, ctl_in, unreadable = _sdr_entries(sdr or {})
    unknown = {
        "ksi": sorted(k for k in ksi_in if k not in ref.ksi),
        "frr": sorted(r for r in frr_in if r not in ref.frr),
        "controls": unreadable["controls"],
    }
    baseline = ref.baselines[cls]
    counts = dict.fromkeys(STATES, 0)
    rows: list[ControlRow] = []
    for cid in baseline:
        k_ids, f_ids = ref.by_control.get(cid, ((), ()))
        ksi = [
            Link(k, ref.ksi[k].name, ref.ksi[k].group, ref.ksi[k].statement(cls), ksi_in.get(k))
            for k in k_ids
        ]
        frr = [
            Link(r, ref.frr[r].name, ref.frr[r].group, ref.frr[r].statement(cls), frr_in.get(r))
            for r in f_ids
        ]
        direct = ctl_in.get(cid)
        state = coverage_state(direct, [*ksi, *frr])
        counts[state] += 1
        rows.append(
            ControlRow(
                cid,
                cid.split("-", 1)[0],
                control_title(ref, cid),
                state,
                ksi,
                frr,
                direct,
                ref.guidance.get(cid, ()),
            )
        )
    required, optional, basis = expected_ksis(ctype, cls, path)
    rules = applicable_rules(ref, ctype, cls, path)
    completeness = {
        "ksi": {
            "expected": None if required is None else len(required),
            "reported": None if required is None else sum(1 for k in required if k in ksi_in),
            "missing": [] if required is None else [k for k in required if k not in ksi_in],
            "optional": optional,
            "basis": basis,
        },
        "frr": {
            "expected": None if rules is None else len(rules),
            "reported": None if rules is None else sum(1 for r in rules if r in frr_in),
            "missing": [] if rules is None else [r for r in rules if r not in frr_in],
            "path_applied": path is not None,
        },
    }
    inside = set(baseline)
    return Model(
        cls=cls,
        certification_type=ctype,
        certification_path=path,
        rules_version=ref.rules_version,
        controls=rows,
        counts=counts,
        completeness=completeness,
        unknown=unknown,
        outside_baseline=sorted((c for c in ctl_in if c not in inside), key=_control_sort),
        register=build_register(pkg),
        identity=ident,
        vulnerability_files=vulnerability_files(pkg),
        overview=package_overview(cpo or None),
        ongoing=ongoing_report(pkg.get("ocr") if isinstance(pkg.get("ocr"), dict) else None),
    )


def vulnerability_files(pkg: Mapping[str, Any]) -> list[str]:
    """Which vulnerability documents the package holds (VDR, AVI, history)."""
    return [k for k in VULNERABILITY_KINDS if isinstance(pkg.get(k), dict)]


VULNERABILITY_KINDS: tuple[str, ...] = ("vdr", "avi", "ver_history")


# ── package overview ─────────────────────────────────────────────────────────

_HTTP_URL = re.compile(r"https?://[^\s<>\"'`\\]+", re.IGNORECASE)


def safe_url(raw: Any) -> str | None:
    """``raw`` when it is an http(s) URL, else ``None``.

    Package text is untrusted: a ``javascript:`` or ``data:`` URL must never
    become a link. Anything else is shown as text, not as an ``href``."""
    text = _str(raw).strip()
    return text if _HTTP_URL.fullmatch(text) else None


def _text(v: Any) -> str:
    """Package text as a reader sees it: a string as written, an object as JSON."""
    if isinstance(v, str):
        return v
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False, sort_keys=True)
    return str(v)


def _items(v: Any) -> list[str] | None:
    """A list field's entries as text; ``None`` when the field is absent or not a
    list, so "not stated" and "none reported" stay different things."""
    if not isinstance(v, list):
        return None
    return [t for t in (_text(x) for x in v) if t.strip()]


def _repo(v: Any) -> dict[str, Any] | None:
    if not isinstance(v, dict):
        return None
    url = _str(v.get("url")).strip()
    auth = v.get("authenticationRequired")
    return {
        "url": url,
        "href": safe_url(url),
        "description": _str(v.get("repositoryDescription")),
        "auth_required": auth if isinstance(auth, bool) else None,
    }


def package_overview(cpo: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """What the Certification Package Overview says about the service, or ``None``
    when there is no overview. Every value is as the package states it; a field
    the package leaves out is empty, never filled in."""
    if not isinstance(cpo, dict) or not cpo:
        return None
    ident = identity(cpo)
    props = _obj(cpo, "serviceProperties")
    assessor = _obj(cpo, "assessor")
    third = _obj(cpo, "thirdPartyInformationResources")
    certified = [
        {
            "id": _str(t.get("fedRampCertifiedThirdPartyInformationResource")),
            "use_case": _str(t.get("useCase")),
        }
        for t in _arr(third.get("certified"))
        if isinstance(t, dict)
    ]
    non_certified = [
        {
            "name": _str(t.get("name")),
            "provider": _str(t.get("provider")),
            "use_case": _str(t.get("useCase")),
            "website": _str(t.get("website")),
            "href": safe_url(t.get("website")),
        }
        for t in _arr(third.get("nonCertified"))
        if isinstance(t, dict)
    ]
    return {
        **ident,
        "service_model": ", ".join(_strs(props.get("serviceType"))),
        "deployment_model": _str(props.get("deploymentModel")),
        "assessor": _str(assessor.get("name")),
        "assessor_id": _str(assessor.get("assessorID")),
        "next_ongoing_report": _str(props.get("nextOngoingCertificationReportDate")),
        "trust_center": _repo(props.get("trustCenter")),
        "secure_configuration": _repo(props.get("secureConfigurationGuidance")),
        "certified_third_party": certified if "certified" in third else None,
        "non_certified_third_party": non_certified if "nonCertified" in third else None,
    }


def ongoing_report(ocr: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """The latest Ongoing Certification Report, as stated, or ``None`` without one.

    A list the report omits is ``None`` (not stated); an empty one is ``[]``
    (none reported). The page says which."""
    if not isinstance(ocr, dict) or not ocr:
        return None
    period = _obj(ocr, "reportPeriod")
    planned = _obj(ocr, "plannedCertificationDataChanges")
    incidents_doc = _obj(ocr, "reportableIncidents")
    incidents = None
    if isinstance(incidents_doc.get("incidents"), list):
        incidents = [
            {
                "summary": _str(i.get("summary")),
                "occurred_at": _str(i.get("occurredAt")),
                "resolved_at": _str(i.get("resolvedAt")),
                "lessons": _items(i.get("incidentLessonsLearned")) or [],
            }
            for i in incidents_doc["incidents"]
            if isinstance(i, dict)
        ]
    accepted = ocr.get("acceptedVulnerabilities")
    return {
        "period_from": _str(period.get("from")),
        "period_to": _str(period.get("to")),
        "changes": _items(ocr.get("certificationDataChanges")),
        "planned": _items(planned.get("changes")),
        "planned_through": _str(planned.get("planningHorizonThrough")),
        "transformative": _items(ocr.get("transformativeChanges")),
        "accepted_vulnerabilities": accepted if isinstance(accepted, str) else "",
        "incidents": incidents,
        "recommendations": _items(ocr.get("updatedRecommendations")),
        "agencies": _items(ocr.get("activeAgencies")),
    }


#: How many schema errors a page lists per file before "and N more".
SHOWN_ERRORS = 25


def schema_errors(errors: Sequence[Any] | None, kept: int | None = None) -> dict[str, Any]:
    """A file's stored schema errors, split for display.

    Each error is ``"path: message"`` as :mod:`ccf.cr26.validation` writes it.
    ``kept`` is how many the store keeps; when a file has that many, more may
    have been dropped, and ``capped`` says so instead of claiming an exact count."""
    errs = [_text(e) for e in (errors or [])]
    shown = []
    for e in errs[:SHOWN_ERRORS]:
        path, sep, message = e.partition(": ")
        shown.append({"path": path, "message": message} if sep else {"path": "", "message": e})
    return {
        "count": len(errs),
        "shown": shown,
        "more": max(0, len(errs) - SHOWN_ERRORS),
        "capped": kept is not None and len(errs) >= kept,
    }


# ── vulnerability register ───────────────────────────────────────────────────

CLOSED_DISPOSITIONS = frozenset({"Remediated", "False Positive", "Fully Mitigated"})


def _doc_date(kind: str, doc: Mapping[str, Any]) -> str:
    """The date a vulnerability document speaks for, as the document writes it."""
    if kind == "ver_history":
        return _str(doc.get("generatedAt"))
    period = doc.get("reportPeriod")
    return _str(period.get("to")) if isinstance(period, dict) else ""


_OLDEST = datetime.min.replace(tzinfo=UTC)


def _instant(text: str) -> datetime:
    """An RFC 3339 date-time as an aware UTC instant, for ordering.

    Compared as text, ``...T23:59:59-04:00`` sorts before ``...T01:00:00Z`` the
    next day, which it follows, and ``.123Z`` before ``Z``. A date alone is
    midnight UTC; anything unreadable sorts as the oldest."""
    s = text.strip()
    if not s:
        return _OLDEST
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        return _OLDEST
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def _observations(
    pkg: Mapping[str, Any],
) -> Iterable[tuple[str, str, int, dict[str, Any], bool, str]]:
    """(date, kind, order, detail, accepted, rationale) for every vulnerability seen."""
    order = 0
    for kind in ("vdr", "avi", "ver_history"):
        doc = pkg.get(kind)
        if not isinstance(doc, dict):
            continue
        when = _doc_date(kind, doc)
        active = (
            _arr(doc.get("vulnerabilities"))
            if kind == "vdr"
            else _arr(doc.get("activeVulnerabilities"))
        )
        for v in active:
            order += 1
            if isinstance(v, dict):
                yield when, kind, order, v, False, ""
        for a in _arr(doc.get("acceptedVulnerabilities")):
            order += 1
            if isinstance(a, dict) and isinstance(a.get("vulnerabilityDetail"), dict):
                yield (
                    when,
                    kind,
                    order,
                    a["vulnerabilityDetail"],
                    True,
                    _str(a.get("acceptanceRationale")),
                )


def build_register(pkg: Mapping[str, Any]) -> list[dict[str, Any]]:
    """One row per provider tracking ID across VDR, AVI and history.

    The newest observation (by the document's own date; file order breaks a tie)
    decides every field, including whether the vulnerability is accepted. Every
    document it appeared in is listed."""
    seen: dict[str, list[tuple[str, int, str, dict[str, Any], bool, str]]] = {}
    for when, kind, order, v, accepted, why in _observations(pkg):
        tid = _str(v.get("providerTrackingId")).strip()
        if tid:
            seen.setdefault(tid, []).append((when, order, kind, v, accepted, why))
    rows: list[dict[str, Any]] = []
    for tid, obs in seen.items():
        when, _, kind, v, accepted, why = max(obs, key=lambda o: (_instant(o[0]), o[1]))
        disposition = _str(v.get("finalDisposition"))
        detection = _obj(v, "detection")
        reduction = _obj(v, "projectedNextReduction")
        overdue = _obj(v, "overdueStatus")
        rating = v.get("currentRating")
        target = reduction.get("targetRating")
        rows.append(
            {
                "id": tid,
                "status": "Accepted"
                if accepted
                else "Closed"
                if disposition in CLOSED_DISPOSITIONS
                else "Open",
                "description": _str(v.get("vulnerabilityDescription")),
                "impact": _str(v.get("potentialAgencyImpact")),
                "rating": rating
                if isinstance(rating, int) and not isinstance(rating, bool)
                else None,
                "detected_at": _str(detection.get("detectedAt")),
                "detection_source": _str(detection.get("detectionSource")),
                "evaluated_at": _str(v.get("evaluationCompletedAt")),
                "internet_reachable": v.get("isInternetReachable")
                if isinstance(v.get("isInternetReachable"), bool)
                else None,
                "likely_exploitable": v.get("isLikelyExploitable")
                if isinstance(v.get("isLikelyExploitable"), bool)
                else None,
                "next_reduction_at": _str(reduction.get("estimatedAt")),
                "next_reduction_target": target
                if isinstance(target, int) and not isinstance(target, bool)
                else None,
                "overdue": overdue.get("isOverdue") is True,
                "overdue_why": _str(overdue.get("explanation")),
                "disposition": disposition,
                "rationale": why,
                "supplementary": _str(v.get("supplementaryRiskInformation")),
                "as_of": when,
                "as_of_kind": kind,
                "sources": sorted({PACKAGE_KINDS[o[2]] for o in obs}),
            }
        )
    rank = {"Open": 0, "Accepted": 1, "Closed": 2}
    rows.sort(
        key=lambda r: (
            rank[r["status"]],
            -(r["rating"] if r["rating"] is not None else -1),
            r["id"],
        )
    )
    return rows


# ── exports ──────────────────────────────────────────────────────────────────


def _day(s: str) -> str:
    return s[:10] if len(s) >= 10 and s[4:5] == "-" and s[7:8] == "-" else s


def _yn(v: bool | None) -> str:
    return "Yes" if v is True else "No" if v is False else ""


def _agency_actions(row: ControlRow) -> str:
    return "\n".join(
        (f"({g.part}) " if g.part != "_" else "") + g.agency_actions
        for g in row.guidance
        if g.agency_actions
    )


def control_rows(model: Model) -> list[list[Any]]:
    head = [
        "Control",
        "Title",
        "Coverage",
        "Mapped KSIs",
        "Reported KSIs",
        "Mapped FedRAMP rules",
        "Reported FedRAMP rules",
        "Not reported",
        "Provider control status",
        "Provider statements",
        "Provider validation",
        "Independent assessment",
        "Evidence",
        "Agency actions (FedRAMP guidance)",
    ]
    out: list[list[Any]] = [head]
    for c in model.controls:
        rep = c.reported
        stmts: list[str] = []
        if c.direct and c.direct.implementation:
            stmts.extend(f"[{c.id}] {s}" for s in c.direct.implementation)
        for x in rep:
            if x.entry is None:
                continue
            stmts.extend(
                f"[{x.id}{' · ' + x.entry.status if x.entry.status else ''}] {s}"
                for s in x.entry.implementation
            )
        val = [f"[{x.id}] {s}" for x in rep if x.entry for s in x.entry.validation]
        asm = [f"[{x.id}] {s}" for x in rep if x.entry for s in x.entry.assessment]
        ev = [
            f"[{x.id}] "
            + " · ".join(
                p
                for p in (
                    e["type"],
                    e["description"],
                    e["location"],
                    e["updated"] and "updated " + e["updated"],
                )
                if p
            )
            for x in rep
            if x.entry
            for e in x.entry.evidence
        ]
        out.append(
            [
                c.id,
                c.title,
                STATES[c.state][0],
                ", ".join(k.id for k in c.ksi),
                ", ".join(k.id for k in c.ksi if k.entry),
                ", ".join(f.id for f in c.frr),
                ", ".join(f.id for f in c.frr if f.entry),
                ", ".join(c.missing),
                c.direct.status if c.direct else "",
                "\n\n".join(stmts),
                "\n\n".join(val),
                "\n\n".join(asm),
                "\n".join(ev),
                _agency_actions(c),
            ]
        )
    return out


def determination_rows(model: Model) -> list[list[Any]]:
    """Every control the package does not settle: what the agency must decide."""
    head = [
        "Control",
        "Title",
        "Coverage",
        "Why",
        "Mapped indicators and rules not reported",
        "Agency actions (FedRAMP guidance)",
    ]
    out: list[list[Any]] = [head]
    for c in model.controls:
        if c.state in ("documented", "traced"):
            continue
        why = "; ".join(c.weak) if c.state == "needs_review" else STATES[c.state][1]
        out.append(
            [c.id, c.title, STATES[c.state][0], why, ", ".join(c.missing), _agency_actions(c)]
        )
    return out


def register_rows(model: Model) -> list[list[Any]]:
    head = [
        "Provider tracking ID",
        "Status",
        "Description",
        "Potential agency impact",
        "N-rating",
        "Detected",
        "Detection source",
        "Evaluation completed",
        "Internet-reachable",
        "Likely exploitable",
        "Next reduction date",
        "Next reduction target N-rating",
        "Overdue",
        "Overdue explanation",
        "Final disposition",
        "Acceptance rationale",
        "Supplementary risk information",
        "As of",
        "Reported in",
    ]
    out: list[list[Any]] = [head]
    for v in model.register:
        out.append(
            [
                v["id"],
                v["status"],
                v["description"],
                v["impact"],
                "" if v["rating"] is None else v["rating"],
                _day(v["detected_at"]),
                v["detection_source"],
                _day(v["evaluated_at"]),
                _yn(v["internet_reachable"]),
                _yn(v["likely_exploitable"]),
                _day(v["next_reduction_at"]),
                "" if v["next_reduction_target"] is None else v["next_reduction_target"],
                "Yes" if v["overdue"] else "No",
                v["overdue_why"],
                v["disposition"],
                v["rationale"],
                v["supplementary"],
                _day(v["as_of"]),
                "; ".join(v["sources"]),
            ]
        )
    return out


def _safe_cell(v: Any) -> str:
    """Package text never runs as a spreadsheet formula."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def to_csv(rows: Sequence[Sequence[Any]]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    for r in rows:
        writer.writerow([_safe_cell(v) for v in r])
    return "﻿" + buf.getvalue()


# ── review workbook (xlsx) ───────────────────────────────────────────────────

#: Characters XML 1.0 cannot carry; openpyxl refuses a cell holding one.
_XML_ILLEGAL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")

#: Excel's cell limit is 32,767 characters; stay under it and say so.
MAX_CELL_CHARS = 32000

XLSX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def _xlsx_cell(v: Any) -> Any:
    """A cell value that is never a formula and is always valid XML.

    Illegal characters are stripped *before* the formula check, so
    ``"\\x01=HYPERLINK(...)"`` cannot shed its first character and become one."""
    if isinstance(v, int) and not isinstance(v, bool):
        return v
    s = _safe_cell(_XML_ILLEGAL.sub("", "" if v is None else str(v)))
    if len(s) > MAX_CELL_CHARS:
        s = s[:MAX_CELL_CHARS] + f" … [cut: {len(s)} characters in the package]"
    return s


def _count(n: int | None, of: int | None) -> str:
    return "not known" if n is None or of is None else f"{n} of {of}"


def workbook_sheets(model: Model, generated: datetime) -> list[tuple[str, list[list[Any]]]]:
    """The review workbook as (sheet name, rows); the first row of each is its header."""
    i = model.identity
    k, f = model.completeness["ksi"], model.completeness["frr"]
    if not model.has_vulnerability_files:
        vulns = (
            "The package holds no vulnerability files (VDR, accepted-vulnerability or history); "
            "the register sheet is empty."
        )
    else:
        vulns = f"{len(model.register)} provider tracking IDs"
    summary: list[list[Any]] = [
        ["Field", "Value"],
        ["Provider", i["provider"]],
        ["Service", i["service"]],
        ["FedRAMP package ID", i["package_id"]],
        ["Certification type", model.certification_type or "not stated in the package"],
        ["Certification path", model.certification_path or "not known"],
        [
            "Baseline compared against",
            f"Rev5 Class {model.cls} (FRC-CSF-BSL), {model.total} controls",
        ],
        ["FedRAMP rules version", model.rules_version],
        ["Generated", utc_stamp(generated)],
        *([STATES[s][0], model.counts[s]] for s in STATES),
        ["Key Security Indicators reported (required)", _count(k["reported"], k["expected"])],
        ["FedRAMP rules reported (applicable)", _count(f["reported"], f["expected"])],
        ["Vulnerability register", vulns],
        ["How to read this", NOTICE],
    ]
    return [
        ("Summary", summary),
        ("Control inheritance", control_rows(model)),
        ("Agency determinations", determination_rows(model)),
        ("Vulnerability register", register_rows(model)),
    ]


_WIDTHS: dict[str, list[int]] = {
    "Summary": [44, 100],
    "Control inheritance": [12, 40, 16, 28, 28, 28, 28, 28, 18, 70, 50, 50, 50, 60],
    "Agency determinations": [12, 40, 16, 50, 40, 70],
    "Vulnerability register": [22, 10, 60, 50, 10, 12, 30, 12, 10, 10, 12, 10, 8, 30, 16, 50, 40],
}


def to_xlsx(sheets: Sequence[tuple[str, Sequence[Sequence[Any]]]], generated: datetime) -> bytes:
    """A workbook: one sheet per entry, bold frozen header, wrapped cells."""
    from openpyxl import Workbook  # noqa: PLC0415 -- only the export needs it
    from openpyxl.styles import Alignment, Font  # noqa: PLC0415
    from openpyxl.utils import get_column_letter  # noqa: PLC0415

    wb = Workbook()
    wb.remove(wb.active)
    wb.properties.creator = "Concord"
    wb.properties.created = wb.properties.modified = generated.replace(tzinfo=None)
    bold, wrap = Font(bold=True), Alignment(vertical="top", wrap_text=True)
    for name, rows in sheets:
        ws = wb.create_sheet(_XML_ILLEGAL.sub("", name)[:31])
        for r in rows:
            ws.append([_xlsx_cell(v) for v in r])
        for cell in ws[1]:
            cell.font = bold
        for row in ws.iter_rows(min_row=2):
            for cell in row:
                cell.alignment = wrap
        ws.freeze_panes = "A2"
        for n, w in enumerate(_WIDTHS.get(name, []), start=1):
            ws.column_dimensions[get_column_letter(n)].width = w
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


# ── OSCAL 1.1.2 exports ──────────────────────────────────────────────────────
#
# Both are skeletons an agency starts from, never a statement that a control is
# satisfied. Where upstream asserted more than the package says, Concord does
# not (see the design's "OSCAL exports" section):
#
# * Implementation status: only Implemented -> implemented and Partially
#   Implemented -> partial. Any other status ("Not Implemented", none, anything
#   unrecognised) leaves ``implementation-status`` out -- it is optional -- and
#   the provider's own words go in a prop. Upstream wrote ``planned`` for "Not
#   Implemented", a plan nobody stated.
# * A Partly reported control is never ``implemented``: upstream called a
#   control implemented when every *reported* entry was, however many mapped
#   entries were missing.
# * No ``inherited`` claim: the package does not say what an agency inherits.
# * An accepted vulnerability is ``open``, not ``deviation-approved``: the
#   package records the provider's acceptance, not an approval by anyone.
# * A missing or malformed detection time is not replaced by the export time;
#   that vulnerability has no observation, and its item says why.

OSCAL_VERSION = "1.1.2"
PROP_NS = "urn:concord:crosswalk20x"
TO_COMPLETE = "AGENCY TO COMPLETE"
OSCAL_STATUS: dict[str, str] = {
    IMPLEMENTED: "implemented",
    "Partially Implemented": "partial",
}
#: Register status -> OSCAL risk status. "Accepted" is the provider accepting
#: the risk; nothing in the package shows a deviation was requested of, or
#: approved by, an authorizing official. The risk is still present, so it is
#: ``open``, and the provider's word is kept in the ``provider-status`` prop.
RISK_STATUS: dict[str, str] = {"Open": "open", "Accepted": "open", "Closed": "closed"}
_OSCAL_DT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})")
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_.\-]*")


def utc_stamp(generated: datetime) -> str:
    if generated.tzinfo is None:
        raise CrosswalkError("the export time must be timezone-aware")
    return generated.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _oscal_dt(text: str) -> str | None:
    """``text`` when it is an OSCAL date-time with a zone (and a real one)."""
    s = text.strip()
    if not _OSCAL_DT.fullmatch(s) or _instant(s) is _OLDEST:
        return None
    return s


def _line(text: str) -> str:
    """One line, no surrounding space: what OSCAL's string and markup-line allow."""
    return " ".join(_XML_ILLEGAL.sub(" ", text).split())


def _prop(name: str, value: str, cls: str | None = None) -> dict[str, str] | None:
    v = _line(value)
    if not v:
        return None
    out = {"name": name, "ns": PROP_NS, "value": v}
    if cls:
        out["class"] = cls
    return out


def _props(*items: dict[str, str] | None) -> list[dict[str, str]]:
    return [p for p in items if p]


def _uuids(seed: str) -> Any:
    def make(name: str) -> str:
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{seed}:{name}"))

    return make


def _seed(model: Model, scope: str, what: str) -> str:
    i = model.identity
    return f"concord-crosswalk20x:{scope}:{i['package_id'] or i['service']}:{model.cls}:{what}"


def oscal_status(row: ControlRow) -> tuple[str | None, str]:
    """(OSCAL implementation state or ``None``, why), from the provider's statuses.

    ``None`` means the state is left out of the export. Never ``planned``;
    never ``implemented`` unless the control is Documented or Traced."""
    statuses = ([row.direct.status] if row.direct else []) + [
        x.entry.status for x in row.reported if x.entry
    ]
    if not statuses:
        return None, "The package reports nothing for this control."
    other = sorted({s or "no status given" for s in statuses if s not in OSCAL_STATUS})
    if other:
        return None, (
            f"No implementation status is exported: the provider reports {', '.join(other)}, "
            "which no OSCAL implementation state expresses without asserting more than the "
            "package says."
        )
    if "Partially Implemented" in statuses:
        return "partial", "The provider reports at least one entry as Partially Implemented."
    if row.state in ("documented", "traced"):
        return "implemented", "Every entry the provider reports for this control is Implemented."
    return None, (
        "No implementation status is exported: the entries reported are Implemented, but "
        f"{', '.join(row.missing)} {'is' if len(row.missing) == 1 else 'are'} not reported, so "
        "the control is not shown as implemented."
    )


def _by_component(row: ControlRow, component: str, u: Any) -> dict[str, Any] | None:
    reported = row.reported
    if row.direct is None and not reported:
        return None
    parts: list[str] = []
    status_props: list[dict[str, str] | None] = []
    if row.direct is not None:
        status_props.append(
            _prop("provider-status", f"{row.id}: {row.direct.status or 'no status given'}")
        )
        text = " ".join(row.direct.implementation)
        parts.append(
            f"{row.id} (provider control entry, {row.direct.status or 'no status given'}): "
            f"{text or 'No implementation statement given.'}"
        )
    links: list[dict[str, str]] = []
    for x in reported:
        if x.entry is None:
            continue
        status_props.append(
            _prop("provider-status", f"{x.id}: {x.entry.status or 'no status given'}")
        )
        parts.append(
            f"{x.id} {x.name} ({x.entry.status or 'no status given'}): "
            f"{' '.join(x.entry.implementation) or 'No implementation statement given.'}"
        )
        for e in x.entry.evidence:
            href = safe_url(e["location"])
            if href:
                text = _line(f"{x.id}: {e['description'] or e['type'] or 'evidence'}")[:300]
                links.append({"href": href, "rel": "evidence", "text": text})
    state, why = oscal_status(row)
    by: dict[str, Any] = {
        "component-uuid": component,
        "uuid": u(f"by:{row.id}"),
        "description": "\n\n".join(parts),
        "props": _props(*status_props),
    }
    if state is not None:
        by["implementation-status"] = {
            "state": state,
            "remarks": (
                f"{why} Status as the provider reports it for the entries listed; not a "
                "statement that the control is satisfied for the agency system."
            ),
        }
    else:
        by["remarks"] = why
    params = [
        {"param-id": p["id"].strip(), "values": [_line(p["value"])]}
        for p in (row.direct.parameters if row.direct else [])
        if _TOKEN.fullmatch(p["id"].strip()) and _line(p["value"])
    ]
    if params:
        by["set-parameters"] = params
    if links:
        by["links"] = links
    if not by["props"]:
        del by["props"]
    return by


def oscal_ssp(model: Model, *, generated: datetime, scope: str) -> dict[str, Any]:
    """An OSCAL 1.1.2 SSP skeleton for the *agency* system that uses the service.

    The cloud service is one component; each baseline control carries what the
    package reports for it. Agency fields read :data:`TO_COMPLETE`. UUIDs are
    deterministic (``uuid5``) in ``scope`` and the package, so a re-export
    gives the same IDs."""
    i = model.identity
    u = _uuids(_seed(model, scope, "ssp"))
    cso, this, party, profile, user = u("cso"), u("this"), u("party"), u("profile"), u("user")
    reqs: list[dict[str, Any]] = []
    for c in model.controls:
        req: dict[str, Any] = {
            "uuid": u(f"req:{c.id}"),
            "control-id": canonical_to_oscal_id(c.id),
            "props": _props(
                _prop("coverage", c.state),
                *(
                    _prop("mapped-ksi", x.id, "reported" if x.entry else "not-reported")
                    for x in c.ksi
                ),
                *(
                    _prop("mapped-rule", x.id, "reported" if x.entry else "not-reported")
                    for x in c.frr
                ),
            ),
        }
        by = _by_component(c, cso, u)
        if by is not None:
            req["by-components"] = [by]
        remarks = []
        if c.state not in ("documented", "traced"):
            remarks.append(f"{STATES[c.state][1]} Agency determination required.")
        actions = _agency_actions(c)
        if actions:
            remarks.append(f"Agency actions per FedRAMP agency control guidance:\n{actions}")
        if remarks:
            req["remarks"] = "\n\n".join(remarks)
        reqs.append(req)
    coverage = ", ".join(f"{model.counts[s]} {STATES[s][0].lower()}" for s in STATES)
    service = _line(i["service"]) or "Cloud service offering"
    provider = _line(i["provider"]) or "Cloud service provider"
    return {
        "system-security-plan": {
            "uuid": u("doc"),
            "metadata": {
                "title": f"Agency SSP skeleton: use of {service} ({provider})",
                "last-modified": utc_stamp(generated),
                "version": "1.0",
                "oscal-version": OSCAL_VERSION,
                "roles": [{"id": "provider", "title": "Cloud Service Provider"}],
                "parties": [{"uuid": party, "type": "organization", "name": provider}],
                "responsible-parties": [{"role-id": "provider", "party-uuids": [party]}],
                "remarks": (
                    f"{NOTICE} Generated {utc_stamp(generated)} from FedRAMP package "
                    f"{i['package_id'] or '(no package ID)'} against the Rev5 Class {model.cls} "
                    f'baseline. Fields reading "{TO_COMPLETE}" describe the agency system '
                    "and are not in the package. Implementation status is exported only where "
                    "the provider reports Implemented or Partially Implemented and every mapped "
                    "entry is reported; elsewhere it is left out and the provider's status is "
                    "kept in a provider-status prop."
                ),
            },
            "import-profile": {
                "href": f"#{profile}",
                "remarks": (
                    "FedRAMP publishes this baseline as a control list (FRC-CSF-BSL), not as "
                    "an OSCAL profile."
                ),
            },
            "system-characteristics": {
                "system-ids": [{"id": TO_COMPLETE}],
                "system-name": TO_COMPLETE,
                "description": TO_COMPLETE,
                "system-information": {
                    "information-types": [{"title": TO_COMPLETE, "description": TO_COMPLETE}]
                },
                "status": {"state": "other", "remarks": TO_COMPLETE},
                "authorization-boundary": {"description": TO_COMPLETE},
            },
            "system-implementation": {
                "users": [{"uuid": user, "title": TO_COMPLETE}],
                "components": [
                    {
                        "uuid": this,
                        "type": "this-system",
                        "title": TO_COMPLETE,
                        "description": "The agency information system that uses the service.",
                        "status": {"state": "other", "remarks": TO_COMPLETE},
                    },
                    {
                        "uuid": cso,
                        "type": "system",
                        "title": service,
                        "description": (
                            i["description"] or "FedRAMP certified cloud service offering."
                        )[:4000],
                        "props": _props(
                            _prop("fedramp-package-id", i["package_id"]),
                            _prop("certification-type", model.certification_type or "not stated"),
                            {"name": "implementation-point", "value": "external"},
                        ),
                        "status": {
                            "state": "other",
                            "remarks": "The package does not state an operational status.",
                        },
                        "responsible-roles": [{"role-id": "provider", "party-uuids": [party]}],
                    },
                ],
            },
            "control-implementation": {
                "description": (
                    f"Controls in the FedRAMP Rev5 Class {model.cls} baseline, each with what "
                    f"the provider's certification package reports for it. Coverage: {coverage}."
                ),
                "implemented-requirements": reqs,
            },
            "back-matter": {
                "resources": [
                    {
                        "uuid": profile,
                        "title": f"FedRAMP Rev5 Class {model.cls} baseline (FRC-CSF-BSL)",
                        "description": (
                            "Control list from the FedRAMP Consolidated Rules, version "
                            f"{model.rules_version}."
                        ),
                        "rlinks": [
                            {
                                "href": "https://github.com/FedRAMP/rules/blob/main/"
                                "fedramp-consolidated-rules.json"
                            }
                        ],
                    }
                ]
            },
        }
    }


def oscal_poam(model: Model, *, generated: datetime, scope: str) -> dict[str, Any]:
    """An OSCAL 1.1.2 POA&M of the provider's vulnerability register.

    Refused (``CrosswalkError``) when the package has no vulnerability files or
    they list nothing: OSCAL requires at least one item, and an empty plan
    would read as "nothing to remediate"."""
    if not model.has_vulnerability_files:
        raise CrosswalkError(
            "The package holds no vulnerability files (VDR, accepted-vulnerability or "
            "history), so there is no register to export."
        )
    if not model.register:
        raise CrosswalkError(
            "The package's vulnerability files list no vulnerabilities; an OSCAL POA&M "
            "needs at least one item."
        )
    i = model.identity
    u = _uuids(_seed(model, scope, "poam"))
    observations: list[dict[str, Any]] = []
    risks: list[dict[str, Any]] = []
    items: list[dict[str, Any]] = []
    for v in model.register:
        oid, rid, pid = u(f"obs:{v['id']}"), u(f"risk:{v['id']}"), u(f"item:{v['id']}")
        title = f"{_line(v['id'])}: {_line(v['description'])[:120] or 'Vulnerability'}"
        description = v["description"] or "No description given."
        collected = _oscal_dt(v["detected_at"])
        item_remarks: list[str] = []
        if collected:
            observations.append(
                {
                    "uuid": oid,
                    "title": title,
                    "description": description,
                    "methods": ["UNKNOWN"],
                    "types": ["finding"],
                    "collected": collected,
                    **(
                        {"remarks": f"Detection source: {v['detection_source']}."}
                        if v["detection_source"]
                        else {}
                    ),
                }
            )
        else:
            item_remarks.append(
                "No observation is exported for this vulnerability: the package gives no "
                f"valid detection time (detectedAt {v['detected_at']!r}), and none is "
                "substituted."
            )
        risk: dict[str, Any] = {
            "uuid": rid,
            "title": title,
            "description": description,
            "statement": v["impact"] or "No potential agency impact statement given.",
            "props": _props(
                _prop("provider-tracking-id", v["id"]),
                _prop("provider-status", v["status"]),
                _prop(
                    "potential-agency-impact-n-rating",
                    "" if v["rating"] is None else str(v["rating"]),
                ),
                _prop("internet-reachable", _yn(v["internet_reachable"]).lower()),
                _prop("likely-exploitable", _yn(v["likely_exploitable"]).lower()),
                _prop("overdue", "yes" if v["overdue"] else "no"),
                _prop("final-disposition", v["disposition"]),
                _prop("next-reduction-estimated-at", v["next_reduction_at"]),
            ),
            "status": RISK_STATUS[v["status"]],
        }
        if collected:
            risk["related-observations"] = [{"observation-uuid": oid}]
        risks.append(risk)
        if v["status"] == "Accepted":
            item_remarks.append(
                "The provider reports this vulnerability as accepted. The package does not "
                "show that a deviation was requested of or approved by an authorizing official."
            )
        for label, text in (
            ("Acceptance rationale", v["rationale"]),
            ("Supplementary risk information", v["supplementary"]),
            ("Overdue", v["overdue_why"]),
        ):
            if text:
                item_remarks.append(f"{label}: {text}")
        item: dict[str, Any] = {
            "uuid": pid,
            "title": title,
            "description": description,
            "props": _props(_prop("provider-status", v["status"])),
            "related-risks": [{"risk-uuid": rid}],
        }
        if collected:
            item["related-observations"] = [{"observation-uuid": oid}]
        if item_remarks:
            item["remarks"] = "\n\n".join(item_remarks)
        items.append(item)
    doc: dict[str, Any] = {
        "uuid": u("doc"),
        "metadata": {
            "title": (
                f"Provider vulnerability register: {_line(i['service']) or 'cloud service'} "
                f"({_line(i['provider']) or 'provider'})"
            ),
            "last-modified": utc_stamp(generated),
            "version": "1.0",
            "oscal-version": OSCAL_VERSION,
            "remarks": (
                f"{NOTICE} Built from the provider's vulnerability files "
                f"({', '.join(PACKAGE_KINDS[k] for k in model.vulnerability_files)}). Ratings "
                "are FedRAMP Potential Agency Impact N-ratings as reported, not converted to "
                "Low/Moderate/High. An accepted vulnerability is exported as open: acceptance "
                "is the provider's, not an approval."
            ),
        },
        "system-id": {
            "identifier-type": "https://fedramp.gov",
            "id": _line(i["package_id"]) or TO_COMPLETE,
        },
    }
    if observations:
        doc["observations"] = observations
    doc["risks"] = risks
    doc["poam-items"] = items
    return {"plan-of-action-and-milestones": doc}
