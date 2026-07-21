"""Parse vulnerability-scan exports and reconcile them into POA&Ms.

Supported formats
-----------------
* ``nessus`` / ``tenable`` — Nessus ``.nessus`` XML (``NessusClientData_v2``).
* ``inspector`` — AWS Inspector v2 findings JSON (``{"findings": [...]}`` or a
  bare list).
* ``csv`` — a generic CSV with fuzzy header matching; also the path for Qualys
  VM CSV exports (pass ``scanner="qualys"``).

Everything normalizes to :class:`ScanFinding`. :func:`reconcile_findings` is the
POA&M reconciliation: it is deterministic and idempotent — re-ingesting the same
scan produces no changes, an improved scan auto-closes fixed findings, and a
regressed scan reopens them.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import POAM

# Remediation SLA (days from identification) by normalized severity. Aligned to
# FedRAMP timelines (High 30 / Moderate 90 / Low 180); Critical is tightened.
SEVERITY_SLA_DAYS: dict[str, int] = {
    "critical": 15,
    "high": 30,
    "moderate": 90,
    "low": 180,
}

# Scanner labels that share the generic CSV parser.
_CSV_SCANNERS = {"csv", "qualys"}


@dataclass
class ScanFinding:
    """One normalized vulnerability finding from any supported scanner."""

    scanner: str
    native_id: str  # plugin id / CVE / QID / finding arn — stable per finding type
    title: str
    severity: str  # low | moderate | high | critical
    asset: str = ""  # host / IP / cloud resource the finding was seen on
    description: str = ""
    solution: str = ""
    refs: list[str] = field(default_factory=list)  # CVE ids etc.

    def fingerprint(self) -> str:
        """Stable id for dedup within a system: scanner + finding type + asset."""
        raw = f"{self.scanner}|{self.native_id}|{self.asset}".encode()
        return hashlib.sha256(raw).hexdigest()[:32]


# --- severity normalization --------------------------------------------------

_SEVERITY_WORDS = {
    "critical": "critical",
    "crit": "critical",
    "high": "high",
    "important": "high",
    "medium": "moderate",
    "moderate": "moderate",
    "med": "moderate",
    "low": "low",
    "minor": "low",
}
# Nessus/Tenable numeric risk factor (0..4).
_NESSUS_NUM = {0: "info", 1: "low", 2: "moderate", 3: "high", 4: "critical"}


def normalize_severity(raw: object) -> str | None:
    """Map a scanner severity (word, Nessus 0-4, or CVSS float) to our scale.

    Returns ``None`` for informational/none — those do not warrant a POA&M.
    """
    if raw is None or isinstance(raw, bool):  # bool guard: it is an int subclass
        return None
    if isinstance(raw, int | float):
        return _sev_from_number(float(raw))
    text = str(raw).strip().lower()
    if not text or text in ("none", "info", "informational", "0"):
        return None
    if text in _SEVERITY_WORDS:
        return _SEVERITY_WORDS[text]
    # A bare number in a string (Nessus severity or CVSS score).
    try:
        return _sev_from_number(float(text))
    except ValueError:
        return None


def _sev_from_number(n: float) -> str | None:
    # Nessus risk factor is 0-4; CVSS is 0-10. Both are covered by these bands
    # because 4 (Nessus critical) also lands in the CVSS "moderate" range — so
    # treat the small-integer Nessus scale explicitly first.
    if n == int(n) and 0 <= n <= 4:
        sev = _NESSUS_NUM[int(n)]
        return None if sev == "info" else sev
    if n >= 9.0:
        return "critical"
    if n >= 7.0:
        return "high"
    if n >= 4.0:
        return "moderate"
    if n > 0.0:
        return "low"
    return None


# --- parsers -----------------------------------------------------------------


def detect_format(filename: str | None, data: bytes) -> str:
    """Best-effort format sniff for ``scanner="auto"``."""
    head = data[:4096].lstrip()
    name = (filename or "").lower()
    if head[:1] in (b"{", b"[") or name.endswith(".json"):
        return "inspector"
    if b"NessusClientData" in data[:8192] or name.endswith(".nessus"):
        return "nessus"
    if head[:5] == b"<?xml" or head[:1] == b"<":
        return "nessus"
    return "csv"


def parse_scan(
    scanner: str, data: bytes, filename: str | None = None
) -> tuple[str, list[ScanFinding]]:
    """Dispatch to the right parser; returns ``(resolved_scanner, findings)``."""
    resolved = scanner.strip().lower()
    if resolved in ("auto", ""):
        resolved = detect_format(filename, data)
    if resolved in ("nessus", "tenable"):
        return resolved, parse_nessus(data, scanner=resolved)
    if resolved == "inspector":
        return resolved, parse_inspector(data)
    if resolved in _CSV_SCANNERS:
        return resolved, parse_csv(data, scanner=resolved)
    raise ValueError(f"unsupported scanner format: {scanner!r}")


def parse_nessus(data: bytes, *, scanner: str = "nessus") -> list[ScanFinding]:
    """Parse a Nessus ``.nessus`` v2 XML export."""
    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        raise ValueError(f"invalid Nessus XML: {e}") from e
    out: list[ScanFinding] = []
    for host in root.iter("ReportHost"):
        asset = host.get("name", "")
        for item in host.findall("ReportItem"):
            sev = normalize_severity(item.get("severity"))
            if sev is None:  # informational — skip
                continue
            plugin_id = item.get("pluginID", "")
            title = item.get("pluginName") or f"Plugin {plugin_id}"
            cves = [c.text.strip() for c in item.findall("cve") if c.text]
            out.append(
                ScanFinding(
                    scanner=scanner,
                    native_id=plugin_id or (cves[0] if cves else title),
                    title=title,
                    severity=sev,
                    asset=asset,
                    description=_first_text(item, "synopsis", "description"),
                    solution=_first_text(item, "solution"),
                    refs=cves,
                )
            )
    return out


def _first_text(item: ET.Element, *tags: str) -> str:
    for tag in tags:
        el = item.find(tag)
        if el is not None and el.text:
            return el.text.strip()
    return ""


def parse_inspector(data: bytes) -> list[ScanFinding]:
    """Parse AWS Inspector v2 findings JSON."""
    try:
        doc = json.loads(data)
    except json.JSONDecodeError as e:
        raise ValueError(f"invalid Inspector JSON: {e}") from e
    findings = doc.get("findings", doc) if isinstance(doc, dict) else doc
    if not isinstance(findings, list):
        raise ValueError("Inspector JSON: expected a 'findings' list")
    out: list[ScanFinding] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        sev = normalize_severity(f.get("severity"))
        if sev is None:
            continue
        vuln = (f.get("packageVulnerabilityDetails") or {}).get("vulnerabilityId")
        resources = f.get("resources") or []
        asset = ""
        if resources and isinstance(resources[0], dict):
            asset = str(resources[0].get("id", ""))
        remediation = ((f.get("remediation") or {}).get("recommendation") or {}).get("text", "")
        out.append(
            ScanFinding(
                scanner="inspector",
                native_id=str(vuln or f.get("findingArn") or f.get("title", "")),
                title=str(f.get("title", "")) or "Inspector finding",
                severity=sev,
                asset=asset,
                description=str(f.get("description", "")),
                solution=str(remediation),
                refs=[vuln] if vuln else [],
            )
        )
    return out


# CSV header aliases (lower-cased) → normalized field.
_CSV_ALIASES: dict[str, tuple[str, ...]] = {
    "title": ("title", "name", "plugin_name", "pluginname", "synopsis", "vulnerability"),
    "severity": ("severity", "risk", "risk_factor", "criticality", "cvss", "cvss3", "cvss_base"),
    "description": ("description", "details", "synopsis", "threat"),
    "asset": ("asset", "host", "hostname", "ip", "ip_address", "resource", "dns"),
    "native_id": ("plugin_id", "pluginid", "qid", "cve", "finding_id", "id"),
    "solution": ("solution", "remediation", "fix", "recommendation"),
}


def parse_csv(data: bytes, *, scanner: str = "csv") -> list[ScanFinding]:
    """Parse a generic / Qualys CSV with fuzzy header matching."""
    text = data.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return []
    # Map each normalized field to the first matching real column.
    lower = {(h or "").strip().lower(): h for h in reader.fieldnames}
    colmap: dict[str, str] = {}
    for field_name, aliases in _CSV_ALIASES.items():
        for alias in aliases:
            if alias in lower:
                colmap[field_name] = lower[alias]
                break
    def cell(row: dict[str, str], field_name: str) -> str:
        col = colmap.get(field_name)
        return (row.get(col) or "").strip() if col else ""

    out: list[ScanFinding] = []
    for i, row in enumerate(reader):
        sev = normalize_severity(cell(row, "severity"))
        if sev is None:
            continue
        title = cell(row, "title") or "Unnamed finding"
        native = cell(row, "native_id") or f"row-{i}"
        out.append(
            ScanFinding(
                scanner=scanner,
                native_id=native,
                title=title,
                severity=sev,
                asset=cell(row, "asset"),
                description=cell(row, "description"),
                solution=cell(row, "solution"),
                refs=[native] if native.upper().startswith("CVE-") else [],
            )
        )
    return out


# --- reconciliation ----------------------------------------------------------


@dataclass
class ReconcileResult:
    findings_total: int = 0
    created: int = 0
    updated: int = 0
    reopened: int = 0
    closed: int = 0
    unchanged: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "findings_total": self.findings_total,
            "created": self.created,
            "updated": self.updated,
            "reopened": self.reopened,
            "closed": self.closed,
            "unchanged": self.unchanged,
        }


_OPEN_STATES = ("open", "in_progress")
_RESOLVED_STATES = ("completed", "closed", "risk_accepted")


def _weakness(f: ScanFinding) -> str:
    parts = [f.description.strip()]
    if f.refs:
        parts.append("Refs: " + ", ".join(f.refs))
    if f.asset:
        parts.append(f"Asset: {f.asset}")
    if f.solution:
        parts.append(f"Remediation: {f.solution}")
    return "\n".join(p for p in parts if p) or f.title


async def reconcile_findings(
    session: AsyncSession,
    *,
    system_id: int,
    scanner: str,
    findings: list[ScanFinding],
    today: date | None = None,
) -> ReconcileResult:
    """Reconcile parsed findings into POA&Ms for ``system_id`` (idempotent).

    New findings open POA&Ms; recurring ones update in place or reopen if they
    had been resolved; previously-open findings absent from this scan are
    auto-closed. Does not commit — the caller owns the transaction.
    """
    today = today or datetime.now(UTC).date()
    res = ReconcileResult(findings_total=len(findings))

    existing = (
        (
            await session.execute(
                select(POAM).where(
                    POAM.system_id == system_id,
                    POAM.scanner == scanner,
                    POAM.finding_uid.is_not(None),
                )
            )
        )
        .scalars()
        .all()
    )
    by_uid: dict[str, POAM] = {p.finding_uid: p for p in existing if p.finding_uid}
    seen: set[str] = set()

    for f in findings:
        uid = f.fingerprint()
        if uid in seen:  # duplicate finding line in the same file — collapse
            continue
        seen.add(uid)
        due = today + timedelta(days=SEVERITY_SLA_DAYS.get(f.severity, 90))
        weakness = _weakness(f)
        title = f.title[:512]
        poam = by_uid.get(uid)
        if poam is None:
            session.add(
                POAM(
                    system_id=system_id,
                    title=title,
                    weakness=weakness,
                    severity=f.severity,
                    status="open",
                    source="scan",
                    scanner=scanner,
                    finding_uid=uid,
                    identified_on=today,
                    due_on=due,
                    original_due_on=due,
                )
            )
            res.created += 1
        elif poam.status in _RESOLVED_STATES:
            poam.status = "open"
            poam.closed_on = None
            poam.severity = f.severity
            poam.weakness = weakness
            poam.due_on = due
            res.reopened += 1
        else:
            changed = (
                poam.severity != f.severity
                or poam.weakness != weakness
                or poam.title != title
            )
            poam.severity = f.severity
            poam.weakness = weakness
            poam.title = title
            if changed:
                res.updated += 1
            else:
                res.unchanged += 1

    # Auto-close open POA&Ms whose finding no longer appears in the latest scan.
    # ACCEPTED EXCEPTION to the interactive POA&M closure gate / separation-of-duties
    # (ISSM-08/09, enforced in api/routes/poams.py): scan absence is itself the
    # remediation evidence, and this is an automated, non-interactive path. The
    # closure is auditable — every auto-closed POA&M is stamped with the scanner +
    # date note below (and, via the API layer, the audit_log). It deliberately does
    # not require a milestone/evidence artifact or a separate approver.
    for uid, poam in by_uid.items():
        if uid in seen or poam.status not in _OPEN_STATES:
            continue
        poam.status = "closed"
        poam.closed_on = today
        note = f"Auto-closed: not present in latest {scanner} scan ({today.isoformat()})."
        poam.remediation_plan = (
            f"{poam.remediation_plan}\n{note}" if poam.remediation_plan else note
        )
        res.closed += 1

    return res
