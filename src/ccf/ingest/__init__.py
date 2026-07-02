"""Scanner ingestion — vulnerability findings → reconciled POA&Ms.

Turns an exported vulnerability scan (Nessus/Tenable ``.nessus`` XML, AWS
Inspector JSON, or a generic/Qualys CSV) into normalized :class:`ScanFinding`
records, then reconciles them against the system's POA&M register: new findings
open POA&Ms with severity-driven due dates, recurring findings update in place,
resolved findings that no longer appear in the latest scan are auto-closed.
"""

from __future__ import annotations

from .scanners import (
    SEVERITY_SLA_DAYS,
    ScanFinding,
    detect_format,
    normalize_severity,
    parse_scan,
    reconcile_findings,
)

__all__ = [
    "SEVERITY_SLA_DAYS",
    "ScanFinding",
    "detect_format",
    "normalize_severity",
    "parse_scan",
    "reconcile_findings",
]
