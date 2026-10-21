"""CISA's Known Exploited Vulnerabilities catalog, and which of a tenant's
weaknesses it names.

The catalog is global reference data (``ccf.kev_entries``, no
``organization_id``). Matching it against a tenant's records happens in
:func:`kev_matches`, under that tenant's scope.

**Where CVE ids live.** Concord has no scan-finding table: a scan upload is
reconciled straight into POA&Ms (``ccf.ingest.scanners.reconcile_findings``),
and a finding's CVE references are written into the POA&M's ``weakness`` text
as ``Refs: CVE-...`` (``_weakness``). A CSV whose id column is a CVE puts it
there too. So the match reads CVE ids out of each POA&M's ``title`` and
``weakness`` with :data:`CVE_RE` -- for scan-sourced POA&Ms (the scan
findings) and for every other POA&M whose text names one. That is a text
match, and the page says so.

Failure is never an empty catalog. :func:`fetch_kev` raises
:class:`KevFetchError` on a timeout, a non-200, a body over
:data:`MAX_BYTES`, a redirect off CISA's host, or anything that is not the
feed's schema; :func:`sync_kev` refuses a payload with no vulnerabilities, a
``count`` that disagrees with the list, or a malformed record set, before it
touches a row.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
from sqlalchemy import delete, func, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from ..analytics.posture import org_system_subq
from ..constants import POAM_ACTIVE_STATUSES
from ..models import POAM, System
from ..models_program import KevEntry

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
#: The feed is ~1.5 MB in 2026. Sixteen times that is room to grow; anything
#: larger is not the feed.
MAX_BYTES = 24 * 1024 * 1024
#: Seconds: connect, then each read/write/pool wait.
TIMEOUT = httpx.Timeout(30.0, connect=10.0)
_ALLOWED_HOSTS = frozenset({"www.cisa.gov", "cisa.gov"})
_UA = "ConcordKevSync/0.1 (+compliance-controls-platform)"

#: A CVE id as MITRE assigns them: year, then four or more digits.
CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)
_CVE_EXACT = re.compile(r"^CVE-\d{4}-\d{4,7}$")

#: Column widths in ccf.kev_entries.
_WIDTHS = {"vendor": 255, "product": 255, "name": 512, "known_ransomware": 16}


class KevError(RuntimeError):
    """Base: the catalog could not be refreshed. The message says why."""


class KevFetchError(KevError):
    """The download failed: network, status, size, or redirect."""


class KevFormatError(KevError):
    """The body is not CISA's KEV feed format."""


# ── fetch ────────────────────────────────────────────────────────────────────


async def fetch_kev(
    *,
    url: str = KEV_URL,
    timeout: httpx.Timeout = TIMEOUT,
    max_bytes: int = MAX_BYTES,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """Download the KEV feed and return it parsed and schema-checked.

    ``transport`` exists for tests (``httpx.MockTransport``); production
    passes nothing and talks to CISA. Raises :class:`KevFetchError` or
    :class:`KevFormatError`; never returns an empty catalog.
    """
    chunks = bytearray()
    try:
        async with (
            httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=True,
                transport=transport,
                headers={"User-Agent": _UA, "Accept": "application/json"},
            ) as client,
            client.stream("GET", url) as resp,
        ):
            final = urlsplit(str(resp.url))
            if final.scheme != "https" or final.hostname not in _ALLOWED_HOSTS:
                raise KevFetchError(
                    f"the KEV download ended at {final.scheme}://{final.hostname}, "
                    "which is not CISA; refusing it"
                )
            if resp.status_code != 200:
                raise KevFetchError(f"CISA answered HTTP {resp.status_code} for the KEV feed")
            declared = resp.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > max_bytes:
                raise KevFetchError(
                    f"the KEV feed declares {int(declared)} bytes, over the {max_bytes}-byte cap"
                )
            async for chunk in resp.aiter_bytes():
                chunks.extend(chunk)
                if len(chunks) > max_bytes:
                    raise KevFetchError(f"the KEV feed exceeded the {max_bytes}-byte cap")
    except httpx.TimeoutException as exc:
        raise KevFetchError(f"the KEV download timed out ({type(exc).__name__})") from exc
    except httpx.HTTPError as exc:
        raise KevFetchError(f"the KEV download failed: {type(exc).__name__}: {exc}") from exc
    return parse_kev(bytes(chunks))


# ── parse ────────────────────────────────────────────────────────────────────


@dataclass
class ParsedKev:
    catalog_version: str
    rows: list[dict[str, Any]]
    skipped: list[str] = field(default_factory=list)


def parse_kev(body: bytes | str) -> dict[str, Any]:
    """Bytes to the feed document, with the top-level shape checked."""
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise KevFormatError(f"the KEV feed is not JSON: {exc}") from exc
    _check_shape(doc)
    return doc  # type: ignore[no-any-return]


def _check_shape(doc: Any) -> None:
    if not isinstance(doc, dict):
        raise KevFormatError("the KEV feed is not a JSON object")
    vulns = doc.get("vulnerabilities")
    if not isinstance(vulns, list):
        raise KevFormatError("the KEV feed has no 'vulnerabilities' list")
    if not vulns:
        raise KevFormatError("the KEV feed lists no vulnerabilities; refusing an empty catalog")
    version = doc.get("catalogVersion")
    if not isinstance(version, str) or not version.strip():
        raise KevFormatError("the KEV feed has no 'catalogVersion'")
    count = doc.get("count")
    if count is not None and count != len(vulns):
        raise KevFormatError(
            f"the KEV feed says count={count} but lists {len(vulns)}; refusing a "
            "truncated or inconsistent catalog"
        )
    if not all(isinstance(v, dict) for v in vulns):
        raise KevFormatError("a KEV 'vulnerabilities' entry is not an object")


def _date(raw: Any) -> date | str | None:
    """A ``YYYY-MM-DD`` date, ``None`` when absent, or the string ``"bad"``."""
    if raw in (None, ""):
        return None
    if not isinstance(raw, str):
        return "bad"
    try:
        return date.fromisoformat(raw[:10])
    except ValueError:
        return "bad"


def normalise(doc: dict[str, Any]) -> ParsedKev:
    """Feed records to ``kev_entries`` rows. A record that cannot be stored is
    named in ``skipped`` rather than failing every other record."""
    _check_shape(doc)
    version = str(doc["catalogVersion"]).strip()[:32]
    rows: list[dict[str, Any]] = []
    skipped: list[str] = []
    seen: set[str] = set()
    for v in doc["vulnerabilities"]:
        cve = str(v.get("cveID") or "").strip().upper()
        if not _CVE_EXACT.match(cve):
            skipped.append(f"{cve[:40] or 'a record'}: not a CVE id")
            continue
        if cve in seen:
            skipped.append(f"{cve}: listed twice; first kept")
            continue
        added, due = _date(v.get("dateAdded")), _date(v.get("dueDate"))
        if added == "bad" or due == "bad":
            skipped.append(f"{cve}: unreadable date")
            continue
        row = {
            "cve_id": cve,
            "vendor": v.get("vendorProject") or None,
            "product": v.get("product") or None,
            "name": v.get("vulnerabilityName") or None,
            "description": v.get("shortDescription") or None,
            "date_added": added,
            "due_date": due,
            "known_ransomware": v.get("knownRansomwareCampaignUse") or None,
            "catalog_version": version,
        }
        too_long = [k for k, w in _WIDTHS.items() if row[k] and len(str(row[k])) > w]
        if too_long:
            skipped.append(f"{cve}: {', '.join(too_long)} too long")
            continue
        seen.add(cve)
        rows.append(row)
    if not rows:
        raise KevFormatError("no KEV record could be read; refusing an empty catalog")
    return ParsedKev(version, rows, skipped)


# ── sync ─────────────────────────────────────────────────────────────────────


async def sync_kev(session: AsyncSession, payload: dict[str, Any] | bytes | str) -> dict[str, Any]:
    """Upsert ``KevEntry`` rows from a KEV feed document.

    The catalog afterwards is the payload's: entries CISA no longer lists are
    removed (CISA does withdraw entries), except an entry whose record in this
    payload was skipped as malformed -- that is not evidence it was withdrawn.
    Runs in a savepoint and does not commit.
    """
    doc = parse_kev(payload) if isinstance(payload, (bytes, str)) else payload
    parsed = normalise(doc)
    now = datetime.now(UTC)
    keep = {r["cve_id"] for r in parsed.rows} | {
        s.split(":", 1)[0] for s in parsed.skipped if _CVE_EXACT.match(s.split(":", 1)[0])
    }
    async with session.begin_nested():
        before = set((await session.execute(select(KevEntry.cve_id))).scalars())
        for start in range(0, len(parsed.rows), 500):
            batch = [{**r, "synced_at": now} for r in parsed.rows[start : start + 500]]
            stmt = insert(KevEntry).values(batch)
            stmt = stmt.on_conflict_do_update(
                index_elements=[KevEntry.cve_id],
                set_={
                    c: stmt.excluded[c]
                    for c in (
                        "vendor",
                        "product",
                        "name",
                        "description",
                        "date_added",
                        "due_date",
                        "known_ransomware",
                        "catalog_version",
                        "synced_at",
                    )
                },
            )
            await session.execute(stmt)
        gone = before - keep
        if gone:
            await session.execute(delete(KevEntry).where(KevEntry.cve_id.in_(gone)))
    return {
        "catalog_version": parsed.catalog_version,
        "total": len(parsed.rows),
        "added": len({r["cve_id"] for r in parsed.rows} - before),
        "removed": len(gone),
        "skipped": len(parsed.skipped),
        "skipped_detail": parsed.skipped[:10],
    }


async def catalog_status(session: AsyncSession) -> dict[str, Any]:
    """How many entries, which catalog version, and when it was last synced.

    ``entries == 0`` means never synced (or wiped); the page says so rather
    than reporting "no known exploited vulnerabilities"."""
    n, last = (await session.execute(select(func.count(), func.max(KevEntry.synced_at)))).one()
    version = None
    if n:
        version = (
            await session.execute(
                select(KevEntry.catalog_version)
                .order_by(KevEntry.synced_at.desc(), KevEntry.catalog_version.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
    return {"entries": int(n or 0), "catalog_version": version, "synced_at": last}


async def refresh_kev(session: AsyncSession, *, today: date | None = None) -> dict[str, Any]:
    """The scheduler step: download and sync, at most once per ``today``.

    Global, not per organization: the catalog is one table for every tenant,
    so the scheduler calls this once per cycle, not once per org. A failure
    raises (:class:`KevError`) for the caller to log; it never empties the
    catalog. Does not commit.
    """
    status = await catalog_status(session)
    last = status["synced_at"]
    last_day = last.astimezone(UTC).date() if last is not None else None
    if today is not None and last_day is not None and last_day >= today:
        return {"status": "skipped", "reason": f"already synced {last_day.isoformat()} (UTC)"}
    result = await sync_kev(session, await fetch_kev())
    return {"status": "synced", **result}


# ── matching ─────────────────────────────────────────────────────────────────


def cve_ids(*texts: str | None) -> list[str]:
    """Every distinct CVE id named in ``texts``, upper-cased, in order."""
    out: list[str] = []
    for t in texts:
        for m in CVE_RE.finditer(t or ""):
            cve = f"CVE-{m.group(1)}-{m.group(2)}"
            if cve not in out:
                out.append(cve)
    return out


@dataclass
class KevMatch:
    poam_id: int
    title: str
    system: str
    source: str | None
    scanner: str | None
    severity: str
    status: str
    due_on: date | None
    entry: KevEntry

    @property
    def past_kev_due(self) -> bool:
        """The POA&M is due after CISA's date, or has no due date at all."""
        if self.entry.due_date is None:
            return False
        return self.due_on is None or self.due_on > self.entry.due_date


async def kev_matches(session: AsyncSession, org_id: int | None) -> dict[str, Any]:
    """The organization's open POA&Ms (scan findings included) naming a CVE id
    that KEV lists.

    Scope: POA&Ms on the org's **live** systems, statuses ``open`` and
    ``in_progress``. ``examined`` and ``with_cve`` are the denominators the
    page names: how many open POA&Ms were read, and how many named any CVE.
    """
    scope = (
        POAM.system_id.in_(org_system_subq(org_id)),
        POAM.status.in_(POAM_ACTIVE_STATUSES),
    )
    examined, scan_examined = (
        await session.execute(
            select(func.count(), func.count().filter(POAM.source == "scan")).where(*scope)
        )
    ).one()
    # A literal prefilter (no user input): only rows whose text could hold an id.
    rows = (
        await session.execute(
            select(POAM, System.name)
            .join(System, System.id == POAM.system_id)
            .where(*scope, or_(POAM.title.ilike("%cve-%"), POAM.weakness.ilike("%cve-%")))
        )
    ).all()
    named: list[tuple[POAM, str, list[str]]] = []
    for poam, sysname in rows:
        ids = cve_ids(poam.title, poam.weakness)
        if ids:
            named.append((poam, sysname, ids))
    all_ids = {c for _, _, ids in named for c in ids}
    entries: dict[str, KevEntry] = {}
    if all_ids:
        entries = {
            e.cve_id: e
            for e in (
                await session.execute(select(KevEntry).where(KevEntry.cve_id.in_(all_ids)))
            ).scalars()
        }
    matches: list[KevMatch] = []
    for poam, sysname, ids in named:
        for cve in ids:
            e = entries.get(cve)
            if e is not None:
                matches.append(
                    KevMatch(
                        poam_id=poam.id,
                        title=poam.title,
                        system=sysname,
                        source=poam.source,
                        scanner=poam.scanner,
                        severity=poam.severity,
                        status=poam.status,
                        due_on=poam.due_on,
                        entry=e,
                    )
                )
    matches.sort(
        key=lambda m: (
            m.entry.known_ransomware != "Known",
            m.entry.due_date or date.max,
            m.poam_id,
        )
    )
    return {
        "examined": int(examined),
        "with_cve": len(named),
        "scan_examined": int(scan_examined),
        "matches": matches,
        "poams_matched": len({m.poam_id for m in matches}),
        "ransomware": sum(1 for m in matches if m.entry.known_ransomware == "Known"),
        "past_due": sum(1 for m in matches if m.past_kev_due),
    }
