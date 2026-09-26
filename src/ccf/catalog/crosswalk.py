"""800-53 control ids to NIST SP 800-171 requirement numbers, from the catalog.

A posture scan records its results against **800-53** control ids -- that is
what a :class:`~ccf.posture.types.PostureCheck` declares. A system held to
NIST SP 800-171 (or CMMC Level 2, which assesses the same 110 requirements) has
to be reported against *requirement numbers*, so the two vocabularies have to
be joined.

The join is **sourced, not invented**. ``ccf.framework_mappings`` carries the
crosswalk that shipped with the catalog, under the ``NIST_800_171_R2``
framework and the ``NIST 800-171 Rev. 2`` column key. Nothing here derives a
mapping from a control's family, its title, or any other resemblance: a
requirement attributed to the wrong control ends up in a document an assessor
acts on, and a plausible guess is indistinguishable from a citation until
somebody checks.

**It is incomplete, and that is reported rather than hidden.** On the catalog as
loaded the R2 column holds 131 rows, and those reach **80 of the 110
requirements** -- 30 requirements (3.1.2, 3.5.2, 3.12.4 and 27 others) have no
800-53 control mapped to them at all, so no scan can ever evidence them through
this crosswalk. Nothing in the other direction is spurious: every requirement
the crosswalk names is one of the 110.

So :func:`practices_for_controls` returns what mapped *and* what did not, and
every caller is expected to surface both. Dropping the unmapped half silently
would make an 800-171 report understate its own coverage while looking
complete, which is worse than reporting less. (The figures above were measured
against the loaded catalog, not estimated; an earlier draft of this docstring
asserted that ``AC-6`` carried no mapping, which a flawed ad-hoc query had
suggested and :func:`practices_for_controls` immediately disproved -- it maps to
3.1.5 and 3.1.6.)

Two value shapes appear in that column and both are accepted:

- ``"3.1.1 Limit system access to authorized users..."`` -- the Rev. 2
  requirement number followed by its text.
- ``"03-01-01"`` / ``"03-01-01f.03"`` -- the Rev. 3 dashed identifier, which
  reduces to the same Rev. 2 number (``03-01-01`` is 3.1.1). The objective
  suffix is dropped: a requirement is the unit 800-171A assesses and the unit
  SPRS scores.
"""

from __future__ import annotations

import re

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Control, Framework, FrameworkMapping

#: The framework row whose mappings carry the crosswalk.
CROSSWALK_FRAMEWORK = "NIST_800_171_R2"
#: The one column key that is a mapping. The same framework also carries
#: ``NIST 800-171 Discussion``, which is explanatory prose -- reading it as a
#: mapping would attribute every discussion paragraph to a requirement.
CROSSWALK_COLUMN = "NIST 800-171 Rev. 2"

#: ``3.1.1``, optionally followed by its requirement text.
_DOTTED = re.compile(r"^(3)\.(\d+)\.(\d+)")
#: ``03-01-01``, optionally with a Rev. 3 objective suffix (``f.03``).
_DASHED = re.compile(r"^0*(\d+)-0*(\d+)-0*(\d+)")


def requirement_from_value(value: str) -> str | None:
    """The 800-171 Rev. 2 requirement a mapping value names, or ``None``.

    ``None`` for anything this does not recognise. A caller must treat that as
    "not mapped", never as "maps to nothing relevant".
    """
    text = (value or "").strip()
    if not text:
        return None
    m = _DOTTED.match(text)
    if m:
        return f"{m.group(1)}.{int(m.group(2))}.{int(m.group(3))}"
    m = _DASHED.match(text)
    if m:
        family, section, item = (int(g) for g in m.groups())
        # The dashed form is Rev. 3's spelling of the same numbering: family 3
        # is implicit, so `03-01-01` is 3.1.1. A value whose first group is not
        # 3 is not an 800-171 requirement number and is refused rather than
        # coerced into one.
        return f"3.{section}.{item}" if family == 3 else None
    return None


def _canonical(identifier: str) -> str:
    """``AC-02(03)`` -> ``AC-2(3)``; the form a ControlTest stores.

    Objective and ODP suffixes are kept out: a mapping hung on
    ``AC-02(03)_ODP[01]`` is still a statement about ``AC-2(3)``.
    """
    cleaned = (identifier or "").strip().upper().split("_ODP")[0]
    m = re.match(r"^([A-Z]{2,3})-0*(\d+)(?:\(0*(\d+)\))?", cleaned)
    if not m:
        return cleaned
    family, number, enhancement = m.group(1), int(m.group(2)), m.group(3)
    return f"{family}-{number}({int(enhancement)})" if enhancement else f"{family}-{number}"


async def practices_for_controls(
    session: AsyncSession, control_ids: set[str]
) -> tuple[dict[str, set[str]], set[str]]:
    """``({control id: requirement numbers}, {control ids with no mapping})``.

    Both halves matter. The second is what stops an 800-171 view from quietly
    shrinking to the controls the shipped crosswalk happens to cover.

    A control's enhancement is tried first and its base control second:
    ``IA-2(1)`` carries no R2 mapping of its own, but it is an enhancement *of*
    ``IA-2``, which maps to 3.5.1 -- and a check evidencing ``IA-2(1)`` does
    bear on that requirement. The fallback is recorded as the base control's
    mapping rather than invented for the enhancement.
    """
    if not control_ids:
        return {}, set()
    rows = (
        await session.execute(
            select(Control.identifier, FrameworkMapping.value)
            .join(FrameworkMapping, FrameworkMapping.control_id == Control.id)
            .join(Framework, Framework.id == FrameworkMapping.framework_id)
            .where(
                Framework.code == CROSSWALK_FRAMEWORK,
                FrameworkMapping.column_key == CROSSWALK_COLUMN,
            )
        )
    ).all()

    by_control: dict[str, set[str]] = {}
    for identifier, value in rows:
        requirement = requirement_from_value(value)
        if requirement is None:
            continue
        by_control.setdefault(_canonical(identifier), set()).add(requirement)

    mapped: dict[str, set[str]] = {}
    unmapped: set[str] = set()
    for cid in control_ids:
        canon = _canonical(cid)
        found = by_control.get(canon)
        if not found:
            base = re.sub(r"\(\d+\)$", "", canon)
            found = by_control.get(base) if base != canon else None
        if found:
            mapped[cid] = set(found)
        else:
            unmapped.add(cid)
    return mapped, unmapped


__all__ = [
    "CROSSWALK_COLUMN",
    "CROSSWALK_FRAMEWORK",
    "practices_for_controls",
    "requirement_from_value",
]
