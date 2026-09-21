"""Automatic implementation-statement composition.

Turns a control's derivation (responsibility, inheritance source, state), the
system environment, the filled organization-defined parameters, and any captured
live configuration into a tailored implementation statement — instead of a
generic template sentence. Pure and side-effect-free; the orchestration
(loading data, optional AI) lives in :mod:`ccf.governance.automation`.
"""

from __future__ import annotations

from collections.abc import Sequence

from .constants import DRAFT_PREFIX as DRAFT_PREFIX  # noqa: PLC0414 — explicit re-export
from .constants import responsible_role_for


def source_label(source: str | None, environment: str) -> str:
    """Human label for a derivation source string (``vendor:X`` / ``platform:Y``)."""
    if not source:
        return environment
    if source.startswith("vendor:"):
        return source.split(":", 1)[1]
    if source.startswith("platform:"):
        return environment
    return environment


def _params_clause(odp_values: dict[str, str], captured: list[dict[str, str]]) -> str:
    parts: list[str] = []
    for key, val in (odp_values or {}).items():
        if val:
            parts.append(f"{key.replace('_', ' ')}: {val}")
    for cap in captured or []:
        parts.append(
            f"{cap['odp_key'].replace('_', ' ')} = {cap['value']} "
            f"(captured from {cap['connector']})"
        )
    return (" Organization-defined parameters — " + "; ".join(parts) + ".") if parts else ""


def is_draft_narrative(part_narratives: list[dict[str, str]] | None) -> bool:
    """True if any part narrative still carries the machine-drafted marker.

    ``compose()``'s ``needs_review`` flag is not persisted on the entry —
    once a narrative is written to ``SSPControlEntry.part_narratives`` the
    presence of :data:`DRAFT_PREFIX` in the stored text is the only durable
    record that it hasn't been human-reviewed yet (CISO-02: AI-drafted
    content must stay visibly distinguishable until a human clears it).

    Deliberately kept strict (``startswith(DRAFT_PREFIX)``, the full literal
    WITH its trailing space) rather than widened the way
    ``ssp.completeness.is_draft_or_placeholder`` was: every producer of this
    marker (``statements.py``/``platforms.py``/``nist80053.py``/
    ``governance/automation.py``) always writes the space, so the strict form
    never misses machine-drafted content -- widening it would instead let a
    human's own hand-typed ``"[DRAFT]"`` register as "AI-sourced" here (this
    predicate drives the UI's AI-provenance badges, ``ui.py``'s and
    ``reports.py``'s ``is_draft_entry``/``ai_sourced_map``), which is a false
    claim about *authorship* -- a different question from
    ``is_draft_or_placeholder``'s "is this text real content yet," which a
    human-typed marker answers correctly either way.
    """
    for part in part_narratives or []:
        text = (part or {}).get("text") or ""
        if text.startswith(DRAFT_PREFIX):
            return True
    return False


STYLES = ("concise", "standard", "detailed")

# Rendered when no real frequency/cadence was supplied — the same bracket
# convention ssp/odp.py's render() and ssp/completeness.py's
# _ODP_PLACEHOLDER_TOKENS use for an unresolved organization-defined
# parameter, so a fabricated-sounding but actually-unknown cadence never
# silently passes as filled in.
_FREQUENCY_PLACEHOLDER = "[ORGANIZATION-DEFINED: frequency]"


def _domain_from_control_id(control_id: str) -> str:
    """Best-effort CMMC domain prefix from a control id like ``AC.L2-3.1.1``."""
    return (control_id or "").split(".", 1)[0]


def _resolved_role(control_id: str, responsible_role: str | None) -> str:
    """Prefer an explicitly supplied (named) responsible role; fall back to
    the generic, flagged domain-level label only when none is supplied."""
    if responsible_role and responsible_role.strip():
        return responsible_role.strip()
    return responsible_role_for(_domain_from_control_id(control_id))


def _resolved_frequency(frequency: str | None) -> str:
    return frequency.strip() if frequency and frequency.strip() else _FREQUENCY_PLACEHOLDER


def _role_clause(role: str) -> str:
    return f" Responsible role: {role}."


def _frequency_clause(frequency: str) -> str:
    return f" Frequency: {frequency}."


def _policy_clause(policy_ref: str | None) -> str:
    if not policy_ref or not policy_ref.strip():
        return ""
    return f" Governing policy/procedure: {policy_ref.strip()}."


def _evidence_clause(responsibility: str) -> str:
    return {
        "shared": " Evidence: provider CRM plus the organization's configuration export.",
        "customer": " Evidence: configuration export and screenshots from the tenant.",
    }.get(responsibility, "")


def _inherited_evidence_clause(provider: str, crm_ref: str | None) -> tuple[str, bool]:
    """Evidence clause + ``needs_review`` for an inherited control.

    Only claims evidence is "retained" when a real leveraged-authorization /
    CRM reference was actually supplied (FR-11). Without one, the statement
    must not be auto-accepted and must say plainly that nothing is linked yet.
    """
    ref = crm_ref.strip() if crm_ref else ""
    if ref:
        return (
            f" Evidence: {provider}'s authorization package and customer responsibility "
            f"matrix (reference: {ref}) are linked and retained as evidence.",
            False,
        )
    return (
        f" Evidence: no leveraged-authorization or CRM reference is linked for {provider}; "
        "this control cannot be considered evidenced until one is on file.",
        True,
    )


# Sentence-ending punctuation a statement may arrive with: a period, question
# mark, exclamation point, or the Unicode ellipsis. All four are stripped from
# the end the same way a bare trailing period always was, so "Is legacy auth
# blocked?" does not render "Is legacy auth blocked?." once the clause's own
# terminal period is appended.
_SENTENCE_END_CHARS = ".?!…"


def _strip_trailing_sentence_end(text: str) -> str:
    return text.rstrip(_SENTENCE_END_CHARS)


def _join_statements(cleaned: Sequence[str]) -> str:
    """Join already-normalized statements into one clause body (no lead/colon).

    Authors write whole sentences (the design premise), so a statement often
    already contains its own internal sentence-ending punctuation once its
    single *trailing* mark has been stripped -- e.g. "MFA is enforced. Legacy
    auth is blocked." normalizes to "MFA is enforced. Legacy auth is blocked".
    Folding that into a ``"; "``-joined list would splice a sentence break
    into what reads as one list item ("Disk encryption is on; MFA is
    enforced. Legacy auth is blocked."). So when *any* statement in the group
    still carries internal sentence-ending punctuation, the whole group
    renders as separate sentences instead of a semicolon list; otherwise the
    semicolon-joined form is used, unchanged from before.
    """
    if any(ch in _SENTENCE_END_CHARS for s in cleaned for ch in s):
        return " ".join(f"{s}." for s in cleaned)
    return "; ".join(cleaned) + "."


def _usable_statements(capability_statements: Sequence[tuple[str, str]]) -> list[str]:
    """Non-empty capability statements, normalized, sorted by capability key.

    ``capability_statements`` is a sequence of ``(capability_key, statement)``
    pairs, sorted here by the *key* -- not the statement text. Editing a
    capability's wording must not reorder the clause on every other control
    that capability shares with others; only adding, removing, or renaming a
    capability changes order. (Tuple comparison falls back to statement text
    only to break a tie between two distinct capabilities that share a key,
    which the caller's unique-key constraint should already prevent -- this
    is belt-and-suspenders determinism, not a real ordering signal.)
    Reproducibility -- regenerating an SSP without edits produces identical
    prose -- and this ordering is a precondition for narrative redline later.

    Empty and whitespace-only entries are dropped: an empty clause would
    render "Implementation: ." . A trailing sentence-ending mark is stripped,
    because :func:`capability_clause` (via :func:`_join_statements`) supplies
    the terminal punctuation and authors write whole sentences -- without this
    every statement rendered "...no legacy-auth exclusions..". Normalizing
    before de-duplication also means the same statement with and without its
    trailing period is one statement, not two.
    """
    # ``if s`` is the None guard: ``Capability.statement`` is a nullable
    # column, and a caller that forgets to filter should get dropped entries
    # rather than an AttributeError from deep inside the SSP generator.
    # Whitespace- and punctuation-only entries are caught after stripping.
    ordered = sorted(
        (key, s.strip()) for key, s in capability_statements if s and s.strip()
    )
    seen: set[str] = set()
    out: list[str] = []
    for _key, s in ordered:
        cleaned = _strip_trailing_sentence_end(s).strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        out.append(cleaned)
    return out


def capability_clause(
    capability_statements: Sequence[tuple[str, str]],
    partial_capability_statements: Sequence[tuple[str, str]] = (),
    *,
    residual: bool = False,
) -> str:
    """An implementation sentence naming the capabilities that cover a control.

    Appended rather than spliced into the body sentence. Capability statements
    are whole sentences, and the ``customer`` and ``shared`` branches need
    different grammatical forms ("by configuring X" versus "configures X"), so
    interpolating one string into both would either break the grammar or force
    rewording the existing prose -- and rewording it would break the
    byte-identical guarantee for controls no capability covers.

    ``capability_statements`` covers capabilities whose status is genuinely a
    live implementation (``implemented`` / ``inherited``); a capability with
    ``status == "partial"`` belongs in ``partial_capability_statements``
    instead and renders under its own "Partial implementation:" lead so the
    SSP narrates real partial work without overstating it as complete. Each is
    a sequence of ``(capability_key, statement)`` pairs -- see
    :func:`_usable_statements` for why key, not text, drives order.

    ``residual`` frames it for an inherited control, where the provider
    implements the control and the organization's capability covers only what
    is left.
    """
    full = _usable_statements(capability_statements)
    partial = _usable_statements(partial_capability_statements)
    if not full and not partial:
        return ""
    full_lead = "The organization's residual implementation" if residual else "Implementation"
    partial_lead = (
        "The organization's partial residual implementation"
        if residual
        else "Partial implementation"
    )
    clause = ""
    if full:
        clause += f" {full_lead}: {_join_statements(full)}"
    if partial:
        clause += f" {partial_lead}: {_join_statements(partial)}"
    return clause


def compose(
    *,
    control_id: str,
    requirement: str | None,
    responsibility: str,
    source: str | None,
    environment: str,
    services: str,
    odp_values: dict[str, str] | None = None,
    captured: list[dict[str, str]] | None = None,
    style: str = "standard",
    include_captured: bool = True,
    mark_draft: bool = True,
    responsible_role: str | None = None,
    frequency: str | None = None,
    policy_ref: str | None = None,
    crm_ref: str | None = None,
    capability_statements: Sequence[tuple[str, str]] = (),
    partial_capability_statements: Sequence[tuple[str, str]] = (),
) -> tuple[str, bool]:
    """Return ``(statement_text, needs_review)`` tailored to the derivation.

    Options: ``style`` (concise | standard | detailed), ``include_captured``
    (fold live connector captures into the parameters clause), and ``mark_draft``
    (prefix customer/shared statements with the [DRAFT] indicator for review).

    ``responsible_role`` should be the project's real named role (system_owner
    / ISSO) when known; it falls back to a flagged generic domain label
    otherwise (FR-13). ``frequency`` is the control's review/monitoring
    cadence; left unfilled it renders a flagged organization-defined
    placeholder rather than a fabricated cadence. ``policy_ref`` names the
    governing policy/procedure when one is available. ``crm_ref`` is a real
    leveraged-authorization / customer-responsibility-matrix reference for an
    *inherited* control — required for the statement to be auto-accepted
    (FR-11). ``capability_statements`` are the ``(capability_key, statement)``
    pairs of capabilities that genuinely describe a live implementation of
    this control (P1); when present, an implementation sentence naming them
    is appended to the body, so one capability edited once re-renders every
    control it maps to. ``partial_capability_statements`` are the same shape
    for capabilities whose status is ``partial`` -- real work, but rendered
    under a distinct "Partial implementation:" lead so the SSP does not
    overstate it as complete. Both empty by default, which makes every
    existing call byte-identical.
    """
    obj = (requirement or "the control requirement").strip().rstrip(".")
    caps = captured if include_captured else []
    params = "" if style == "concise" else _params_clause(odp_values or {}, caps or [])
    role = _resolved_role(control_id, responsible_role)
    freq = _resolved_frequency(frequency)
    policy = _policy_clause(policy_ref)

    def _finish(
        text: str, needs_review: bool, *, evidence: str = "", include_role_freq: bool = True
    ) -> tuple[str, bool]:
        tail = params
        if include_role_freq:
            tail += _role_clause(role) + _frequency_clause(freq)
        tail += evidence + policy
        text = text + tail
        if needs_review and mark_draft:
            text = DRAFT_PREFIX + text
        return text, needs_review

    if responsibility == "not_applicable":
        return _finish(
            f"Control {control_id} is not applicable to this system's authorization "
            f"boundary and scope.",
            False,
            include_role_freq=False,
        )

    if responsibility == "inherited":
        provider = source_label(source, environment)
        evidence, needs_review = _inherited_evidence_clause(provider, crm_ref)
        customer_line = (
            f" Customer responsibility: {role} monitors {provider}'s continued authorization "
            f"and performs any residual configuration or hybrid actions needed to {obj} that "
            f"{provider} does not fully cover."
        ) + capability_clause(capability_statements, partial_capability_statements, residual=True)
        text = (
            f"Control {control_id} is inherited from {provider}. The organization relies on "
            f"the provider's authorized implementation to {obj}." + customer_line
        )
        return _finish(text, needs_review, evidence=evidence)

    if responsibility == "shared":
        return _finish(
            f"Control {control_id} is a shared responsibility on {environment}. The platform "
            f"provides the underlying capability, and the organization configures {services} "
            f"to {obj}." + capability_clause(capability_statements, partial_capability_statements),
            True,
            evidence=_evidence_clause("shared"),
        )

    # customer-responsible
    evidence = _evidence_clause("customer")
    if style == "concise":
        return _finish(
            f"The organization configures {services} on {environment} to {obj}."
            + capability_clause(capability_statements, partial_capability_statements),
            True,
            evidence=evidence,
        )
    return _finish(
        f"The organization implements Control {control_id} on {environment} by configuring "
        f"{services} to {obj}."
        + capability_clause(capability_statements, partial_capability_statements),
        True,
        evidence=evidence,
    )
