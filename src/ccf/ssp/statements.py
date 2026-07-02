"""Automatic implementation-statement composition.

Turns a control's derivation (responsibility, inheritance source, state), the
system environment, the filled organization-defined parameters, and any captured
live configuration into a tailored implementation statement — instead of a
generic template sentence. Pure and side-effect-free; the orchestration
(loading data, optional AI) lives in :mod:`ccf.governance.automation`.
"""

from __future__ import annotations

from .constants import DRAFT_PREFIX as DRAFT_PREFIX  # noqa: PLC0414 — explicit re-export


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


STYLES = ("concise", "standard", "detailed")


def _evidence_hint(responsibility: str) -> str:
    return {
        "inherited": " Evidence: provider authorization package and CRM.",
        "shared": " Evidence: provider CRM plus the organization's configuration export.",
        "customer": " Evidence: configuration export and screenshots from the tenant.",
    }.get(responsibility, "")


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
) -> tuple[str, bool]:
    """Return ``(statement_text, needs_review)`` tailored to the derivation.

    Options: ``style`` (concise | standard | detailed), ``include_captured``
    (fold live connector captures into the parameters clause), and ``mark_draft``
    (prefix customer/shared statements with the [DRAFT] indicator for review).
    """
    obj = (requirement or "the control requirement").strip().rstrip(".")
    caps = captured if include_captured else []
    params = "" if style == "concise" else _params_clause(odp_values or {}, caps or [])
    evidence = _evidence_hint(responsibility) if style == "detailed" else ""

    def _finish(text: str, needs_review: bool) -> tuple[str, bool]:
        text = text + params + evidence
        if needs_review and mark_draft:
            text = DRAFT_PREFIX + text
        return text, needs_review

    if responsibility == "not_applicable":
        return _finish(
            f"Control {control_id} is not applicable to this system's authorization "
            f"boundary and scope.",
            False,
        )

    if responsibility == "inherited":
        provider = source_label(source, environment)
        return _finish(
            f"Control {control_id} is inherited from {provider}. The organization relies on "
            f"the provider's authorized implementation to {obj}; the provider's customer "
            f"responsibility matrix and authorization package are retained as evidence.",
            False,
        )

    if responsibility == "shared":
        return _finish(
            f"Control {control_id} is a shared responsibility on {environment}. The platform "
            f"provides the underlying capability, and the organization configures {services} "
            f"to {obj}.",
            True,
        )

    # customer-responsible
    if style == "concise":
        return _finish(f"The organization configures {services} on {environment} to {obj}.", True)
    return _finish(
        f"The organization implements Control {control_id} on {environment} by configuring "
        f"{services} to {obj}.",
        True,
    )
