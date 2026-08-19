"""Regression tests for the Tier 0 audit batch.

Each test targets a defect that shipped because nothing asserted the behaviour.
"""

from __future__ import annotations

import re
from pathlib import Path

from ccf.api.routes.grc import RegulatoryIn, RegulatoryUpdateIn

_SRC = Path(__file__).resolve().parents[1] / "src" / "ccf"


# --- F-S16-2: PATCH must not reset the workflow fields -----------------------


def test_patch_model_has_no_non_none_defaults() -> None:
    """The create model's defaults silently reset status/applicability on PATCH.

    ``RegulatoryIn`` defaults ``applicability`` to "assessing" and ``status`` to
    "new". The handler applies ``model_dump(exclude_none=True)``, which filters
    None but not those literals — so a PATCH of any single field rewrote both.
    Every field on the update model must therefore default to None.
    """
    bad = {
        name: f.default
        for name, f in RegulatoryUpdateIn.model_fields.items()
        if f.default is not None
    }
    assert bad == {}, f"non-None defaults would be written on PATCH: {bad}"


def test_partial_patch_does_not_carry_status_or_applicability() -> None:
    """A title-only PATCH must produce no status/applicability write at all."""
    payload = RegulatoryUpdateIn(title="renamed").model_dump(exclude_none=True)
    assert payload == {"title": "renamed"}
    # Contrast: the create model would have carried both through.
    legacy = RegulatoryIn(title="renamed").model_dump(exclude_none=True)
    assert legacy["status"] == "new"
    assert legacy["applicability"] == "assessing"


def test_create_model_is_unchanged() -> None:
    """POST still gets its defaults — only the update path changed."""
    assert RegulatoryIn.model_fields["status"].default == "new"
    assert RegulatoryIn.model_fields["applicability"].default == "assessing"


# --- F-S28-1: a blocked AI action must not exit 0 ---------------------------


def test_blocked_ai_decision_exits_non_zero() -> None:
    """``_ai_decision`` could return "blocked: ...", and the caller ignored it.

    Both ``ai-actions approve`` and ``ai-actions reject`` route through it, so a
    guardrail-blocked decision printed in cyan and exited 0 — indistinguishable
    from success to any CI or cron caller.
    """
    src = (_SRC / "cli.py").read_text(encoding="utf-8")
    body = src[src.index("def _ai_decision("):]
    body = body[: body.index("\n\n\n")]
    assert 'return f"blocked: {e}"' in body, "the blocked outcome should still exist"
    assert 'status.startswith("blocked:")' in body, "caller must handle the blocked outcome"


# --- F-S27-2: approval gates must compare, not test truthiness --------------


def test_approval_gates_compare_explicitly() -> None:
    """``entity_state`` returns a string; "draft" is truthy.

    Replacing the old boolean ``_is_approved`` with ``entity_state`` is only
    safe if every gate compares to "approved". A bare ``not await
    entity_state(...)`` would fail OPEN for an unapproved entity.
    """
    for name in ("poams.py", "risks.py"):
        src = (_SRC / "api" / "routes" / name).read_text(encoding="utf-8")
        assert "not await entity_state" not in src, f"{name}: truthiness test on a state string"
        for m in re.finditer(r"await entity_state\([^)]*\)(?P<tail>[^\n]*)", src):
            tail = m.group("tail")
            # Either it is compared, or its result is bound to a variable for later use.
            assert ('"approved"' in tail) or tail.strip() in ("", ")"), (
                f"{name}: ungated entity_state result: {m.group(0)!r}"
            )


def test_no_duplicate_approval_helper_remains() -> None:
    for name in ("poams.py", "risks.py"):
        src = (_SRC / "api" / "routes" / name).read_text(encoding="utf-8")
        assert "async def _is_approved" not in src, f"{name}: duplicate helper still present"


# --- F-S09-2: badge classes must exist in the stylesheet --------------------


def test_templates_only_use_defined_chip_classes() -> None:
    """`.badge--*` was defined in no stylesheet, so those spans rendered bare."""
    css = (_SRC / "api" / "static" / "css" / "app.css").read_text(encoding="utf-8")
    for tpl in ("reliability.html", "fedramp20x.html"):
        src = (_SRC / "api" / "templates" / tpl).read_text(encoding="utf-8")
        assert "badge--" not in src, f"{tpl}: undefined badge-- class"
        for cls in set(re.findall(r"chip--[a-z]+", src)):
            assert f".{cls}" in css, f"{tpl}: {cls} is not defined in app.css"
