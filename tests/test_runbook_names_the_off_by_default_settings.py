"""A setting that defaults to off must be named in the production runbook.

`CCF_SCHEDULER_ENABLED` defaults to `false` and the runbook never mentioned it.
Follow every other section exactly and you deploy a continuous-monitoring
platform where nothing is continuous: no connector collection, no ConMon scan,
no control-test auto-runs, no assurance-graph rebuild. The app comes up healthy,
serves every page, warns about nothing, and sits still. The operator's first
sign is a posture page that never changes.

Documenting that one is not the fix; nothing would have caught the next one. So
this asserts the general rule, with an allowlist for settings that are genuinely
not operational guidance — each named, so the exception is a decision somebody
made rather than a gap nobody noticed. The same shape as the schema-wipe guard,
which found a module on its first run that reading had not.
"""

from __future__ import annotations

from pathlib import Path

from ccf.config import Settings

RUNBOOK = Path(__file__).resolve().parents[1] / "docs" / "runbooks" / "production-deployment.md"

#: Off-by-default settings the runbook deliberately does not carry, with why.
#: An entry here is a claim that an operator deploying to production does not
#: need to know about it — not that documenting it would be tedious.
_NOT_OPERATIONAL_GUIDANCE = {
    # Optional identity integrations. Each is inert unless a deployment chooses
    # it, and each has its own setup beyond a single flag.
    "CCF_OIDC_ENABLED": "optional SSO integration with its own configuration",
    "CCF_OIDC_REQUIRE_EMAIL_VERIFIED": "only meaningful once OIDC is enabled",
    "CCF_PIV_ENABLED": "optional PIV/CAC integration with its own configuration",
    "CCF_SCIM_ENABLED": "optional SCIM provisioning with its own configuration",
    # Presentation and internal bookkeeping: neither changes what the platform
    # does nor what it can claim.
    "CCF_LOG_JSON": "log format; operators set it to taste",
    "CCF_CATALOG_CAPTURE_REVISIONS": "catalog bookkeeping, no runtime behaviour",
    # Feature previews, off until a deployment opts in.
    "CCF_ASSESSMENT_ENGINE_ENABLED": "preview feature, inert when off",
    "CCF_ASSESSMENT_DISSENT_ENABLED": "preview feature, inert when off",
}


def _off_by_default() -> set[str]:
    """Every boolean setting whose default is False, as its env var name."""
    return {
        f"CCF_{name.upper()}"
        for name, field in Settings.model_fields.items()
        if field.annotation is bool and field.default is False
    }


def test_every_off_by_default_setting_is_documented_or_excused() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")
    undocumented = {
        var
        for var in _off_by_default()
        if var not in text and var not in _NOT_OPERATIONAL_GUIDANCE
    }
    assert not undocumented, (
        "these settings default to off and the production runbook never names "
        f"them, so a deployment that follows it gets them off without being "
        f"told: {sorted(undocumented)}. Document each in "
        "docs/runbooks/production-deployment.md, or add it to "
        "_NOT_OPERATIONAL_GUIDANCE here with the reason it does not belong there."
    )


def test_the_exclusion_list_has_no_stale_entries() -> None:
    """A list nothing keeps true reads as checked and is worse than no list."""
    stale = set(_NOT_OPERATIONAL_GUIDANCE) - _off_by_default()
    assert not stale, (
        f"these are no longer off-by-default booleans and can leave the "
        f"exclusion list: {sorted(stale)}"
    )


def _automation_section() -> str:
    """Section 2a only — the section whose job is naming the automation gates.

    Scoped deliberately: asserting these strings appear *anywhere* in the
    runbook passes on incidental mentions elsewhere (the verification table in
    section 6 names the scheduler too), so deleting the section that actually
    tells an operator what to set left the test green. Mutation testing showed
    that, twice.
    """
    text = RUNBOOK.read_text(encoding="utf-8")
    assert "## 2a." in text, "the runbook no longer has a section naming the automation gates"
    after = text.split("## 2a.", 1)[1]
    return after.split("\n## ", 1)[0]


def test_the_scheduler_is_documented_as_gating_every_recurring_job() -> None:
    """The specific case, pinned as well as the rule.

    The rule above is satisfied by the variable name appearing anywhere. What an
    operator actually needs is the list of what stops without it, in the section
    they are reading when they decide.
    """
    section = _automation_section()
    assert "CCF_SCHEDULER_ENABLED" in section, (
        "the automation-gates section does not name the scheduler flag"
    )
    for job in ("collection", "ConMon", "control-test", "assurance-graph"):
        assert job in section, (
            f"the automation-gates section does not say {job!r} stops without the scheduler"
        )


def test_the_runbook_says_how_to_tell_the_scheduler_is_actually_running() -> None:
    """"Set the flag" is not verification. `scheduler.started` is."""
    assert "scheduler.started" in RUNBOOK.read_text(encoding="utf-8"), (
        "the runbook gives no way to confirm the scheduler is running"
    )


def test_the_runbook_and_the_compose_file_agree_about_the_scheduler() -> None:
    """Section 2a's claim about the bundled stack must match the bundled stack.

    The section's whole argument is that these gates default to off and a
    deployment that skips it "comes up healthy and then sits still". That is
    true of `config.py` and became false of `docker-compose.yml` the moment the
    scheduler was switched on there. A runbook that tells an operator the stack
    does nothing on its own, while the stack in the same repository runs a cycle
    fifteen seconds after boot, is worse than one that says nothing: it is read,
    and it is wrong.

    Both directions are checked, so this fails whichever side moves.
    """
    import re  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415

    compose = (Path(__file__).resolve().parents[1] / "docker-compose.yml").read_text(
        encoding="utf-8"
    )
    runbook = RUNBOOK.read_text(encoding="utf-8")

    enabled_in_compose = bool(
        re.search(r'^\s*CCF_SCHEDULER_ENABLED:\s*"true"', compose, flags=re.M)
    )
    claimed_in_runbook = "bundled `docker-compose.yml` turns the scheduler on" in runbook

    assert enabled_in_compose == claimed_in_runbook, (
        "docker-compose.yml "
        f"{'enables' if enabled_in_compose else 'does not enable'} the scheduler "
        f"and the runbook {'says it does' if claimed_in_runbook else 'does not say so'}. "
        "Update whichever one is wrong."
    )


def test_the_scheduler_is_enabled_on_exactly_one_service() -> None:
    """Two schedulers means every tenant's cycle runs twice.

    `scheduler.start()` is idempotent within a process and has no cross-process
    lock, so the only thing keeping one cycle per interval is that exactly one
    container sets the flag. Putting it on the shared `x-ccf-env` anchor -- the
    obvious-looking place -- would silently multiply it by the number of
    services that use the anchor.
    """
    import re  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415

    compose_path = Path(__file__).resolve().parents[1] / "docker-compose.yml"
    compose = compose_path.read_text(encoding="utf-8")

    occurrences = re.findall(r'^\s*CCF_SCHEDULER_ENABLED:\s*"(\w+)"', compose, flags=re.M)
    enabled = [o for o in occurrences if o == "true"]
    assert len(enabled) <= 1, (
        f"CCF_SCHEDULER_ENABLED is set true {len(enabled)} times in "
        "docker-compose.yml; each container that sets it runs its own scheduler"
    )

    if enabled:
        # And it must not be in the shared anchor, which several services inherit.
        anchor = compose.split("services:", 1)[0]
        assert "CCF_SCHEDULER_ENABLED" not in anchor, (
            "CCF_SCHEDULER_ENABLED is in the x-ccf-env anchor; every service "
            "using the anchor would start a scheduler"
        )
