"""Form A: parameterizing a platform posture check from a pack.

Some expectations are declarable as data (see :mod:`ccf.posture.declared`) and
some are not -- the stale-account check needs a clock and date arithmetic, and
a declarative form expressive enough for it would be a date DSL. The answer for
those is not a weaker language but a *parameter*: the platform keeps the logic,
and a pack supplies the threshold.

``providers/m365.py`` anticipated exactly this, saying of ``STALE_ACCOUNT_DAYS``
that it "wants to be an organization-defined parameter -- the ODP machinery
already exists for exactly this".

Two invariants hold this together:

* **The vocabulary is declared once.** :data:`PARAMETERIZABLE` names every
  platform check and the parameters it accepts, so ``packs.catalog`` can reject
  an unknown parameter at install rather than raising ``TypeError`` mid-scan. A
  check missing from the mapping cannot be named by a pack at all, which is why
  a test asserts every platform check appears in it.
* **The prose follows the parameter.** :func:`parameterize` re-renders the
  check's ``expected`` text from the provider's template. A check enforcing 60
  days while its statement claims 90 would put a false sentence into an
  authorization package -- the parameter is worthless if the narrative lies
  about it.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from .providers import m365
from .types import PostureCheck


class ParameterError(ValueError):
    """A parameter set that cannot be applied to a check."""


#: Check key -> the parameter names it accepts. An empty tuple means the check
#: takes none, which is different from the check being unknown.
PARAMETERIZABLE: dict[str, tuple[str, ...]] = {
    m365.MFA_REGISTERED.key: (),
    m365.LEGACY_AUTH_BLOCKED.key: (),
    m365.STALE_ACCOUNTS.key: ("threshold_days",),
}

#: Check key -> the ``expected`` template to re-render when parameterized.
#: Sourced from the provider module so the wording lives in exactly one place.
EXPECTED_TEMPLATES: dict[str, str] = {
    m365.STALE_ACCOUNTS.key: m365.STALE_ACCOUNTS_EXPECTED,
}

#: Parameter name -> validator. Every parameter needs one: an unvalidated
#: parameter is a ``TypeError`` waiting for a scan.
_VALIDATORS: dict[str, str] = {"threshold_days": "positive_int"}


def _positive_int_error(name: str, value: Any) -> str | None:
    # bool is checked before int because True is an int in Python, and a
    # threshold of one day derived from ``true`` is the sort of thing that
    # reaches production.
    if isinstance(value, bool) or not isinstance(value, int):
        return f"parameter {name!r} must be an integer, got {type(value).__name__}"
    if value <= 0:
        return f"parameter {name!r} must be greater than zero, got {value}"
    return None


def validate_parameters(evaluator_key: str, parameters: Any) -> list[str]:
    """Errors for one Form A rule's parameters; empty means valid.

    Returns errors rather than raising, matching ``packs.catalog``'s
    fail-closed-but-readable contract.
    """
    if evaluator_key not in PARAMETERIZABLE:
        return [f"unknown evaluator {evaluator_key!r}"]
    if not isinstance(parameters, dict):
        return ["'parameters' must be an object"]
    accepted = PARAMETERIZABLE[evaluator_key]
    errors: list[str] = []
    for name, value in parameters.items():
        if name not in accepted:
            allowed = ", ".join(accepted) or "none"
            errors.append(
                f"parameter {name!r} is not accepted by {evaluator_key!r} (accepts: {allowed})"
            )
            continue
        if _VALIDATORS.get(name) == "positive_int":
            problem = _positive_int_error(name, value)
            if problem:
                errors.append(problem)
    return errors


def parameterize(check: PostureCheck, parameters: dict[str, Any]) -> PostureCheck:
    """The check as parameterized, with its ``expected`` text re-rendered.

    Raises :class:`ParameterError` on anything :func:`validate_parameters`
    rejects. The two cannot be allowed to disagree: validation runs at install,
    but a row written before a validator existed would otherwise be applied
    unchecked at scan time.
    """
    if not parameters:
        return check
    errors = validate_parameters(check.key, parameters)
    if errors:
        raise ParameterError("; ".join(errors))
    template = EXPECTED_TEMPLATES.get(check.key)
    if template is None:
        # Accepted parameters but no template: the check's wording does not
        # mention the parameter, so there is nothing to re-render.
        return check
    return replace(check, expected=template.format(**parameters))
