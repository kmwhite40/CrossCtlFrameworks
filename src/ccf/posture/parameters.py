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

from .providers import aws, m365
from .types import PostureCheck


class ParameterError(ValueError):
    """A parameter set that cannot be applied to a check."""


#: Check key -> the parameter names it accepts. An empty tuple means the check
#: takes none, which is different from the check being unknown.
PARAMETERIZABLE: dict[str, tuple[str, ...]] = {
    m365.MFA_REGISTERED.key: (),
    m365.LEGACY_AUTH_BLOCKED.key: (),
    m365.STALE_ACCOUNTS.key: ("threshold_days",),
    # Empty tuples: each takes no parameter yet. Present because a check absent
    # from this mapping cannot be named by a pack at all, so omitting one
    # silently removes it from Form A -- which is why the guard exists.
    m365.PHISHING_RESISTANT_MFA.key: (),
    m365.PHISHABLE_METHODS_DISABLED.key: (),
    m365.GUEST_INVITES_RESTRICTED.key: (),
    m365.DEFAULT_USER_PERMISSIONS_RESTRICTED.key: (),
    m365.SIGNIN_AUDIT_CURRENT.key: (),
    m365.DIRECTORY_AUDIT_CURRENT.key: (),
    m365.DEVICE_COMPLIANCE.key: (),
    m365.RISKY_USERS_RESOLVED.key: (),
    # The inactivity period is organization-defined in both FedRAMP and CMMC, so
    # this one takes a parameter rather than shipping 15 minutes as though the
    # figure were settled.
    m365.SESSION_LOCK_ENFORCED.key: ("max_minutes",),
    m365.STORAGE_ENCRYPTION_REQUIRED.key: (),
    m365.SESSION_REAUTHENTICATION_REQUIRED.key: (),
    aws.ROOT_MFA_ENABLED.key: (),
    aws.PASSWORD_POLICY.key: (),
    aws.ACCESS_KEY_ROTATION.key: ("threshold_days",),
    aws.CLOUDTRAIL_MULTI_REGION.key: (),
    aws.CLOUDTRAIL_LOG_FILE_VALIDATION.key: (),
    aws.S3_PUBLIC_ACCESS_BLOCKED.key: (),
    # No parameter, and the reason is worth recording rather than leaving as an
    # empty tuple somebody later reads as an oversight: the tunable thing here
    # would be *which* SSE algorithms are acceptable, and this check
    # deliberately does not judge the algorithm. SC-28(1) is where a package may
    # require a customer-managed key, and that is an organization's decision --
    # so the check fails only on the absence of any default rule and records the
    # algorithm for an assessor. Adding a parameter would mean adding a judgment.
    aws.S3_DEFAULT_ENCRYPTION.key: (),
    aws.EBS_ENCRYPTION_BY_DEFAULT.key: (),
    # No parameter, deliberately. The tunable thing would be *which* ports count
    # as administrative, and widening that list is how this check turns into "no
    # unrestricted ingress at all" -- which fails every public load balancer on
    # 443 and is the shape an operator learns to ignore. A package that needs a
    # different boundary rule wants its own check, not a looser version of this
    # one.
    # 3.1.8 is organization-defined -- DoD guidance commonly says three, FedRAMP
    # Moderate says not more than three in fifteen minutes -- so the bound is a
    # parameter and the expectation re-renders with it.
    m365.LOCKOUT_THRESHOLD.key: ("max_attempts",),
    # How long a high-severity alert may sit before it is a finding is a
    # programme decision, not a product one.
    m365.SECURITY_ALERTS_TRIAGED.key: ("threshold_days",),
    # Blocked or not; nothing to tune.
    m365.REMOVABLE_STORAGE_BLOCKED.key: (),
    aws.SECURITY_GROUP_ADMIN_INGRESS.key: (),
    # Nor here: a flow log is either delivering or it is not. "How much logging
    # is enough" is a retention question, which `azure.monitor.log_retention`
    # and `gcp.logging.retention` already parameterize on their own terms.
    aws.VPC_FLOW_LOGS.key: (),
    # Publicly accessible or not; there is no threshold to tune.
    aws.RDS_NOT_PUBLICLY_ACCESSIBLE.key: (),
}

#: Check key -> the ``expected`` template to re-render when parameterized.
#: Sourced from the provider module so the wording lives in exactly one place.
EXPECTED_TEMPLATES: dict[str, str] = {
    m365.STALE_ACCOUNTS.key: m365.STALE_ACCOUNTS_EXPECTED,
    m365.SESSION_LOCK_ENFORCED.key: m365.SESSION_LOCK_EXPECTED,
    m365.LOCKOUT_THRESHOLD.key: m365.LOCKOUT_EXPECTED,
    m365.SECURITY_ALERTS_TRIAGED.key: m365.ALERT_TRIAGE_EXPECTED,
    aws.ACCESS_KEY_ROTATION.key: aws.ACCESS_KEY_ROTATION_EXPECTED,
}

#: Parameter name -> validator. Every parameter needs one: an unvalidated
#: parameter is a ``TypeError`` waiting for a scan.
_VALIDATORS: dict[str, str] = {
    "threshold_days": "positive_int",
    "max_minutes": "positive_int",
}


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
