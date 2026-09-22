"""AWS GovCloud config-capture connector.

Reads AWS account configuration to inform organization-defined parameters.
Live capture uses ``boto3`` (against ``us-gov-west-1`` by default); boto3 is an
optional dependency, so this connector reports "not configured" unless it is
installed, the deployment has opted in via ``CCF_AWS_CAPTURE_ENABLED``, *and*
the calling organization has its own bound credential (access key or named
profile) passed in as ``credential`` — see :mod:`ccf.connectors.credentials`.
There is no global/env credential fallback (IA-05): an org with no bound
credential never captures under another org's or a shared account's identity.
The provider calls live behind ``_session`` — a single, clearly-marked
integration seam — so wiring real credentials is additive and does not change
the interface the API depends on.

What ``PARAMETER_MAP`` may claim
-------------------------------
``PARAMETER_MAP`` is shown to an operator as what this connector *would* pull
once credentials are configured (``connectors/base.py`` says so, and
``api/routes/ssp.py`` returns it for an unconfigured connector so the UI can
display it). It is therefore a claim about the product, not a backlog. This map
once advertised six keys while ``capture()`` emitted two --
``flaw_remediation_timeframe``, ``risk_assessment_frequency``,
``incident_report_timeframe`` and ``nonlocal_maintenance_mfa`` were advertised
and never captured by anything. They have been removed rather than implemented:
the defect was the claim, and four new AWS integrations do not belong inside a
parity fix. ``tests/test_connector_capture_parity.py`` now drives ``capture()``
against a stubbed session and asserts the emitted keys equal this map's keys,
for this connector and every other one that has a ``PARAMETER_MAP``.

Which ``nist_id`` namespace, and how that was decided
-----------------------------------------------------
``CapturedParameter.nist_id`` is the join key that decides whether a capture is
ever read: ``governance/automation.py`` keys ``caps_by_nist`` on it and matches
it against ``SSPControlEntry.nist_id``, and ``api/routes/ssp.py``'s autofill
builds ``by_nist`` the same way. A capture in the wrong namespace is captured,
stored, and silently never rendered.

``encryption_at_rest`` used to emit ``"SC-28"``. Measured against the dev
database, grouping every ``SSPControlEntry`` by its project's platform and the
namespace of its ``nist_id``:

* ``platform = "aws_govcloud"``: 7 projects, 770 entries, **all** 800-171
  (``3.x.y``), zero 800-53. Every one of those 7 projects carries a ``3.13.16``
  entry and a ``3.3.1`` entry.
* ``platform = "m365"``: 8 projects, 880 entries, all 800-171.

An AWS project is seeded by ``ssp/seed.py`` from ``ScoringControl.nist_id``,
which is 800-171 throughout, so no AWS project could ever match ``"SC-28"`` --
the EBS-encryption value was captured and discarded at the join on every run.
**This connector emits 800-171 ids**, the choice ``connectors/azure_arm.py``
made one branch earlier for the same reason. The 800-53r5 equivalent is carried
in ``detail["nist_80053_id"]`` -- carried, not emitted as ``nist_id``, so it
cannot silently become a second competing answer, and a future 800-53 join has
a documented value to read instead of a re-derivation.

``scan()`` assesses the account against the posture checks in
:mod:`ccf.posture.providers.aws`. The division of labour is the one the Graph
connector established: transport and credentials live here, judgement lives in
the provider module, and every evaluator there is pure so it is testable
without an AWS account. The source tokens this connector dispatches on are not
URLs — AWS has none — which has a consequence for pack-declared checks that
the provider module's docstring states plainly rather than leaving implied.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, ClassVar

from ..config import get_settings
from ..logging import get_logger
from ..posture.providers import aws as aws_checks
from ..posture.resolve import ResolvedCheck, resolve_checks_from_registry
from ..posture.types import CheckOutcome, PostureCheck, ResourceFinding
from .base import CapturedParameter, ConfigConnector

log = get_logger(__name__)


class UnknownAwsSourceError(RuntimeError):
    """A check named a data source this connector has no reader for.

    Raised rather than ignored. The token in ``ENDPOINTS`` is a key into a
    fixed dispatch table, never a value handed to boto3, so an unrecognised
    one cannot become an arbitrary AWS call made with the organization's own
    credentials -- it stops here and the check reports as unrunnable. The one
    way to reach this in practice is a pack-declared (Form B) rule naming
    ``provider: aws_govcloud``; see ``posture.providers.aws``'s docstring on
    why those cannot be supported, stated there rather than left implied.
    """


# GovCloud regions live in the aws-us-gov partition; boto3 resolves endpoints
# (sts.<region>.amazonaws.com in-partition) automatically from the region name.
GOVCLOUD_REGIONS = ("us-gov-west-1", "us-gov-east-1")


class AwsGovCloudConnector(ConfigConnector):
    key = "aws_govcloud"
    label = "AWS GovCloud (US)"

    # ODP key → the AWS signal it IS derived from. Every key here is one
    # ``capture()`` below actually emits; see the module docstring on why this
    # map may not carry an aspiration.
    PARAMETER_MAP: ClassVar[dict[str, str]] = {
        "audit_retention_period": "CloudWatch Logs retention (log group retentionInDays)",
        "encryption_at_rest": "EC2 default EBS encryption (get_ebs_encryption_by_default)",
    }

    # ODP key → the 800-53r5 control the same signal informs. Carried in each
    # capture's ``detail`` (never as ``nist_id``); see the module docstring.
    _NIST_80053: ClassVar[dict[str, str]] = {
        "audit_retention_period": "AU-11",
        "encryption_at_rest": "SC-28",
    }

    def _boto3_available(self) -> bool:
        try:
            import boto3  # noqa: F401, PLC0415
        except ImportError:
            return False
        return True

    def _region(self) -> str:
        c = self.credential or {}
        region = c.get("region")
        return region if isinstance(region, str) and region else get_settings().aws_region

    def is_configured(self) -> bool:
        if not (get_settings().aws_capture_enabled and self._boto3_available()):
            return False
        c = self.credential
        if not c:
            return False
        return bool((c.get("access_key_id") and c.get("secret_access_key")) or c.get("profile"))

    def _session(self) -> Any:
        import boto3  # noqa: PLC0415

        c = self.credential or {}
        # This org's own access key pair, or its own named profile — never the
        # ambient credential chain / a global profile (IA-05: no cross-tenant
        # attribution). ``is_configured`` guarantees one of these is present.
        if c.get("access_key_id") and c.get("secret_access_key"):
            return boto3.Session(
                aws_access_key_id=c["access_key_id"],
                aws_secret_access_key=c["secret_access_key"],
                aws_session_token=c.get("session_token"),
            )
        return boto3.Session(profile_name=c["profile"])

    async def verify(self) -> dict[str, Any]:
        """Confirm we can connect into the GovCloud account (STS caller identity)."""
        if not self._boto3_available():
            return {"connected": False, "reason": "boto3 not installed"}
        if not self.is_configured():
            return {
                "connected": False,
                "reason": "AWS credentials not configured for this organization",
            }
        region = self._region()

        def _call() -> dict[str, Any]:
            sts = self._session().client("sts", region_name=region)
            ident = sts.get_caller_identity()
            arn = ident.get("Arn", "")
            partition = arn.split(":")[1] if arn.count(":") >= 2 else "aws"
            return {
                "connected": True,
                "account": ident.get("Account"),
                "arn": arn,
                "region": region,
                "partition": partition,
                "govcloud": partition == "aws-us-gov" or region in GOVCLOUD_REGIONS,
            }

        try:
            return await asyncio.to_thread(_call)
        except Exception as e:
            return {"connected": False, "reason": str(e)[:200], "region": region}

    def _captured(
        self,
        odp_key: str,
        value: str,
        nist_id: str,
        source: str,
        *,
        confidence: str = "medium",
        detail: dict[str, Any] | None = None,
    ) -> CapturedParameter:
        """One capture, with the 800-53 equivalent carried in ``detail``.

        Built through here rather than at each call site so no sub-capture can
        ship without its ``nist_id`` or without the 800-53 cross-reference --
        the two fields that decide whether it ever reaches a narrative. The
        same helper ``connectors/azure_arm.py`` uses, for the same reason;
        ``_NIST_80053[odp_key]`` raises rather than defaulting, so a new
        capture cannot be added without deciding what it cross-references.
        """
        return CapturedParameter(
            odp_key=odp_key,
            value=value,
            nist_id=nist_id,
            source=source,
            confidence=confidence,
            detail={**(detail or {}), "nist_80053_id": self._NIST_80053[odp_key]},
        )

    async def capture(self) -> list[CapturedParameter]:
        if not self.is_configured():
            return []
        out: list[CapturedParameter] = []
        # Isolate each sub-capture: one failing AWS call (throttling, a single
        # service permission gap) must not discard parameters other calls captured.
        for sub in (self._capture_log_retention, self._capture_ebs_encryption):
            try:
                out.extend(await sub())
            except Exception as e:  # best-effort — never break the caller
                log.warning(
                    "connector.aws.capture_failed", capture=sub.__name__, error=str(e)[:200]
                )
        return out

    async def _capture_log_retention(self) -> list[CapturedParameter]:
        """CloudWatch Logs retention → audit record retention ODP.

        Integration seam: run the (blocking) boto3 call in a thread. Wired to
        return the maximum configured log-group retention as the audit period.
        """

        def _read() -> str | None:
            client = self._session().client("logs", region_name=self._region())
            retentions: list[int] = []
            paginator = client.get_paginator("describe_log_groups")
            for page in paginator.paginate():
                for grp in page.get("logGroups", []):
                    if grp.get("retentionInDays"):
                        retentions.append(int(grp["retentionInDays"]))
            if not retentions:
                return None
            return f"{min(retentions)} days"

        value = await asyncio.to_thread(_read)
        if not value:
            return []
        return [
            self._captured(
                "audit_retention_period",
                value,
                "3.3.1",
                "AWS: CloudWatch Logs retentionInDays (minimum across log groups)",
            )
        ]

    async def _capture_ebs_encryption(self) -> list[CapturedParameter]:
        """EC2 default EBS encryption → encryption-at-rest signal (KSI-SVC-03).

        Emits ``3.13.16`` — the 800-171 practice an AWS GovCloud project's
        entries are actually keyed on — with ``SC-28`` carried in ``detail``.
        See the module docstring for the measurement behind that: while this
        emitted ``SC-28`` as its ``nist_id``, the value was captured on every
        run and then discarded at the join, because no AWS project has an
        800-53 id on any entry.
        """

        def _read() -> bool:
            client = self._session().client("ec2", region_name=self._region())
            return bool(client.get_ebs_encryption_by_default().get("EbsEncryptionByDefault"))

        if not await asyncio.to_thread(_read):
            return []
        return [
            self._captured(
                "encryption_at_rest",
                "enabled",
                "3.13.16",
                "AWS: EC2 default EBS encryption enabled",
                confidence="high",
            )
        ]

    # ── posture scanning ────────────────────────────────────────────────────

    def _readers(self) -> dict[str, Callable[[], list[dict[str, Any]]]]:
        """Source token -> the (blocking) boto3 reader that answers it.

        A fixed dispatch table, deliberately. ``ENDPOINTS`` for this provider
        holds ``<service>.<operation>`` tokens rather than URLs, and the only
        thing a token is ever used for is a lookup here -- never a service or
        operation name passed through to boto3. A token with no entry raises
        :class:`UnknownAwsSourceError`, so the blast radius of an unexpected
        one is a single unrunnable check rather than an arbitrary AWS API call
        under this organization's credentials.

        A test asserts every registered AWS endpoint has a reader here, so a
        check cannot be registered into a source nothing can read.
        """
        return {
            aws_checks.ENDPOINTS[aws_checks.ROOT_MFA_ENABLED.key]: self._read_account_summary,
            aws_checks.ENDPOINTS[aws_checks.PASSWORD_POLICY.key]: self._read_password_policy,
            aws_checks.ENDPOINTS[aws_checks.ACCESS_KEY_ROTATION.key]: self._read_access_keys,
            aws_checks.ENDPOINTS[
                aws_checks.CLOUDTRAIL_MULTI_REGION.key
            ]: self._read_cloudtrail_trails,
        }

    def _iam(self) -> Any:
        return self._session().client("iam", region_name=self._region())

    def _read_account_summary(self) -> list[dict[str, Any]]:
        """``iam.get_account_summary`` — the account's identity counters."""
        return [self._iam().get_account_summary()]

    @staticmethod
    def _is_no_such_entity(error: Exception) -> bool:
        """Is this the IAM error meaning "that thing does not exist"?

        Duck-typed on the botocore error shape rather than importing
        ``botocore.exceptions``: boto3 is an optional dependency here (see
        ``_boto3_available``), and importing its internals at module scope
        would make this module unimportable in a deployment that never uses
        AWS. The error code is read from the response envelope, which is the
        documented, stable location.
        """
        response = getattr(error, "response", None)
        if not isinstance(response, dict):
            return False
        code = (response.get("Error") or {}).get("Code")
        return code in ("NoSuchEntity", "NoSuchEntityException")

    def _read_password_policy(self) -> list[dict[str, Any]]:
        """``iam.get_account_password_policy`` — empty ONLY when none exists.

        IAM raises ``NoSuchEntity`` for an account with no password policy.
        That one error becomes ``[]``, which the evaluator reads as a ``fail``
        (AWS's permissive default is in force). Every other error propagates,
        so "there is no policy" and "I could not look" never collapse into the
        same answer.
        """
        try:
            return [self._iam().get_account_password_policy()]
        except Exception as e:
            if self._is_no_such_entity(e):
                return []
            raise

    def _read_access_keys(self) -> list[dict[str, Any]]:
        """``iam.list_access_keys`` for every user, flattened into one fleet.

        Both calls are paginated through boto3's paginators: an account whose
        users or keys spill past one page would otherwise be silently
        short-read, and the unread rows are exactly as likely to be the stale
        ones.
        """
        iam = self._iam()
        keys: list[dict[str, Any]] = []
        for page in iam.get_paginator("list_users").paginate():
            for user in page.get("Users", []) or []:
                name = user.get("UserName")
                if not name:
                    continue
                for key_page in iam.get_paginator("list_access_keys").paginate(UserName=name):
                    keys.extend(key_page.get("AccessKeyMetadata", []) or [])
        return keys

    def _read_cloudtrail_trails(self) -> list[dict[str, Any]]:
        """``cloudtrail.describe_trails``, with each trail's logging status merged.

        ``describe_trails`` says a trail is *configured*; it does not say the
        trail is *running*. A multi-region trail that somebody stopped would
        satisfy a configuration-only check while recording nothing, which is
        the failure AU-12 is about -- so ``get_trail_status`` is called per
        trail and ``IsLogging`` merged onto the row.

        ``includeShadowTrails=False`` because a multi-region trail appears as a
        shadow copy in every other region; counting those would report one
        trail many times.

        A trail whose status call fails is returned *without* an ``IsLogging``
        key rather than with a guessed one. The evaluator treats that as
        unknown (``manual_review_required``), never as stopped and never as
        running.
        """
        client = self._session().client("cloudtrail", region_name=self._region())
        trails = client.describe_trails(includeShadowTrails=False).get("trailList", []) or []
        rows: list[dict[str, Any]] = []
        for trail in trails:
            row = dict(trail)
            name = trail.get("TrailARN") or trail.get("Name")
            try:
                row["IsLogging"] = bool(client.get_trail_status(Name=name).get("IsLogging"))
            except Exception as e:
                log.warning(
                    "connector.aws.trail_status_unreadable",
                    trail=str(name)[:200],
                    error=str(e)[:200],
                )
            rows.append(row)
        return rows

    async def _fetch(self, endpoint: str) -> list[dict[str, Any]]:
        """The rows for one source token, read off the event loop."""
        reader = self._readers().get(endpoint)
        if reader is None:
            raise UnknownAwsSourceError(endpoint)
        return await asyncio.to_thread(reader)

    async def _account_id(self) -> str:
        """Which account these findings are about — never empty.

        A singleton finding whose ``resource_id`` is blank tells an operator
        nothing about *where* to go and fix it. Prefers an account id the
        credential already carries (no API call); otherwise asks STS once for
        the whole scan rather than once per check.
        """
        declared = (self.credential or {}).get("account_id")
        if isinstance(declared, str) and declared:
            return declared

        def _call() -> str:
            sts = self._session().client("sts", region_name=self._region())
            return str(sts.get_caller_identity().get("Account") or "unknown")

        return await asyncio.to_thread(_call)

    async def scan(
        self, checks: tuple[ResolvedCheck, ...] | None = None
    ) -> list[CheckOutcome]:
        """Assess this account against its resolved posture checks.

        ``checks`` is ``None`` for a caller that predates declared checks, in
        which case the platform registry is used and behaviour is unchanged.
        An empty tuple scans nothing and must NOT fall back to the registry --
        it means this tenant has nothing to scan. See ``ConfigConnector.scan``.

        Never raises: an unconfigured org, a missing credential, or a provider
        error all produce results (or none) rather than an exception, because
        ``ConfigConnector.scan``'s contract says so and ``scan_for_system``
        does not expect one.
        """
        if not self.is_configured():
            return []
        resolved = resolve_checks_from_registry(self.key) if checks is None else tuple(checks)
        if not resolved:
            return []
        try:
            account_id = await self._account_id()
        except Exception as e:
            # Not fatal to the scan: the checks each report their own failure
            # below if the credential is genuinely broken, and a singleton
            # finding is still more useful labelled "unknown" than not emitted.
            log.warning("connector.aws.account_id_unreadable", error=str(e)[:200])
            account_id = "unknown"
        now = datetime.now(UTC)
        outcomes: list[CheckOutcome] = []
        for rc in resolved:
            # Per-check isolation: one service permission gap -- or one
            # malformed row -- must not discard the checks that did run,
            # matching capture()'s per-sub-capture try and the Graph
            # connector's scan. Fetch and evaluation each get their own try,
            # so an exception from either produces an unrunnable outcome for
            # THIS check rather than escaping and discarding every outcome
            # collected so far.
            try:
                rows = await self._fetch(rc.endpoint)
            except Exception as e:
                outcomes.append(self._unrunnable(rc.check, e, account_id=account_id))
                continue
            try:
                outcomes.append(
                    self._evaluate(rc, rows, account_id=account_id, now=now)
                )
            except Exception as e:
                # A check that silently stops producing results is
                # indistinguishable from one that passes, so it reports.
                outcomes.append(self._unrunnable(rc.check, e, account_id=account_id))
        return outcomes

    def _evaluate(
        self,
        rc: ResolvedCheck,
        rows: list[dict[str, Any]],
        *,
        account_id: str,
        now: datetime,
    ) -> CheckOutcome:
        """Judge one check's rows via its evaluator.

        Dispatches on ``evaluator_key`` rather than the check's own key,
        because a pack that parameterized a platform check (Form A) runs under
        the pack's key while still using the platform's logic.

        The evaluators take different keyword arguments -- the account-scoped
        ones need to know which account, the rotation check needs a clock --
        so each is called with what it declares rather than forcing a uniform
        signature most checks would ignore. Declared parameters are merged on
        top, which is what makes a pack's ``threshold_days`` take effect.
        """
        key = rc.evaluator_key or rc.check.key
        evaluator = aws_checks.EVALUATORS[key]
        kwargs: dict[str, Any] = dict(rc.parameters or {})
        if key in aws_checks.ACCOUNT_SCOPED:
            kwargs["account_id"] = account_id
        if key == aws_checks.ACCESS_KEY_ROTATION.key:
            kwargs["now"] = now
        findings = evaluator(rows, **kwargs)
        return CheckOutcome.from_findings(rc.check, tuple(findings))

    def _unrunnable(
        self, check: PostureCheck, error: Exception, *, account_id: str
    ) -> CheckOutcome:
        """A check that could not run — never a clean account.

        The rollup maps zero findings to ``not_applicable``, so returning
        nothing here would hide a missing IAM permission behind a
        benign-looking verdict. One finding carries ``manual_review_required``
        and names the reason, which puts it where an operator looks.
        """
        observed = self._describe_failure(check, error)
        log.warning(
            "connector.aws.check_unrunnable", check=check.key, error=str(error)[:200]
        )
        return CheckOutcome.from_findings(
            check,
            (
                ResourceFinding(
                    resource_id=account_id,
                    resource_type=check.resource_type,
                    verdict="manual_review_required",
                    observed=observed,
                    detail={"error": str(error)[:300]},
                ),
            ),
        )

    @staticmethod
    def _describe_failure(check: PostureCheck, error: Exception) -> str:
        """A human-readable reason a check could not run.

        Only an authorization failure names the required permissions. Every
        other failure class is described by what it actually is, so an
        operator is never told to grant an IAM action that was never the
        problem — the judgement ``msgraph._describe_failure`` makes for a 429
        or a timeout.
        """
        if isinstance(error, UnknownAwsSourceError):
            return (
                f"this check reads {str(error)!r}, which the AWS connector has no "
                "reader for; tenant-declared AWS checks are not supported"
            )
        response = getattr(error, "response", None)
        code = ""
        if isinstance(response, dict):
            code = str((response.get("Error") or {}).get("Code") or "")
        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
            needed = ", ".join(check.required_permissions) or "unknown permissions"
            return f"{code}: could not read AWS; requires {needed}"
        if code:
            return f"AWS returned {code}; could not evaluate this check"
        return f"could not evaluate this check ({type(error).__name__})"
