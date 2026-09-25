"""What a usable credential looks like, for every connector Concord stores one for.

One declaration, read by three callers that used to disagree:

* the settings form, which renders the fields;
* ``set_credential``, which refuses a bundle that cannot authenticate;
* ``tests/test_credential_spec.py``, which drives each connector's own
  ``is_configured()`` against what is declared here.

That third caller is the point. A field list is a *claim* about what a
connector needs, and this programme has shipped a parity guard that scanned
source text and passed vacuously for two connectors out of three. So the test
builds a credential from the declaration and asserts the connector agrees --
complete when every field of an accepted group is present, and incomplete when
any one of them is removed.

Before this existed, ``set_credential`` stored whatever it was given and set
``status = "configured"`` unconditionally. An empty Microsoft bundle was
accepted, displayed a ``key_last4`` of ``…{}``, reported the connector as
configured, and could never authenticate.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .clouds import AWS_REGION_CHOICES, CLOUD_CHOICES


@dataclass(frozen=True)
class CredentialField:
    """One input on the credential form."""

    name: str
    label: str
    #: Rendered as a password input, never echoed back, and a candidate for
    #: the ``key_last4`` display value.
    secret: bool = False
    help: str = ""
    multiline: bool = False
    #: ``(value, label)`` pairs. Present means the form renders a select, and
    #: the first pair is the default -- which is how "US Government unless
    #: someone deliberately chooses otherwise" is expressed.
    choices: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class CredentialSpec:
    """The fields a connector takes, and which combinations are usable."""

    label: str
    fields: tuple[CredentialField, ...]
    #: A bundle is complete when every name in **any one** group is present.
    #: A tuple of groups rather than a flat list because AWS genuinely accepts
    #: either an access-key pair or a named profile, and flattening that would
    #: either reject a valid credential or accept an unusable one.
    accepts: tuple[tuple[str, ...], ...]
    #: Non-secret settings stored on ``ConnectorConfig.config`` instead of in
    #: the enveloped bundle, so they can be changed without re-entering a key.
    config_fields: tuple[CredentialField, ...] = field(default_factory=tuple)
    doc: str = ""


_MICROSOFT_APP_REGISTRATION = (
    CredentialField(
        "cloud",
        "Sovereign cloud",
        choices=CLOUD_CHOICES,
        help=(
            "US Government unless this app registration was issued in a "
            "commercial tenant. Never required: absent means the deployment's "
            "configured endpoints, which default to US Government."
        ),
    ),
    CredentialField(
        "tenant_id",
        "Directory (tenant) ID",
        help="The Entra ID tenant the app registration lives in.",
    ),
    CredentialField(
        "client_id",
        "Application (client) ID",
        help="From the app registration's Overview blade.",
    ),
    CredentialField(
        "client_secret",
        "Client secret",
        secret=True,
        help="A client secret value, not its ID. Certificates are not yet supported.",
    ),
)


SPECS: dict[str, CredentialSpec] = {
    "msgraph": CredentialSpec(
        label="Microsoft 365 (Graph)",
        fields=_MICROSOFT_APP_REGISTRATION,
        accepts=(("tenant_id", "client_id", "client_secret"),),
        doc=(
            "An Entra ID app registration with application permissions granted "
            "and admin consent recorded. Read-only scopes are sufficient for capture."
        ),
    ),
    "msgraph_write": CredentialSpec(
        label="Microsoft 365 (Graph) — write",
        fields=_MICROSOFT_APP_REGISTRATION,
        accepts=(("tenant_id", "client_id", "client_secret"),),
        doc=(
            "A deliberately separate app registration from the read connector, so a "
            "deployment that never created one cannot have enforcement write to its "
            "tenant."
        ),
    ),
    "azure_arm": CredentialSpec(
        label="Azure (Resource Manager)",
        fields=(
            *_MICROSOFT_APP_REGISTRATION,
            CredentialField(
                "subscription_id",
                "Subscription ID",
                help=(
                    "Required: every ARM read is subscription-scoped, so a credential "
                    "without one authenticates and reads nothing."
                ),
            ),
        ),
        accepts=(("tenant_id", "client_id", "client_secret", "subscription_id"),),
        doc="A service principal with Reader on the subscription.",
    ),
    "gcp": CredentialSpec(
        label="Google Cloud",
        fields=(
            CredentialField("project_id", "Project ID"),
            CredentialField("client_email", "Service account email"),
            CredentialField(
                "private_key",
                "Private key",
                secret=True,
                multiline=True,
                help="The PEM block from the service account's JSON key file.",
            ),
        ),
        accepts=(("project_id", "client_email", "private_key"),),
        doc="A service account with Viewer on the project.",
    ),
    "aws_govcloud": CredentialSpec(
        label="AWS GovCloud (US)",
        fields=(
            CredentialField("access_key_id", "Access key ID"),
            CredentialField("secret_access_key", "Secret access key", secret=True),
            CredentialField(
                "profile",
                "Named profile",
                help="Alternative to an access key pair, for a host with a shared config.",
            ),
            CredentialField(
                "region",
                "Region",
                choices=AWS_REGION_CHOICES,
                help=(
                    "GovCloud unless these keys belong to a commercial account. "
                    "Never required: absent means the deployment's configured "
                    "region, which defaults to us-gov-west-1."
                ),
            ),
        ),
        accepts=(("access_key_id", "secret_access_key"), ("profile",)),
        doc=(
            "Either an access key pair or a named profile, in the aws-us-gov "
            "partition. Capture additionally requires CCF_AWS_CAPTURE_ENABLED and "
            "the boto3 package."
        ),
    ),
    "puppetdb": CredentialSpec(
        label="PuppetDB",
        fields=(
            CredentialField("base_url", "Base URL", help="https origin of the PuppetDB API."),
            CredentialField(
                "token",
                "API token",
                secret=True,
                help="Optional: many deployments sit behind mTLS or a private network.",
            ),
        ),
        accepts=(("base_url",),),
    ),
    "jira": CredentialSpec(
        label="Jira Cloud",
        fields=(
            CredentialField("base_url", "Site URL", help="https://your-site.atlassian.net"),
            CredentialField("email", "Account email"),
            CredentialField("api_token", "API token", secret=True),
        ),
        accepts=(("base_url", "email", "api_token"),),
        config_fields=(
            CredentialField("project_key", "Project key", help="e.g. SEC"),
            CredentialField("issue_type", "Issue type", help="Defaults to Task."),
        ),
        doc="Outbound only. Concord files and updates issues and never reads status back.",
    ),
    "emass": CredentialSpec(
        label="eMASS",
        fields=(
            CredentialField("base_url", "Base URL"),
            CredentialField("api_key", "API key", secret=True),
            CredentialField("user_uid", "User UID", help="The CAC-backed registered user."),
        ),
        accepts=(("base_url", "api_key", "user_uid"),),
        config_fields=(CredentialField("system_id", "eMASS system ID"),),
        doc=(
            "Outbound only, and unverified against a live eMASS instance -- written "
            "from the published specification."
        ),
    ),
}


class IncompleteCredential(ValueError):
    """A stored bundle that could never authenticate.

    Raised rather than recorded: a credential accepted and marked configured is
    a claim the connector cannot honour, and the failure surfaces much later as
    "capture produced nothing" with no indication why.
    """


def spec_for(connector_type: str) -> CredentialSpec | None:
    return SPECS.get(connector_type)


def missing_fields(connector_type: str, secret: dict) -> tuple[str, ...]:
    """Field names still needed, or ``()`` when the bundle is usable.

    Where a connector accepts alternatives, the group closest to satisfied is
    reported: telling someone who filled in an access key ID that they also
    need a "named profile" would be actively misleading.

    With *nothing* filled in there is no evidence of intent, and "closest to
    satisfied" degenerates to "fewest fields" -- which would answer a blank AWS
    form with "you need: profile" when the access-key pair is the primary path.
    An empty bundle therefore reports the first declared group.
    """
    spec = spec_for(connector_type)
    if spec is None:
        return ()
    present = {k for k, v in (secret or {}).items() if str(v or "").strip()}
    if not present:
        return tuple(spec.accepts[0]) if spec.accepts else ()
    best: tuple[str, ...] | None = None
    for group in spec.accepts:
        outstanding = tuple(name for name in group if name not in present)
        if not outstanding:
            return ()
        if best is None or len(outstanding) < len(best):
            best = outstanding
    return best or ()


__all__ = [
    "SPECS",
    "CredentialField",
    "CredentialSpec",
    "IncompleteCredential",
    "missing_fields",
    "spec_for",
]
