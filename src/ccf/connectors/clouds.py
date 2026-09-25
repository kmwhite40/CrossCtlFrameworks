"""Which sovereign cloud an organization's connector talks to.

Concord defaults to the **US Government** clouds throughout, because that is
who it is built for: a federal deployment that silently reached a commercial
endpoint would send tenant configuration to the wrong sovereign boundary. So
every default here is the government one, and reaching a commercial tenant is
an explicit per-organization choice.

Per organization, not per deployment. The endpoints used to live only in
``Settings`` (``graph_base_url``, ``arm_login_url``, ``aws_region``), which
made the sovereign cloud a property of the *instance*: one Concord could not
serve a GovCloud tenant and a commercial one at the same time, and an
organization whose app registration was commercial simply could not
authenticate. The selection now travels with the credential it belongs to,
beside the app registration it was issued from.

Stored in the credential bundle rather than in ``ConnectorConfig.config``
because that is the only thing plumbed to a connector instance, and because
AWS already carried its ``region`` there -- adding a second, differently
located home for the same kind of setting would be worse than the
inconsistency it fixed.
"""

from __future__ import annotations

from dataclasses import dataclass

US_GOV = "usgov"
COMMERCIAL = "commercial"

#: Offered in this order, so the first is the default: US Government.
CLOUD_CHOICES: tuple[tuple[str, str], ...] = (
    (US_GOV, "US Government"),
    (COMMERCIAL, "Commercial"),
)


@dataclass(frozen=True)
class MicrosoftEndpoints:
    login_url: str
    graph_base_url: str
    arm_base_url: str


_MICROSOFT: dict[str, MicrosoftEndpoints] = {
    US_GOV: MicrosoftEndpoints(
        login_url="https://login.microsoftonline.us",
        graph_base_url="https://graph.microsoft.us",
        arm_base_url="https://management.usgovcloudapi.net",
    ),
    COMMERCIAL: MicrosoftEndpoints(
        login_url="https://login.microsoftonline.com",
        graph_base_url="https://graph.microsoft.com",
        arm_base_url="https://management.azure.com",
    ),
}


def microsoft_endpoints(cloud: str | None) -> MicrosoftEndpoints | None:
    """Endpoints for a named cloud, or ``None`` when none was chosen.

    ``None`` means "fall back to the deployment settings", which keeps an
    existing installation on whatever it was configured with and keeps the
    government endpoints as the default. An *unrecognised* value also returns
    ``None`` rather than guessing: a typo must not silently redirect a
    federal tenant's traffic to a commercial endpoint.
    """
    if not cloud:
        return None
    return _MICROSOFT.get(str(cloud).strip().lower())


#: GovCloud first, for the same reason the Microsoft list is ordered this way.
AWS_REGION_CHOICES: tuple[tuple[str, str], ...] = (
    ("us-gov-west-1", "GovCloud (US-West)"),
    ("us-gov-east-1", "GovCloud (US-East)"),
    ("us-east-1", "Commercial (N. Virginia)"),
    ("us-east-2", "Commercial (Ohio)"),
    ("us-west-2", "Commercial (Oregon)"),
)

__all__ = [
    "AWS_REGION_CHOICES",
    "CLOUD_CHOICES",
    "COMMERCIAL",
    "US_GOV",
    "MicrosoftEndpoints",
    "microsoft_endpoints",
]
