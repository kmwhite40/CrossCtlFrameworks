"""Which sovereign cloud a connector reaches, chosen per organization.

The endpoints used to live only in ``Settings``, making the cloud a property
of the *instance*: one Concord could not serve a GovCloud tenant and a
commercial one at the same time, and an organization whose app registration
was commercial could not authenticate at all -- the failure looked like
``AADSTS90002: Tenant not found``.

Every assertion here drives the connector and reads the URL it would actually
call, rather than checking the lookup table against itself.
"""

from __future__ import annotations

import httpx
import pytest

from ccf.config import get_settings
from ccf.connectors.azure_arm import AzureArmConnector
from ccf.connectors.clouds import AWS_REGION_CHOICES, CLOUD_CHOICES, microsoft_endpoints
from ccf.connectors.credential_spec import SPECS, missing_fields
from ccf.connectors.msgraph import MsGraphConnector

_APP_REG = {
    "tenant_id": "t-1",
    "client_id": "c-1",
    "client_secret": "s-1",
    "subscription_id": "sub-1",
}


async def _token_url(connector) -> str:
    """The URL the connector would post its client-credentials grant to."""
    captured: dict[str, str] = {}

    async def _capture(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        return httpx.Response(200, json={"access_token": "x"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(_capture)) as client:
        await connector._token(client)
    return captured["url"]


# --- the default is the government cloud -------------------------------------


def test_us_government_is_the_first_choice_and_therefore_the_default() -> None:
    """Concord is built for federal deployments: a connector that silently
    reached a commercial endpoint would cross a sovereign boundary."""
    assert CLOUD_CHOICES[0][0] == "usgov"
    assert AWS_REGION_CHOICES[0][0].startswith("us-gov-")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("connector_class", "expected"),
    [
        (MsGraphConnector, "https://login.microsoftonline.us"),
        (AzureArmConnector, "https://login.microsoftonline.us"),
    ],
)
async def test_a_credential_naming_no_cloud_stays_on_the_government_endpoints(
    connector_class, expected: str
) -> None:
    """Every credential stored before this existed carries no cloud."""
    url = await _token_url(connector_class(credential=dict(_APP_REG)))
    assert url.startswith(expected)


@pytest.mark.asyncio
async def test_an_unrecognised_cloud_does_not_silently_go_commercial() -> None:
    """A typo must not redirect a federal tenant's traffic.

    `microsoft_endpoints` returns None for anything it does not know, which
    falls back to the deployment settings -- government by default.
    """
    assert microsoft_endpoints("comercial") is None
    url = await _token_url(MsGraphConnector(credential={**_APP_REG, "cloud": "comercial"}))
    assert url.startswith("https://login.microsoftonline.us")


# --- and the choice is honoured ----------------------------------------------


@pytest.mark.asyncio
async def test_choosing_commercial_moves_graph_to_the_commercial_endpoints() -> None:
    connector = MsGraphConnector(credential={**_APP_REG, "cloud": "commercial"})
    url = await _token_url(connector)
    assert url.startswith("https://login.microsoftonline.com")
    assert connector._graph_base == "https://graph.microsoft.com"


@pytest.mark.asyncio
async def test_choosing_commercial_moves_arm_to_the_commercial_endpoints() -> None:
    connector = AzureArmConnector(credential={**_APP_REG, "cloud": "commercial"})
    url = await _token_url(connector)
    assert url.startswith("https://login.microsoftonline.com")
    assert connector._arm_base == "https://management.azure.com"


@pytest.mark.asyncio
async def test_two_organizations_reach_different_clouds_from_one_deployment() -> None:
    """The point of the change: the cloud belongs to the credential, not the
    instance. One deployment, one settings object, two sovereign boundaries."""
    gov = await _token_url(MsGraphConnector(credential={**_APP_REG, "cloud": "usgov"}))
    com = await _token_url(MsGraphConnector(credential={**_APP_REG, "cloud": "commercial"}))
    assert gov.startswith("https://login.microsoftonline.us")
    assert com.startswith("https://login.microsoftonline.com")


@pytest.mark.asyncio
async def test_the_pagination_guard_follows_the_organizations_own_cloud() -> None:
    """`_safe_url` pins every page to a base URL. Pinning it to the *deployment's*
    base would reject a commercial tenant's own nextLink as off-host, so the
    connector could authenticate and then read nothing."""
    connector = MsGraphConnector(credential={**_APP_REG, "cloud": "commercial"})

    pages = [
        httpx.Response(
            200,
            json={
                "value": [{"id": "1"}],
                "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skip=1",
            },
        ),
        httpx.Response(200, json={"value": [{"id": "2"}]}),
    ]
    seen: list[str] = []

    async def _serve(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return pages[len(seen) - 1]

    # Driven through `_get_all`, which is where the base is chosen. Passing a
    # base in by hand would test `_safe_url` and leave the wiring free to pin
    # to the deployment's endpoint -- the mutation that survived the first
    # time this was written.
    async with httpx.AsyncClient(transport=httpx.MockTransport(_serve)) as client:
        rows = await connector._get_all(
            client, "https://graph.microsoft.com/v1.0/users", {}
        )

    assert [r["id"] for r in rows] == ["1", "2"]
    assert all(u.startswith("https://graph.microsoft.com/") for u in seen), seen


# --- AWS ---------------------------------------------------------------------


def test_the_aws_region_travels_with_the_credential_and_defaults_to_govcloud() -> None:
    from ccf.connectors.aws import AwsGovCloudConnector  # noqa: PLC0415

    default = AwsGovCloudConnector(credential={"access_key_id": "A", "secret_access_key": "B"})
    assert default._region() == get_settings().aws_region == "us-gov-west-1"

    commercial = AwsGovCloudConnector(
        credential={"access_key_id": "A", "secret_access_key": "B", "region": "us-east-1"}
    )
    assert commercial._region() == "us-east-1"


# --- neither selector may become mandatory -----------------------------------


@pytest.mark.parametrize(
    ("connector_type", "credential"),
    [
        ("msgraph", {"tenant_id": "t", "client_id": "c", "client_secret": "s"}),
        (
            "azure_arm",
            {"tenant_id": "t", "client_id": "c", "client_secret": "s", "subscription_id": "x"},
        ),
        ("aws_govcloud", {"access_key_id": "A", "secret_access_key": "B"}),
    ],
)
def test_the_cloud_selector_is_never_required(
    connector_type: str, credential: dict
) -> None:
    """Every credential stored before this existed omits it, and must keep
    working rather than being reported incomplete on the next save."""
    assert missing_fields(connector_type, credential) == ()
    names = {f.name for f in SPECS[connector_type].fields}
    assert names & {"cloud", "region"}, f"{connector_type} offers no cloud selector"
