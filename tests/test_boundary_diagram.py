"""Mermaid diagram generators (``boundary_mermaid``/``data_flow_mermaid``) —
pure functions over a ``BoundarySummary``, no DB required.

Assertions target structural substrings (node/edge/subgraph presence), not
exact layout, so the tests stay stable as the rendering evolves.
"""

from __future__ import annotations

from ccf.boundary.diagram import boundary_mermaid, data_flow_mermaid
from ccf.boundary.summary import BoundarySummary
from ccf.models import InformationType, Interconnection, InventoryItem, SystemComponent


def _comp(
    comp_id: int, title: str, comp_type: str = "software", oscal_uuid: str | None = None
) -> SystemComponent:
    c = SystemComponent(title=title, type=comp_type)
    c.id = comp_id
    c.oscal_uuid = oscal_uuid
    return c


def _inv(
    inv_id: int,
    asset_id: str,
    component_id: int | None,
    oscal_uuid: str | None = None,
) -> InventoryItem:
    i = InventoryItem(asset_id=asset_id, asset_type="hardware", component_id=component_id)
    i.id = inv_id
    i.oscal_uuid = oscal_uuid
    return i


def _ic(
    ic_id: int,
    remote_system_name: str,
    direction: str = "incoming",
    agreement_type: str = "isa",
    data_description: str | None = None,
    oscal_uuid: str | None = None,
) -> Interconnection:
    ic = Interconnection(
        remote_system_name=remote_system_name,
        direction=direction,
        agreement_type=agreement_type,
        data_description=data_description,
    )
    ic.id = ic_id
    ic.oscal_uuid = oscal_uuid
    return ic


def _info(
    info_id: int,
    title: str,
    conf: str | None = "moderate",
    integ: str | None = "moderate",
    avail: str | None = "moderate",
) -> InformationType:
    it = InformationType(
        title=title,
        confidentiality_impact=conf,
        integrity_impact=integ,
        availability_impact=avail,
    )
    it.id = info_id
    return it


# --- boundary_mermaid -------------------------------------------------------


def test_boundary_mermaid_has_components_and_interconnections() -> None:
    summary = BoundarySummary(
        components=[_comp(1, "Web App")],
        inventory=[],
        info_types=[],
        interconnections=[_ic(1, "Agency IdP", direction="incoming")],
    )
    out = boundary_mermaid(summary, "Sys A")
    assert out.startswith("flowchart")
    assert "Web App" in out
    assert "subgraph" in out
    assert "Agency IdP" in out


def test_boundary_mermaid_uses_oscal_uuid_for_node_ids() -> None:
    summary = BoundarySummary(
        components=[_comp(1, "Web App", oscal_uuid="1234abcd-56ef-78gh-90ij-klmnopqrstuv")],
        inventory=[],
        info_types=[],
        interconnections=[],
    )
    out = boundary_mermaid(summary, "Sys A")
    # dashes get sanitized to underscores; the raw uuid string never appears verbatim.
    assert "1234abcd-56ef" not in out
    assert "1234abcd_56ef" in out


def test_boundary_mermaid_node_ids_are_mermaid_safe() -> None:
    summary = BoundarySummary(
        components=[_comp(1, "Weird / Title (v2)"), _comp(2, "Another One")],
        inventory=[],
        info_types=[],
        interconnections=[],
    )
    out = boundary_mermaid(summary, "Sys A")
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith(("c0[", "c1[")):
            node_id = stripped.split("[", 1)[0]
            assert node_id.replace("_", "").isalnum() or node_id.isalnum()


def test_boundary_mermaid_lists_inventory_under_component() -> None:
    summary = BoundarySummary(
        components=[_comp(1, "Web App")],
        inventory=[_inv(1, "ASSET-001", component_id=1)],
        info_types=[],
        interconnections=[],
    )
    out = boundary_mermaid(summary, "Sys A")
    assert "ASSET-001" in out


def test_boundary_mermaid_edge_label_has_direction_and_agreement() -> None:
    summary = BoundarySummary(
        components=[],
        inventory=[],
        info_types=[],
        interconnections=[_ic(1, "Payments Gateway", direction="outgoing", agreement_type="mou")],
    )
    out = boundary_mermaid(summary, "Sys A")
    assert "outgoing/mou" in out


def test_empty_boundary_is_safe() -> None:
    out = boundary_mermaid(BoundarySummary([], [], [], []), "Sys A")
    assert "flowchart" in out
    assert "Sys A" in out


def test_boundary_mermaid_deterministic_ordering() -> None:
    summary = BoundarySummary(
        components=[_comp(1, "Zeta"), _comp(2, "Alpha")],
        inventory=[],
        info_types=[],
        interconnections=[_ic(1, "Zulu System"), _ic(2, "Alpha System")],
    )
    out1 = boundary_mermaid(summary, "Sys A")
    out2 = boundary_mermaid(summary, "Sys A")
    assert out1 == out2
    assert out1.index("Alpha") < out1.index("Zeta")
    assert out1.index("Alpha System") < out1.index("Zulu System")


def test_boundary_mermaid_title_with_quote_and_newline_is_safe() -> None:
    summary = BoundarySummary(
        components=[_comp(1, 'Weird "Title"\nwith a newline')],
        inventory=[],
        info_types=[],
        interconnections=[_ic(1, 'Remote "Sys"\nB')],
    )
    out = boundary_mermaid(summary, "Sys A")
    assert '"Title"' not in out
    assert '"Sys"' not in out
    for line in out.splitlines():
        # every emitted line is a single logical Mermaid statement (no embedded
        # newline broke a line in two, and no raw double-quote survived inside a label)
        assert line.count('"') % 2 == 0


# --- data_flow_mermaid -------------------------------------------------------


def test_data_flow_mermaid_has_components_and_info_types() -> None:
    summary = BoundarySummary(
        components=[_comp(1, "Web App")],
        inventory=[],
        info_types=[_info(1, "PII")],
        interconnections=[],
    )
    out = data_flow_mermaid(summary, "Sys A")
    assert out.startswith("flowchart")
    assert "Web App" in out
    assert "PII" in out


def test_data_flow_mermaid_has_interconnection_flow() -> None:
    summary = BoundarySummary(
        components=[],
        inventory=[],
        info_types=[],
        interconnections=[
            _ic(1, "Agency IdP", direction="incoming", data_description="SSO assertions")
        ],
    )
    out = data_flow_mermaid(summary, "Sys A")
    assert "Agency IdP" in out
    assert "SSO assertions" in out


def test_empty_data_flow_is_safe() -> None:
    out = data_flow_mermaid(BoundarySummary([], [], [], []), "Sys A")
    assert "flowchart" in out
    assert "Sys A" in out


def test_data_flow_mermaid_title_with_quote_and_newline_is_safe() -> None:
    summary = BoundarySummary(
        components=[_comp(1, 'Weird "Title"\nwith a newline')],
        inventory=[],
        info_types=[_info(1, 'Odd "Info"\nType')],
        interconnections=[],
    )
    out = data_flow_mermaid(summary, "Sys A")
    assert '"Title"' not in out
    assert '"Info"' not in out
    for line in out.splitlines():
        assert line.count('"') % 2 == 0
