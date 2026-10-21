"""The information architecture: one source for the rail, the command palette,
the breadcrumbs and the "planned" pages.

Before this module the IA lived in a Jinja dict in ``base.html`` and again, by
hand, in ``app.js``'s palette list, and the two had drifted. Everything that
needs to know "what is in Concord and where" now reads :data:`NAV`.

Every item carries a :class:`Status`, because the requested navigation names
more capabilities than Concord has. An item is one of:

``live``
    A page that does what the label says.
``partial``
    A real page that covers part of it. ``note`` says which part is missing,
    and the rail marks it so nobody reads the label as a promise.
``planned``
    Nothing in Concord does this yet. The item routes to ``/planned/<slug>``,
    which says so plainly and links what exists nearby. It never routes to a
    real page wearing a label it does not earn.

Highlighting: a route passes ``active=<key>``; exactly one item owns each key.
Several items may share an ``href`` (two registers over the one ``/risks``
page), but only one of them owns the page's key, so a page never lights two
rail entries. ``tests/test_ui_shell.py`` pins both rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Status(StrEnum):
    LIVE = "live"
    PARTIAL = "partial"
    PLANNED = "planned"


@dataclass(frozen=True)
class Item:
    key: str
    label: str
    href: str
    status: Status = Status.LIVE
    #: What is missing (partial) or what would be needed (planned).
    note: str = ""
    #: Real pages a reader can use today instead (planned items only).
    nearby: tuple[str, ...] = ()
    #: Who the route admits, mirrored from its dependency so the rail never
    #: offers a page that answers 403. ``None``: every signed-in user.
    #: ``PLATFORM``: ``require_platform_admin``; otherwise ``require_role``'s
    #: roles. Display only -- the route's dependency is the control.
    audience: frozenset[str] | None = None
    #: The route answers 400 without an organization (a global principal).
    needs_org: bool = False

    @property
    def planned_slug(self) -> str | None:
        return self.href.removeprefix("/planned/") if self.status is Status.PLANNED else None


@dataclass(frozen=True)
class Group:
    key: str
    label: str
    icon: str
    items: tuple[Item, ...] = field(default_factory=tuple)


#: ``require_platform_admin``: an unscoped (global) principal only.
PLATFORM = frozenset({"__platform__"})


def visible_to(item: Item, principal: Any) -> bool:
    """Whether the rail should offer ``item`` to ``principal``.

    Mirrors the two route gates exactly: ``require_role`` admits a global
    principal or a listed role; ``require_platform_admin`` admits a global
    principal only. No principal (auth off) sees everything, as the routes do."""
    if principal is None:
        return True
    if item.needs_org and getattr(principal, "org_id", None) is None:
        return False
    if item.audience is None:
        return True
    if getattr(principal, "is_global", False):
        return True
    if item.audience is PLATFORM:
        return False
    return getattr(principal, "role", None) in item.audience


def _planned(key: str, label: str, note: str, *nearby: str) -> Item:
    return Item(key, label, f"/planned/{key}", Status.PLANNED, note, tuple(nearby))


def _partial(key: str, label: str, href: str, note: str) -> Item:
    return Item(key, label, href, Status.PARTIAL, note)


NAV: tuple[Group, ...] = (
    Group(
        "command",
        "Command Center",
        "layout-dashboard",
        (
            Item("dashboard", "Executive Dashboard", "/dashboard"),
            Item("posture", "Compliance Posture", "/posture"),
            Item("intel", "Security & Risk Intelligence", "/intel"),
            Item("operations", "Operations Overview", "/operations"),
            Item("mytasks", "My Tasks", "/my-tasks"),
            Item("notifications", "Notifications", "/notifications"),
            Item("workspace", "Guided Workspace", "/workspace"),
        ),
    ),
    Group(
        "governance",
        "Governance",
        "landmark",
        (
            Item("org_units", "Organization & Business Units", "/org-units"),
            Item("policies", "Policies & Procedures", "/policies"),
            Item("committees", "Governance Committees", "/committees"),
            Item("objectives", "Strategic Objectives", "/objectives"),
            Item("exceptions", "Exception Management", "/exceptions"),
            Item("policy_acks", "Policy Acknowledgments", "/policies#acknowledgments"),
            Item("personnel", "People & Access Reviews", "/personnel"),
            Item("ai_agents", "AI Governance", "/ai-agents"),
        ),
    ),
    Group(
        "risk",
        "Risk Management",
        "triangle-alert",
        (
            Item("risks", "Enterprise Risk Register", "/risks"),
            Item("risks_cyber", "Cybersecurity Risk Register", "/risks?register=cyber"),
            Item("risk_assess", "Risk Assessments", "/risks/assessments"),
            Item("riskheat", "Risk Heat Maps", "/risks/heatmap"),
            Item("risk_treat", "Risk Treatment Plans", "/risks/treatment"),
            Item("kri", "Risk Appetite & KRIs", "/kri"),
            Item("risk_accept", "Risk Acceptance", "/exceptions#risk"),
        ),
    ),
    Group(
        "compliance",
        "Compliance",
        "shield-check",
        (
            Item("frameworks", "Framework Library", "/frameworks"),
            Item("regreq", "Regulatory Requirements", "/obligations?source=regulatory"),
            Item("obligations", "Compliance Obligations", "/obligations"),
            Item("regulatory", "Regulatory Change", "/regulatory"),
            Item("mappings", "Cross-Framework Mapping", "/mappings"),
            Item("assessments", "Compliance Assessments", "/assessments"),
            Item("governance", "Continuous Monitoring", "/governance"),
            Item("gaps", "Gap Analysis", "/gaps"),
            Item("coverage", "Mapping Coverage", "/coverage"),
        ),
    ),
    Group(
        "authorization",
        "Authorization",
        "file-check",
        (
            Item("systems", "Systems & Boundaries", "/systems"),
            Item("intake", "System Intake", "/intake"),
            Item("ssp", "SSP Builder", "/ssp"),
            Item("fedramp20x", "FedRAMP 20x & KSIs", "/fedramp20x"),
            Item("scoring", "CMMC / 800-171 Scoring", "/scoring"),
            Item("assurance", "Assurance Graph", "/assurance"),
            Item("graph", "Compliance Graph", "/graph"),
        ),
    ),
    Group(
        "controls",
        "Control Management",
        "sliders-horizontal",
        (
            Item("controls", "Unified Control Library", "/controls"),
            Item("ctrl_impl", "Control Implementations", "/implementations"),
            Item("controltests", "Control Testing", "/control-tests"),
            Item("ctrl_eff", "Control Effectiveness", "/controls/effectiveness"),
            Item("ctrl_owners", "Control Owners", "/control-owners"),
            Item("ctrl_inherit", "Control Inheritance", "/inheritance"),
            Item("compensating", "Compensating Controls", "/compensating-controls"),
        ),
    ),
    Group(
        "audit",
        "Audit & Assurance",
        "clipboard-check",
        (
            Item("auditws", "Audit Planning", "/audit-workspace"),
            Item("workpapers", "Audit Workpapers", "/audit/workpapers"),
            Item("audit_findings", "Audit Findings", "/audit/findings"),
            Item("poams", "Corrective Action Plans", "/poams"),
            Item("audit_ready", "Audit Readiness", "/audit/readiness"),
            Item("portaladmin", "Auditor Portal", "/admin/portal"),
            Item("trust", "Trust Center", "/trust"),
        ),
    ),
    Group(
        "evidence",
        "Evidence",
        "folder-lock",
        (
            Item("evidence_repo", "Evidence Repository", "/evidence"),
            Item("evidence_req", "Evidence Requests", "/evidence/requests"),
            Item("connectors", "Collection Automation", "/connectors"),
            Item("evidence_map", "Evidence-to-Control Mapping", "/evidence/mapping"),
            Item("evidence_exp", "Evidence Expiration", "/evidence/expiration"),
            Item("evidence_pkg", "Evidence Packages", "/evidence/packages"),
            Item("scans", "Scan Ingestion", "/scans"),
            Item("ingestions", "Workbook Ingestions", "/ingestions"),
        ),
    ),
    Group(
        "tprm",
        "Third-Party Risk",
        "building-2",
        (
            Item("vendors", "Vendor Inventory", "/vendors"),
            Item("questionnaires", "Vendor Assessments", "/vendor-questionnaires"),
            Item("vendor_scores", "Vendor Risk Scores", "/vendors#vendor-scores"),
            Item("due_diligence", "Due Diligence", "/due-diligence"),
            Item("vendor_findings", "Vendor Findings", "/vendor-findings"),
            Item("contracts", "Contract Obligations", "/contracts"),
        ),
    ),
    Group(
        "operations",
        "Operations",
        "workflow",
        (
            Item("remediation", "Remediation Workflows", "/remediation"),
            Item("issues", "Issues & Exceptions", "/issues"),
            Item("projects", "Projects & Action Plans", "/projects"),
            Item("scheduled", "Scheduled Assessments", "/assessments/schedule"),
            Item("approvals", "Approval Workflows", "/approvals"),
        ),
    ),
    Group(
        "intelligence",
        "Intelligence",
        "bar-chart-3",
        (
            Item("analytics", "Analytics Studio", "/analytics"),
            Item("queries", "Assurance Queries", "/queries"),
            Item("executive", "Executive Reporting", "/executive"),
            Item("trends", "Compliance Trends", "/trends"),
            Item("forecast", "Risk Forecasting", "/forecast"),
            Item("ai_analysis", "AI-Assisted Analysis", "/ai/analysis"),
            Item("reports", "Report Builder", "/reports"),
        ),
    ),
    Group(
        "admin",
        "Platform Administration",
        "settings",
        (
            Item("users", "Users, Teams & Roles", "/users"),
            Item("teams", "Teams", "/teams"),
            Item("rbac", "RBAC & Permissions", "/admin/rbac", audience=frozenset({"admin"})),
            Item("settings", "Organization Settings", "/settings"),
            Item("org_settings", "Organization Profile", "/settings/organization"),
            Item("packs", "Framework Administration", "/packs"),
            Item(
                "catalogintegrity",
                "Catalog Integrity",
                "/catalog/integrity",
                audience=frozenset({"admin"}),
            ),
            Item("worksheets", "Source Workbooks", "/worksheets"),
            Item("diff", "Workbook Diff", "/diff"),
            Item("search", "Catalog Search", "/search"),
            Item("integrations", "Integrations", "/integrations"),
            Item(
                "ai_settings",
                "AI Providers",
                "/admin/ai-settings",
                audience=frozenset({"admin"}),
                needs_org=True,
            ),
            Item("apitokens", "API Management", "/settings/api-tokens"),
            Item("audit", "Audit Logs", "/audit", audience=frozenset({"admin", "assessor"})),
            Item("reliability", "System Health", "/admin/reliability"),
            Item("selfassurance", "Self-Assurance", "/admin/self-assurance", audience=PLATFORM),
        ),
    ),
)

#: The quick-access chips at the top of the rail.
PINNED: tuple[tuple[str, str], ...] = (
    ("Executive", "/executive"),
    ("FedRAMP 20x", "/fedramp20x"),
    ("Gaps", "/gaps"),
)


def all_items() -> list[tuple[Group, Item]]:
    return [(g, i) for g in NAV for i in g.items]


def locate(active: str | None) -> tuple[Group | None, Item | None]:
    """The group and item that own ``active`` (both None for an unknown key)."""
    for g, i in all_items():
        if i.key == active:
            return g, i
    return None, None


def planned(slug: str) -> tuple[Group, Item] | None:
    for g, i in all_items():
        if i.planned_slug == slug:
            return g, i
    return None


def palette_entries(principal: Any = None) -> list[dict[str, Any]]:
    """What the command palette offers: the rail's destinations, in rail
    order, filtered exactly as the rail is for ``principal``."""
    return [
        {"label": i.label, "href": i.href, "group": g.label, "status": i.status.value}
        for g, i in all_items()
        if visible_to(i, principal)
    ]


def counts() -> dict[str, int]:
    out = {s.value: 0 for s in Status}
    for _, i in all_items():
        out[i.status.value] += 1
    return out
