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
            _partial(
                "operations",
                "Security & Risk Intelligence",
                "/operations",
                "Vulnerability response, SLA, MTTR and risk bands. No "
                "external threat-intelligence feed.",
            ),
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
            _planned(
                "org_units",
                "Organization & Business Units",
                "Organizations can be created (on Assets & Systems) but not edited, and "
                "there is no business-unit model.",
                "/systems",
                "/settings",
            ),
            Item("policies", "Policies & Procedures", "/policies"),
            _planned(
                "committees",
                "Governance Committees",
                "No committee, charter or meeting-record model exists.",
            ),
            _planned(
                "objectives",
                "Strategic Objectives",
                "No objective model exists, and nothing links risks or controls to one.",
            ),
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
            _partial(
                "risks_cyber",
                "Cybersecurity Risk Register",
                "/risks",
                "One register; risks carry a free-text category, not a separate cyber register.",
            ),
            _partial(
                "risk_assess",
                "Risk Assessments",
                "/risks",
                "Likelihood, impact, inherent and residual scores live on the risk itself; "
                "there is no separate assessment record.",
            ),
            Item("riskheat", "Risk Heat Maps", "/risks/heatmap"),
            _partial(
                "risk_treat",
                "Risk Treatment Plans",
                "/poams",
                "Treatment is one field on the risk; action plans are tracked as POA&Ms.",
            ),
            _planned(
                "kri",
                "Risk Appetite & KRIs",
                "No appetite statement, tolerance threshold or key-risk-indicator model exists.",
                "/risks/heatmap",
            ),
            Item("risk_accept", "Risk Acceptance", "/exceptions#risk"),
        ),
    ),
    Group(
        "compliance",
        "Compliance",
        "shield-check",
        (
            Item("frameworks", "Framework Library", "/frameworks"),
            _partial(
                "regulatory",
                "Regulatory Requirements",
                "/regulatory",
                "A register of regulatory change. Requirements "
                "themselves come from the framework catalog.",
            ),
            _partial(
                "fedramp20x",
                "Compliance Obligations",
                "/fedramp20x",
                "Only FedRAMP obligations (KSIs and rules) are modelled.",
            ),
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
            _partial(
                "ctrl_impl",
                "Control Implementations",
                "/systems",
                "Implementations are shown per system (system detail, "
                "SSP); there is no cross-system list.",
            ),
            Item("controltests", "Control Testing", "/control-tests"),
            _partial(
                "ctrl_eff",
                "Control Effectiveness",
                "/control-tests",
                "Pass/fail metrics from control tests; there is no effectiveness rating.",
            ),
            Item("ctrl_owners", "Control Owners", "/control-owners"),
            _partial(
                "ctrl_inherit",
                "Control Inheritance",
                "/systems",
                "Inherited status shows per system; there is no inheritance management page.",
            ),
            _planned(
                "compensating",
                "Compensating Controls",
                "No compensating-control record links a substitute to the control it covers.",
                "/exceptions",
            ),
        ),
    ),
    Group(
        "audit",
        "Audit & Assurance",
        "clipboard-check",
        (
            Item("auditws", "Audit Planning", "/audit-workspace"),
            _planned(
                "workpapers",
                "Audit Workpapers",
                "No workpaper model. Evidence requests (PBC) exist inside each engagement.",
                "/audit-workspace",
            ),
            _partial(
                "audit_findings",
                "Audit Findings",
                "/audit-workspace",
                "Findings are recorded per engagement; there is no cross-engagement list.",
            ),
            Item("poams", "Corrective Action Plans", "/poams"),
            _partial(
                "audit_ready",
                "Audit Readiness",
                "/operations",
                "FedRAMP 20x readiness is computed per system; "
                "there is no general readiness score.",
            ),
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
            _partial(
                "evidence_req",
                "Evidence Requests",
                "/audit-workspace",
                "Requests (PBC) exist only inside an audit engagement.",
            ),
            Item("connectors", "Collection Automation", "/connectors"),
            _partial(
                "evidence_map",
                "Evidence-to-Control Mapping",
                "/evidence",
                "Each evidence object names its control; there is no mapping view.",
            ),
            _partial(
                "evidence_exp",
                "Evidence Expiration",
                "/queries?key=expired-evidence&run=1",
                "Expired and stale evidence queries; no expiry workflow page.",
            ),
            _planned(
                "evidence_pkg",
                "Evidence Packages",
                "Authorization packages exist in the API and are shared from the Auditor Portal, "
                "but have no page of their own.",
                "/admin/portal",
            ),
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
            _partial(
                "vendor_scores",
                "Vendor Risk Scores",
                "/vendors",
                "A rating per vendor and a score per questionnaire; no composite scoring model.",
            ),
            _planned(
                "due_diligence",
                "Due Diligence",
                "Nothing beyond questionnaires: no document checklist or onboarding review.",
                "/vendor-questionnaires",
            ),
            _partial(
                "vendor_findings",
                "Vendor Findings",
                "/vendor-questionnaires",
                "A questionnaire review can open a task per gap; there is no findings model.",
            ),
            _planned(
                "contracts",
                "Contract Obligations",
                "No contract or obligation model exists.",
                "/vendors",
            ),
        ),
    ),
    Group(
        "operations",
        "Operations",
        "workflow",
        (
            _partial(
                "remediation",
                "Remediation Workflows",
                "/poams?status=open",
                "POA&Ms and milestones. Remediation plans and patch campaigns are API-only.",
            ),
            _partial(
                "issues",
                "Issues & Exceptions",
                "/exceptions",
                "Exceptions are unified; issues remain split across POA&Ms, gaps and findings.",
            ),
            _partial(
                "projects",
                "Projects & Action Plans",
                "/poams",
                "Action plans are POA&Ms with milestones; there is no project model.",
            ),
            _planned(
                "scheduled",
                "Scheduled Assessments",
                "Implementations carry a ConMon frequency and next-due "
                "date, but nothing renders a schedule.",
                "/governance",
                "/control-tests",
            ),
            Item("approvals", "Approval Workflows", "/approvals"),
        ),
    ),
    Group(
        "intelligence",
        "Intelligence",
        "bar-chart-3",
        (
            _partial(
                "queries",
                "Analytics Studio",
                "/queries",
                "Six fixed assurance queries; no ad-hoc query builder.",
            ),
            Item("executive", "Executive Reporting", "/executive"),
            _planned(
                "trends",
                "Compliance Trends",
                "Concord does not keep posture history: SPRS, framework posture and implementation "
                "status are overwritten in place, so no honest trend can be drawn for them. "
                "The command center trends only what is recorded with a date.",
                "/dashboard",
            ),
            _planned(
                "forecast",
                "Risk Forecasting",
                "No forecasting model, and no risk history to forecast from.",
            ),
            _planned(
                "ai_analysis",
                "AI-Assisted Analysis",
                "Governed AI actions exist in the API (/api/ai-actions) with review and audit; "
                "there is no analysis page yet.",
                "/ai-agents",
            ),
            Item("reports", "Report Builder", "/reports"),
        ),
    ),
    Group(
        "admin",
        "Platform Administration",
        "settings",
        (
            Item("users", "Users, Teams & Roles", "/users"),
            _planned(
                "rbac",
                "RBAC & Permissions",
                "Four fixed roles (admin, control owner, assessor, viewer). IdP group-to-role "
                "mappings are API-only; there is no permission model.",
                "/users",
            ),
            Item("settings", "Organization Settings", "/settings"),
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
            _partial(
                "integrations",
                "Integrations",
                "/connectors",
                "Connectors have pages; webhooks, IdP and issue-tracker push are API-only.",
            ),
            Item(
                "ai_settings",
                "AI Providers",
                "/admin/ai-settings",
                audience=frozenset({"admin"}),
                needs_org=True,
            ),
            _partial(
                "apidocs",
                "API Management",
                "/docs",
                "Interactive API reference only; tokens are issued by CLI, not managed here.",
            ),
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
