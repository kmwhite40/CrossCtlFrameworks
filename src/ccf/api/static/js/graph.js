// Compliance graph: draws the system view embedded in #graph-data.
// Labels are tenant-entered text: they reach the DOM through textContent only.
(function () {
  "use strict";
  var dataEl = document.getElementById("graph-data");
  if (!dataEl || !window.cytoscape) return;
  var view = JSON.parse(dataEl.textContent);
  var limit = Number(dataEl.getAttribute("data-limit"));
  var canvas = document.getElementById("graph-canvas");
  var notice = document.getElementById("graph-notice");
  var panel = document.getElementById("graph-panel");
  var ownerSelect = document.getElementById("graph-owner");
  var byId = {};
  view.nodes.forEach(function (n) { byId[n.id] = n; });
  var cy = null;

  function token(name, fallback) {
    var v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback;
  }
  // Colour is status only (docs/DESIGN.md).
  var STATUS = {
    implemented: token("--success", "#2e7d32"), pass: token("--success", "#2e7d32"),
    partial: token("--warning", "#b26a00"), planned: token("--warning", "#b26a00"),
    warn: token("--warning", "#b26a00"),
    not_implemented: token("--danger", "#c62828"), fail: token("--danger", "#c62828"),
    open: token("--danger", "#c62828"),
    inherited: token("--accent", "#3b6fd8"),
    not_applicable: token("--text-muted", "#8a8f98")
  };
  var NEUTRAL = token("--text-secondary", "#6b7280");

  function owners(n) { return (n.metadata && n.metadata.owners) || []; }

  // Owner picker: every owner named on any node, alphabetical.
  var allOwners = {};
  view.nodes.forEach(function (n) { owners(n).forEach(function (o) { allOwners[o] = true; }); });
  Object.keys(allOwners).sort().forEach(function (o) {
    var opt = document.createElement("option");
    opt.value = o;
    opt.textContent = o;
    ownerSelect.appendChild(opt);
  });

  function visibleTypes() {
    var out = {};
    document.querySelectorAll("[data-graph-type]").forEach(function (el) {
      if (el.checked) out[el.value] = true;
    });
    return out;
  }

  function draw() {
    var types = visibleTypes();
    var nodes = view.nodes.filter(function (n) {
      return n.id === view.root.id || types[n.entity_type];
    });
    if (cy) { cy.destroy(); cy = null; }
    if (nodes.length > limit) {
      notice.textContent = nodes.length + " nodes match these filters; the graph draws at most " +
        limit + ". Untick a node type to draw it, or open the table.";
      return;
    }
    notice.textContent = "";
    var shown = {};
    nodes.forEach(function (n) { shown[n.id] = true; });
    var elements = nodes.map(function (n) {
      return { data: { id: "n" + n.id, nid: n.id, label: n.label, type: n.entity_type,
                       colour: STATUS[n.status] || NEUTRAL } };
    });
    view.edges.forEach(function (e, i) {
      if (shown[e.source] && shown[e.target]) {
        elements.push({ data: { id: "e" + i, source: "n" + e.source, target: "n" + e.target,
                                rel: e.relationship_type, provenance: e.provenance } });
      }
    });
    var line = token("--shell-border", "#9aa4b2");
    cy = window.cytoscape({
      container: canvas,
      elements: elements,
      layout: { name: "cose", animate: false },
      style: [
        { selector: "node", style: { "background-color": "data(colour)", label: "data(label)",
          "font-size": 9, color: token("--text", "#222"), "text-valign": "bottom",
          "text-margin-y": 2, width: 14, height: 14 } },
        { selector: 'node[type = "system"]', style: { shape: "round-rectangle", width: 26, height: 26 } },
        { selector: 'node[type = "capability"]', style: { shape: "diamond" } },
        { selector: 'node[type = "ksi"]', style: { shape: "hexagon" } },
        { selector: "edge", style: { width: 1, "line-color": line, "curve-style": "bezier",
          "target-arrow-shape": "triangle", "target-arrow-color": line, "arrow-scale": 0.6 } },
        { selector: ".faded", style: { opacity: 0.15 } },
        { selector: ":selected", style: { "border-width": 3, "border-color": token("--text", "#222") } }
      ]
    });
    cy.on("tap", "node", function (evt) { showPanel(byId[evt.target.data("nid")]); });
    cy.on("mouseover", "edge", function (evt) {
      canvas.title = evt.target.data("rel").replace(/_/g, " ") + " (source: " +
        evt.target.data("provenance") + ")";
    });
    cy.on("mouseout", "edge", function () { canvas.title = ""; });
    applyOwner();
  }

  function applyOwner() {
    if (!cy) return;
    var who = ownerSelect.value;
    cy.nodes().forEach(function (node) {
      var n = byId[node.data("nid")];
      var keep = !who || owners(n).indexOf(who) !== -1 || n.id === view.root.id;
      node.toggleClass("faded", !keep);
    });
  }

  function row(label, value) {
    var p = document.createElement("p");
    var b = document.createElement("strong");
    b.textContent = label + ": ";
    p.appendChild(b);
    p.appendChild(document.createTextNode(value));
    panel.appendChild(p);
  }

  function showPanel(n) {
    panel.replaceChildren();
    var h = document.createElement("h3");
    h.textContent = n.label;
    panel.appendChild(h);
    var meta = n.metadata || {};
    row("Type", n.entity_type.replace(/_/g, " "));
    row("Status", n.status || "—");
    if (owners(n).length) row("Owners", owners(n).join(", "));
    if (meta.rows > 1) row("Catalog rows", String(meta.rows));
    if (meta.placed === false) {
      row("Catalog", "This row names no control and has no sequence control; it is shown as recorded.");
    }
    if (meta.unlinked_reason) row("Not linked", meta.unlinked_reason);
    var list = document.createElement("ul");
    view.edges.forEach(function (e) {
      if (e.source !== n.id && e.target !== n.id) return;
      var other = byId[e.source === n.id ? e.target : e.source];
      if (!other) return;
      var li = document.createElement("li");
      li.textContent = (e.source === n.id ? "" : "← ") + e.relationship_type.replace(/_/g, " ") +
        " " + other.label + " (" + e.provenance + ")";
      list.appendChild(li);
    });
    if (list.children.length) panel.appendChild(list);
    var href = recordLink(n);
    if (href) {
      var a = document.createElement("a");
      a.href = href;
      a.textContent = LIST_TYPES[n.entity_type] ? "Open list" : "Open record";
      panel.appendChild(a);
    }
    panel.hidden = false;
  }

  var LIST_TYPES = { poam: 1, risk: 1, evidence_object: 1, ai_agent: 1 };

  // Only routes that exist in ui*.py; a type with no record page gets no link.
  function recordLink(n) {
    var meta = n.metadata || {};
    switch (n.entity_type) {
      case "system": return "/systems/" + encodeURIComponent(n.entity_id);
      case "connector": return "/connectors/" + encodeURIComponent(n.entity_id);
      case "control_test": return "/control-tests/" + encodeURIComponent(n.entity_id);
      case "ksi": return meta.system_id ? "/fedramp20x?system_id=" + encodeURIComponent(meta.system_id) : null;
      case "poam": return "/poams";
      case "risk": return "/risks";
      case "evidence_object": return "/evidence";
      case "ai_agent": return "/ai-agents";
      default: return null;
    }
  }

  document.querySelectorAll("[data-graph-type]").forEach(function (el) {
    el.addEventListener("change", draw);
  });
  ownerSelect.addEventListener("change", applyOwner);
  document.getElementById("graph-search").addEventListener("change", function (evt) {
    var q = evt.target.value.trim().toUpperCase();
    if (!q) { notice.textContent = ""; return; }
    // Look in the data, not the drawn set: a control can be in the graph and not drawn.
    var found = view.nodes.filter(function (n) {
      return n.entity_type === "control" && String(n.label).toUpperCase() === q;
    })[0];
    if (!found) {
      notice.textContent = "No control " + q + " in this system's graph.";
      return;
    }
    var hit = cy ? cy.nodes().filter(function (node) { return node.data("nid") === found.id; }) : null;
    if (hit && hit.length) {
      notice.textContent = "";
      cy.elements().unselect();
      hit.select();
      cy.animate({ center: { eles: hit }, zoom: 1.5 });
    } else {
      notice.textContent = "Control " + q + " is in this system's graph but is not drawn " +
        "(its type is unticked or the graph is over the node limit). Its details are shown.";
    }
    showPanel(found);
  });
  var toggle = document.getElementById("graph-table-toggle");
  toggle.addEventListener("click", function () {
    var tables = document.getElementById("graph-tables");
    tables.hidden = !tables.hidden;
    toggle.setAttribute("aria-expanded", String(!tables.hidden));
  });
  draw();
})();
