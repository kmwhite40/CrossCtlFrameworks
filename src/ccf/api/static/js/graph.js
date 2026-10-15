// Compliance graph: draws the system view embedded in #graph-data.
// Labels are tenant-entered text: they reach the DOM through textContent only.
(function () {
  "use strict";
  var dataEl = document.getElementById("graph-data");
  if (!dataEl) return;
  var notice = document.getElementById("graph-notice");
  var toggle = document.getElementById("graph-table-toggle");
  var tables = document.getElementById("graph-tables");

  function showTables(open) {
    tables.hidden = !open;
    toggle.setAttribute("aria-expanded", String(open));
  }
  toggle.addEventListener("click", function () { showTables(tables.hidden); });

  // The notice is server-rendered as "Drawing the graph…". If the library did
  // not load, say so and open the tables rather than leave an empty canvas.
  if (!window.cytoscape) {
    notice.textContent = "The graph could not be drawn; the table below has the same data.";
    showTables(true);
    return;
  }
  var view = JSON.parse(dataEl.textContent);
  var limit = Number(dataEl.getAttribute("data-limit"));
  var canvas = document.getElementById("graph-canvas");
  var panel = document.getElementById("graph-panel");
  // Absent when no node names an owner: the page says so instead of a picker.
  var ownerSelect = document.getElementById("graph-owner");
  // What the last draw said (empty, or the over-limit message). A search
  // message replaces it; clearing the search puts it back.
  var drawNotice = "";
  // cose is a force-directed layout: its cost grows with the square of the
  // node count, and above a few hundred nodes it can hold the page for
  // seconds. It has never been measured here at the 3,000-node cap, so above
  // this many nodes the page uses concentric, which places nodes in one pass.
  var COSE_MAX_NODES = 500;
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
  if (ownerSelect) {
    Object.keys(allOwners).sort().forEach(function (o) {
      var opt = document.createElement("option");
      opt.value = o;
      opt.textContent = o;
      ownerSelect.appendChild(opt);
    });
  }

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
      drawNotice = nodes.length + " nodes match these filters; the graph draws at most " +
        limit + ". Untick a node type to draw it, or open the table.";
      notice.textContent = drawNotice;
      return;
    }
    drawNotice = "";
    notice.textContent = drawNotice;
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
    var line = token("--text-secondary", "#6b7280");
    cy = window.cytoscape({
      container: canvas,
      elements: elements,
      layout: nodes.length <= COSE_MAX_NODES
        ? { name: "cose", animate: false }
        : { name: "concentric", animate: false },
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
    if (!cy || !ownerSelect) return;
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
  if (ownerSelect) ownerSelect.addEventListener("change", applyOwner);

  // A control id the way ccf.catalog.canonical writes it: no spaces, upper
  // case, no leading zeros in the number or in any "(n)" enhancement, so
  // "ac-02", "AC 2" and "AC-02(01)" find the node labelled "AC-2" / "AC-2(1)".
  // Unverified in a browser; there is no JS test harness.
  function canonicalControl(raw) {
    var q = String(raw).replace(/\s+/g, "").toUpperCase();
    return q
      .replace(/^([A-Z]{2,3})-?0*(\d+)/, "$1-$2")
      .replace(/\(0*(\d+)\)/g, "($1)");
  }

  document.getElementById("graph-search").addEventListener("change", function (evt) {
    var raw = evt.target.value.trim();
    // Clearing the search restores what the drawing said, never blanks it.
    if (!raw) { notice.textContent = drawNotice; return; }
    var q = canonicalControl(raw);
    var lower = raw.toLowerCase();
    // Look in the data, not the drawn set: a control can be in the graph and not drawn.
    // An unplaced row keeps its catalog label, so an exact (case-insensitive)
    // match on the label is accepted as well.
    var found = view.nodes.filter(function (n) {
      return n.entity_type === "control" &&
        (String(n.label) === q || String(n.label).toLowerCase() === lower);
    })[0];
    if (!found) {
      notice.textContent = "No control " + raw + " in this system's graph.";
      return;
    }
    var hit = cy ? cy.nodes().filter(function (node) { return node.data("nid") === found.id; }) : null;
    if (hit && hit.length) {
      notice.textContent = drawNotice;
      cy.elements().unselect();
      hit.select();
      cy.animate({ center: { eles: hit }, zoom: 1.5 });
    } else {
      notice.textContent = "Control " + found.label + " is in this system's graph but is not drawn " +
        "(its type is unticked or the graph is over the node limit). Its details are shown.";
    }
    showPanel(found);
  });
  draw();
})();
