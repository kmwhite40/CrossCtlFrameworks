/* Concord — UI behavior layer */

(() => {
  // ── Theme (persisted; the OS decides until the user does) ──
  // base.html applies the theme inline before first paint; this keeps the two
  // in step and is the only writer of the stored value. An explicit choice
  // ('light' or 'dark') always wins. No choice -- including an unreadable
  // localStorage -- means the operating system's preference, followed live.
  const THEME_KEY = 'concord:theme';
  const RAIL_KEY = 'concord:rail';
  function storedTheme() {
    try { return localStorage.getItem(THEME_KEY); } catch (e) { return null; }
  }
  function systemTheme() {
    try {
      return window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    } catch (e) { return 'dark'; }
  }
  function resolvedTheme() {
    const t = storedTheme();
    return t === 'light' || t === 'dark' ? t : systemTheme();
  }
  document.documentElement.setAttribute('data-theme', resolvedTheme());
  window.setTheme = (choice) => {
    if (choice === 'system') {
      try { localStorage.removeItem(THEME_KEY); } catch (e) { /* private mode */ }
      document.documentElement.setAttribute('data-theme', systemTheme());
      return;
    }
    const next = choice === 'light' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    try { localStorage.setItem(THEME_KEY, next); } catch (e) { /* private mode */ }
  };
  window.toggleTheme = () => {
    const cur = document.documentElement.getAttribute('data-theme') || 'dark';
    window.setTheme(cur === 'dark' ? 'light' : 'dark');
  };
  try {
    const mq = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)');
    const follow = () => {
      const t = storedTheme();
      if (t !== 'light' && t !== 'dark') document.documentElement.setAttribute('data-theme', systemTheme());
    };
    if (mq && mq.addEventListener) mq.addEventListener('change', follow);
  } catch (e) { /* no matchMedia: the bootstrap value stands */ }

  // ── Navigation rail ────────────────────────────────────
  // One <nav>: at desktop width it is the permanent rail (optionally collapsed
  // to icons), below 1024px the same element slides in as a drawer. There is
  // no second copy of the navigation to fall out of step with the first.
  function setMobileNav(open) {
    const rail = document.getElementById('sidebar');
    if (!rail) return;
    if (open) document.body.setAttribute('data-nav', 'open');
    else document.body.removeAttribute('data-nav');
    document.querySelector('.topbar__burger')?.setAttribute('aria-expanded', String(open));
    if (open) rail.querySelector('a, button')?.focus();
  }
  window.toggleMobileNav = () => setMobileNav(document.body.getAttribute('data-nav') !== 'open');
  window.closeMobileNav = () => setMobileNav(false);
  // Deprecated alias — older inline handlers must not throw.
  window.toggleSidebar = () => window.toggleMobileNav();

  function setRail(collapsed) {
    const root = document.documentElement;
    if (collapsed) root.setAttribute('data-rail', 'collapsed'); else root.removeAttribute('data-rail');
    const btn = document.querySelector('.sidebar__collapse');
    if (btn) {
      btn.setAttribute('aria-pressed', String(collapsed));
      btn.setAttribute('aria-label', collapsed ? 'Expand navigation' : 'Collapse navigation');
    }
    try { localStorage.setItem(RAIL_KEY, collapsed ? 'collapsed' : 'expanded'); } catch (e) { /* private mode */ }
  }
  window.toggleRail = () => setRail(document.documentElement.getAttribute('data-rail') !== 'collapsed');

  // ── Workspace menu (bottom of the rail) ────────────────
  function closeAllMenus() {
    document.querySelectorAll('.sidebar__menu[data-open="true"]').forEach((m) => {
      m.removeAttribute('data-open');
      document.querySelector(`[aria-controls="${m.id}"]`)?.setAttribute('aria-expanded', 'false');
    });
  }
  window.toggleWorkspaceMenu = (trigger) => {
    const menu = document.getElementById(trigger.getAttribute('aria-controls'));
    if (!menu) return;
    const isOpen = menu.getAttribute('data-open') === 'true';
    closeAllMenus();
    if (!isOpen) { menu.setAttribute('data-open', 'true'); trigger.setAttribute('aria-expanded', 'true'); }
  };

  window.signOut = async () => {
    try { await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' }); } catch (e) { /* the redirect still clears nothing; login will re-check */ }
    window.location = '/login';
  };

  // ── Notification center ────────────────────────────────
  const notifPanel = () => document.getElementById('notif-panel');
  function setNotifications(open) {
    const panel = notifPanel();
    if (!panel) return;
    const bell = document.querySelector('.topbar__bell');
    if (open) {
      panel.hidden = false;
      bell?.setAttribute('aria-expanded', 'true');
      document.body.dispatchEvent(new CustomEvent('notif-open'));
      panel.querySelector('.drawer__head button, .drawer__head a')?.focus();
    } else {
      panel.hidden = true;
      bell?.setAttribute('aria-expanded', 'false');
    }
  }
  window.toggleNotifications = () => setNotifications(notifPanel()?.hidden !== false);
  window.closeNotifications = () => { setNotifications(false); document.querySelector('.topbar__bell')?.focus(); };

  // ── Toasts ─────────────────────────────────────────────
  const toastRoot = () => {
    let el = document.getElementById('toasts');
    if (!el) {
      el = document.createElement('div');
      el.id = 'toasts'; el.className = 'toasts';
      el.setAttribute('role', 'status');
      el.setAttribute('aria-live', 'polite');
      el.setAttribute('aria-atomic', 'false');
      document.body.appendChild(el);
    }
    return el;
  };
  window.toast = (msg, kind = 'info') => {
    const el = document.createElement('div');
    el.className = 'toast';
    el.textContent = msg;
    toastRoot().appendChild(el);
    setTimeout(() => { el.style.opacity = 0; el.style.transition = 'opacity .3s'; }, 2400);
    setTimeout(() => el.remove(), 2900);
  };

  // ── Copy buttons ───────────────────────────────────────
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-copy]');
    if (!btn) return;
    e.preventDefault();
    navigator.clipboard.writeText(btn.dataset.copy).then(() => toast('Copied to clipboard'));
  });

  // ── Tooltips for [data-tip] (charts, heat map, bars) ───
  // Hover and keyboard focus both show it, so the value behind a mark is
  // never mouse-only. The same text is also in each chart's table view.
  let tipEl = null;
  function showTip(target) {
    const text = target.getAttribute('data-tip');
    if (!text) return;
    if (!tipEl) { tipEl = document.createElement('div'); tipEl.className = 'tip'; tipEl.setAttribute('role', 'tooltip'); document.body.appendChild(tipEl); }
    tipEl.textContent = text;
    const r = target.getBoundingClientRect();
    tipEl.style.left = '0px'; tipEl.style.top = '0px';
    tipEl.setAttribute('data-show', 'true');
    const w = tipEl.offsetWidth, h = tipEl.offsetHeight;
    const x = Math.min(Math.max(8, r.left + r.width / 2 - w / 2), window.innerWidth - w - 8);
    const y = r.top - h - 8 < 8 ? r.bottom + 8 : r.top - h - 8;
    tipEl.style.left = `${x}px`; tipEl.style.top = `${y}px`;
  }
  function hideTip() { tipEl?.setAttribute('data-show', 'false'); }
  document.addEventListener('mouseover', (e) => { const t = e.target.closest?.('[data-tip]'); if (t) showTip(t); });
  document.addEventListener('mouseout', (e) => { if (e.target.closest?.('[data-tip]')) hideTip(); });
  document.addEventListener('focusin', (e) => { const t = e.target.closest?.('[data-tip]'); if (t) showTip(t); else hideTip(); });
  window.addEventListener('scroll', hideTip, { passive: true });

  // ── Command palette ────────────────────────────────────
  // Destinations come from the same navigation data as the rail (#nav-data,
  // rendered from ccf/api/navigation.py), so the two cannot drift. Typing two
  // or more characters also searches records via /ui/search, which applies
  // the caller's organization scope server-side.
  const palette = { open: false, pages: [], records: [], selected: 0, seq: 0, timer: null };
  function navData() {
    if (palette.pages.length) return palette.pages;
    try { palette.pages = JSON.parse(document.getElementById('nav-data')?.textContent || '[]'); } catch (e) { palette.pages = []; }
    return palette.pages;
  }
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  // Only same-origin paths are ever offered as destinations: escaping stops
  // markup injection but not a `javascript:` or protocol-relative URL.
  const safeHref = (h) => (typeof h === 'string' && h.startsWith('/') && !h.startsWith('//') ? h : '#');
  function paletteRows(query) {
    const q = query.trim().toLowerCase();
    const pages = navData().filter((i) => !q || i.label.toLowerCase().includes(q) || i.group.toLowerCase().includes(q));
    const rows = [];
    if (palette.records.length && q.length >= 2) {
      rows.push({ header: 'Records' });
      palette.records.forEach((r) => rows.push({ label: r.label, href: r.href, hint: r.kind }));
    }
    if (pages.length) {
      rows.push({ header: 'Pages' });
      pages.slice(0, q ? 40 : 60).forEach((i) => rows.push({ label: i.label, href: i.href, hint: i.group, status: i.status }));
    }
    return rows;
  }
  function renderPalette(query = '') {
    const root = document.getElementById('cmd-root');
    if (!root) return;
    const rows = paletteRows(query);
    const items = rows.filter((r) => !r.header);
    palette.selected = Math.min(palette.selected, Math.max(0, items.length - 1));
    let idx = -1;
    root.innerHTML = rows.map((r) => {
      if (r.header) return `<div class="cmd__group" role="presentation">${esc(r.header)}</div>`;
      idx += 1;
      const tag = r.status === 'planned' ? '<small class="sidebar__tag sidebar__tag--planned">Planned</small>'
        : r.status === 'partial' ? '<small class="sidebar__tag">Partial</small>' : '';
      return `<a href="${esc(safeHref(r.href))}" role="option" id="cmd-opt-${idx}" class="cmd__row" data-idx="${idx}"
         aria-selected="${idx === palette.selected}"><span>${esc(r.label)}</span>${tag}<small>${esc(r.hint || '')}</small></a>`;
    }).join('') || '<div class="cmd__empty">No pages or records match.</div>';
    root.dataset.count = items.length;
    document.getElementById('cmd-input')?.setAttribute('aria-activedescendant', items.length ? `cmd-opt-${palette.selected}` : '');
    root.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: 'nearest' });
  }
  function searchRecords(query) {
    clearTimeout(palette.timer);
    const q = query.trim();
    if (q.length < 2) { palette.records = []; return; }
    palette.timer = setTimeout(async () => {
      const seq = ++palette.seq;
      try {
        const res = await fetch(`/ui/search?q=${encodeURIComponent(q)}`, { credentials: 'same-origin', headers: { Accept: 'application/json' } });
        if (!res.ok || seq !== palette.seq) return;
        const data = await res.json();
        palette.records = data.results || [];
        renderPalette(document.getElementById('cmd-input')?.value || '');
      } catch (e) { /* offline or signed out: pages still work */ }
    }, 160);
  }

  function openPalette() {
    palette.open = true;
    palette.records = [];
    document.getElementById('cmd-backdrop').style.display = 'grid';
    const input = document.getElementById('cmd-input');
    input.value = ''; palette.selected = 0; renderPalette(''); input.focus();
  }
  function closePalette() {
    palette.open = false;
    document.getElementById('cmd-backdrop').style.display = 'none';
  }
  window.openPalette = openPalette;
  window.closePalette = closePalette;

  // ── Keyboard shortcuts ─────────────────────────────────
  // ⌘K / Ctrl-K palette · / page search · [ rail · g then a letter to jump ·
  // ? lists them. Never while typing in a field.
  const JUMPS = { d: '/dashboard', p: '/posture', r: '/risks', c: '/controls', e: '/evidence', a: '/poams', n: '/notifications', t: '/my-tasks', s: '/systems', f: '/frameworks' };
  let pendingG = 0;
  const typing = () => ['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName) || document.activeElement?.isContentEditable;
  function showShortcuts() {
    let dlg = document.getElementById('shortcuts-dialog');
    if (!dlg) {
      const rows = [['⌘K / Ctrl K', 'Command palette and record search'], ['/', 'Focus the page search'],
        ['[', 'Collapse or expand the rail'], ['Esc', 'Close panels'], ['?', 'This list'],
        ...Object.entries(JUMPS).map(([k, v]) => [`g ${k}`, `Go to ${v}`])];
      dlg = document.createElement('dialog');
      dlg.id = 'shortcuts-dialog'; dlg.className = 'shortcuts';
      dlg.setAttribute('aria-labelledby', 'shortcuts-title');
      const h = document.createElement('h2'); h.id = 'shortcuts-title'; h.textContent = 'Keyboard shortcuts';
      const dl = document.createElement('dl');
      rows.forEach(([k, v]) => {
        const dt = document.createElement('dt'); const kb = document.createElement('kbd'); kb.textContent = k; dt.appendChild(kb);
        const dd = document.createElement('dd'); dd.textContent = v; dl.append(dt, dd);
      });
      const close = document.createElement('button'); close.type = 'button'; close.className = 'btn btn--secondary btn--sm'; close.textContent = 'Close';
      close.addEventListener('click', () => dlg.close());
      dlg.append(h, dl, close);
      document.body.appendChild(dlg);
    }
    dlg.showModal();
  }

  document.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault(); openPalette(); return;
    }
    if (e.key === 'Escape') {
      if (palette.open) closePalette();
      closeAllMenus();
      if (notifPanel() && !notifPanel().hidden) window.closeNotifications();
      if (document.body.getAttribute('data-nav') === 'open') {
        setMobileNav(false);
        document.querySelector('.topbar__burger')?.focus();
      }
      return;
    }
    if (palette.open) {
      const root = document.getElementById('cmd-root');
      const count = parseInt(root?.dataset.count || '0', 10);
      if (!count) return;
      if (e.key === 'ArrowDown') { palette.selected = (palette.selected + 1) % count; renderPalette(document.getElementById('cmd-input').value); e.preventDefault(); }
      if (e.key === 'ArrowUp')   { palette.selected = (palette.selected - 1 + count) % count; renderPalette(document.getElementById('cmd-input').value); e.preventDefault(); }
      if (e.key === 'Enter') {
        const sel = document.querySelector('.cmd__row[aria-selected="true"]');
        if (sel) { e.preventDefault(); window.location = sel.getAttribute('href'); }
      }
      return;
    }
    if (typing() || e.metaKey || e.ctrlKey || e.altKey) return;
    if (pendingG && Date.now() - pendingG < 1200 && JUMPS[e.key]) {
      pendingG = 0; e.preventDefault(); window.location = JUMPS[e.key]; return;
    }
    pendingG = 0;
    if (e.key === 'g') { pendingG = Date.now(); return; }
    if (e.key === '/') {
      const search = document.querySelector('main input[name="q"]');
      e.preventDefault();
      if (search) search.focus(); else openPalette();
    } else if (e.key === '[') {
      window.toggleRail();
    } else if (e.key === '?') {
      showShortcuts();
    }
  });

  // ── HTMX UX polish ─────────────────────────────────────
  document.addEventListener('htmx:beforeRequest', (e) => { e.target?.setAttribute('aria-busy', 'true'); });
  document.addEventListener('htmx:afterRequest',  (e) => {
    e.target?.removeAttribute('aria-busy');
    // Notification read-state changed: refresh the badge, and the list it
    // came from. Only on success -- a refused write must not look applied.
    const scope = e.target?.getAttribute?.('data-refresh-notifs');
    if (scope && e.detail?.successful) {
      document.body.dispatchEvent(new CustomEvent('notif-changed'));
      if (scope === 'panel') document.body.dispatchEvent(new CustomEvent('notif-open'));
      else window.location.reload();
    }
  });
  // A failed HTMX swap is said out loud rather than leaving a stale panel.
  document.addEventListener('htmx:responseError', (e) => {
    const status = e.detail?.xhr?.status;
    toast(status === 403 ? 'You do not have permission for that.' : `Request failed${status ? ` (${status})` : ''}. Nothing was changed.`);
  });
  document.addEventListener('htmx:sendError', () => toast('Could not reach Concord. Check your connection.'));

  // ── Small render-time niceties ─────────────────────────
  function relative(el) {
    const t = Date.parse(el.getAttribute('datetime'));
    if (Number.isNaN(t)) return;
    const s = Math.round((Date.now() - t) / 1000);
    const fmt = s < 60 ? 'just now' : s < 3600 ? `${Math.floor(s / 60)} min ago` : s < 86400 ? `${Math.floor(s / 3600)} h ago` : s < 7 * 86400 ? `${Math.floor(s / 86400)} d ago` : null;
    if (fmt) { el.title = el.textContent; el.textContent = fmt; }
  }

  // ── Wire up on load ────────────────────────────────────
  document.addEventListener('DOMContentLoaded', () => {
    if (window.lucide) window.lucide.createIcons();

    const collapsed = document.documentElement.getAttribute('data-rail') === 'collapsed';
    const cbtn = document.querySelector('.sidebar__collapse');
    if (cbtn && collapsed) { cbtn.setAttribute('aria-pressed', 'true'); cbtn.setAttribute('aria-label', 'Expand navigation'); }

    // In the collapsed rail a group icon reopens the rail on that group.
    document.querySelectorAll('.sidebar__group > summary').forEach((s) => {
      s.addEventListener('click', (e) => {
        if (document.documentElement.getAttribute('data-rail') === 'collapsed' && window.innerWidth > 1024) {
          e.preventDefault();
          setRail(false);
          s.parentElement.open = true;
        }
      });
    });

    const greet = document.querySelector('[data-greeting]');
    if (greet) {
      const h = new Date().getHours();
      const part = h < 12 ? 'Good morning' : h < 18 ? 'Good afternoon' : 'Good evening';
      const name = greet.getAttribute('data-greeting');
      greet.textContent = name ? `${part}, ${name}` : part;
    }
    document.querySelectorAll('time[data-relative]').forEach(relative);

    const cmdInput = document.getElementById('cmd-input');
    cmdInput?.addEventListener('input', (e) => { palette.selected = 0; renderPalette(e.target.value); searchRecords(e.target.value); });
    document.getElementById('cmd-backdrop')?.addEventListener('click', (e) => {
      if (e.target.id === 'cmd-backdrop') closePalette();
    });

    // Close the workspace menu when the click lands outside the rail's foot.
    document.addEventListener('click', (e) => {
      if (!e.target.closest('.sidebar__footer')) closeAllMenus();
      const panel = notifPanel();
      if (panel && !panel.hidden && !e.target.closest('#notif-panel') && !e.target.closest('.topbar__bell')) setNotifications(false);
    });

    // Choosing a destination closes the drawer; the rail stays put on desktop,
    // where the drawer is never open in the first place.
    document.getElementById('sidebar')?.addEventListener('click', (e) => {
      if (e.target.closest('a')) setMobileNav(false);
    });
  });
})();
