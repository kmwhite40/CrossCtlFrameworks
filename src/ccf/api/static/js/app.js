/* Concord — UI behavior layer */

(() => {
  // ── Theme (persisted, DARK-FIRST) ──────────────────────
  // base.html applies the stored theme inline before first paint; this keeps
  // the two in step and is the only writer of the stored value. An unset
  // preference -- and an unreadable localStorage -- both mean dark.
  const THEME_KEY = 'concord:theme';
  function storedTheme() {
    try { return localStorage.getItem(THEME_KEY); } catch (e) { return null; }
  }
  document.documentElement.setAttribute('data-theme', storedTheme() === 'light' ? 'light' : 'dark');
  window.toggleTheme = () => {
    const cur = document.documentElement.getAttribute('data-theme') || 'dark';
    const next = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    try { localStorage.setItem(THEME_KEY, next); } catch (e) { /* private mode */ }
  };

  // ── Navigation rail ────────────────────────────────────
  // One <nav>: at desktop width it is the permanent rail, below 1024px the
  // same element slides in as a drawer. There is no second copy of the
  // navigation to fall out of step with the first.
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

  // ── Command palette ────────────────────────────────────
  const palette = {
    open: false,
    items: [
      { label: 'Dashboard',   href: '/dashboard',   hint: 'g d' },
      { label: 'Compliance',  href: '/posture',     hint: '' },
      { label: 'Controls',    href: '/controls',    hint: 'g c' },
      { label: 'Frameworks',  href: '/frameworks',  hint: 'g f' },
      { label: 'Coverage',    href: '/coverage',    hint: '' },
      { label: 'Mappings',    href: '/mappings',    hint: '' },
      { label: 'Assessments', href: '/assessments', hint: '' },
      { label: 'Live scoring', href: '/scoring',    hint: '' },
      { label: 'SSP builder', href: '/ssp',         hint: '' },
      { label: 'Systems',     href: '/systems',     hint: '' },
      { label: 'Evidence',    href: '/ingestions',  hint: '' },
      { label: 'Reports',     href: '/reports',     hint: 'g r' },
      { label: 'Governance',  href: '/governance',  hint: '' },
      { label: 'POA&Ms',      href: '/poams',       hint: '' },
      { label: 'Risks',       href: '/risks',       hint: '' },
      { label: 'Audit trail', href: '/audit',       hint: '' },
      { label: 'Search',      href: '/search',      hint: '/' },
      { label: 'Settings',    href: '/settings',    hint: '' },
      { label: 'API docs',    href: '/docs',        hint: '' },
      { label: 'Executive dashboard', href: '/executive', hint: '' },
      { label: 'FedRAMP 20x / KSI',   href: '/fedramp20x', hint: '' },
      { label: 'AI governance',       href: '/ai-agents',  hint: '' },
    ],
    selected: 0,
  };

  function renderPalette(query = '') {
    const root = document.getElementById('cmd-root');
    if (!root) return;
    const q = query.trim().toLowerCase();
    const list = palette.items
      .filter(i => !q || i.label.toLowerCase().includes(q) || i.href.includes(q));
    palette.selected = Math.min(palette.selected, Math.max(0, list.length - 1));
    root.innerHTML = list.map((i, idx) => `
      <a href="${i.href}" role="option" class="cmd__row" data-idx="${idx}"
         aria-selected="${idx === palette.selected}">
        <span>${i.label}</span>
        ${i.hint ? `<small><kbd>${i.hint}</kbd></small>` : ''}
      </a>
    `).join('');
    root.dataset.count = list.length;
  }

  function openPalette() {
    palette.open = true;
    document.getElementById('cmd-backdrop').style.display = 'grid';
    const input = document.getElementById('cmd-input');
    input.value = ''; renderPalette(''); input.focus();
  }
  function closePalette() {
    palette.open = false;
    document.getElementById('cmd-backdrop').style.display = 'none';
  }
  window.openPalette = openPalette;
  window.closePalette = closePalette;

  document.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault(); openPalette();
    } else if (e.key === '/' && !['INPUT','TEXTAREA','SELECT'].includes(document.activeElement.tagName)) {
      e.preventDefault();
      const search = document.querySelector('input[name="q"]');
      if (search) search.focus();
    } else if (e.key === 'Escape') {
      if (palette.open) closePalette();
      closeAllMenus();
      if (document.body.getAttribute('data-nav') === 'open') {
        setMobileNav(false);
        document.querySelector('.topbar__burger')?.focus();
      }
    }
    if (palette.open) {
      const root = document.getElementById('cmd-root');
      const count = parseInt(root?.dataset.count || '0', 10);
      if (e.key === 'ArrowDown') { palette.selected = (palette.selected + 1) % count; renderPalette(document.getElementById('cmd-input').value); e.preventDefault(); }
      if (e.key === 'ArrowUp')   { palette.selected = (palette.selected - 1 + count) % count; renderPalette(document.getElementById('cmd-input').value); e.preventDefault(); }
      if (e.key === 'Enter') {
        const sel = document.querySelector('.cmd__row[aria-selected="true"]');
        if (sel) { window.location = sel.getAttribute('href'); }
      }
    }
  });

  // ── HTMX UX polish ─────────────────────────────────────
  document.addEventListener('htmx:beforeRequest', (e) => { e.target?.setAttribute('aria-busy', 'true'); });
  document.addEventListener('htmx:afterRequest',  (e) => { e.target?.removeAttribute('aria-busy'); });

  // ── Wire up on load ────────────────────────────────────
  document.addEventListener('DOMContentLoaded', () => {
    if (window.lucide) window.lucide.createIcons();

    const cmdInput = document.getElementById('cmd-input');
    cmdInput?.addEventListener('input', (e) => { palette.selected = 0; renderPalette(e.target.value); });
    document.getElementById('cmd-backdrop')?.addEventListener('click', (e) => {
      if (e.target.id === 'cmd-backdrop') closePalette();
    });

    // Close the workspace menu when the click lands outside the rail's foot.
    document.addEventListener('click', (e) => {
      if (!e.target.closest('.sidebar__footer')) closeAllMenus();
    });

    // Choosing a destination closes the drawer; the rail stays put on desktop,
    // where the drawer is never open in the first place.
    document.getElementById('sidebar')?.addEventListener('click', (e) => {
      if (e.target.closest('a')) setMobileNav(false);
    });
  });
})();
