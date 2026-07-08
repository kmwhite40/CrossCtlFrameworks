/* Concord — UI behavior layer */

(() => {
  // ── Theme toggle (persisted, light-first) ──────────────
  const stored = localStorage.getItem('concord:theme') || 'light';
  document.documentElement.setAttribute('data-theme', stored);
  window.toggleTheme = () => {
    const cur = document.documentElement.getAttribute('data-theme') || 'light';
    const next = cur === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('concord:theme', next);
  };

  // ── Deprecated sidebar API — kept as a harmless no-op ──
  // The permanent left rail was replaced by top navigation. Any lingering
  // references to toggleSidebar() must not throw.
  window.toggleSidebar = () => {};

  // ── Mobile navigation ──────────────────────────────────
  function setMobileNav(open) {
    const nav = document.getElementById('mobilenav');
    const burger = document.querySelector('.globalnav__burger');
    if (!nav) return;
    nav.hidden = !open;
    burger?.setAttribute('aria-expanded', String(open));
    document.body.style.overflow = open ? 'hidden' : '';
    if (open) nav.querySelector('a')?.focus();
  }
  window.toggleMobileNav = () => setMobileNav(document.getElementById('mobilenav')?.hidden);
  window.closeMobileNav = () => setMobileNav(false);

  // ── Mega menus (hover via CSS; keyboard + escape here) ──
  function closeAllMenus() {
    document.querySelectorAll('.megamenu[data-open="true"]').forEach((m) => {
      m.removeAttribute('data-open');
      m.closest('.gnav-item')?.querySelector('[aria-haspopup]')?.setAttribute('aria-expanded', 'false');
    });
  }
  function toggleMenu(trigger) {
    const item = trigger.closest('.gnav-item');
    const menu = item?.querySelector('.megamenu');
    if (!menu) return;
    const isOpen = menu.getAttribute('data-open') === 'true';
    closeAllMenus();
    if (!isOpen) { menu.setAttribute('data-open', 'true'); trigger.setAttribute('aria-expanded', 'true'); }
  }

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
      if (!document.getElementById('mobilenav')?.hidden) { setMobileNav(false); document.querySelector('.globalnav__burger')?.focus(); }
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

    // Mega-menu triggers: click toggles (keyboard/touch); hover is CSS-driven.
    document.querySelectorAll('.gnav-item [aria-haspopup]').forEach((trigger) => {
      trigger.addEventListener('click', (e) => {
        // Let the top-level link still navigate on a second activation only if
        // already open; first activation reveals the menu.
        if (trigger.tagName === 'A' && trigger.getAttribute('aria-expanded') === 'true') return;
        e.preventDefault();
        toggleMenu(trigger);
      });
    });

    // Close menus when focus/click leaves the nav.
    document.addEventListener('click', (e) => { if (!e.target.closest('.gnav-item')) closeAllMenus(); });

    // Close the mobile menu after choosing a destination or tapping the scrim.
    const mnav = document.getElementById('mobilenav');
    mnav?.addEventListener('click', (e) => {
      if (e.target === mnav || e.target.closest('a')) setMobileNav(false);
    });
  });
})();
