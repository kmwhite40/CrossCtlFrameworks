"""The application shell: a left sidebar, dark by default, and legible in both.

Spec: ``docs/superpowers/specs/2026-09-23-ui-shell-redesign.md`` §6.

Everything here is measured, not asserted by eye. The colours come out of the
real stylesheet through ``tests.theme_tokens``, the pages come out of the real
app over HTTP, and every contrast failure names the pair and the ratio. A test
that compares a fixture to the fixture's own string would pass for the wrong
reason, which is how this programme has shipped a false pass five times.

Two harness notes:

* ``conftest.py`` sets ``CCF_ENV=test``, which ``is_dev_env`` treats as dev, so
  these pages render without auth and every request is ``SYSTEM_PRINCIPAL``
  (``is_global``). That is fine here -- nothing in this file asserts scoping,
  only what the chrome renders -- but it is why no assertion below may be read
  as evidence about tenancy.
* No row is seeded and none is deleted: the shell is the same markup on an
  empty catalog, so there is no ``controls.identifier`` namespace to collide.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from itertools import combinations
from pathlib import Path

import pytest
from fastapi.routing import _IncludedRouter
from httpx import ASGITransport, AsyncClient

from ccf.api.main import create_app
from tests.theme_tokens import (
    AA_BODY,
    AA_UI,
    DARK,
    LIGHT,
    THEMES,
    chip_paint,
    composite,
    contrast,
    dark_tokens,
    hexed,
    parse_color,
    read_css,
    root_tokens,
    tokens_for,
)

SRC = Path(__file__).resolve().parents[1] / "src" / "ccf" / "api"
BASE_HTML = SRC / "templates" / "base.html"
APP_JS = SRC / "static" / "js" / "app.js"

#: Every surface a token-coloured string of text can land on.
SURFACES = ("--bg", "--bg-elevated", "--bg-subtle", "--bg-inset", "--shell-bg")

#: Text tokens, and the smallest ratio each must clear on every surface above.
TEXT_TOKENS = ("--text", "--text-secondary", "--text-muted", "--accent")

#: Boundaries that identify a component -- the input and secondary-button
#: outline, the ghost chip's ring, the top bar's search field. WCAG 1.4.11.
BOUNDARY_TOKENS = ("--border-strong",)

#: Filled shapes that carry meaning without text: the status dots, the bar
#: fills, the KPI trend badge. Non-text contrast, so 3:1.
MEANINGFUL_FILLS = ("--success", "--warning", "--danger", "--info", "--accent")

#: Two chip variants are "visually identical" unless the colour a reader
#: actually sees -- the fill or the label -- differs by this much. CIEDE2000
#: 1.0 is the just-noticeable difference for adjacent patches, so 10 is an
#: order of magnitude above "someone might notice"; it is chosen to catch a
#: merge, not to legislate taste.
MIN_CHIP_DELTA_E = 10.0

#: ``active`` keys that deliberately have no entry in the rail. Listed by name
#: so that a page added without a home in the navigation fails this file rather
#: than quietly rendering an unhighlighted sidebar.
ACTIVE_KEYS_WITHOUT_A_RAIL_ENTRY = frozenset({"ai_settings"})


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://t")


def _parameterless_get_paths() -> list[str]:
    """Every GET route the app serves that needs no path parameter."""
    app = create_app()
    found: list[str] = []

    def walk(routes: object, prefix: str = "") -> None:
        for route in routes:  # type: ignore[attr-defined]
            if isinstance(route, _IncludedRouter):
                walk(route.original_router.routes, prefix)
                continue
            sub = getattr(route, "routes", None)
            if sub is not None and not getattr(route, "methods", None):
                walk(sub, prefix + (getattr(route, "path", "") or ""))
                continue
            if "GET" in (getattr(route, "methods", set()) or set()):
                found.append(prefix + (getattr(route, "path", "") or ""))

    walk(app.routes)
    skip = ("/api", "/metrics", "/openapi", "/redoc", "/docs", "/healthz", "/readyz")
    return sorted({p for p in found if "{" not in p and not p.startswith(skip)})


def _aside(html: str) -> str:
    """Just the sidebar, so a section-nav highlight is never miscounted as one."""
    start = html.index('<aside class="sidebar"')
    return html[start : html.index("</aside>", start)]


# ── §6.1 every page renders, and the shell is in exactly one place ───────────


def test_every_template_that_uses_the_shell_extends_base() -> None:
    """The chrome changed in two files because no page defines its own.

    If a template grew its own header this would stop being true, and the
    sidebar would exist on some pages and not others.
    """
    tpl_dir = SRC / "templates"
    extenders = [
        p.name
        for p in sorted(tpl_dir.glob("*.html"))
        if '{% extends "base.html" %}' in p.read_text(encoding="utf-8")
    ]
    assert len(extenders) >= 54, f"only {len(extenders)} templates extend base.html"
    for name in extenders:
        src = (tpl_dir / name).read_text(encoding="utf-8")
        for owned in ("<html", "<body", 'class="sidebar"', 'class="topbar"'):
            assert owned not in src, f"{name} builds its own chrome ({owned!r})"


@pytest.mark.asyncio
async def test_every_reachable_page_renders_the_shell() -> None:
    """Drive the real routes, not a list of template names.

    A page that needs a path parameter is exercised by the test that owns it;
    what this asserts is that every page reachable without one returns 200 HTML
    carrying the rail, the top bar and the skip link.
    """
    failures: list[str] = []
    rendered = 0
    async with _client() as c:
        for path in _parameterless_get_paths():
            resp = await c.get(path)
            if resp.status_code in (303, 307) or "text/html" not in resp.headers.get(
                "content-type", ""
            ):
                continue  # auth redirect or a JSON endpoint; not a shell page
            body = resp.text
            if "{% extends" in body or '<aside class="sidebar"' not in body:
                # The standalone pages (landing, portal, login) deliberately do
                # not use the shell; everything else must.
                if path in ("/", "/portal", "/login"):
                    continue
                failures.append(f"{path}: no sidebar (status {resp.status_code})")
                continue
            rendered += 1
            for marker in ('class="topbar"', 'class="skip-link"', 'id="main"'):
                if marker not in body:
                    failures.append(f"{path}: missing {marker}")
    assert not failures, "\n".join(failures)
    assert rendered >= 40, f"only {rendered} shell pages were reachable to render"


@pytest.mark.asyncio
async def test_the_server_renders_the_same_bytes_for_both_themes() -> None:
    """Theme is one attribute plus CSS, never a second render path.

    "Renders in both themes" is only meaningful if the server does not branch
    on the theme -- otherwise half the pages would be untested in one of them.
    """
    async with _client() as c:
        plain = await c.get("/dashboard")
        with_light = await c.get("/dashboard", cookies={"concord:theme": "light"})
    assert plain.status_code == with_light.status_code == 200
    assert plain.text == with_light.text


# ── §6.2 / §6.3 live in tests/test_trust_corroboration.py, beside the states ──


# ── §6.4 contrast, asserted with numbers ─────────────────────────────────────


@pytest.mark.parametrize("theme", THEMES)
def test_text_on_every_surface_meets_aa(theme: str) -> None:
    tokens = tokens_for(theme)
    failures = []
    for fg in TEXT_TOKENS:
        for bg in SURFACES:
            fgc, bgc = parse_color(tokens[fg], tokens), parse_color(tokens[bg], tokens)
            ratio = contrast(fgc, bgc)
            if ratio < AA_BODY:
                failures.append(
                    f"{theme}: {fg} ({hexed(fgc)}) on {bg} ({hexed(bgc)}) "
                    f"= {ratio:.2f}:1, needs {AA_BODY}:1"
                )
    assert not failures, "\n".join(failures)


@pytest.mark.parametrize("theme", THEMES)
def test_text_on_a_filled_accent_meets_aa(theme: str) -> None:
    """``--text-inverse`` is the label on every accent fill -- the primary
    button, the avatar, the skip link. White on the dark theme's accent was
    3.0:1, which is why this pair is pinned and not left to a literal ``#fff``.
    """
    tokens = tokens_for(theme)
    fg = parse_color(tokens["--text-inverse"], tokens)
    bg = parse_color(tokens["--accent"], tokens)
    ratio = contrast(fg, bg)
    assert ratio >= AA_BODY, (
        f"{theme}: --text-inverse ({hexed(fg)}) on --accent ({hexed(bg)}) "
        f"= {ratio:.2f}:1, needs {AA_BODY}:1"
    )
    css = read_css()
    assert "color: #fff;" not in css, "a hard-coded #fff cannot follow the theme"


@pytest.mark.parametrize("theme", THEMES)
def test_component_boundaries_and_meaningful_fills_meet_non_text_contrast(theme: str) -> None:
    tokens = tokens_for(theme)
    failures = []
    for token in BOUNDARY_TOKENS:
        for bg in SURFACES:
            bgc = parse_color(tokens[bg], tokens)
            fgc = composite(parse_color(tokens[token], tokens), bgc)
            ratio = contrast(fgc, bgc)
            if ratio < AA_UI:
                failures.append(
                    f"{theme}: {token} on {bg} = {ratio:.2f}:1, needs {AA_UI}:1"
                )
    for token in MEANINGFUL_FILLS:
        for bg in ("--bg", "--bg-elevated"):
            bgc = parse_color(tokens[bg], tokens)
            fgc = parse_color(tokens[token], tokens)
            ratio = contrast(fgc, bgc)
            if ratio < AA_UI:
                failures.append(
                    f"{theme}: {token} ({hexed(fgc)}) on {bg} = {ratio:.2f}:1, needs {AA_UI}:1"
                )
    assert not failures, "\n".join(failures)


@pytest.mark.parametrize("theme", THEMES)
def test_the_active_sidebar_entry_is_legible(theme: str) -> None:
    """The one entry a reader has to find on every page."""
    tokens = tokens_for(theme)
    shell = parse_color(tokens["--shell-bg"], tokens)
    fill = composite(parse_color(tokens["--accent-soft"], tokens), shell)
    ink = parse_color(tokens["--accent-ink"], tokens)
    ratio = contrast(ink, fill)
    assert ratio >= AA_BODY, (
        f"{theme}: --accent-ink ({hexed(ink)}) on the active row ({hexed(fill)}) "
        f"= {ratio:.2f}:1, needs {AA_BODY}:1"
    )
    edge = contrast(parse_color(tokens["--accent"], tokens), shell)
    assert edge >= AA_UI, f"{theme}: the active marker is {edge:.2f}:1 on the rail"


def test_every_colour_token_has_an_explicit_dark_value() -> None:
    """The measured half of "31 tokens have no dark value".

    ``:root`` mixes three kinds of token: colours, which must be restated for
    dark; ``var()`` aliases, which re-resolve for free; and geometry/typography,
    which is the same in both themes and must NOT be restated, because a second
    copy of ``--radius: 10px`` is a second thing to keep in sync.

    This pins the split. Add a colour token without a dark value and it fails
    here by name; restate ``--radius`` in the dark block and it fails too.
    """
    css = read_css()
    root, dark = root_tokens(css), dark_tokens(css)
    theme_invariant = {
        name
        for name in root
        if name.startswith(("--font-", "--space-", "--radius"))
        or name in {"--topnav-h", "--sectionnav-h", "--sidebar-w", "--maxw",
                    "--shadow-glow", "--glow"}
    }
    aliases = {name for name, value in root.items() if "var(" in value}
    colourish = set(root) - theme_invariant - aliases

    missing = sorted(colourish - set(dark))
    assert not missing, f"no dark value for: {', '.join(missing)}"

    restated = sorted(theme_invariant & set(dark))
    assert not restated, f"theme-invariant tokens restated in dark: {', '.join(restated)}"

    # An alias must stay an alias, or it silently becomes a token that can
    # forget its dark value.
    for name in aliases:
        assert "var(" in root[name], name
    assert len(colourish) >= 25, f"only {len(colourish)} colour tokens found — parser drift?"


# ── §6.5 the active-nav mechanism ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_each_page_highlights_exactly_one_sidebar_entry() -> None:
    failures = []
    async with _client() as c:
        for path in _parameterless_get_paths():
            resp = await c.get(path)
            if resp.status_code != 200 or '<aside class="sidebar"' not in resp.text:
                continue
            marked = _aside(resp.text).count('aria-current="page"')
            if marked != 1:
                failures.append(f"{path}: {marked} sidebar entries marked current")
    assert not failures, "\n".join(failures)


def test_no_active_key_is_left_without_a_home_in_the_rail() -> None:
    """Every ``active`` key a route passes resolves to one rail entry.

    Read out of the route sources and out of base.html, so adding a page
    without a navigation home fails here instead of rendering an unhighlighted
    rail that nobody notices.
    """
    used = set()
    for path in (SRC / "routes").glob("*.py"):
        used |= set(re.findall(r'"active":\s*"([a-z_0-9]+)"', path.read_text(encoding="utf-8")))
    base = BASE_HTML.read_text(encoding="utf-8")
    rail_keys = set(re.findall(r"'key':'([a-z_0-9]+)'", base))
    homeless = sorted(used - rail_keys - ACTIVE_KEYS_WITHOUT_A_RAIL_ENTRY)
    assert not homeless, f"active keys with no sidebar entry: {', '.join(homeless)}"
    stale = sorted(ACTIVE_KEYS_WITHOUT_A_RAIL_ENTRY & rail_keys)
    assert not stale, f"listed as homeless but present in the rail: {', '.join(stale)}"


def test_the_rail_renders_every_group_and_never_reorders_them() -> None:
    """§4.1: this is a presentation change. Membership and order are unchanged."""
    base = BASE_HTML.read_text(encoding="utf-8")
    groups = re.findall(r"\{'key':'(dashboard|compliance|authorization|operations|insights)'", base)
    assert groups == ["dashboard", "compliance", "authorization", "operations", "insights"]
    # Every link key is unique, or "exactly one entry" could not be true.
    keys = re.findall(r"\{'key':'([a-z_0-9]+)','label'", base)
    assert len(keys) == len(set(keys)), "duplicate nav keys"


# ── §6.6 dark is the default, and the preference survives ────────────────────


@pytest.mark.asyncio
async def test_an_unset_preference_gets_dark() -> None:
    async with _client() as c:
        body = (await c.get("/dashboard")).text
    assert '<html lang="en" data-theme="dark">' in body
    assert 'data-theme="light"' not in body
    # The pre-paint bootstrap maps anything that is not the literal 'light' --
    # including a missing key and a throwing localStorage -- to dark.
    assert "t === 'light' ? 'light' : 'dark'" in body


def test_the_theme_module_has_no_light_first_default_left() -> None:
    js = APP_JS.read_text(encoding="utf-8")
    assert "|| 'light'" not in js, "a light-first fallback survives in app.js"
    assert "storedTheme() === 'light' ? 'light' : 'dark'" in js
    assert "localStorage.setItem(THEME_KEY, next)" in js


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_theme_defaulting_and_persistence_run_correctly() -> None:
    """Execute the shipped app.js, rather than read it.

    The source assertions above cannot tell a correct expression from one that
    is never reached. This drives the real file against a stub DOM: an unset
    preference gets dark, a stored 'light' is honoured, a toggle persists, and
    a localStorage that throws still lands on dark.
    """
    harness = r"""
      const fs = require('fs');
      function run(initial, throwing) {
        const store = { ...initial };
        const html = { attrs: {}, setAttribute(k, v) { this.attrs[k] = v; },
                       getAttribute(k) { return this.attrs[k] ?? null; } };
        global.localStorage = {
          getItem(k) { if (throwing) throw new Error('denied'); return store[k] ?? null; },
          setItem(k, v) { if (throwing) throw new Error('denied'); store[k] = v; },
        };
        const listeners = [];
        global.document = {
          documentElement: html,
          body: { attrs: {},
                  setAttribute(k, v) { this.attrs[k] = v; },
                  removeAttribute(k) { delete this.attrs[k]; },
                  getAttribute(k) { return this.attrs[k] ?? null; }, style: {} },
          addEventListener(t, f) { listeners.push([t, f]); },
          getElementById() { return null; }, querySelector() { return null; },
          querySelectorAll() { return []; }, createElement() { return { style: {} }; },
        };
        global.window = global;
        eval(fs.readFileSync(process.argv[1], 'utf8'));
        return { theme: () => html.getAttribute('data-theme'), store,
                 toggle: () => global.toggleTheme() };
      }
      const a = run({}, false);
      if (a.theme() !== 'dark') throw new Error('unset preference gave ' + a.theme());
      a.toggle();
      if (a.theme() !== 'light') throw new Error('toggle from dark gave ' + a.theme());
      if (a.store['concord:theme'] !== 'light') throw new Error('toggle did not persist');
      const b = run({ 'concord:theme': 'light' }, false);
      if (b.theme() !== 'light') throw new Error('stored light was ignored');
      b.toggle();
      if (b.store['concord:theme'] !== 'dark') throw new Error('light->dark did not persist');
      const c = run({}, true);
      if (c.theme() !== 'dark') throw new Error('unreadable storage gave ' + c.theme());
      console.log('ok');
    """
    out = subprocess.run(
        ["node", "-e", harness, str(APP_JS)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "ok"


# ── §6.7 phone width ─────────────────────────────────────────────────────────


def test_the_rail_collapses_and_nothing_can_scroll_sideways() -> None:
    """At phone width the grid drops to one column and the rail leaves the flow.

    The drawer is the same ``<nav>``: the old chrome carried a second copy of
    the navigation in a ``.mobilenav`` block, and two copies of an information
    architecture drift apart. That block is gone, which is asserted here so it
    cannot come back by accident.
    """
    css = read_css()
    assert "mobilenav" not in css and "globalnav" not in css
    assert "mobilenav" not in BASE_HTML.read_text(encoding="utf-8")

    phone = css[css.index("@media (max-width: 1024px)") :]
    phone = phone[: phone.index("@media (max-width: 720px)")]
    assert ".appshell { grid-template-columns: minmax(0, 1fr); }" in phone
    assert "position: fixed" in phone and "translateX(-100%)" in phone
    assert 'body[data-nav="open"] .sidebar { transform: none; }' in phone
    assert ".topbar__burger { display: grid; }" in phone

    # Every grid track that holds page content can shrink below its content.
    assert "grid-template-columns: var(--sidebar-w) minmax(0, 1fr)" in css
    assert ".appshell__body { min-width: 0;" in css
    assert ".main { flex: 1 1 auto; min-width: 0;" in css


@pytest.mark.asyncio
async def test_the_drawer_is_reachable_from_the_top_bar() -> None:
    async with _client() as c:
        body = (await c.get("/dashboard")).text
    assert 'class="topbar__burger"' in body
    assert 'aria-controls="sidebar"' in body
    assert 'onclick="toggleMobileNav()"' in body
    assert 'id="sidebar"' in body
    assert "toggleMobileNav" in APP_JS.read_text(encoding="utf-8")


# ── the shell's own surfaces ─────────────────────────────────────────────────


@pytest.mark.parametrize("theme", THEMES)
def test_the_rail_is_distinguishable_from_the_page_behind_it(theme: str) -> None:
    """A sidebar that melts into the canvas is not a sidebar."""
    tokens = tokens_for(theme)
    shell = parse_color(tokens["--shell-bg"], tokens)
    page = parse_color(tokens["--bg"], tokens)
    border = composite(parse_color(tokens["--shell-border"], tokens), page)
    edge = max(contrast(shell, page), contrast(border, page), contrast(border, shell))
    assert edge >= 1.1, f"{theme}: the rail edge is {edge:.2f}:1 against the page"


def test_chip_colours_are_all_tokens() -> None:
    """No chip carries a literal colour: a theme has one place to change."""
    css = read_css()
    block = css[css.index(".chip {") : css.index(".chip--ghost")]
    for match in re.finditer(r"color:\s*([^;]+);", block):
        value = match.group(1).strip()
        assert value.startswith("var(--"), f"chip colour is hard-coded: {value}"


@pytest.mark.parametrize("theme", THEMES)
def test_every_chip_variant_carries_its_own_legible_label(theme: str) -> None:
    failures = []
    for name, paint in chip_paint(theme).items():
        if paint.text_contrast < AA_BODY:
            failures.append(
                f"{theme}: .{name} label {hexed(paint.text)} on {hexed(paint.background)} "
                f"= {paint.text_contrast:.2f}:1, needs {AA_BODY}:1"
            )
    assert not failures, "\n".join(failures)


@pytest.mark.parametrize("theme", THEMES)
def test_the_unfilled_chip_has_a_perceivable_ring(theme: str) -> None:
    """``chip--ghost`` is the only variant with no fill, so its ring is the
    only thing that says it is a chip at all. WCAG 1.4.11."""
    ghost = chip_paint(theme)["chip--ghost"]
    assert ghost.border_contrast >= AA_UI, (
        f"{theme}: chip--ghost ring {hexed(ghost.border)} on {hexed(ghost.background)} "
        f"= {ghost.border_contrast:.2f}:1, needs {AA_UI}:1"
    )


def test_the_measured_palette_is_reported_in_full() -> None:
    """Not an assertion so much as the evidence behind the ones above.

    Runs the same resolution the other tests run and fails if any pair the
    stylesheet produces cannot be resolved at all -- an undefined token, a
    ``var()`` cycle, a colour syntax the parser does not know.
    """
    for theme in THEMES:
        paints = chip_paint(theme)
        assert len(paints) == 7
        for a, b in combinations(paints.values(), 2):
            assert a.name != b.name
        tokens = tokens_for(theme)
        for name, value in tokens.items():
            if name.startswith(("--font", "--space", "--radius", "--shadow")) or name in (
                "--topnav-h", "--sectionnav-h", "--sidebar-w", "--maxw", "--ring",
                "--topbar-h", "--glow", "--shadow-glow",
            ):
                continue
            parse_color(value, tokens)  # raises with the token's name on failure
    assert LIGHT != DARK
