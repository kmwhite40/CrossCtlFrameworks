# Concord — design system

Deep navy surfaces with a cyan primary and violet secondary accent (dark, the
primary theme); white and slate with a blue primary and violet secondary
(light). Colour that reports a state is still reserved for state: the accent is
a brand colour for action, focus, the active rail entry and links, and it is
kept off every status hue.

All tokens and class names live in
[`src/ccf/api/static/css/app.css`](../src/ccf/api/static/css/app.css) and are a
**stable contract** consumed by the Jinja templates. Restyle the *values*,
never rename the tokens or classes. There is no build step and no
`package.json`; `htmx`, `Alpine`, `Lucide` and `Mermaid` are vendored.

## What changed in the 2026-10 redesign, and why

The previous system was monochrome: the accent was ink, on the argument that
any hue competes with a status chip. The redesign brief asked for a cyan/violet
brand. The argument still holds for *status*, so the redesign keeps its
consequence rather than its palette:

- **`--info` moved off cyan** in dark (now blue `#60a5fa`) because the accent
  *is* cyan there. In light the accent is blue, so `--info` is sky (`#0369a1`).
- **Status chips are unchanged in kind**: tinted fills with their own ink
  tokens, and `chip--brand` (a categorical tag) is the one solid neutral.
- **Links still carry an underline** inside tables, so colour is never the only
  link signal (WCAG 1.4.1).

## Themes

`data-theme` on `<html>`. **An explicit choice wins; with no choice the
operating system decides**, and a change of OS preference is followed live.
"Use system theme" (profile menu) forgets the choice. The server always sends
`data-theme="dark"` and never varies the markup by theme; an inline script sets
the real value before first paint. The previous rule was dark-for-everyone;
the tests that pinned it now pin this one, including a node harness that runs
the shipped `app.js` against a stubbed `matchMedia` in both directions.

| Role | Light | Dark |
|---|---|---|
| Page · rail · card · elevated | `#f5f7fc` · `#ffffff` · `#ffffff` · `#f0f4fa` | `#060b16` · `#091426` · `#101f35` · `#172b45` |
| Text · secondary · muted | `#0f172a` · `#526075` · `#5a687d` | `#f8fafc` · `#a3b1c6` · `#94a3b8` |
| Primary · secondary accent | `#2563eb` · `#7c3aed` | `#22d3ee` · `#8b5cf6` |
| Success · warning · danger · info | `#047857` · `#b45309` · `#e11d48` · `#0369a1` | `#14b8a6` · `#f59e0b` · `#f43f5e` · `#60a5fa` |

The brief's secondary text (`#64748b` light, `#94a3b8` dark) is used as
`--text-muted` in dark and stepped down in light, where `#64748b` does not
reach AA on the elevated surface.

Measured by `tests/theme_tokens.py` against the stylesheet as committed
(2026-10-20): text on card 17.85:1 light / 15.81:1 dark; secondary text on
card 6.39 / 7.61; muted text on its worst surface 5.13 / 5.58; label on a
filled accent 5.17 / 10.48. Worst pair of chip variants ΔE 12.5 light / 13.3
dark (floor 10). Re-run the measurement rather than trusting these
figures after any token change.

## Charts

Server-rendered SVG macros in `templates/_viz.html` (`ring`, `stackbar`,
`columns`, `riskgrid`, `sevlist`); no chart library. Every chart carries three
channels for the same data: the marks with a hover/focus tooltip (`data-tip`),
a legend or direct label, and a "View as table" disclosure.

`--series-1…4` are categorical, in a fixed order that alternates warm and cool
(blue, orange, violet, aqua): blue beside violet is not separable under
deuteranopia, so the brand pair is never adjacent in a chart. The order passes
the dataviz palette validator (lightness band, chroma, adjacent-pair CVD ΔE,
normal-vision floor, contrast) in both themes against `--bg-elevated`. Status
charts (test pass/fail, framework posture) use status tokens, never series.

## The shell

- **One information architecture**: `ccf/api/navigation.py` drives the rail,
  the breadcrumbs and the command palette. Every item is `live`, `partial`
  (with a note on what is missing, shown as a tooltip and a tag) or `planned`
  (routes to `/planned/<slug>`, which names the missing model and shows no
  sample data). Items whose route is role-gated carry the same `audience`, so
  the rail never offers a page that answers 403.
- **Rail**: collapsible to icons (`[` or the button; persisted per browser),
  an off-canvas drawer below 1024px. Still one `<nav>`.
- **Top bar**: palette trigger (⌘K), theme switch, notification bell with an
  unread badge and drawer, the signed-in user.
- **Command palette**: pages from the IA plus org-scoped record search
  (`/ui/search`). Keyboard: ⌘K, `/`, `[`, `g` then a letter, `?`, Esc.
- **Errors**: a browser that hits a 4xx gets the shell with what happened and
  where to go; API clients keep their JSON (`ccf/api/errors.py`).

## Contrast and layout are tested, not eyeballed

`tests/test_ui_shell.py` measures every text/surface pair, boundary and
meaningful fill in both themes; checks chip distinctness, undefined CSS
variables and classes, line-height on display type, and `fr` tracks that can
overflow. A browser sweep (74 pages × 2 themes × 2 widths) found and fixed five
pages that scrolled sideways on a phone and one link colour at 4.35:1.

## Out of scope

The landing page (`landing.html`), the external portal (`portal.html`) and the
printable questionnaire report (`questionnaire_report.html`) are standalone
documents with their own local styles.
