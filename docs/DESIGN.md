# Concord — Design System (indigo glassmorphism)

A single, app-specific visual language for the CMMC/NIST compliance command
console: a deep indigo/violet gradient canvas with **frosted-glass panels**,
periwinkle (`--brand`) and teal (`--accent`) accents, soft glows, and Open Sans
type — modern, calm, and legible over the dark surface.

All tokens and class names live in [`src/ccf/api/static/css/app.css`](../src/ccf/api/static/css/app.css)
and are a **stable contract** consumed by the Jinja templates — restyle the
*values*, never rename the tokens/classes.

## Aesthetic direction

| Element | Decision | Why |
|---|---|---|
| Surface | Indigo/violet gradient `#0c1024`→`#080a18` with radial brand/teal pools | Modern, atmospheric depth |
| Panels | Frosted glass: translucent fill + `backdrop-blur(20px)` + hairline border + inner highlight, `--radius-lg` (18px) | The signature "glass" look |
| Primary | **Periwinkle** `--brand-500 #6f7bff` | Active nav, primary buttons, links, focus, brand mark |
| Accent | **Teal** `--accent-500 #2dd4bf` | Secondary highlights / data |
| Status | semantic chips + optional `.led--ok/warn/err/live` dots | At-a-glance health |

Dominant indigo + glass, with periwinkle/teal accents and semantic green/amber/red.

## Type

| Role | Family | Usage |
|---|---|---|
| Display | **Open Sans** (`--font-display`) | Page titles, card titles, KPI/metric numbers |
| Body | **Open Sans** (`--font-body`) | Prose, controls, buttons |
| Mono | **Open Sans** (`--font-mono`) | Telemetry labels, table headers, control IDs, metadata |

A single family (**Open Sans**) is used throughout; the three `--font-*` tokens
remain so a future tier change is a one-line edit. Numerals are **tabular**
wherever data lives (metrics, tables, chips). The heavy, uppercase,
letter-spaced **micro-label** (mono token) is the signature texture — use
`.label`, `.kpi__label`, `.card__subtitle`, and `<th>` for it.

## Tokens (the contract)

- Color ramps: `--brand-50…700` (periwinkle), `--accent-400…600` (teal),
  `--ok/warn/err/info-500/700` (+ `-50` translucent fills).
- Surface/text: `--bg-0/1`, `--panel`, `--text`, `--text-dim`, `--text-mute`,
  `--glass`, `--glass-2`, `--glass-border(-2)`, `--hairline`, `--field-bg`.
- Geometry: `--radius-sm/(lg/xl)`, `--shadow-xs…lg`, `--glow`, `--glow-signal`,
  `--ring`, `--sidebar-w`, `--topbar-h`.
- Legacy aliases `--ink-25…950` map onto the surface ramp so older inline styles
  keep working. **Prefer the semantic names in new markup.**

A `[data-theme="light"]` block re-points the surface/text tokens for a
graphite-on-paper variant; components inherit it automatically.

## Reusable patterns

- **Panel**: `.card` (`.card--elevated`) with `.card__header/__title/__subtitle/__body/__footer`.
- **Brand mark**: the Concord logo (`static/img/logo*.png`) renders as the
  topbar `.topbar__brand-mark`, the landing nav `.lp-mark` + floating
  `.lp-logo` hero, and the favicon / apple-touch-icon.
- **Metric/KPI**: `.kpi` → `.kpi__label` (mono) + `.kpi__value` + `.kpi__meta` + optional `.kpi__trend` icon chip; a teal→periwinkle accent rail runs down the left edge.
- **Status**: `.chip--ok/warn/err/info/brand/ghost` (mono) and `.led--ok/warn/err/live` dots; `--live` pulses for real-time elements.
- **Telemetry label**: `.label` — mono, uppercase, `0.14em` tracking, muted.
- **Tables**: wrap in `.table-wrap`; mono uppercase `<th>`, brand row-hover, brand ID links, `.mono` cells for identifiers.
- **Buttons**: `.btn--primary` (periwinkle), `.btn--secondary` (outline), `.btn--ghost`; `.btn--sm` / `.btn--lg`.
- **Inputs**: `.input` / `.select` + `.field-group` (mono label).
- **Layout**: `.cols-2/3/4`, `.grid-cards`, `.stack`, `.row`, `.layout-split-l/r` (responsive split views), `.between`.

## Motion

One orchestrated page-load moment: `.page > *` rises in with a small stagger.
Live elements use the LED pulse. The landing page layers an ambient scene
(rising light beams, perspective grid floor, a gently floating logo). Everything
is disabled under `prefers-reduced-motion`. Keep app transitions ≤ 200ms and
CSS-only.

## Conventions for new components

1. Compose from the existing tokens + classes; add a token before a hardcoded color.
2. Labels/IDs/units → `--font-mono`; numbers → tabular; headings/metrics → `--font-display`.
3. Periwinkle (`--brand`) is structure/authority; **teal (`--accent`) is rationed** for highlights, with semantic green/amber/red reserved for live/critical status.
4. Hairline borders + small radii; the glass blur is the signature — avoid competing heavy shadows.
5. Verify both `data-theme` values and `prefers-reduced-motion`.
