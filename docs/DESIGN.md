# Concord — Design System ("SIGINT")

A single, app-specific visual language for the CMMC/NIST compliance command
console. The aesthetic is **defense-grade instrumentation**: a graphite mission-
control surface, steel-cyan authority, a sharp signal-amber live accent, and
dense, legible telemetry. It is deliberately *not* the generic "Inter + purple
gradient on white" look.

All tokens and class names live in [`src/ccf/api/static/css/app.css`](../src/ccf/api/static/css/app.css)
and are a **stable contract** consumed by the Jinja templates — restyle the
*values*, never rename the tokens/classes.

## Aesthetic direction

| Element | Decision | Why |
|---|---|---|
| Surface | Graphite `#090b10`→`#0c0f15` + faint 34px HUD grid | Mission-control / SCIF, depth without noise |
| Authority color | **Steel cyan** `--brand-500 #2bb0c6` | Primary actions, active nav, links, focus — calm, technical |
| Live accent | **Signal amber** `--accent-500 #ffb224` | Sparse, high-impact: brand glyph, active-nav LED, live metrics, warnings |
| Panels | Hairline 1px border, light blur, small radius (8–12px) | Precise instrument panels, not pillowy "glass blobs" |
| Status | **LED dots** (`.led--ok/warn/err/live`) + semantic chips | Reads at a glance like a control board |

Dominant graphite + cyan, **sharp amber accents** — never an even rainbow.

## Type

| Role | Family | Usage |
|---|---|---|
| Display | **Chivo** (`--font-display`) | Page titles, card titles, KPI/metric numbers |
| Body | **IBM Plex Sans** (`--font-body`) | Prose, controls, buttons |
| Mono | **IBM Plex Mono** (`--font-mono`) | Telemetry labels, table headers, control IDs, metadata |

Numerals are **tabular** wherever data lives (metrics, tables, chips). The
heavy, uppercase, letter-spaced **mono micro-label** is the signature texture —
use `.label`, `.kpi__label`, `.card__subtitle`, and `<th>` for it.

## Tokens (the contract)

- Color ramps: `--brand-50…700` (cyan), `--accent-400…600` (amber),
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
- **Metric/KPI**: `.kpi` → `.kpi__label` (mono) + `.kpi__value` (Chivo) + `.kpi__meta` + optional `.kpi__trend` icon chip; an amber→cyan accent rail runs down the left edge.
- **Status**: `.chip--ok/warn/err/info/brand/ghost` (mono) and `.led--ok/warn/err/live` dots; `--live` pulses for real-time elements.
- **Telemetry label**: `.label` — mono, uppercase, `0.14em` tracking, muted.
- **Tables**: wrap in `.table-wrap`; mono uppercase `<th>`, cyan row-hover, cyan ID links, `.mono` cells for identifiers.
- **Buttons**: `.btn--primary` (cyan), `.btn--secondary` (outline), `.btn--ghost`; `.btn--sm`.
- **Inputs**: `.input` / `.select` + `.field-group` (mono label).
- **Layout**: `.cols-2/3/4`, `.grid-cards`, `.stack`, `.row`, `.layout-split-l/r` (responsive split views), `.between`.

## Motion

One orchestrated page-load moment: `.page > *` rises in with a small stagger.
Live elements use the amber LED pulse. Everything is disabled under
`prefers-reduced-motion`. Keep transitions ≤ 200ms and CSS-only.

## Conventions for new components

1. Compose from the existing tokens + classes; add a token before a hardcoded color.
2. Labels/IDs/units → `--font-mono`; numbers → tabular; headings/metrics → `--font-display`.
3. Cyan is structure/authority; **amber is rationed** for live/critical signals only.
4. Hairline borders + small radii; avoid heavy blur and large drop shadows.
5. Verify both `data-theme` values and `prefers-reduced-motion`.
