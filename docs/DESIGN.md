# Concord — design system

Monochrome chrome, semantic colour. The application is greyscale everywhere
except where a colour reports a state, because this product's job is to say
what is true about a control, and colour that means nothing competes with
colour that does.

All tokens and class names live in
[`src/ccf/api/static/css/app.css`](../src/ccf/api/static/css/app.css) and are a
**stable contract** consumed by 54 Jinja templates. Restyle the *values*, never
rename the tokens or classes.

There is no build step and no `package.json`. The stylesheet is hand-authored
and served as-is; `htmx`, `Alpine`, `Lucide` and `Mermaid` are vendored.

## The rule that decides everything else

**Colour is reserved for status.** Action, active, link and focus are ink, not
a hue. An accent that competes with a status chip is one more thing a reader
has to learn *not* to read as meaning, and this product renders claims a
federal regulator will act on.

Two consequences worth stating, because both look like mistakes otherwise:

- **Links carry an underline**, not a colour. Once the accent is ink, colour no
  longer distinguishes a link from the text beside it (WCAG 1.4.1), so the
  underline is the only remaining signal and is not decoration.
- **`chip--brand` is a solid neutral fill**, while every status chip is a tint.
  It labels a framework code, a connector type, a count — it names a thing, it
  does not report a state. Three neutral chips cannot be told apart by hue, so
  it separates from the plain and the ghost chip on *lightness*, which a tint
  cannot do: a tint composites toward the card and lands on top of them.

## Themes

`data-theme` on `<html>`, **dark by default**, persisted to storage. 109 root
tokens, 42 dark overrides, 107 distinct. Geometry, type and layout metrics are
deliberately theme-invariant and are not restated in the dark block; a second
copy of `--radius: 10px` is a second thing to keep in sync.

| Role | Light | Dark |
|---|---|---|
| Page / card / inset | `#f2f2f3` · `#ffffff` · `#e7e7e9` | `#0a0a0b` · `#161618` · `#242428` |
| Text / secondary / muted | `#18181b` · `#51515a` · `#5f5f68` | `#f2f2f3` · `#b2b2b9` · `#9a9aa2` |
| Accent (action, active, focus) | `#18181b` | `#fafafa` |
| Categorical tag fill | `#26262c` on white | `#52525a` |

Neutrals are true greys. The previous scheme tinted every surface toward blue
(`--bg: #f4f5f8`, `--bg-elevated: #161b25`), which is what read as "blue and
black" far more than the accent did.

## Colour that means something

| Token | Carries |
|---|---|
| `--success` / `--warning` / `--danger` | pass, attention, fail |
| `--info` | deliberately **teal**, not a second blue — it must hold off `--success` as well as the accent |
| `--sev-critical/high/moderate/low/none` | the severity ramp: five ordered steps, so it cannot fold into four statuses without losing one |

The severity ramp is data-viz colour and lived as hex literals inside
`dashboard.html`, which meant it never followed the theme. It is tokenised in
both themes now.

## Type

System stack, no webfont and no network dependency. `--font-display` for page
and card titles and KPI values, `--font-body` for everything else,
`--font-mono` for control IDs and telemetry. Numerals are tabular wherever they
are compared down a column.

## Contrast is a requirement, not a preference

AA in **both** themes: 4.5:1 body text, 3:1 large text, UI boundaries and
meaningful fills. A compliance platform that publishes other people's control
evidence should not fail its own accessibility controls.

None of this is asserted by eye. `tests/theme_tokens.py` resolves the real
stylesheet, and `tests/test_ui_shell.py` measures every foreground/background
pair the tokens produce, failing with the pair and the ratio.

## What the tests pin

- Every one of the 54 pages renders the shell, in both themes.
- **No two chip variants are visually identical** — every ordered pair, both
  themes, CIEDE2000 floor of 10. The worst surviving pair is 15.3.
- No page references a **CSS variable or class that is defined nowhere**. Both
  are silent: the property simply does not apply and nothing logs it.
  `--radius-md` was referenced by three templates and defined by none, so every
  tile using it rendered square for as long as it existed, with a green suite.
- Every colour token has an explicit dark value, and no theme-invariant token
  is restated in the dark block.

## Out of scope

The landing page (`landing.html`) and the printable questionnaire report
(`questionnaire_report.html`) are standalone documents with their own local
design systems. The landing page is monochrome with a single mint accent — a
deliberate brand choice, in a different register from the application chrome.
