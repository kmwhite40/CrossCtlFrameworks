# UI shell redesign — sidebar, dark-first

**Status:** design 2026-09-23. Converts the application chrome to a left
sidebar and makes dark the default, without touching page content.

---

## 1. Why this is smaller than it looks

Measured:

- **54 templates extend `base.html`** and fill only `title`, `subtitle`,
  `heading`, `content`, `actions`. None assumes the shell's structure, so the
  chrome can change in two files.
- **`nav_groups` is already data** — four groups, ~40 destinations with labels
  and descriptions, plus `nav_pinned`. Rendering it as a sidebar is a template
  change over the same structure, not an information-architecture exercise.
- **70 CSS custom properties** already exist, with real semantic names
  (`--bg`, `--bg-elevated`, `--bg-subtle`, `--border`, `--accent`).
- **Dark mode already works** — `data-theme` on `<html>`, `toggleTheme()`
  persisting to storage. It defaults to `light`.
- **Lucide** is already the icon set.

So this is a restyle plus one structural change, not a rewrite.

---

## 2. The risk is that CSS now carries meaning

**237 chip usages across six semantic variants** — `chip--ok` 59,
`chip--warn` 60, `chip--err` 56, `chip--brand` 38, `chip--ghost` 16,
`chip--info` 8.

They are not decoration. Since this cycle they encode:

- Trust Center corroboration — `corroborated` / `unsupported` / `contradicted`
- The guided onboarding path's five states, where `unknown` must never read as
  `done` or as `not_started`
- Portal grant status, where `engagement ended` is distinct from `expired`
- Assessment findings across two standards' vocabularies

`tests/test_trust_corroboration.py` already asserts **no two states share a
chip or a label**. That test is the contract this redesign must not break.

**No two semantically distinct states may become visually identical**, in
either theme. A restyle that merges `warn` and `err` into one accent, or makes
`ghost` and `info` indistinguishable on a dark background, is a correctness
regression wearing a visual change.

---

## 3. Dark-first: 31 tokens are the actual work

Measured: `:root` defines **52** tokens; `[data-theme="dark"]` overrides
**21**. So **31 tokens have no dark value** and currently inherit light ones.

Dark is the less-exercised theme today. Flipping the default makes those 31
the defaults users see, so each needs a value chosen and checked — not copied.

**Contrast is a requirement, not a preference.** Text and interactive elements
must meet WCAG AA (4.5:1 body, 3:1 large text and UI boundaries) in **both**
themes. This is an accessibility control in a federal compliance product; a
platform that publishes other people's control evidence should not fail its
own.

Enumerate the 31, give each an explicit dark value, and measure the contrast
ratio of every foreground/background pair the chips and cards produce. Report
the measurements.

---

## 4. The shell

**Left sidebar**, from the existing `nav_groups`:

- Grouped sections with headings, as the reference shows
  (`GENERAL` / `TOOLS & RESOURCES` / `SETTINGS`)
- The active page highlighted — `active` is already passed in every template's
  context and already drives the current nav; keep that mechanism
- Profile block pinned at the bottom
- `nav_pinned` keeps its one-click role

**Top bar** retains search (⌘K, `openPalette()` already exists), theme toggle,
and the existing icon affordances.

**Mobile is not optional.** The current chrome has a burger and a mobile menu.
A sidebar must collapse to something usable at phone width — the existing
mobile nav is the fallback if a better one is not warranted.

### 4.1 What does NOT change

- No page content, no `content` blocks, no route changes.
- No new dependency and no build step. The repo has no `package.json`
  deliberately; vendored `htmx`, `alpine`, `lucide` and `mermaid` stay as they
  are.
- `nav_groups`' membership and ordering — this is a presentation change. If the
  grouping is wrong, that is a separate decision with its own evidence.

---

## 5. Card and surface treatment

- Tinted KPI tiles, as the reference shows, **derived from existing semantic
  tokens** rather than a new palette — a fifth hard-coded colour is a fifth
  thing to keep in sync.
- Softer radius and a consistent spacing scale, expressed as tokens so the
  values live in one place.
- A hero/banner card is available to the dashboard; it is not imposed on all
  54 pages.

**The reference is a different product.** It is a dashboard for AI tooling —
"Quick Launch Agents", "Favorite Prompts", "Flows Executed". Concord's
equivalents are systems, controls, evidence and findings. Adopt the **visual
language**; do not invent metrics to fill a layout.

---

## 6. Testing requirements

1. **Every one of the 54 pages renders** without error in both themes. Several
   are already smoke-tested; extend to all.
2. **No two semantically distinct chips are visually identical** in either
   theme — extend `tests/test_trust_corroboration.py`'s existing assertion to
   every variant pair, both themes.
3. **The five onboarding states stay distinguishable**, `unknown` included.
4. **Contrast ratios are asserted**, not eyeballed: every token pair used for
   text on a surface meets AA, in both themes. A failure names the pair and the
   ratio.
5. **The active-nav mechanism still works** — each page's `active` key
   highlights exactly one sidebar entry.
6. **Theme persistence survives** a reload, and an unset preference gets dark.
7. **Phone width**: no horizontal scroll, navigation reachable.

Mutation-verify the ones that carry meaning: merge two chip variants and
confirm test 2 fails; drop a dark token and confirm test 4 fails.

---

## 7. Out of scope

- **The AI assistant drawer.** A persistent chat surface is a feature, not a
  restyle — it needs decisions about what it can see, what it may act on, and
  how its output is marked as machine-generated, which this codebase has
  strong existing rules about.
- **Changing what any page shows.**
- **Re-grouping the navigation** (§4.1).
