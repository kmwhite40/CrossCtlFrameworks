# Concord — Landing page

Modern Next.js 14 + TypeScript + Tailwind + shadcn/ui landing page for Concord,
featuring the `ShaderBackground` WebGL component behind the hero.

```
web/landing/
├── app/
│   ├── layout.tsx          # Inter + Space Grotesk fonts, metadata, HTML shell
│   ├── page.tsx            # Full marketing page (hero / features / frameworks / steps / CTA)
│   └── globals.css         # Tailwind + shadcn CSS variables
├── components/
│   ├── ui/
│   │   ├── shader-background.tsx   # ← dropped in from the prompt (TS + cleanup)
│   │   ├── button.tsx              # shadcn primitive
│   │   ├── card.tsx                # shadcn primitive
│   │   └── badge.tsx               # shadcn primitive
│   └── demo.tsx            # ShaderBackground usage demo
├── lib/utils.ts            # cn() helper (clsx + tailwind-merge)
├── components.json         # shadcn project config
├── tailwind.config.ts
├── postcss.config.mjs
├── tsconfig.json
├── next.config.mjs
└── package.json
```

## Why `components/ui/`

shadcn copies component source into your repo (it is not a package). Every shadcn
doc, example, and third-party snippet imports from `@/components/ui/*`. Keeping
that exact folder:

1. Lets `npx shadcn@latest add <name>` drop new primitives in place.
2. Keeps UI primitives (stateless, reusable) separate from composed, app-specific
   components (which live under `components/<feature>/`).
3. Makes drop-in components like the `ShaderBackground` in this prompt work
   without path gymnastics.

## Setup (from scratch — if you want to rebuild this directory with the shadcn CLI)

```sh
# Node 20+ required
npx create-next-app@latest concord-landing --typescript --tailwind --eslint --app --src-dir=false --import-alias "@/*"
cd concord-landing
npx shadcn@latest init          # pick new-york, slate, CSS variables
npx shadcn@latest add button card badge
npm i lucide-react
```

Then drop `components/ui/shader-background.tsx` and `components/demo.tsx` from
the prompt in, and replace `app/page.tsx` with the landing implementation in
this folder.

## Install & run

```sh
cd web/landing
npm install
npm run dev          # http://localhost:3000

# Production
npm run build && npm run start
```

## Dependencies pulled in by this integration

- `next@14.2`, `react@18`, `typescript@5`
- `tailwindcss@3.4`, `tailwindcss-animate`, `autoprefixer`, `postcss`
- `@radix-ui/react-slot`, `class-variance-authority`, `clsx`, `tailwind-merge`
- `lucide-react` (icons)

## Integration answers (per the prompt)

- **Props/data:** `ShaderBackground` is self-contained — no props, no context.
- **State management:** uses `useRef` for the canvas and a `useEffect` for
  WebGL program lifecycle + window resize. No external state.
- **Assets:** none required. The hero is a live WebGL shader. The preview
  strip uses one Unsplash image: `images.unsplash.com/photo-1518770660439-4636190af475`.
- **Responsive:** the canvas is `fixed inset-0 -z-10` and resizes with
  `window.innerWidth/Height`. Content sits above it in normal flow.
- **Best placement:** rendered at the top of `app/page.tsx` so the entire
  scrollable landing is layered over the shader.

## Notes

- The original JSX is `"use client"` (it touches `window` and WebGL) — added
  to the top of `shader-background.tsx`.
- Loose types (`any` on refs and WebGL helpers) were tightened to
  `HTMLCanvasElement`, `WebGLRenderingContext`, `WebGLShader`, `WebGLProgram`
  for strict TS mode.
- `requestAnimationFrame` handle is captured so the cleanup function cancels
  it — the original didn't, which caused a stale-frame leak on unmount.
