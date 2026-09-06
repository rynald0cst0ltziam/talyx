# agentguard.dev — marketing site

Astro 5 + Tailwind 4, fully static. No SSR, no server, no database.

```bash
cd site
npm install
npm run dev        # http://localhost:4321
npm run build      # -> site/dist  (static, deploy anywhere)
npm run check      # astro + TS diagnostics
```

## Deploy

`npm run build` emits `site/dist`. Point any static host at it:

| Host              | Setting                                              |
|-------------------|-----------------------------------------------------|
| Cloudflare Pages  | build `npm run build`, output dir `dist`, root `site` |
| Netlify           | base `site`, build `npm run build`, publish `site/dist` |
| Vercel            | root `site`, framework "Astro" (auto)                |
| GitHub Pages      | build in CI, upload `site/dist`                      |

Set the production origin in `astro.config.mjs` (`site:`) so canonical URLs
and `sitemap-index.xml` resolve.

## Before launch — required edits

All in **`src/data/site.ts`**:

1. `checkoutUrl` — real Lemon Squeezy checkout URL
   (Store → Products → your product → Share → copy). Every "Buy" button and
   the pricing card point at this; `class="lemonsqueezy-button"` + the
   `lemon.js` script (loaded in `src/layouts/Base.astro`) make it open in an
   overlay instead of a full-page nav.
2. `storeSlug` — your `*.lemonsqueezy.com` subdomain.
3. `price.*` — keep `amount` / `regularAmount` / `launchEndsISO` in sync with
   the Lemon Squeezy variant and your launch window. `launchEndsISO` drives
   the countdown on the pricing card and the top banner copy.
4. `domain` / `url` / `email` / `github` — real values.

Also:

- **`get.agentguard.dev`** — the install one-liner (`curl … | sh`,
  `irm … | iex`) points here. Stand up a redirect / worker that serves
  `scripts/install.sh` and `scripts/install.ps1` from the repo root, or
  change the URLs in `src/data/content.ts` and `src/pages/docs.astro`.
- **`public/og.svg`** — social card. Some scrapers want raster; convert to
  `og.png` (1200×630) and switch the reference in `src/layouts/Base.astro`
  if link previews matter.
- The comparison table (`src/data/content.ts` → `comparison`) is a
  point-in-time claim set. Re-verify against competitors' public docs
  before launch and date it.

## Structure

```
src/
  data/site.ts        commerce + product config (edit this)
  data/content.ts     copy, features, comparison rows, FAQ
  layouts/Base.astro  <head>, nav, footer, lemon.js, reveal script
  components/          Hero, ThreatDemo (animated terminal), Features,
                      Comparison, Pricing, FAQ, CTA, …
  pages/              index, pricing, docs, security, legal, 404
```

Animations degrade to fully-visible content under `prefers-reduced-motion`,
without JS, and in a backgrounded tab.
