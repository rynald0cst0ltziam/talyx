// @ts-check
import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';
import sitemap from '@astrojs/sitemap';

// Static marketing site. No SSR, no adapter — deploys to any static host
// (Cloudflare Pages / Netlify / Vercel / GitHub Pages). Set `site` to the
// real production origin before launch so canonical URLs and the sitemap
// resolve correctly.
export default defineConfig({
  site: 'https://gettalyx.dev',
  trailingSlash: 'never',
  integrations: [sitemap()],
  vite: {
    // Cast: @tailwindcss/vite@4 and astro@5 can resolve slightly different
    // `vite` type versions; the plugin shape is compatible at runtime.
    plugins: [/** @type {any} */ (tailwindcss())],
  },
  build: {
    inlineStylesheets: 'auto',
  },
});
