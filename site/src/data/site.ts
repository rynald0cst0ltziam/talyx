/**
 * Single source of truth for cross-page site config.
 *
 * LEMON SQUEEZY WIRING — before launch, replace the three placeholder
 * values below with the real ones from your Lemon Squeezy dashboard:
 *
 *   1. `checkoutUrl`   — Store → Products → your product → "Share" → copy the
 *                        checkout URL. Looks like
 *                        https://agentguard.lemonsqueezy.com/buy/xxxxxxxx-xxxx-...
 *   2. `storeSlug`     — your store subdomain (the "agentguard" in the URL above).
 *                        Used by the lemon.js overlay script.
 *   3. price fields    — keep in sync with the Lemon Squeezy variant price.
 *
 * The overlay checkout (lemon.js) is loaded in Base.astro. Any link with
 * `class="lemonsqueezy-button"` pointing at a *.lemonsqueezy.com URL opens
 * in the overlay instead of a full navigation.
 */
export const site = {
  name: 'AgentGuard',
  tagline: 'Supply-chain security for AI coding agents.',
  domain: 'agentguard.dev',
  url: 'https://agentguard.dev',
  description:
    'Your AI coding agents auto-load MCP servers, plugins, skills and hooks — untrusted code with access to your shell, your credentials and your source. AgentGuard scans every one across 27 agents with a real tree-sitter AST and source-to-sink taint, and physically blocks what is malicious before it launches. Fully local, no telemetry, source-available.',
  email: 'hello@agentguard.dev',
  github: 'https://github.com/agentguard/agentguard',

  // ── commerce ──────────────────────────────────────────────
  checkoutUrl: 'https://agentguard.lemonsqueezy.com/buy/REPLACE-WITH-REAL-CHECKOUT-ID',
  storeSlug: 'agentguard',
  price: {
    amount: 149,
    currency: 'USD',
    unit: '/ developer / year',
    launchAmount: 149,
    regularAmount: 249,
    // launch window copy — drives the urgency banner
    launchEndsISO: '2026-10-15',
  },

  // ── product facts (keep in sync with repo STATUS.md) ──────
  agentsCovered: 27,
  attackClasses: 14,
  testsGreen: 333,
} as const;

export type Site = typeof site;
