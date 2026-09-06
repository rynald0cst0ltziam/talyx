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
  tagline: 'The security layer for AI coding agents.',
  domain: 'agentguard.dev',
  url: 'https://agentguard.dev',
  description:
    'AgentGuard scans and enforces every MCP server, skill, plugin, extension, hook and config your AI coding agents load — across 28 agents, fully local, no telemetry. Tree-sitter AST + source-to-sink taint, prompt-injection and hidden-Unicode detection, tool-shadowing and typosquat detection, real launch-time blocking.',
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
  agentsCovered: 28,
  attackClasses: 13,
  testsGreen: 291,
} as const;

export type Site = typeof site;
