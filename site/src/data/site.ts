/**
 * Single source of truth for cross-page site config.
 *
 * The overlay checkout (lemon.js) is loaded in Base.astro. Any link with
 * `class="lemonsqueezy-button"` pointing at a *.lemonsqueezy.com URL opens
 * in the overlay instead of a full navigation.
 */
export const site = {
  name: 'Talyx',
  tagline: 'Supply-chain security for AI coding agents.',
  domain: 'gettalyx.dev',
  url: 'https://gettalyx.dev',
  description:
    'Your AI coding agents auto-load MCP servers, plugins, skills and hooks — untrusted code with access to your shell, your credentials and your source. Talyx scans every one across 27 agents with a real tree-sitter AST and source-to-sink taint, and physically blocks what is malicious before it launches. Fully local, no telemetry, source-available.',
  email: 'rynald0cst0ltziam@gmail.com',
  // Update if the repo moves to an org later — see LAUNCH_RUNBOOK.md §2 for
  // the private/public decision this also depends on.
  github: 'https://github.com/rynald0cst0ltziam/talyx',

  // ── commerce ──────────────────────────────────────────────
  checkoutUrl: 'https://agenify.lemonsqueezy.com/checkout/buy/ea5892a0-d32f-4a75-9398-c177bd28a69d',
  storeSlug: 'agenify',
  // One-time purchase, lifetime license — must match the Lemon Squeezy
  // product (single payment, license keys never expire).
  price: {
    amount: 99,
    currency: 'USD',
    unit: 'one-time',
  },

  // ── product facts (keep in sync with repo STATUS.md) ──────
  agentsCovered: 27,
  attackClasses: 15,
  testsGreen: 357,
} as const;

export type Site = typeof site;
