/** Single source of truth for cross-page site config. */
export const site = {
  name: 'Talyx',
  tagline: 'Supply-chain security for AI coding agents.',
  domain: 'gettalyx.dev',
  url: 'https://gettalyx.dev',
  description:
    'Your AI coding agents auto-load MCP servers, plugins, skills and hooks — untrusted code with access to your shell, your credentials and your source. Talyx scans every one across 27 agents with a real tree-sitter AST and source-to-sink taint, and physically blocks what is malicious before it launches. Fully free, fully local, no telemetry, source-available.',
  email: 'rynald0cst0ltziam@gmail.com',
  github: 'https://github.com/rynald0cst0ltziam/talyx',

  // ── product facts ─────────────────────────────────────────
  agentsCovered: 27,
  attackClasses: 15,
  testsGreen: 357,
} as const;

export type Site = typeof site;
