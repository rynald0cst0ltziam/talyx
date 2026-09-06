/** Marketing copy + structured data, kept out of the templates. */

export const agents = [
  'Claude Code',
  'Claude Desktop',
  'Cursor',
  'Codex',
  'Windsurf',
  'Devin CLI',
  'Antigravity',
  'Gemini CLI',
  'GitHub Copilot CLI',
  'VS Code Copilot',
  'OpenClaw',
  'Amp',
  'Kiro',
  'Amazon Q',
  'Continue.dev',
  'Cline',
  'Roo Code',
  'Zed',
  'JetBrains AI',
  'opencode',
  'Tabnine',
  'Cody',
  'Goose',
  'Aider',
  'OpenHands',
  'Crush',
];

export interface Feature {
  title: string;
  body: string;
  icon: 'radar' | 'inject' | 'mask' | 'shield' | 'ci' | 'lock';
  tag: string;
}

export const features: Feature[] = [
  {
    icon: 'radar',
    tag: 'Discovery',
    title: 'Finds every artifact your agents load',
    body: 'MCP servers, skills, plugins, hooks and agent configs across 27 coding agents — user scope and project scope, JSON, YAML and TOML. One scan, every surface. No agent-by-agent setup.',
  },
  {
    icon: 'inject',
    tag: 'Content analysis',
    title: 'Reads the text your agent will obey',
    body: 'Skill markdown and instruction files are scanned for prompt-injection phrasing, invisible Unicode and Unicode-tag smuggling, base64 / hex / \\x encoded payloads, and data-exfiltration directives — the attacks that never touch a shell command.',
  },
  {
    icon: 'mask',
    tag: 'Impersonation',
    title: 'Catches tool shadowing and typosquats',
    body: 'A server that borrows a trusted name, typosquats "github" or "filesystem", or ships a poisoned tool description gets flagged as impersonation — scored across every artifact at once, not one file in isolation.',
  },
  {
    icon: 'shield',
    tag: 'Enforcement',
    title: 'Blocks the bad ones — for real',
    body: 'Approved servers launch through the AgentGuard shim. Blocked ones are removed from the config so the agent physically cannot start them. Remote entries are stripped and restored on approval. Skills are quarantined. Every change is checksum-verified and reversible.',
  },
  {
    icon: 'ci',
    tag: 'CI',
    title: 'SARIF + a GitHub Action',
    body: 'Run the same scan in CI. Results upload as SARIF straight into GitHub code scanning, with a non-zero exit on Block so a poisoned dependency fails the build instead of shipping.',
  },
  {
    icon: 'lock',
    tag: 'Local-first',
    title: 'Nothing leaves your machine',
    body: 'No account, no daemon, no cloud, no telemetry. Registry lookups (npm / PyPI) are the only outbound calls, and you opt into those. Your config, your threat surface, your machine.',
  },
];

export interface ThreatLine {
  t: number; // ms delay before this line types in
  prompt?: boolean;
  text: string;
  cls?: string; // tailwind classes for the line
}

/** The animated terminal transcript on the hero. */
export const threatDemo: ThreatLine[] = [
  { t: 0, prompt: true, text: 'agentguard scan --project .' },
  { t: 550, text: 'scanning 4 agents · 19 artifacts · 2 registry packages', cls: 'text-mist' },
  { t: 1500, text: '', },
  { t: 1650, text: '  CRITICAL  mcp: "github-mcp"  — impersonates trusted "github"', cls: 'text-threat font-semibold' },
  { t: 1900, text: '            launch: node ./.cursor/gh-helper.js', cls: 'text-mist' },
  { t: 2100, text: '            + reads ~/.ssh/id_rsa, posts to paste.ee', cls: 'text-mist' },
  { t: 2600, text: '  HIGH      skill: "pr-review"  — hidden instructions in SKILL.md', cls: 'text-warn font-semibold' },
  { t: 2850, text: '            10 zero-width chars decode to a prompt override', cls: 'text-mist' },
  { t: 3300, text: '  BLOCKED   both removed from config — agent cannot load them', cls: 'text-safe font-semibold' },
  { t: 3750, text: '', },
  { t: 3850, text: '  17 artifacts verified clean · 2 blocked · 0 need review', cls: 'text-fog' },
  { t: 4200, text: 'protection active. run  agentguard why github-mcp  for detail.', cls: 'text-signal' },
];

export interface CompareRow {
  capability: string;
  agentguard: 'full' | 'partial' | 'none';
  snyk: 'full' | 'partial' | 'none';
  mcpscan: 'full' | 'partial' | 'none';
  note?: string;
}

export const comparison: CompareRow[] = [
  { capability: 'Runs fully local, no account or cloud', agentguard: 'full', snyk: 'none', mcpscan: 'partial' },
  { capability: 'Coverage across 27 coding agents', agentguard: 'full', snyk: 'partial', mcpscan: 'partial' },
  { capability: 'Scans skills / instruction files for injection', agentguard: 'full', snyk: 'partial', mcpscan: 'none' },
  { capability: 'Invisible-Unicode & encoded-payload detection', agentguard: 'full', snyk: 'none', mcpscan: 'partial' },
  { capability: 'Tool shadowing / name typosquat detection', agentguard: 'full', snyk: 'full', mcpscan: 'full' },
  { capability: 'Poisoned tool-description detection', agentguard: 'full', snyk: 'full', mcpscan: 'full' },
  { capability: 'Actually blocks a server from launching', agentguard: 'full', snyk: 'none', mcpscan: 'partial' },
  { capability: 'Protection survives if a proxy is not running', agentguard: 'full', snyk: 'full', mcpscan: 'none' },
  { capability: 'Registry (npm / PyPI) pre-resolution', agentguard: 'full', snyk: 'full', mcpscan: 'none' },
  { capability: 'SARIF + CI action', agentguard: 'full', snyk: 'full', mcpscan: 'none' },
  { capability: 'No telemetry', agentguard: 'full', snyk: 'none', mcpscan: 'partial' },
];

export interface Step {
  n: string;
  title: string;
  body: string;
  code?: string;
}

export const steps: Step[] = [
  {
    n: '01',
    title: 'Install',
    body: 'One binary and its enforcement shim. No runtime, no dependencies.',
    code: 'curl -fsSL https://get.agentguard.dev | sh',
  },
  {
    n: '02',
    title: 'Activate your license',
    body: 'Paste the key from your purchase email. Activates offline for 30 days at a time.',
    code: 'agentguard activate AG-XXXX-XXXX-XXXX',
  },
  {
    n: '03',
    title: 'Scan',
    body: 'Point it at a project or your home directory. It finds every agent and every artifact.',
    code: 'agentguard scan --project .',
  },
  {
    n: '04',
    title: 'Enforce',
    body: 'Route every approved MCP server through the shim; blocked ones are pulled from the config. Reversible any time.',
    code: 'agentguard init --project ~',
  },
];

export interface Faq {
  q: string;
  a: string;
}

export const faqs: Faq[] = [
  {
    q: 'What exactly does AgentGuard protect against?',
    a: 'The artifact supply chain for AI coding agents: a malicious MCP server launched from a config file, a skill or instruction file carrying hidden prompt-injection, an encoded payload in a tool description, a server impersonating a trusted one, a hook running an exfiltration command. It inspects what your agent is about to load and either verifies it, flags it for review, or blocks it.',
  },
  {
    q: 'Is it actually local? What leaves my machine?',
    a: 'It is a single binary. There is no account, no daemon, no cloud backend, and no telemetry. The only outbound network calls are optional npm / PyPI registry lookups when you pass --fetch-registry, and a license check against Lemon Squeezy on activation and roughly monthly after. Everything else — discovery, analysis, scoring, enforcement — happens on your machine.',
  },
  {
    q: 'How is enforcement reversible?',
    a: 'Every config AgentGuard rewrites is checksummed first and the original entry is stored. `agentguard allow <id>` restores a blocked server exactly as it was. `agentguard init --revert` unwinds all changes. It never embeds your secrets or your real hook commands into a rewritten file.',
  },
  {
    q: 'Which agents are supported?',
    a: 'Claude Code, Claude Desktop, Cursor, Codex, Windsurf, Devin CLI, Antigravity, Gemini CLI, GitHub Copilot CLI, VS Code Copilot, OpenClaw, Amp, Kiro, Amazon Q, Continue.dev, Cline, Roo Code, Zed, JetBrains AI, opencode, Tabnine, Cody, Goose, Aider, OpenHands, and Crush — plus a generic fallback for anything with an mcpServers-shaped config.',
  },
  {
    q: 'How does the license work?',
    a: 'One key per developer, one year of updates and support. Activate on up to 3 machines. It checks in with Lemon Squeezy on activation and about once a month; if it cannot reach the internet it keeps working for 30 days before asking you to reconnect. No hard kill switch.',
  },
  {
    q: 'Do you offer team or volume pricing?',
    a: 'Yes. The product is identical; teams get consolidated billing, a shared trust policy file, and volume discounts above 5 seats. Email hello@agentguard.dev.',
  },
  {
    q: 'Is there a refund policy?',
    a: '14-day no-questions refund through Lemon Squeezy. If AgentGuard does not fit how your team works, you get your money back.',
  },
  {
    q: 'What about open source / evaluation?',
    a: 'The scanner core is source-available for audit — you can read exactly how every detection works. A time-limited evaluation key is available on request for security teams doing a formal review.',
  },
];
