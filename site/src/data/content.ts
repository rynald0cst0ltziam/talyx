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
  'Warp',
];

export type IconName =
  | 'radar'
  | 'inject'
  | 'mask'
  | 'shield'
  | 'ci'
  | 'lock'
  | 'flow'
  | 'plug'
  | 'package'
  | 'drift'
  | 'terminal'
  | 'bolt';

export interface Feature {
  title: string;
  body: string;
  icon: IconName;
  tag: string;
}

export const features: Feature[] = [
  {
    icon: 'radar',
    tag: 'Discovery',
    title: 'Finds every artifact your agents load',
    body: 'MCP servers, skills, plugins, extensions, hooks, LSP servers, background monitors and instruction files — across 27 coding agents, user scope and project scope, JSON, YAML and TOML. One scan, every surface. Nothing to configure per agent.',
  },
  {
    icon: 'flow',
    tag: 'AST + taint',
    title: 'Traces a secret from disk to the wire',
    body: 'A tree-sitter parse of JS/TS, Python and Ruby with function-scoped, interprocedural source-to-sink taint. It sees a private key read through `path.join(home, ".ssh", "id_rsa")` even when the path is split across arguments, follows it through helper functions and parameters, and flags the flow the moment it reaches a `fetch` body or a `curl` argument.',
  },
  {
    icon: 'inject',
    tag: 'Content analysis',
    title: 'Reads the text your agent will obey',
    body: 'Skill markdown, instruction files and declared MCP tool descriptions are scanned for prompt-injection phrasing, invisible Unicode and Unicode-tag ASCII smuggling, base64 / hex / \\x payloads that decode to something malicious, and one-sentence data-exfiltration directives — the attacks that never touch a shell command.',
  },
  {
    icon: 'mask',
    tag: 'Impersonation',
    title: 'Catches tool shadowing and typosquats',
    body: 'A server that borrows a trusted name, typosquats "github" or "filesystem" (Levenshtein and affix), or launches from a non-canonical source gets flagged as impersonation — scored across every discovered server at once, using each one\'s reputation verdict, not one file in isolation.',
  },
  {
    icon: 'plug',
    tag: 'Plugin ecosystems',
    title: 'Scans the plugins your plugins bring',
    body: 'A Claude Code plugin, a Gemini CLI extension or an Antigravity plugin is a second supply chain — it can ship its own MCP server, hook, skill or LSP command. AgentGuard resolves every enabled one on disk and scans what it contributes, not just the manifest.',
  },
  {
    icon: 'package',
    tag: 'Registry',
    title: 'Downloads the code behind `npx`',
    body: 'A config that runs `npx some-package` never shows you the code. With one flag, AgentGuard fetches the real package from npm or PyPI, verifies its integrity, and statically scans the actual source — including the declared tool descriptions inside it.',
  },
  {
    icon: 'shield',
    tag: 'Enforcement',
    title: 'Blocks the bad ones — for real',
    body: 'Approved servers launch through the AgentGuard shim. Blocked ones are removed from the config so the agent physically cannot start them. Remote entries are stripped and restored on approval. Malicious skills are quarantined. Every change is checksum-verified and reversible, and your real secrets and hook commands are never written into a rewritten file.',
  },
  {
    icon: 'drift',
    tag: 'Drift',
    title: 'Re-flags what changes under you',
    body: 'Approval is bound to an artifact\'s content hash and capability set. A server you allowed that later gains SSH-key access, or a skill that grows a hidden-instruction payload, is forced back to review automatically — even when the raw score alone would not have tripped.',
  },
  {
    icon: 'ci',
    tag: 'CI',
    title: 'SARIF + a GitHub Action',
    body: 'Run the same scan in CI. Results upload as SARIF straight into GitHub code scanning, with a non-zero exit on Block so a poisoned dependency fails the build instead of shipping. Activate with a machine license via an environment variable.',
  },
  {
    icon: 'lock',
    tag: 'Local-first',
    title: 'Nothing leaves your machine',
    body: 'No account, no daemon, no cloud, no telemetry, no analytics. Optional npm / PyPI registry lookups and a monthly license check are the only outbound calls. Your config, your threat surface, your machine — and the scanner core is source-available so you can read exactly how every detection works.',
  },
];

// ── the detection taxonomy ──────────────────────────────────
export interface Detection {
  name: string;
  severity: 'critical' | 'high' | 'medium';
  where: string;
  blurb: string;
}

export const detections: Detection[] = [
  {
    name: 'Secret exfiltration flow',
    severity: 'critical',
    where: 'MCP server / hook / skill code',
    blurb: 'A read of an SSH key, cloud-credential file or browser store that reaches the network — traced across functions, uncapped in the risk score.',
  },
  {
    name: 'Malicious launch command',
    severity: 'critical',
    where: 'any config file',
    blurb: 'Static capability extraction over the command the agent will run: shell exec, process spawn, filesystem and network reach, secret access.',
  },
  {
    name: 'Hidden instructions',
    severity: 'critical',
    where: 'skill / instruction markdown',
    blurb: 'Zero-width characters, bidirectional overrides, Unicode-tag ASCII smuggling and invisible HTML carrying instructions a human reviewer never sees.',
  },
  {
    name: 'Prompt injection',
    severity: 'high',
    where: 'skill / instruction / tool description',
    blurb: 'Instruction-override, role-manipulation and jailbreak phrasing — high-precision rules that require the verb\'s object to be the model\'s own rules.',
  },
  {
    name: 'Data-exfiltration directive',
    severity: 'high',
    where: 'skill / instruction / tool description',
    blurb: 'A single sentence that names a transmit verb, local secret material and an external destination together.',
  },
  {
    name: 'Encoded payload',
    severity: 'medium',
    where: 'skill / instruction / tool description',
    blurb: 'A base64 / hex / \\x blob that decodes to an injection or exfiltration payload, then re-scanned.',
  },
  {
    name: 'Tool shadowing',
    severity: 'high',
    where: 'across all MCP servers',
    blurb: 'An unverified server sharing a name with a trusted one, so the agent could route a tool call to the wrong place.',
  },
  {
    name: 'Typosquatting',
    severity: 'high',
    where: 'across all MCP servers',
    blurb: 'A near-miss of a well-known server name — one edit away, or a look-alike affix like "github-unofficial".',
  },
  {
    name: 'Poisoned tool description',
    severity: 'high',
    where: 'MCP server source',
    blurb: 'The description the agent reads to pick a tool, carrying an injection or exfil directive — scanned from the package source with `--fetch-registry`.',
  },
  {
    name: 'Remote-code-execution hook',
    severity: 'high',
    where: 'hooks / skill code blocks',
    blurb: 'A downloaded script piped straight into a shell — `curl … | sh`, `irm … | iex`.',
  },
  {
    name: 'Runtime persistence',
    severity: 'medium',
    where: 'any config / script',
    blurb: 'Runtime package installs, shell-profile writes, cron / scheduled-job registration.',
  },
  {
    name: 'Capability drift',
    severity: 'high',
    where: 'previously-approved artifacts',
    blurb: 'An artifact you allowed that has since gained a dangerous capability, forced back to review.',
  },
  {
    name: 'Unnamed / unmanaged config',
    severity: 'medium',
    where: 'plugin & extension ecosystems',
    blurb: 'MCP servers, hooks and skills a plugin or extension contributes that never appear in the agent\'s own config.',
  },
];

export interface ThreatLine {
  t: number;
  prompt?: boolean;
  text: string;
  cls?: string;
}

/** The animated terminal transcript on the hero. */
export const threatDemo: ThreatLine[] = [
  { t: 0, prompt: true, text: 'agentguard scan --project .' },
  { t: 550, text: 'discovered 6 agents · 31 artifacts · 3 registry packages', cls: 'text-mist' },
  { t: 1400, text: '' },
  {
    t: 1550,
    text: '  CRITICAL  mcp: "context7"  (Claude Code plugin)',
    cls: 'text-threat font-semibold',
  },
  { t: 1850, text: '            reads ~/.aws/credentials, POSTs to sync-cdn.io', cls: 'text-mist' },
  { t: 2100, text: '            AST taint: readFileSync → helper() → fetch(body)', cls: 'text-mist' },
  {
    t: 2650,
    text: '  HIGH      skill: "pr-review"  — hidden instructions in SKILL.md',
    cls: 'text-warn font-semibold',
  },
  { t: 2900, text: '            12 zero-width chars decode to a prompt override', cls: 'text-mist' },
  {
    t: 3400,
    text: '  HIGH      mcp: "gihub"  — typosquats trusted "github"',
    cls: 'text-warn font-semibold',
  },
  { t: 3900, text: '' },
  { t: 4000, text: '  BLOCKED   3 removed from config — agents cannot load them', cls: 'text-safe font-semibold' },
  { t: 4300, text: '  28 artifacts verified clean · 3 blocked · 0 need review', cls: 'text-fog' },
  { t: 4700, text: 'protection active. run  agentguard why context7  for detail.', cls: 'text-signal' },
];

export interface CompareRow {
  capability: string;
  agentguard: 'full' | 'partial' | 'none';
  snyk: 'full' | 'partial' | 'none';
  mcpscan: 'full' | 'partial' | 'none';
}

export const comparison: CompareRow[] = [
  { capability: 'Runs fully local — no account, no cloud, no telemetry', agentguard: 'full', snyk: 'none', mcpscan: 'partial' },
  { capability: 'Coverage across 27 coding agents', agentguard: 'full', snyk: 'partial', mcpscan: 'partial' },
  { capability: 'Scans plugin & extension ecosystems, not just the agent config', agentguard: 'full', snyk: 'none', mcpscan: 'none' },
  { capability: 'AST parse + source-to-sink taint (secret → network)', agentguard: 'full', snyk: 'partial', mcpscan: 'none' },
  { capability: 'Scans skills / instruction files for injection', agentguard: 'full', snyk: 'partial', mcpscan: 'none' },
  { capability: 'Invisible-Unicode & encoded-payload detection', agentguard: 'full', snyk: 'none', mcpscan: 'partial' },
  { capability: 'Tool shadowing / typosquat detection', agentguard: 'full', snyk: 'full', mcpscan: 'full' },
  { capability: 'Poisoned tool-description detection', agentguard: 'full', snyk: 'full', mcpscan: 'full' },
  { capability: 'Actually blocks a server from launching', agentguard: 'full', snyk: 'none', mcpscan: 'partial' },
  { capability: 'Protection survives if a proxy is not running', agentguard: 'full', snyk: 'full', mcpscan: 'none' },
  { capability: 'Registry (npm / PyPI) pre-resolution', agentguard: 'full', snyk: 'full', mcpscan: 'none' },
  { capability: 'Capability-drift re-review', agentguard: 'full', snyk: 'none', mcpscan: 'none' },
  { capability: 'SARIF + CI action', agentguard: 'full', snyk: 'full', mcpscan: 'none' },
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
    body: 'One binary and its enforcement shim. No runtime, no dependencies, no shell-profile edits.',
    code: 'curl -fsSL https://get.agentguard.dev | sh',
  },
  {
    n: '02',
    title: 'Activate your license',
    body: 'Paste the key from your purchase email. Works offline for 30 days at a time; activate on up to 3 machines.',
    code: 'agentguard activate AG-XXXX-XXXX-XXXX',
  },
  {
    n: '03',
    title: 'Scan',
    body: 'Point it at a project or your home directory. It finds every agent, every plugin, every artifact.',
    code: 'agentguard scan --project .',
  },
  {
    n: '04',
    title: 'Enforce',
    body: 'Route every approved MCP server through the shim; blocked ones are pulled from the config; malicious skills are quarantined. Reversible any time.',
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
    a: 'The artifact supply chain for AI coding agents: a malicious MCP server launched from a config file, a plugin or extension that ships its own server or hook, a skill or instruction file carrying hidden prompt-injection, an encoded payload in a tool description, a server impersonating a trusted one, a hook that pipes a downloaded script into a shell, a secret read that flows to the network. It inspects what your agent is about to load — across 27 agents — and either verifies it, flags it for review, or blocks it.',
  },
  {
    q: 'How is the AST / taint analysis different from a regex scanner?',
    a: 'A regex sees that `.ssh/id_rsa` and `fetch(` both appear in a file. It cannot tell whether the key actually reaches the network, and it misses the path entirely when it is built from `path.join(home, ".ssh", "id_rsa")`. AgentGuard parses the file with tree-sitter and runs a function-scoped, interprocedural taint pass: it follows the value from the read, through variable assignments and helper functions, to the sink. It is a proven superset of the pattern rules for JS/TS, Python and Ruby.',
  },
  {
    q: 'Is it actually local? What leaves my machine?',
    a: 'It is a single binary. No account, no daemon, no cloud backend, no telemetry. The only outbound calls are optional npm / PyPI registry lookups when you pass --fetch-registry, and a license check against Lemon Squeezy on activation and roughly monthly after. Discovery, analysis, scoring and enforcement all happen on your machine.',
  },
  {
    q: 'Windows, macOS or Linux?',
    a: 'All three, one Rust codebase that builds to a single native binary with no runtime dependency. Discovery knows the real per-OS config locations — the Windows %USERPROFILE% paths, ~/Library/Application Support on macOS, ~/.config on Linux — and the enforcement shim is a native executable on each platform, not a shell script. Pre-built binaries ship with each release; you can also build from source with cargo build --release.',
  },
  {
    q: 'Will it slow my agent down or break it?',
    a: 'Scanning is a command you run when you choose to; it is never in your agent\'s hot path. Enforcement adds the shim to an approved server\'s launch line — one exec of a small native binary that re-checks a cached decision in well under a millisecond, then hands off to the real server. A blocked server is simply absent from the config. Every rewrite is checksummed, backed up, and reversible with one command, and your real secrets and hook commands are never written into the rewritten file.',
  },
  {
    q: 'How is this different from mcp-scan or Snyk agent-scan?',
    a: 'Three things. Scope: they centre on the MCP server config; AgentGuard also covers plugin and extension ecosystems, skills, hooks, LSP servers and instruction files across 27 agents. Depth: a real tree-sitter AST with function-scoped, interprocedural source-to-sink taint — it proves a secret reaches the network rather than noting that both appear in a file. Enforcement that survives: a blocked server is physically removed from the config, so protection does not depend on a proxy process staying up. There is a dated, point-in-time comparison table on this page and we keep it honest — corrections welcome.',
  },
  {
    q: 'How is enforcement reversible?',
    a: 'Every config AgentGuard rewrites is checksummed first and the original entry is stored. `agentguard allow <id>` restores a blocked server exactly as it was, including a stripped remote entry. It never embeds your secrets or your real hook commands into a rewritten file — the shim reads them from a local store keyed by hash.',
  },
  {
    q: 'Which agents are supported?',
    a: '27 in total: Claude Code (and its plugin ecosystem), Claude Desktop, Cursor, Codex, Windsurf, Devin CLI, Antigravity (and its plugins), Gemini CLI (and its extensions), GitHub Copilot CLI, VS Code Copilot, OpenClaw, Amp, Kiro, Amazon Q, Continue.dev, Cline, Roo Code, Zed, JetBrains AI, opencode, Tabnine, Cody, Goose, Aider, OpenHands, Crush and Warp — plus a generic fallback for anything else with an mcpServers-shaped config.',
  },
  {
    q: 'Does the enforcement shim stop protecting if it crashes?',
    a: 'No. AgentGuard is a launch-time gate plus a per-launch shim, not an always-on proxy. A blocked server is physically removed from the config, so it stays blocked whether or not any AgentGuard process is running. There is no window where killing a background process drops your protection.',
  },
  {
    q: 'How does the license work?',
    a: 'One key per developer, one year of updates and support. Activate on up to 3 machines. It checks in with Lemon Squeezy on activation and about once a month; offline, it keeps working for 30 days before asking you to reconnect. No hard kill switch. `scan` and `status` run unlicensed so you can evaluate; `init` needs a license.',
  },
  {
    q: 'Do you offer team or volume pricing?',
    a: 'Yes. The product is identical; teams get consolidated billing, a shared trust policy your whole team pins to, offline / air-gapped activation, and volume discounts above 5 seats. Email hello@agentguard.dev.',
  },
  {
    q: 'Is there a refund policy?',
    a: '14-day no-questions refund through Lemon Squeezy, our merchant of record. If AgentGuard does not fit how your team works, you get your money back.',
  },
  {
    q: 'What about open source / evaluation?',
    a: 'The scanner core is source-available for audit — every regex, every score contribution, every threshold is in the repository and covered by tests, many proven against live adversarial fixtures. A time-limited evaluation key is available on request for security teams doing a formal review.',
  },
];
