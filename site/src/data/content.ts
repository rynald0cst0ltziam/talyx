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
  | 'list'
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
    body: 'A Claude Code plugin, a Gemini CLI extension or an Antigravity plugin is a second supply chain — it can ship its own MCP server, hook, skill or LSP command. Talyx resolves every enabled one on disk and scans what it contributes, not just the manifest.',
  },
  {
    icon: 'package',
    tag: 'Registry',
    title: 'Downloads the code behind `npx`',
    body: 'A config that runs `npx some-package` never shows you the code. With one flag, Talyx fetches the real package from npm or PyPI, verifies its integrity, and statically scans the actual source — including the declared tool descriptions inside it.',
  },
  {
    icon: 'list',
    tag: 'Advisory feed',
    title: 'Knows the packages that are already known bad',
    body: 'Behaviour analysis catches the unknown. The advisory feed catches the known: a small, hand-curated, fully-sourced list of MCP artifacts confirmed malicious or vulnerable in the wild — `postmark-mcp` and its publisher, `mcp-remote` before the CVE-2025-6514 fix, the public tool-poisoning PoCs, typosquat name patterns. Matched by identity — package + version range, publisher, host, repo owner — not heuristics. Bundled in the binary so it works offline, overridable by a local file. A confirmed-malicious match forces a block and cancels any reputation discount; a bounded advisory forces review.',
  },
  {
    icon: 'shield',
    tag: 'Enforcement',
    title: 'Blocks the bad ones — for real',
    body: 'Approved servers launch through the Talyx shim. Blocked ones are removed from the config so the agent physically cannot start them. Remote entries are stripped and restored on approval. Malicious skills are quarantined. Every change is checksum-verified and reversible, and your real secrets and hook commands are never written into a rewritten file.',
  },
  {
    icon: 'drift',
    tag: 'Drift',
    title: 'Re-flags what changes under you',
    body: 'Approval is bound to an artifact\'s content hash and capability set. A server you allowed that later gains SSH-key access, or a skill that grows a hidden-instruction payload, is forced back to review automatically — even when the raw score alone would not have tripped.',
  },
  {
    icon: 'flow',
    tag: 'Live proxy',
    title: 'Watches the session, not just the launch',
    body: 'With `init --live` the shim stays between the agent and each server for the whole session. It scans the `tools/list` handshake, pins the tool set on first use so a mid-session rug pull is caught, scans tool results, and — the part no fixed ruleset can match — runs your own guardrails: a local YAML file whose `block` / `redact` / `allow` rules fire on any JSON-RPC message you can describe with a path condition. It fails open to the launch-time gate, so it never leaves you worse off.',
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
  {
    name: 'Mid-session rug pull',
    severity: 'high',
    where: 'live MCP session (init --live)',
    blurb: 'A server that served a clean tool list at approval, then swaps or adds a tool definition mid-session — caught by the live proxy against a trust-on-first-use baseline.',
  },
  {
    name: 'Known-malicious artifact',
    severity: 'critical',
    where: 'any MCP server / package',
    blurb: 'A package, publisher, host or repo owner named in the bundled advisory feed as confirmed malicious or vulnerable in the wild — matched by identity and version range, forcing a block or a review regardless of behaviour score.',
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
  { t: 0, prompt: true, text: 'talyx scan --project .' },
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
  { t: 4700, text: 'protection active. run  talyx why context7  for detail.', cls: 'text-signal' },
];

/**
 * First-person capability checklist. Every row describes Talyx's own
 * implementation and is substantiated by the repository — no claims about
 * any other product.
 */
export interface Capability {
  capability: string;
  how: string;
}

export const capabilities: Capability[] = [
  {
    capability: 'Runs fully local',
    how: 'One binary. No account, no daemon, no cloud backend, no telemetry. The only outbound calls are optional npm / PyPI lookups and a periodic license check.',
  },
  {
    capability: 'Covers 27 coding agents in one scan',
    how: 'MCP servers, skills, plugins, extensions, hooks, LSP servers, background monitors and instruction files — user scope and project scope, JSON / YAML / TOML.',
  },
  {
    capability: 'Scans plugin & extension ecosystems',
    how: 'Every enabled Claude Code plugin, Gemini CLI extension and Antigravity plugin is resolved on disk and its bundled MCP servers, hooks, skills and LSP commands are scanned — not just the manifest.',
  },
  {
    capability: 'AST parse + source-to-sink taint',
    how: 'A tree-sitter parse of JS/TS, Python and Ruby with function-scoped, interprocedural taint that follows a secret from the read, through helpers and parameters, to a network sink.',
  },
  {
    capability: 'Reads the text your agent will obey',
    how: 'Skill markdown, instruction files and declared tool descriptions are scanned for prompt-injection phrasing, invisible Unicode, ASCII smuggling, encoded payloads and one-sentence exfiltration directives.',
  },
  {
    capability: 'Catches impersonation across all servers',
    how: 'Tool shadowing, name typosquatting (edit-distance and affix) and non-canonical launch sources — scored across every discovered server at once using each one’s reputation verdict.',
  },
  {
    capability: 'Known-bad advisory feed',
    how: 'Publicly-disclosed malicious or vulnerable MCP artifacts matched by identity — package + version range, publisher, host, repo owner, look-alike name pattern. Bundled, offline, overridable.',
  },
  {
    capability: 'Blocks a server from launching — for real',
    how: 'Approved servers run through the Talyx shim; blocked ones are removed from the config so the agent physically cannot start them; malicious skills are quarantined. Every change is checksum-verified and reversible.',
  },
  {
    capability: 'Live JSON-RPC inspection',
    how: 'With init --live the shim stays between agent and server for the session: handshake scanning, a trust-on-first-use tool baseline that catches a mid-session rug pull, tool-result scanning.',
  },
  {
    capability: 'Custom local guardrail rules',
    how: 'A local YAML file whose block / redact / allow rules fire on any JSON-RPC message you can describe with a path condition — on top of the built-in detectors.',
  },
  {
    capability: 'Protection survives the proxy not running',
    how: 'The live proxy fails open to the launch-time gate. A blocked server is absent from the config whether or not any Talyx process is alive.',
  },
  {
    capability: 'Registry pre-resolution',
    how: 'With one flag, the real package behind npx / uvx is fetched from npm or PyPI, integrity-checked, and statically scanned — including the tool descriptions inside it.',
  },
  {
    capability: 'Capability-drift re-review',
    how: 'Approval is bound to an artifact’s content hash and capability set. One that later gains a dangerous capability is forced back to review automatically.',
  },
  {
    capability: 'SARIF + a GitHub Action',
    how: 'The same scan runs in CI, uploads as SARIF into GitHub code scanning, and exits non-zero on a Block so a poisoned dependency fails the build.',
  },
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
    code: 'curl -fsSL https://get.talyx.dev | sh',
  },
  {
    n: '02',
    title: 'Activate your license',
    body: 'Paste the key from your purchase email. Works offline for 30 days at a time; activate on up to 3 machines.',
    code: 'talyx activate AG-XXXX-XXXX-XXXX',
  },
  {
    n: '03',
    title: 'Scan',
    body: 'Point it at a project or your home directory. It finds every agent, every plugin, every artifact.',
    code: 'talyx scan --project .',
  },
  {
    n: '04',
    title: 'Enforce',
    body: 'Route every approved MCP server through the shim; blocked ones are pulled from the config; malicious skills are quarantined. Reversible any time.',
    code: 'talyx init --project ~',
  },
];

export interface Faq {
  q: string;
  a: string;
}

export const faqs: Faq[] = [
  {
    q: 'What exactly does Talyx protect against?',
    a: 'The artifact supply chain for AI coding agents: a malicious MCP server launched from a config file, a plugin or extension that ships its own server or hook, a skill or instruction file carrying hidden prompt-injection, an encoded payload in a tool description, a server impersonating a trusted one, a hook that pipes a downloaded script into a shell, a secret read that flows to the network. It inspects what your agent is about to load — across 27 agents — and either verifies it, flags it for review, or blocks it.',
  },
  {
    q: 'How is the AST / taint analysis different from a regex scanner?',
    a: 'A regex sees that `.ssh/id_rsa` and `fetch(` both appear in a file. It cannot tell whether the key actually reaches the network, and it misses the path entirely when it is built from `path.join(home, ".ssh", "id_rsa")`. Talyx parses the file with tree-sitter and runs a function-scoped, interprocedural taint pass: it follows the value from the read, through variable assignments and helper functions, to the sink. It is a proven superset of the pattern rules for JS/TS, Python and Ruby.',
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
    q: 'How is this different from other MCP scanners?',
    a: 'Three things define Talyx. Scope: it covers plugin and extension ecosystems, skills, hooks, LSP servers and instruction files across 27 agents — not just the MCP server config. Depth: a real tree-sitter AST with function-scoped, interprocedural source-to-sink taint — it proves a secret reaches the network rather than noting that both appear in a file. Enforcement that survives: a blocked server is physically removed from the config, and the optional live proxy (init --live) fails open to that static gate, so your protection never silently vanishes when a process is not running. Compare it against anything you like — the full capability list is on this page and every line is in the open repository.',
  },
  {
    q: 'What does `talyx init --live` do?',
    a: 'It keeps the Talyx shim between your agent and each approved MCP server for the whole session, inspecting the JSON-RPC traffic on top of the launch-time scan. It scans the initialize / tools/list / resources/list / prompts/list handshake responses for injection and exfil directives, records a trust-on-first-use snapshot of each server\'s tool list and flags a mid-session rug pull (a tool swapped or added after you approved it), and scans tool-call results for a payload smuggled back as "file contents". Per level (TALYX_PROXY_LEVEL: quiet / balanced / strict) it logs, replaces a poisoned response with a JSON-RPC error, or ends the session. It is opt-in while it builds real-session mileage.',
  },
  {
    q: 'Won\'t the live proxy break my agent session?',
    a: 'It is designed not to. It is opt-in (plain init never enables it), it is the same process your agent already spawns for the server (no daemon), and it fails open: if the proxy ever hits an internal error it falls back to exactly the launch-time protection you would have without --live. TALYX_NO_PROXY=1 is a hard per-launch kill switch, and running plain talyx init again downgrades the config. Large tool results are forwarded before inspection, so bulk traffic gets no added latency. We will not flip it on by default until it has real multi-hour session mileage.',
  },
  {
    q: 'Does the live proxy send my traffic anywhere?',
    a: 'No. Every message is inspected locally by the shim. Findings are appended to ~/.talyx/sessions/<date>-<pid>.jsonl and summarised by `talyx status`; nothing about your traffic, your code or what was found leaves the machine. TALYX_PROXY_LOG can capture a full local transcript for debugging.',
  },
  {
    q: 'Can I write my own rules for the proxy?',
    a: 'Yes — guardrails. A local YAML file (~/.talyx/guardrails.yaml, or per-project, or $TALYX_GUARDRAILS) whose rules the proxy runs on every JSON-RPC message on top of the built-in detectors. A rule matches by direction, method and path conditions (contains / regex / glob / equals / exists / gt-lt, with wildcards in the JSON path) and does one of: allow (forward, skip the built-in scan), warn (log), redact (strip matched strings), or block (the message never reaches its peer — a blocked tools/call gets a JSON-RPC error back and the server never sees it). Validate with `talyx guardrails check`; start from `talyx guardrails example`.',
  },
  {
    q: 'How does the advisory feed differ from the behaviour analysis?',
    a: 'The AST, taint and content analysis catch code and text you have never seen before, on behaviour alone. The advisory feed catches artifacts the security community has already disclosed — matched by identity, not behaviour: a package name and affected version range, an npm publisher, a remote host, a source-repo owner, or a typosquat name pattern. It ships as a small hand-curated file inside the binary (every entry carries a public reference URL), works fully offline, and can be overridden by ~/.talyx/advisories.json or $TALYX_ADVISORIES. A confirmed-malicious match adds a decisive penalty, suppresses any reputation discount (a trusted publisher in the known-bad list means the account is compromised) and forces a block; a bounded advisory — a CVE fixed in a later version, say — forces a review. Inspect it with `talyx advisories list` or check one package with `talyx advisories check <name> --version <v>`.',
  },
  {
    q: 'How is enforcement reversible?',
    a: 'Every config Talyx rewrites is checksummed first and the original entry is stored. `talyx allow <id>` restores a blocked server exactly as it was, including a stripped remote entry. It never embeds your secrets or your real hook commands into a rewritten file — the shim reads them from a local store keyed by hash.',
  },
  {
    q: 'Which agents are supported?',
    a: '27 in total: Claude Code (and its plugin ecosystem), Claude Desktop, Cursor, Codex, Windsurf, Devin CLI, Antigravity (and its plugins), Gemini CLI (and its extensions), GitHub Copilot CLI, VS Code Copilot, OpenClaw, Amp, Kiro, Amazon Q, Continue.dev, Cline, Roo Code, Zed, JetBrains AI, opencode, Tabnine, Cody, Goose, Aider, OpenHands, Crush and Warp — plus a generic fallback for anything else with an mcpServers-shaped config.',
  },
  {
    q: 'Does the enforcement shim stop protecting if it crashes?',
    a: 'No. Talyx is a launch-time gate plus a per-launch shim, not an always-on proxy. A blocked server is physically removed from the config, so it stays blocked whether or not any Talyx process is running. There is no window where killing a background process drops your protection.',
  },
  {
    q: 'How does the license work?',
    a: 'One key per developer, one year of updates and support. Activate on up to 3 machines. It checks in with Lemon Squeezy on activation and about once a month; offline, it keeps working for 30 days before asking you to reconnect. No hard kill switch. `scan` and `status` run unlicensed so you can evaluate; `init` needs a license.',
  },
  {
    q: 'Do you offer team or volume pricing?',
    a: 'Yes. The product is identical; teams get consolidated billing, a shared trust policy your whole team pins to, offline / air-gapped activation, and volume discounts above 5 seats. Email hello@talyx.dev.',
  },
  {
    q: 'Is there a refund policy?',
    a: '14-day no-questions refund through Lemon Squeezy, our merchant of record. If Talyx does not fit how your team works, you get your money back.',
  },
  {
    q: 'Is it open source? Can I evaluate it first?',
    a: 'The source is available for review, not open source in the OSI sense — it ships under a proprietary source-available license (LICENSE in the repo) that lets you read, compile, run and security-audit it freely, and run the scanner without a key, while enforcement and redistribution need a license. Every regex, score contribution and threshold is in the repository and covered by tests, many proven against live adversarial fixtures. A time-limited evaluation key is available on request for security teams doing a formal review.',
  },
];
