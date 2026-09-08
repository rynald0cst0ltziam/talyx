# Talyx

Cross-agent security scanner for AI coding agent artifacts — MCP servers,
skills, plugins, and hooks.

Read first:
- [`STATUS.md`](STATUS.md) — what's actually built and tested right now, and what's next
- [`BUILD_PLAN.md`](BUILD_PLAN.md) — the full architecture and build plan
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — what this defends against, and what it explicitly doesn't (v1)

## Status

v0: discovery across 27 agents (Claude Code, Claude Desktop, Cursor,
Codex, Windsurf/Devin Desktop, Devin CLI, Antigravity, Gemini CLI,
GitHub Copilot CLI, VS Code Copilot, OpenClaw, Amp, Kiro, Amazon Q
Developer CLI, Continue.dev, Cline, Roo Code, Zed, JetBrains AI
Assistant, opencode, Tabnine, Cody, Goose, Aider, OpenHands, Crush,
Warp, plus a generic Unknown Agent Mode fallback), static
capability extraction (JS/TS/Python/Ruby/Perl/shell heuristics,
registry-resolved npm/PyPI packages), content analysis of skill markdown
and agent-instruction files (prompt-injection phrasing, hidden/invisible
Unicode, base64/hex-encoded payloads, data-exfiltration directives — see
STATUS.md #39), cross-artifact MCP tool-shadowing / server-impersonation
detection (STATUS.md #44), the risk engine (capped evidence +
reputation discount + context modifiers), and real enforcement —
MCP-server config-rewrite through `talyx-shim` (BUILD_PLAN.md §5a),
remote-entry removal, skill quarantine, drift detection, and hook
enforcement across five agents (Claude Code, Codex, Antigravity, Gemini
CLI, GitHub Copilot CLI, sharing one discovery/rewrite path — see
STATUS.md #26-#30; VS Code Copilot rides on Claude Code's and Copilot
CLI's own hook files for free) — are implemented and tested end-to-end,
most proven against live adversarial fixtures (real SSH-exfiltration
payloads genuinely blocked, benign hooks genuinely running), not just
unit tests. Agent coverage was directly benchmarked against the other
MCP/agent scanners in the space (see STATUS.md #31) rather than assumed
comprehensive. See STATUS.md for what's proven vs. still open, and
BUILD_PLAN.md §14 for the full picture.

No published release exists yet — the install methods below (`curl`/`irm`,
npm) are complete and tested as scripts, but will fail at the download step
until a real GitHub repo + release exists (see `.github/workflows/release.yml`
and each script's own TODO on the placeholder repo name). Build from source
in the meantime — see below.

## Install (once a release exists)

```bash
# macOS / Linux
curl -fsSL https://<install-url>/install.sh | sh
```

```powershell
# Windows
irm https://<install-url>/install.ps1 | iex
```

```bash
# npm (any platform)
npm install -g talyx
```

All three do the same thing: install `talyx` + `talyx-shim`, then
run `talyx init --project "$HOME"` automatically so every MCP server
config reachable from your home directory (which is where Claude Code's own
user-scope config lives) is immediately routed through enforcement. Pass
`--no-init` (shell installers) or set `TALYX_SKIP_INIT=1` (npm) to
install without activating.

Talyx is a paid tool (per developer, per year, via Lemon Squeezy).
`scan` and `status` run unlicensed for evaluation; `init` requires
`talyx activate <key>` first (or `TALYX_LICENSE_KEY` in CI). The
enforcement shim itself is never license-gated, so a lapsed license can't
break a running agent. See [`crates/talyx-cli/src/license.rs`](crates/talyx-cli/src/license.rs).
The marketing site lives in [`site/`](site/) (Astro, static).

None of the installers modify your shell profile or PATH automatically —
pass `--modify-path` (shell) or `-ModifyPath` (PowerShell) to opt into that;
otherwise they print the line to add yourself.

## Layout

```
crates/
  talyx-core       shared types: Artifact, Capability, Decision, RiskBand, ScoreBreakdown
  talyx-scanner     static capability extraction (JS/TS, Python, Ruby/Perl, shell scripts; package.json manifest); ast.rs: the authoritative capability + taint pass for JS/TS + Python + Ruby — tree-sitter AST, function-scoped interprocedural source-to-sink taint (secret read -> network sink, across helper returns and parameters); the regex rules are the parse-failure fallback; content.rs: prompt-injection / hidden-Unicode / encoded-payload / exfiltration-directive analysis of skill markdown and agent-instruction files; shadowing.rs: cross-artifact MCP tool-shadowing / server-impersonation / typosquat detection
  talyx-adapters    per-agent discovery: Claude Code (+ its plugin ecosystem: MCP servers, hooks, skills, agents, LSP servers, monitors from enabled plugins), Claude Desktop, Cursor, Codex, Windsurf/Devin Desktop, Devin CLI, Antigravity (+ plugins), Gemini CLI (+ extensions), GitHub Copilot CLI, VS Code (Copilot), OpenClaw, Amp, Kiro, Amazon Q Developer CLI, Continue.dev, Cline, Roo Code, Zed, JetBrains AI Assistant, opencode, Tabnine, Cody, Goose, Aider, OpenHands, Crush, Warp, Unknown Agent Mode
  talyx-risk        risk engine: capped evidence − reputation + context → decision
  talyx-registry    fetches + extracts npm/PyPI packages for a registry-resolved MCP server (--fetch-registry)
  talyx-store       local decision cache (~/.talyx/decisions.json)
  talyx-shim        the enforcement binary — allows/blocks a gated MCP server launch; with --proxy (init --live) runs the server through talyx-mcp-proxy
  talyx-mcp-proxy   the live stdio firewall (ADR 0001): newline-delimited JSON-RPC forwarding between agent and server for the session; inspects the initialize/tools/list/... handshake responses through talyx-content, blocks a poisoned or rug-pulled response per level (TALYX_PROXY_LEVEL), trust-on-first-use tool baseline, custom guardrails.yaml rules (block/redact/allow on any message), findings to ~/.talyx/sessions/
  talyx-content     instruction-text / prompt-injection / hidden-unicode / encoded-payload / exfil-directive detectors (tree-sitter-free leaf crate, shared by scanner + mcp-proxy)
  talyx-advisories  known-bad feed: matches an artifact's identity (npm/PyPI package + version range, publisher, remote host, repo owner, typosquat pattern) against publicly-disclosed malicious/vulnerable MCP artifacts; include_str!-bundled, overridable by ~/.talyx/advisories.json or $TALYX_ADVISORIES
  talyx-cli         `talyx` binary: scan, status, init, allow, why, guardrails, advisories, activate, license (license.rs: Lemon Squeezy activation, offline grace, CI key)
data/
  trust_seed.json        v0 hand-seeded trust graph (stand-in for BUILD_PLAN.md §7's pre-launch scan)
  advisories.json        BUILD_PLAN.md §7's "known-bad" half — hand-curated, fully-sourced disclosures of malicious/vulnerable MCP artifacts (talyx-advisories)
scripts/
  install.sh              curl-pipeable installer (macOS/Linux)
  install.ps1              irm-pipeable installer (Windows)
npm/
  package.json             npm-publishable wrapper (postinstall downloads the native binaries)
site/
  Astro static marketing site for talyx.dev — see site/README.md for deploy + pre-launch edits
.github/workflows/
  ci.yml                  clippy -D warnings + cargo test --workspace + site astro check/build, on every push/PR
  talyx-scan.yml          runs `talyx scan` on the repo, uploads SARIF to code scanning
  release.yml             builds + drafts a GitHub Release for a pushed v* tag
```

## Build & run

Requires a Rust toolchain (stable) and, on Windows, the MSVC linker (Visual
Studio "C++ build tools" workload, or `rustup target add
x86_64-pc-windows-gnu` + a MinGW toolchain as an alternative).

```bash
cargo build --workspace
cargo test --workspace

# Scan the current project (and user-level Claude Code config) at the
# Balanced protection preset:
cargo run -p talyx-cli -- scan --project .

# Add --fetch-registry to also fetch and statically scan the actual code
# behind an npx/uvx-launched MCP server (off by default -- makes a real
# outbound call to the npm/PyPI registry; see talyx-registry's crate
# doc comment):
cargo run -p talyx-cli -- scan --project . --fetch-registry

# Short status summary:
cargo run -p talyx-cli -- status --project .

# Scan, cache decisions, AND route MCP servers through the enforcement
# shim (only rewrites configs inside --project unless you pass
# --include-user-config — see talyx-cli/src/init.rs):
cargo run -p talyx-cli -- init --project .

# Add --live to ALSO keep the shim between the agent and each approved
# server for the session and inspect its JSON-RPC traffic (ADR 0001):
# handshake-response scanning, trust-on-first-use tool baseline / rug-pull
# detection, tool-result scanning. Opt-in; fails open to the static gate.
# TALYX_PROXY_LEVEL=quiet|balanced|strict, TALYX_NO_PROXY=1 to
# disable per launch. Findings -> ~/.talyx/sessions/*.jsonl.
cargo run -p talyx-cli -- init --project . --live

# Approve something flagged ASK/BLOCK, or see the full reasoning behind
# a cached decision (ids are printed by `scan`/`init`):
cargo run -p talyx-cli -- allow "<artifact-id>"
cargo run -p talyx-cli -- why "<artifact-id>"

# Inspect the bundled known-bad advisory feed, or check one package:
cargo run -p talyx-cli -- advisories list
cargo run -p talyx-cli -- advisories check postmark-mcp --version 1.0.17
```

## CI / pull-request gating (SARIF)

`talyx scan` can emit a [SARIF 2.1.0](https://sarifweb.azurewebsites.net)
log for GitHub code scanning, Azure DevOps, or any CI security dashboard —
no Talyx-hosted service involved:

```bash
# SARIF to stdout:
talyx scan --project . --format sarif

# keep the human-readable table on stdout AND write a file for CI to upload:
talyx scan --project . --sarif-file talyx.sarif

# make the job itself fail: exit 2 on any BLOCK/QUARANTINE, 1 on any ASK:
talyx scan --project . --exit-code
```

A ready-to-use workflow that builds Talyx, scans the repo, and uploads
the SARIF as PR annotations is at
[`.github/workflows/talyx-scan.yml`](.github/workflows/talyx-scan.yml).
Each finding carries a repo-relative file location (the exact `SKILL.md`
line for a poisoned skill, the config entry for a risky MCP server) and a
stable fingerprint so results dedupe across runs.

## Design rules this codebase follows

From `BUILD_PLAN.md` / the project's coding principles:
- Adapters only discover; they never decide or enforce.
- Every risk score carries its full breakdown (`ScoreBreakdown`) — never
  surface a bare number without the reasons behind it.
- A capability finding always records its `EvidenceBasis` (Declared /
  Inferred / Inherited) and, for Inferred findings, the exact pattern that
  matched — no finding is asserted without evidence attached.
- `verified` on a publisher is only ever set by an explicit verification
  step, never inferred from a name or package scope.

## License

Talyx is **source-available under a commercial license** — see
[`LICENSE`](LICENSE). You may read, compile, run, and security-audit the
source, and run the read-only commands (`scan`, `status`, `why`,
`guardrails`, `advisories`) for any purpose including commercially;
enforcement (`init` / the shim) needs a paid per-developer license, and
redistribution / resale / hosting is not granted. Two placeholders to fill
before publishing: the owning entity's legal name and the governing-law
state — both marked in the file.

Third-party open-source components are listed with their full license texts
in [`THIRD-PARTY-LICENSES.txt`](THIRD-PARTY-LICENSES.txt). None are
GPL/LGPL/AGPL/SSPL; the only weak-copyleft dependency is one MPL-2.0 crate
used unmodified. Regenerate the notices after any dependency change:

```bash
cargo about generate about.hbs -o THIRD-PARTY-LICENSES.txt
```
