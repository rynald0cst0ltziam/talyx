# AgentGuard

Cross-agent security scanner for AI coding agent artifacts — MCP servers,
skills, plugins, and hooks.

Read first:
- [`BUILD_PLAN.md`](BUILD_PLAN.md) — the full architecture and build plan
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — what this defends against, and what it explicitly doesn't (v1)

## Status

v0: discovery (Claude Code adapter + generic Unknown Agent Mode), static
capability extraction (JS/TS + Python heuristics), the risk engine (capped
evidence + reputation discount + context modifiers), and real config-time
**enforcement** (BUILD_PLAN.md §5a — `agentguard init` routes MCP servers
through `agentguard-shim`, which genuinely blocks or allows them) are
implemented and tested end-to-end. Not yet built: hook/skill enforcement,
Cursor/Codex adapters, drift detection, the daemon, cloud sync. See
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
npm install -g agentguard
```

All three do the same thing: install `agentguard` + `agentguard-shim`, then
run `agentguard init --project "$HOME"` automatically so every MCP server
config reachable from your home directory (which is where Claude Code's own
user-scope config lives) is immediately routed through enforcement — no
separate activation step. Pass `--no-init` (shell installers) or set
`AGENTGUARD_SKIP_INIT=1` (npm) to install without activating.

None of the installers modify your shell profile or PATH automatically —
pass `--modify-path` (shell) or `-ModifyPath` (PowerShell) to opt into that;
otherwise they print the line to add yourself.

## Layout

```
crates/
  agentguard-core       shared types: Artifact, Capability, Decision, RiskBand, ScoreBreakdown
  agentguard-scanner     static capability extraction (JS/TS, Python; package.json manifest)
  agentguard-adapters    per-agent discovery: Claude Code, Unknown Agent Mode
  agentguard-risk        risk engine: capped evidence − reputation + context → decision
  agentguard-store       local decision cache (~/.agentguard/decisions.json)
  agentguard-shim        the enforcement binary — allows/blocks a gated MCP server launch
  agentguard-cli         `agentguard` binary: scan, status, init, allow, why
data/
  trust_seed.json        v0 hand-seeded trust graph (stand-in for BUILD_PLAN.md §7's pre-launch scan)
scripts/
  install.sh              curl-pipeable installer (macOS/Linux)
  install.ps1              irm-pipeable installer (Windows)
npm/
  package.json             npm-publishable wrapper (postinstall downloads the native binaries)
.github/workflows/
  release.yml              builds + drafts a GitHub Release for a pushed v* tag
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
cargo run -p agentguard-cli -- scan --project .

# Short status summary:
cargo run -p agentguard-cli -- status --project .

# Scan, cache decisions, AND route MCP servers through the enforcement
# shim (only rewrites configs inside --project unless you pass
# --include-user-config — see agentguard-cli/src/init.rs):
cargo run -p agentguard-cli -- init --project .

# Approve something flagged ASK/BLOCK, or see the full reasoning behind
# a cached decision (ids are printed by `scan`/`init`):
cargo run -p agentguard-cli -- allow "<artifact-id>"
cargo run -p agentguard-cli -- why "<artifact-id>"
```

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
