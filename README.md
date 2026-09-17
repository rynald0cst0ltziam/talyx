<div align="center">

# Talyx

**Supply-chain security for AI coding agents.**

Talyx discovers every MCP server, plugin, skill, and hook your AI coding
agent auto-loads, scans each one with a real tree-sitter AST and
source-to-sink taint pass, and physically blocks what's malicious before
it launches. Fully local. No telemetry. No cloud.

[![CI](https://github.com/rynald0cst0ltziam/talyx/actions/workflows/ci.yml/badge.svg)](https://github.com/rynald0cst0ltziam/talyx/actions/workflows/ci.yml)
[![License: source-available](https://img.shields.io/badge/license-source--available-blue)](LICENSE)
[![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)](https://gettalyx.dev/docs)
[![Rust](https://img.shields.io/badge/rust-stable-orange?logo=rust&logoColor=white)](Cargo.toml)

[gettalyx.dev](https://gettalyx.dev) · [Documentation](https://gettalyx.dev/docs) · [Pricing](https://gettalyx.dev/pricing)

</div>

---

## The problem

Opening a project in Claude Code, Cursor, Copilot, or any of two dozen
other AI coding agents can silently auto-load MCP servers, plugins,
skills, and hooks from a config file in the repo — arbitrary code and
model-facing instructions, running with your shell access and your API
keys, without you reviewing a single line. There's no `npm audit` for
this layer.

## What Talyx does

- **Discovers** every artifact across 27 agents — user scope and project
  scope, including plugin and extension ecosystems most tooling in this
  space doesn't look at.
- **Analyzes** with a real tree-sitter AST and function-scoped,
  interprocedural source-to-sink taint pass for JS/TS, Python, and
  Ruby — it follows a secret from a file read, through a helper
  function, to a network call, not just a keyword match. Separate
  content analysis catches prompt injection, hidden Unicode, and
  data-exfiltration directives in skill and instruction-file text. A
  known-bad advisory feed matches confirmed-malicious identities offline.
- **Enforces** by rewriting the agent's own config: a blocked MCP server
  is physically removed, a poisoned instruction file or skill is
  quarantined. Every change is checksummed, backed up, and reversible
  with one command.

Read the full threat model — what's defended against and what explicitly
isn't (v1) — in [`THREAT_MODEL.md`](THREAT_MODEL.md).

## Install

```bash
# macOS / Linux
curl -fsSL https://gettalyx.dev/install.sh | sh
```

```powershell
# Windows
irm https://gettalyx.dev/install.ps1 | iex
```

```bash
# npm (any platform)
npm install -g talyx
```

The npm package has **no install scripts**. The native binaries ship in
per-platform packages (`@talyx/linux-x64` and friends) declared as
`optionalDependencies`, so npm fetches exactly the one your machine needs
and the bytes it verified are the bytes that run. `npm install
--ignore-scripts` works normally — a postinstall that downloads and
executes a binary is the pattern Talyx itself flags, and shipping one
from a supply-chain security tool would be indefensible.

Then:

```bash
talyx scan --project .              # free, read-only, evaluate anything
talyx activate <YOUR-LICENSE-KEY>   # from your purchase email
talyx init --project .              # turn on enforcement
talyx uninstall --project .         # undo it all, whenever you want
```

Both installers verify the download against the `SHA256SUMS` published
with the release and refuse to install on a mismatch. Every release
archive also carries a [build provenance
attestation](https://docs.github.com/actions/security-guides/using-artifact-attestations),
so you can confirm a binary was built by this repo's release workflow and
not substituted afterwards:

```bash
gh attestation verify talyx-x86_64-unknown-linux-musl.tar.gz --repo rynald0cst0ltziam/talyx
```

`scan` and `status` run without a license so you can evaluate freely;
`init` (the part that rewrites configs and enforces) needs a license —
`talyx-shim` itself is never gated, so a lapsed license can't break a
server that's already running. See
[`crates/talyx-cli/src/license.rs`](crates/talyx-cli/src/license.rs) for
exactly how activation works, and [gettalyx.dev/pricing](https://gettalyx.dev/pricing)
for the license.

None of the installers touch your shell profile or `PATH` automatically —
pass `--modify-path` (shell) / `-ModifyPath` (PowerShell) to opt in;
otherwise they print the line to add yourself.

## CI: SARIF for pull-request gating

`talyx scan` emits a [SARIF 2.1.0](https://sarifweb.azurewebsites.net) log
for GitHub code scanning, Azure DevOps, or any CI security dashboard — no
Talyx-hosted service involved:

```bash
talyx scan --project . --sarif-file talyx.sarif    # write a file for CI to upload
talyx scan --project . --format sarif              # or to stdout
talyx scan --project . --exit-code                 # exit 2 on BLOCK, 1 on ASK
```

A ready-to-use workflow is at
[`.github/workflows/talyx-scan.yml`](.github/workflows/talyx-scan.yml).
Each finding carries a repo-relative file location — the exact
`SKILL.md` line for a poisoned skill, the config entry for a risky MCP
server — and a stable fingerprint so results dedupe across runs. Activate
in CI with `TALYX_LICENSE_KEY` in the job environment.

## Architecture

```
crates/
  talyx-core        shared types: Artifact, Capability, Decision, RiskBand, ScoreBreakdown
  talyx-scanner      static capability extraction; ast.rs: tree-sitter AST + interprocedural
                      source-to-sink taint for JS/TS, Python, Ruby; content.rs: prompt-injection /
                      hidden-Unicode / encoded-payload / exfil-directive analysis of instruction
                      text; shadowing.rs: cross-artifact tool-shadowing / typosquat detection
  talyx-adapters     per-agent discovery across 27 agents, including plugin/extension ecosystems
  talyx-risk         risk engine: capped static evidence − reputation discount + context modifiers
  talyx-registry     fetches + statically scans the real code behind an npx/uvx-resolved package
  talyx-store        local decision cache (~/.talyx/decisions.json)
  talyx-shim         the enforcement binary — allows or blocks a gated MCP server launch
  talyx-mcp-proxy    opt-in live stdio firewall: inspects the MCP handshake and traffic for the
                      whole session, trust-on-first-use tool baseline, user-authored guardrails
  talyx-content      prompt-injection / hidden-Unicode / encoded-payload / exfil-directive
                      detectors, shared by the scanner and the live proxy
  talyx-advisories   known-bad feed — identity-matched, offline, refreshable over HTTPS
  talyx-cli          the `talyx` binary: scan, status, init, allow, why, guardrails, advisories,
                      activate, license
data/
  trust_seed.json         hand-verified publisher trust graph
  advisories.json         hand-curated, fully-sourced disclosures of malicious/vulnerable artifacts
scripts/                  install.sh / install.ps1 — also served from gettalyx.dev
npm/                      npm packages: the `talyx` launcher + per-platform binary packages
                          (build-packages.mjs stages all six; no install scripts anywhere)
site/                     the marketing site (Astro, static) — see site/README.md
.github/workflows/        ci.yml, talyx-scan.yml, release.yml
```

## Build from source

Requires a Rust toolchain (stable) and, on Windows, the MSVC linker
(Visual Studio "C++ build tools", or the `x86_64-pc-windows-gnu` target
with MinGW as an alternative).

```bash
cargo build --workspace
cargo test --workspace

cargo run -p talyx-cli -- scan --project .
```

See `talyx --help` (or [gettalyx.dev/docs](https://gettalyx.dev/docs)) for
the full command reference, including `--fetch-registry`, `init --live`
(the opt-in live proxy), and the guardrails/advisories subcommands.

## Design rules this codebase follows

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
redistribution, resale, or hosting is not granted.

Third-party open-source components are listed with their full license
texts in [`THIRD-PARTY-LICENSES.txt`](THIRD-PARTY-LICENSES.txt). None are
GPL/LGPL/AGPL/SSPL; the only weak-copyleft dependency is one MPL-2.0 crate,
used unmodified. Regenerate the notices after any dependency change:

```bash
cargo about generate about.hbs -o THIRD-PARTY-LICENSES.txt
```
