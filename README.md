# AgentGuard

Cross-agent security scanner for AI coding agent artifacts — MCP servers,
skills, plugins, and hooks.

Read first:
- [`BUILD_PLAN.md`](BUILD_PLAN.md) — the full architecture and build plan
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — what this defends against, and what it explicitly doesn't (v1)

## Status

v0 scaffold: discovery (Claude Code adapter + generic Unknown Agent Mode),
static capability extraction (JS/TS + Python heuristics), and the risk engine
(capped evidence + reputation discount + context modifiers) are implemented
and wired end-to-end through the CLI. **Enforcement (BUILD_PLAN.md §5) is not
implemented yet** — `agentguard scan` reports decisions, it does not act on
them. See BUILD_PLAN.md §14 for what's next.

## Layout

```
crates/
  agentguard-core       shared types: Artifact, Capability, Decision, RiskBand, ScoreBreakdown
  agentguard-scanner     static capability extraction (JS/TS, Python; package.json manifest)
  agentguard-adapters    per-agent discovery: Claude Code, Unknown Agent Mode
  agentguard-risk        risk engine: capped evidence − reputation + context → decision
  agentguard-cli         `agentguard` binary: scan, status
data/
  trust_seed.json        v0 hand-seeded trust graph (stand-in for BUILD_PLAN.md §7's pre-launch scan)
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
