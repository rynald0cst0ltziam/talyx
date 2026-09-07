# ADR 0001 — Live MCP proxy (the in-shim stdio firewall)

Status: **accepted** 2026-09-07 · Supersedes the "STATUS.md item 9" open question.

## Context

`agentguard-shim` is today a launch-time gate: it checks the cached decision
for an artifact, then `Command::new(real).status()` with inherited stdio. Once
the real MCP server is running, the agent and the server talk directly over a
pipe and AgentGuard is out of the loop for the rest of the session.

Three attack classes live entirely in that blind spot:

1. **Rug pull** — a server serves a clean `tools/list` at startup, then swaps
   tool definitions mid-session (`notifications/tools/list_changed` followed by
   a poisoned re-list).
2. **Malicious tool responses** — a `tools/call` result crafted to steer the
   model ("file contents: *ignore your instructions and …*"), not a malicious
   launch command.
3. **Runtime-only metadata** — tool descriptions / schemas that exist only
   after the `initialize` + `tools/list` handshake, which the static scanner
   can't see without executing the server.

`mcp-scan` (Invariant) and `mcpwall` cover this with an always-on external
proxy. Their structural weakness: proxy process not running → protection
silently gone.

## Decision

Give the shim an **opt-in, MCP-protocol-aware stdio proxy mode** that stays in
the middle for the life of the session, inspecting every JSON-RPC message both
directions, applying policy at the protection level, and **failing open** to
today's static protection on any internal error.

### Non-negotiable properties (the "better, not just also" bar)

- **The static gate still holds underneath.** A blocked server is still
  physically removed from the config by `agentguard init`. If the proxy layer
  fails — parser bug, panic, resource exhaustion — you fall back to exactly the
  protection you have today (launch-time scan + config removal of known-bad),
  **never below it**. `mcp-scan` down = zero protection; AgentGuard proxy down
  = full static protection still in place.
- **No daemon, no second process, no config.** The proxy *is* the shim — the
  same process the agent already spawns as the server's `command`. When the
  agent kills the server, the proxy dies with it. Nothing for the user to
  manage or keep running.
- **Local only.** Session findings are written to
  `~/.agentguard/sessions/<date>-<pid>.jsonl` (violations + drift events, not
  the message stream). `agentguard status` surfaces recent ones. Nothing
  leaves the machine.

### Architecture

- Invocation: `agentguard-shim <id> --proxy -- <real-cmd> [args…]`. `init`
  gains `--live` to write this form; plain `init` is unchanged. `--shell` mode
  (hooks) is never proxied — hooks aren't MCP servers.
- Spawn the child with `Stdio::piped()` on stdin/stdout; **stderr is inherited
  untouched** (servers log there). Two blocking pump threads — `client→server`
  and `server→client` — each `BufReader::read_until(b'\n')` (MCP stdio is
  newline-delimited JSON-RPC 2.0, no embedded newlines) and writes straight
  through. Shutdown: either side hits EOF → close that pipe, `wait()` the
  child; the other pump sees EOF and exits.
- Per-message cap of **16 MiB**: forward but skip inspection above it rather
  than buffer unboundedly.
- **Threads, not `tokio`.** Keeps the shim a lean hot-path binary. Two
  unidirectional byte streams don't need an async runtime.
- The framing + pump + classification live in a new `agentguard-mcp-proxy`
  library crate, testable in isolation. The shim `main.rs` stays thin: parse
  args → look up decision → `launch()` or `mcp_proxy::run()`.

### Where policy runs

| message | latency profile | strategy |
|---|---|---|
| handshake / metadata responses (`initialize`, `tools/list`, `resources/list`, `prompts/list`) | small, infrequent, **blocking them is the point** | **inspect-then-forward** — hold, scan through `content.rs`, diff against the approved snapshot, then forward / error / redact |
| `tools/call` results | large, frequent, latency-sensitive | **forward-then-inspect** (report only) by default; **inspect-then-forward** only at `strict` |
| everything else | — | forward verbatim, parse only to classify |

### Enforcement action, by protection level

| level | rug-pulled / poisoned `tools/list` | tool-call result carrying an injection payload |
|---|---|---|
| `quiet` | log only | log only |
| `balanced` (default) | return a JSON-RPC error for that request so the agent never sees the poisoned list; surface a notice | replace the offending content block with a redaction marker, forward the rest, log |
| `strict` | tear the session down with a clear message | tear the session down |

### The approved-tools baseline: trust-on-first-use

`agentguard init` shims a server without its runtime tool list (we'd have to
execute it to get one — which the project deliberately doesn't do). So the
first `tools/list` response the proxy sees for an artifact is recorded as the
baseline in the decision store, keyed by artifact id; **changes** after that
are what trip drift detection. Same model as the existing static content-hash
drift.

### Default vs opt-in

Ships **opt-in** (`agentguard init --live`) so early adopters dogfood it. The
code path is wired everywhere and `AGENTGUARD_NO_PROXY=1` is a hard kill
switch. **Target state is default-on** — the everyday coder benefits from it
being automatic, and "install and forget" is the product's whole pitch —
flipping the `init` default is a one-line change once Phase B is done and the
proxy has real multi-hour session mileage.

## Consequences

- The shim gains a dependency on `serde_json` (Phase A) and, at Phase B, the
  injection/hidden-unicode/encoded-payload detectors — factored into a small
  leaf crate so the shim does not pull in the tree-sitter grammars.
- The shim's failure mode changes from "server doesn't start" to "could, if
  built carelessly, hang or break a live session." Mitigated by: fail-open on
  internal error, a per-message size cap, blocking IO with deterministic EOF
  shutdown, and Phase A being a *transparent* proxy (no policy) proven
  byte-for-byte faithful against every real MCP server before any inspection
  logic is added.
- Verification has a real ceiling: automated tests cover framing, passthrough,
  shutdown, latency, and the malicious fixtures; a multi-hour real agent
  session surviving the proxy can only be proven by dogfooding, and will not
  be claimed until it has been.

## Phasing

- **Phase A — transparent proxy.** `--proxy` mode, piped stdio, two pump
  threads, NDJSON framing + 16 MiB cap, per-message `serde_json` classify,
  `--proxy-log <path>` JSONL capture, clean shutdown. **No policy.** Goal:
  byte-for-byte transparent + negligible latency against every real MCP server
  on the machine.
- **Phase B — handshake inspection.** Scan `initialize`/`*/list` responses
  through the detector leaf crate; TOFU baseline + drift/rug-pull detection;
  the per-level action; `~/.agentguard/sessions/*.jsonl`.
- **Phase C — response-content policy.** Optional `tools/call` result scanning,
  drift-record persistence, `agentguard why` / `agentguard status`
  integration, and the `init` default flip.
