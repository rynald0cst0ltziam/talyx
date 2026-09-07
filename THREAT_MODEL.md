# Talyx — Threat Model v1

This document exists so every risk-engine weight, every enforcement decision,
and every UI claim traces back to a specific defended scenario. If a feature
doesn't map to something below, it doesn't belong in v1.

## Assets we're protecting

1. **Credentials** — SSH private keys, cloud provider credentials (AWS/GCP/Azure),
   API keys and tokens (in env vars, config files, credential stores), OAuth
   tokens, browser-stored secrets.
2. **Code execution** — the ability to run arbitrary commands as the developer's
   user, on the developer's machine, with the developer's access.
3. **Source code / IP** — repository contents, private packages, proprietary
   business logic the agent has access to as part of its normal job.
4. **Lateral reach** — anything the developer's machine can reach that an
   attacker couldn't otherwise: internal networks, CI/CD credentials, internal
   tools, other repos the same SSH key can access.
5. **Persistence** — the ability to survive a reboot or reappear later (cron,
   shell profile, startup items, modified agent config that reloads the
   malicious artifact automatically).
6. **Trust in the AI agent itself** — if a user can't trust that their coding
   agent won't silently exfiltrate data, they stop using AI agents for
   anything sensitive. This is the category-level thing Talyx sells
   confidence in.

## Attacker archetypes (every risk-engine weight in BUILD_PLAN.md §4 maps to one of these)

### A1 — Opportunistic credential grab
Publishes a plausible MCP server / skill / plugin with an obvious, low-effort
payload: read `~/.ssh`, env vars, or a cloud credentials file, then POST it
somewhere. No attempt to hide intent from a human reader, minimal effort to
evade static analysis. **This is what static capability extraction + the
default risk thresholds are built to catch, and should catch nearly 100% of.**

### A2 — Supply-chain drift
A previously legitimate, previously-scanned, previously-trusted artifact
receives a malicious update — either the maintainer's account is compromised,
a maintainer turns malicious, or a transitive dependency is swapped out from
under it. The artifact *looked* safe at first install. **This is what drift
detection (capability diff between versions) and dependency-hash pinning are
built to catch.**

### A3 — Typosquat / impersonation
An attacker publishes `github-mcp-offical` or a fork of a real project with
one added line, relying on a developer not checking the publisher/repo
carefully during a fast `npm install`/config paste. **This is what
publisher/repo identity verification and the trust graph are built to catch** —
distinguishing a verified org/maintainer from a name that merely looks similar.

### A4 — Capability creep / scope mismatch
An artifact that does what it claims, but claims (or silently uses) far more
access than its stated purpose needs — a "markdown linter" skill requesting
`READ_SSH`, a "changelog generator" wanting `NETWORK_UNRESTRICTED`. Not
necessarily malicious yet, but a red flag and a common pattern in genuinely
malicious artifacts too. **This is what context modifiers (declared category
vs. requested capability) are built to catch.**

## Explicitly out of scope for v1 — say this publicly, don't imply otherwise

- **A fully compromised OS or existing kernel-level malware.** Talyx is
  not an antivirus/EDR replacement and doesn't claim to be one in v1.
- **A compromised agent vendor binary itself** (Claude Code / Cursor / Codex
  compiled with a backdoor at the source). Out of scope — we trust the agent
  binary, we scrutinize what it's told to load and run.
- **Zero-days in the artifact's own runtime** (a Node.js or Python interpreter
  sandbox escape triggered by data the artifact processes). Not defended
  against; static analysis and capability gating don't see this class of bug.
- **A sophisticated, targeted attacker who specifically studies Talyx's
  detection and evades it.** v1 static analysis is heuristic, not formally
  verified — a determined, well-resourced, targeted adversary can construct
  something that slips past it. The trust graph, reputation requirements, and
  drift detection raise the cost of this over time; they don't eliminate it.
  Never claim "can't be evaded" in marketing copy.

## What "the product works" means, concretely

For each archetype, v1 should be evaluated against the benchmark corpus
(BUILD_PLAN.md §13) with an explicit target, not a vibe:

| Archetype | v1 target catch rate | Acceptable false-positive rate |
|---|---|---|
| A1 — opportunistic | ≥ 95% | — |
| A2 — supply-chain drift | 100% of capability-adding changes flagged | ≤ 2% of benign version bumps flagged as HIGH+ |
| A3 — typosquat/impersonation | ≥ 90% of known-pattern squats | ≤ 1% of verified publishers ever flagged |
| A4 — capability creep | Advisory (surfaced, not auto-blocked, unless combined with A1/A2 signals) | n/a |

These numbers are placeholders until the benchmark corpus exists — the point
is that a number must exist and be tracked in CI, not that these specific
percentages are final.
