# Talyx — Threat Model

Every detection Talyx ships maps to a specific asset it protects and a
specific attack pattern it's built to catch. This document is that
mapping, published so you can judge the product against real, stated
scenarios instead of marketing language.

## What Talyx protects

1. **Credentials** — SSH private keys, cloud provider credentials
   (AWS/GCP/Azure), API keys and tokens in env vars, config files, and
   credential stores, OAuth tokens, browser-stored secrets.
2. **Code execution** — the ability to run arbitrary commands as you, on
   your machine, with your access.
3. **Source code and IP** — repository contents, private packages,
   proprietary business logic an agent can reach as part of its normal
   job.
4. **Lateral reach** — anything your machine can reach that an attacker
   couldn't otherwise: internal networks, CI/CD credentials, internal
   tools, other repositories the same SSH key can access.
5. **Persistence** — the ability to survive a reboot or reappear later
   (a cron entry, a shell-profile edit, a startup item, a modified agent
   config that reloads the malicious artifact automatically).
6. **Trust in the agent itself.** If you can't trust that your coding
   agent won't silently exfiltrate data, you stop giving it anything
   sensitive to work with — which defeats the point of using one.

## Attack patterns Talyx defends against

### Opportunistic credential grabs
An MCP server, skill, or plugin with a plausible surface and an obvious,
low-effort payload: read `~/.ssh`, environment variables, or a cloud
credentials file, then send it somewhere. No attempt to hide intent from
a human reader, minimal effort to evade static analysis. This is what
static capability extraction and the default risk thresholds are built
to catch, and the class of attack they're most effective against.

### Supply-chain drift
A previously legitimate, previously-scanned, previously-trusted artifact
receives a malicious update — a maintainer's account is compromised, a
maintainer turns malicious, or a transitive dependency is swapped out
from under it. The artifact looked safe at first install; the danger
shows up later. This is what capability-diff drift detection and
content-hash pinning are built to catch: an approved artifact that gains
a dangerous capability is forced back to review automatically, the next
time it's seen, even when nothing else about it changed.

### Typosquatting and impersonation
An attacker publishes `github-mcp-official` (one character off a real
name) or a near-identical fork of a trusted project, relying on a
developer not checking the publisher or repository carefully while
pasting a config or running a fast install. This is what publisher/repo
identity verification and the trust graph are built to catch —
distinguishing a verified maintainer from a name that merely looks
similar, scored across every discovered artifact at once so a fake
sitting next to the real thing gets caught by the comparison itself.

### Capability creep
An artifact that does roughly what it claims, but claims — or silently
uses — far more access than its stated purpose needs: a markdown linter
requesting SSH key access, a changelog generator wanting unrestricted
network reach. Not necessarily malicious on its own, but a real signal,
and a common shape genuinely malicious artifacts also take. This is what
context modifiers (declared category vs. requested capability) surface —
advisory on its own, decisive when it shows up alongside another signal.

### Prompt injection and hidden instructions
Text an agent reads as instructions rather than executes as code — a
skill's markdown, an instruction file, a declared MCP tool description —
carrying an instruction-override phrase, a role-manipulation attempt, or
content hidden from a human reviewer entirely (zero-width characters,
bidirectional-text overrides, Unicode "tag" characters that render as
nothing but decode to a full instruction). This is a different attack
surface from executable code, and it needs a different kind of
detection: content analysis of the text itself, not capability
extraction from a command.

## Explicitly out of scope

Stated plainly, not implied by omission:

- **A fully compromised OS or existing kernel-level malware.** Talyx is
  not an antivirus or EDR replacement and doesn't claim to be one.
- **A compromised agent vendor binary itself** — Claude Code, Cursor, or
  Codex compiled with a backdoor at the source. Talyx trusts the agent
  binary and scrutinizes what it's told to load and run, not the binary
  itself.
- **Zero-days in an artifact's own runtime** — a Node.js or Python
  interpreter sandbox escape triggered by data the artifact processes.
  Static analysis and capability gating don't see this class of bug, and
  Talyx doesn't defend against it.
- **A sophisticated, targeted attacker who studies Talyx's detection
  specifically and evades it.** Static analysis is heuristic, not
  formally verified — a determined, well-resourced, targeted adversary
  can construct something that slips past it. The trust graph,
  reputation requirements, and drift detection raise the cost of doing
  that over time; they don't eliminate it, and Talyx doesn't claim they do.

## How this gets validated

Every detection above is proven against live, adversarial fixtures before
it ships — a real credential-exfiltration payload genuinely blocked, a
benign server genuinely still running, checked through the actual
enforcement shim, not just a unit test asserting the right number came
out of a function. That discipline is what this document is a contract
against: if a change doesn't map to one of the patterns above, or can't
be shown working against a real fixture, it doesn't ship.
