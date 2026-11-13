# Talyx — Product & Data Model

The one source of truth for *what Talyx reasons about* and *what state each
thing moves through*. CLI output, reporting, docs, and the website use this
vocabulary and nothing else. The Rust types that implement it live in
`talyx-core` (domain), `talyx-store` (persistence), and `talyx-mcp-proxy`
(session runtime); where a concept here already has a type, it is named.

This document is the acceptance artifact for roadmap task 0.1 and the
anchor for the reporting/analytics schema (Phase 3). It is deliberately
product-level: field-exact schemas live with the types and the export
commands, not here.

---

## 1. The protected-object model

Eight entities, one direction of reference (each points only at ones above
it), so a decision can always be traced back to the evidence and forward to
what was enforced.

| Entity | What it is | Implemented as |
|---|---|---|
| **Agent** | A supported AI coding tool (Claude Code, Cursor, …) that auto-loads artifacts. 27 supported. | `talyx-adapters` (one module per agent) |
| **Config source** | A concrete file an agent reads to decide what to load (`.mcp.json`, `~/.claude.json`, `.cursorrules`, a TOML/YAML config, a hooks file). The thing Talyx rewrites to enforce. | `ConfigSourceKind` (adapters) |
| **Artifact** | The normalized unit of risk: an MCP server, skill, plugin, hook, agent-config, script, dependency, or executable — agent-agnostic. | `talyx_core::Artifact`, `ArtifactKind` |
| **Capability finding** | One piece of evidence that an artifact can do something sensitive, with its basis (Declared/Inferred/Inherited) and location. | `CapabilityFinding`, `Capability`, `EvidenceBasis` |
| **Decision** | The verdict for an artifact under a policy, with its full score breakdown. Allow / AllowLog / Ask / Block / Quarantine. | `Decision`, `ScoreBreakdown`, `RiskBand` |
| **Approval** | A human (or policy) overriding a decision, scoped (this repo / globally), with who, when, why. | `talyx-store` decision record (approval fields) |
| **Session** | One live run of a shimmed MCP server through the proxy, and the findings it produced (rug-pull, injected tool result, drift). | `~/.talyx/sessions/*.jsonl`, `talyx-mcp-proxy` |
| **Incident** | A finding worth escalating: a Block/Quarantine at enforcement, or a session violation. The unit of the review queue, audit trail, and evidence bundle. | *new in Phase 2/3* |

**Policy** sits across all of them: the rules (a preset plus any overrides)
that turn a `ScoreBreakdown` into a `Decision` and choose enforcement
behavior. Implemented today as `ProtectionLevel` + guardrails; formalized as
a named preset in §4.

---

## 2. Artifact identity & lifecycle

Identity is `(kind, name, source)` hashed into a stable `id`
(`Artifact::compute_id`) so the same logical artifact found via two agents
dedupes, and a decision survives across scans. `content_hash` is the
separate "is this the same *bytes*" axis that drift compares.

Lifecycle states (every artifact is in exactly one; transitions are the
events reporting counts):

```
DISCOVERED ── scan ──▶ SCANNED ──▶ decision ─┬─▶ ALLOWED
                                             ├─▶ ALLOW_LOGGED
                                             ├─▶ IN_REVIEW (Ask)
                                             ├─▶ BLOCKED
                                             └─▶ QUARANTINED
            approval (scope) ──▶ APPROVED ──▶ ENFORCED ──┐
                                                         │ re-scan sees change
                                 DRIFTED ◀───────────────┘
                                   │ forced re-review (never auto-downgrades)
                                   └──▶ IN_REVIEW
            uninstall / allow-restore ──▶ RESTORED
```

Rules that hold across the product (already enforced in `init.rs`):

- **Drift only ever makes a decision more cautious.** A previously approved
  artifact that gains a secret-access, process-exec, or persistence
  capability is forced to at least `Ask` on next sight, with a plain-English
  reason naming what was gained. It never silently re-allows.
- **Approval means *that* artifact.** A cached approval is preserved only
  while the artifact's score and decision are unchanged.
- **Enforcement is reversible.** Every config rewrite is checksummed, backed
  up once, and unwound entry-by-entry by `uninstall` so unrelated edits
  survive.

---

## 3. Decision model

A decision is never a bare number. `ScoreBreakdown` always carries:

```
total = max(0, static_evidence − reputation_discount + context_modifier)
```

- **static_evidence** — capped sum of what the code/text can do, with reasons.
- **reputation_discount** — only from an *explicitly verified* publisher
  (never inferred from a name/scope).
- **context_modifier** — declared-category-vs-requested-capability signals
  (a linter asking for SSH keys), advisory on their own, decisive alongside
  another signal.

Band thresholds (tune against the eval corpus, not by feel):
`0–24 Low · 25–49 Medium · 50–79 High · 80+ Critical`.

`RiskBand × ProtectionLevel → Decision` is the single policy table
(`ProtectionLevel::decision_for`). Raw secret material + network is the one
pattern the evidence cap does not soften (canonical exfiltration).

---

## 4. Policy presets

A **preset** is the user-facing name for a bundle of behavior. It is *not*
only a `ProtectionLevel` — it also sets enforcement scope, live-proxy
default, and drift strictness, so a non-expert picks one word instead of
assembling flags. Presets map onto existing primitives; they add no new
enforcement semantics.

| Preset | ProtectionLevel | Scope default | Live proxy | Intended for |
|---|---|---|---|---|
| `personal` | Quiet | project only | off | A solo dev who wants signal, not interruption |
| `balanced` *(default)* | Balanced | project only | off | The everyday default — log the mediums, block the criticals |
| `strict` | Strict | project + prompt for user config | on | High-trust repos, security-conscious devs |
| `enterprise` | Strict | project + user config | on | Fleet rollout: strict + proxy + drift re-review, meant to be published centrally (Phase 4) |

`balanced` stays the default everywhere so no behavior changes for existing
users. `enterprise` is `strict` plus the rollout/audit defaults; the extra
machinery it implies (central policy bundle, approval queue) is Phase 4 —
the preset name exists now so the vocabulary is stable.

---

## 5. Reporting & analytics vocabulary (Phase 3 anchor)

Every report, export, and future dashboard is built from the entities above
and these derived metrics — one definition, reused across CLI text, JSON,
CSV, SARIF, and HTML:

- **Posture** — current state counts across all artifacts: allowed /
  logged / in-review / blocked / quarantined / drifted.
- **Enforcement** — artifacts currently routed through the shim, by agent
  and config source.
- **Activity** — transitions in a window: newly blocked, newly drifted,
  newly approved, resolved.
- **Session findings** — proxy violations in a window, by class (rug-pull,
  injected result, guardrail hit).
- **Top risk** — the highest-band artifacts with their one-line reason.

"What changed since last scan" is the diff of two posture snapshots; it
needs a durable, timestamped scan history (Phase 3.4), which is the first
thing the reporting layer adds on top of the existing decision store.

---

## 6. What this supersedes

Code comments reference `BUILD_PLAN.md` and `STATUS.md` as the design source
of truth; those files are not in the repository. Until they are, **this
document plus the `talyx-core` types are the authoritative model** for
product, CLI, reporting, and website vocabulary. New work aligns here; a
divergence is a bug in the work or in this doc, resolved before merge.
