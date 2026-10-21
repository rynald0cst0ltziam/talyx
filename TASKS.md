# Talyx Product & Engineering Roadmap

## Objective

Turn Talyx from a strong technical security prototype into a coherent, enterprise-ready product flow:

purchase -> install -> activate -> auto-scan -> auto-enforce -> data/analytics/reporting -> admin controls -> team rollout

The product needs to feel like a security system for AI coding agents, not a collection of excellent but disconnected security primitives.

---

## Product principle

Talyx should be the supply-chain firewall for AI coding agents:

- Discover everything an agent auto-loads
- Verify the code and text those components will run
- Block or quarantine what is malicious or drifted
- Keep a local and audit-friendly record of decisions
- Provide reporting for engineering, security and leadership
- Be easy to install and automatically enforce without requiring a trained specialist

---

## Current strengths in the repo

The repository already has strong foundations:

- strong security posture around install verification and release integrity
- real static analysis with AST and taint tracking
- prompt injection and hidden-instruction analysis
- trust-on-first-use / mid-session drift detection
- live proxy and session logging
- license gating for enforcement, but not for read-only evaluation
- broad agent support and supply-chain logic that goes beyond generic scanner behavior

These are excellent building blocks. The gap is not technical depth; it is product cohesion and operational readiness.

---

## Gaps right now

### 1) Buy -> Install -> First run flow is still too manual

Current state:
- install scripts exist
- activation exists
- scan exists
- init exists
- guardrails and advisories exist

Missing:
- a guided first-run workflow after install
- project bootstrap state and recommended defaults
- automatic onboarding experience for a new user
- a clear “what happened” summary after the first scan and first init
- strong defaults for the first project and personal machine setup

Needed outcome:
- a new user can install Talyx, run it once, and have a clear recommended next step with zero guesswork

### 2) Auto-run / auto-enforce is not yet a complete operational loop

Current state:
- the shim exists
- config rewrite exists
- live proxy exists
- cached decisions exist

Missing:
- smooth default enablement after first scan
- per-project / per-user policy inheritance
- recommended enforcement presets by environment
- continuous drift checks and alerting
- explicit review queue for ASK / suspicious artifacts
- on-machine state summary that tells the user what is currently enforced

Needed outcome:
- the user gets configured and protected without having to understand the internals

### 3) Reporting and analytics are underbuilt

Current state:
- scan output is useful for a terminal user
- SARIF output exists
- some recent proxy findings exist

Missing:
- durable analytics record beyond raw JSONL sessions
- summary dashboards per project / machine / team
- trends over time: blocked, allowed, drifted, quarantined
- report exports: JSON, CSV, SARIF, HTML summary, executive summary
- shareable security snapshot for engineering or leadership reviews
- “what changed since last scan?” comparisons

Needed outcome:
- a user or admin can answer: what was blocked, why, and what changed this week?

### 4) No proper enterprise control plane

Missing:
- org-level policy and approval workflows
- centralized policy store or signed policy envelope
- multiple machine / developer rollout tracking
- audit trail for who approved what
- admin view of status by machine or project
- team-level reporting and risk summaries
- remote policy management for enterprise rollout

Needed outcome:
- Talyx must be usable in an enterprise environment, not just a single developer laptop

### 5) Product story is not unified yet

Current repo has very strong technical features but still reads as a set of modules rather than one coherent product.

Missing:
- single enterprise narrative
- product journey and lifecycle docs
- customer onboarding flow
- top-level “what are we protecting” and “how to operate it” docs
- common data model for decisions, sessions, incidents, and reports

Needed outcome:
- the repo, the CLI, the web site, and the team narrative all describe the same system

### 6) The product needs stronger operational defaults

Missing:
- default baseline generation for known-safe tools
- default protections for common agent setups
- safe local defaults for project root detection
- easy “enforce for this repo only” and “enforce for all user config” modes
- smoothing of app-specific commands for common agents

Needed outcome:
- installation should produce a working protected environment without bespoke setup

---

## Priority mandate

We need to move from “technical security tool” to “operational security product.”

This means the next work is not just adding more detectors. The next work is to close the product loop:

1. install
2. first-run wizard / onboarding
3. baseline + auto init
4. auto policy enforcement
5. evidence + analytics + reporting
6. rollout / enterprise admin

---

## Task list

## Phase 0 — Product foundation and guardrails

### 0.1 Define the operating model and product contract
- Define the core user journeys:
  - personal developer
  - small team
  - enterprise rollout
- Define the exact “protected object” model:
  - agent
  - artifact
  - config source
  - decision
  - session
  - policy
  - approval
- Define one canonical data model for analytics, reporting, and audit
- Define the supported lifecycle states for each artifact

Acceptance criteria:
- the repo has one written source of truth for the product model
- CLI output, reporting, and docs align with the same terminology

### 0.2 Stabilize the working branch strategy and implementation discipline
- Keep the current code stable
- Add a roadmap file and task labels
- Define “safe change” rules for product work
- Define feature gates for major additions

Acceptance criteria:
- changes are made in explicit phases
- no hidden product “surprises” in minor patches

### 0.3 Create the first-run product spec
- Define the exact behavior of install + first scan + first init
- Define recommended defaults for user and project scopes
- Define what should appear in terminal output after install
- Define what the CLI should do when no agents are found

Acceptance criteria:
- a new user has a clear path from install to protection with minimal interpretation

---

## Phase 1 — First-run experience and onboarding

### 1.1 Install success path and anti-friction messaging
- Improve installer messaging to clearly state:
  - what was installed
  - what is free
  - what requires activation
  - what is enabled by default
  - what is not enabled yet
- Print a post-install summary with next steps and recommended defaults
- Provide a “verify installation” command

Acceptance criteria:
- a user can install Talyx and immediately know what to do next without reading the repo

### 1.2 First-run interactive or guided setup
- Add a guided first-run command or mode
- Detect whether there is a repo/project context
- Recommend a default scanning target and policy level
- Offer:
  - local-only scan
  - project enforcement
  - user config enforcement
  - live proxy enablement

Acceptance criteria:
- the user can run one guided command instead of manually assembling CLI flags

### 1.3 Default policy presets
- Define presets:
  - personal-safe
  - balanced
  - strict
  - enterprise-default
- Map each preset to behavior for scan / allow / block / live proxy / drift detection

Acceptance criteria:
- non-expert users can choose a preset without understanding internals

### 1.4 “What changed” summary after init
- After `talyx init`, print a complete report of:
  - how many artifacts were protected
  - which ones were allowed, blocked, or quarantined
  - what was modified in config files
  - what reverts are available
  - what should be reviewed manually

Acceptance criteria:
- the user has a clear confirmation of successful enforcement

---

## Phase 2 — Auto-enforcement and safe defaults

### 2.1 Auto-detect safe project and user scopes
- Improve default behavior for project vs user config detection
- Add explicit scope decision logic with clear explanation
- Avoid surprising modifications outside the intended target

Acceptance criteria:
- users are protected without accidental global config changes

### 2.2 Baseline and approval workflow
- Make initial approval states explicit and explainable
- Introduce “trusted baseline” generation for accepted artifacts
- Track approval timestamp, source, and reason
- Allow “approve this artifact only for this repo” or “approve globally”

Acceptance criteria:
- approval is explicit, auditable, and reversible

### 2.3 Drift monitoring and re-review pipeline
- Re-scan known artifacts on change
- Detect drift in hash, capability set, or launch command
- Force re-review when a previously approved artifact changes
- Surface drift findings alongside normal scan output

Acceptance criteria:
- an approved artifact cannot silently become malicious after approval

### 2.4 Live session analytics and incident capture
- Standardize the session findings log format
- Summarize recent live-proxy findings in one report
- Provide a session summary for blocked tool behavior and prompts
- Keep human-readable and machine-readable outputs consistent

Acceptance criteria:
- each session has an understandable summary and a durable JSON record

---

## Phase 3 — Reporting and analytics layer

### 3.1 Standardized evidence and analytics data model
- Canonical schema for:
  - findings
  - decisions
  - artifact metadata
  - validation / verification data
  - session events
  - incidents
- One output for CLI, JSON export, UI, and reports

Acceptance criteria:
- reporting is built from one structured model rather than ad hoc logs

### 3.2 Executive dashboard data
- Add metrics such as:
  - total artifacts scanned
  - active protections
  - blocked / quarantined totals
  - drifted artifacts
  - live proxy findings count
  - allow/block ratio
  - risk trend over time
  - top attack classes

Acceptance criteria:
- a user can generate a single summary showing project or machine risk posture

### 3.3 JSON/CSV/SARIF report exports
- Add export commands for:
  - JSON findings
  - JSON summary
  - CSV inventory
  - SARIF for CI
  - HTML or markdown summary
- Ensure exports have stable schema and timestamps

Acceptance criteria:
- reports are easy to ingest into CI, spreadsheets, or dashboards

### 3.4 Time-series and change tracking
- Compute differences between scans
- Report newly introduced issues and resolved ones
- Compare against previous baselines
- Maintain a simple local history of scan results

Acceptance criteria:
- a user can see “what changed since last week” without manual diffing

### 3.5 Incident and evidence bundle output
- Create machine-readable incident bundles for flagged artifacts
- Bundle evidence and decision reasoning into a portable artifact
- Include recommended remediation steps

Acceptance criteria:
- security review of a finding is easy to perform and share

---

## Phase 4 — Team and enterprise rollout

### 4.1 Team policy rollout model
- Define rules for:
  - personal mode
  - team-wide default mode
  - repo-specific overrides
  - enterprise baseline
- Support central policy publication to a shared directory or signed bundle

Acceptance criteria:
- policies can be rolled out without requiring each dev to understand every detector

### 4.2 Admin and audit console requirements
- Determine the minimum admin features for enterprise use:
  - overview of users / machines / projects
  - approved / blocked counts
  - drift alerts
  - policy changes
  - activation status
- Add a concept of admin identity or local admin view

Acceptance criteria:
- an enterprise administrator can see the fleet posture clearly

### 4.3 Policy review and approval queue
- Introduce an explicit approval queue for flagged artifacts
- Record approver identity, justification, and scope of approval
- Require re-review on a change in artifact version or capability

Acceptance criteria:
- high-risk findings can be governed, not just evaluated in isolation

### 4.4 Multi-machine / multi-project recordkeeping
- Store state per project and per machine
- Manage installation and activation records centrally or locally
- Support machine-level security snapshots

Acceptance criteria:
- a user or admin can understand state across multiple machines and repos

---

## Phase 5 — CI and developer workflow integration

### 5.1 CI gating and policy enforcement
- Improve repo-level scan jobs for PR and branch protection
- Provide an opinionated CI workflow for Talyx enforcement
- Make output stable enough for dashboards and policy gating

Acceptance criteria:
- Talyx can operate in PR workflows without custom scripting

### 5.2 Developer experience improvements
- Add an obvious “why did this get blocked?” command output
- Make blocked artifact remediation clear and short
- Add guided fix suggestions for common cases

Acceptance criteria:
- developers can understand and resolve issues without deep security expertise

### 5.3 Integration with team tooling
- Determine support for GitHub/GitLab/Azure DevOps integration
- Add policy outputs and findings referencing CI actions
- Provide consistent issue/PR annotations where appropriate

Acceptance criteria:
- Talyx fits naturally into existing software delivery workflows

---

## Phase 6 — Security hardening and product readiness

### 6.1 Harden the runtime trust model
- Audit all env var handling and config overrides
- Verify that live proxy settings cannot be tampered with by config content
- Review every interception point for security bypass possibilities
- Review all “debug-only” features for release safety

Acceptance criteria:
- the product’s enforcement cannot be weakened by config tricks or environment injection

### 6.2 Improve operational resilience
- Add graceful handling for missing config, stale decisions, and partially broken flows
- Ensure uninstall and recovery paths work reliably
- Improve error messages and failure explanations

Acceptance criteria:
- users can recover cleanly from broken states without reinstalling from scratch

### 6.3 Upgrade the package and distribution story
- Make the install + upgrade story explicit and predictable
- Ensure versioned upgrade behavior is clear
- Add migration notes between releases
- Distinguish new install from upgrade paths

Acceptance criteria:
- users know what changed and how to safely update

---

## Phase 7 — Documentation and enterprise trust narrative

### 7.1 Product docs cleanup
- Expand the docs around:
  - install flow
  - first-run flow
  - configuration decisions
  - local policy vs team policy
  - threat model and limitation model
  - common agent setup patterns

Acceptance criteria:
- new users can learn without reading the source tree

### 7.2 Customer-facing messaging
- Tighten the narrative around:
  - what Talyx protects
  - what it does not protect
  - why local-first matters
  - why enforcement is built into the shim and not external service-based

Acceptance criteria:
- the product story is consistent across website, docs, CLI, and repo

### 7.3 Compliance and audit support
- Define evidence needed for security review and procurement
- Provide human-readable and machine-readable security documentation
- Prepare key statements for enterprise trust and legal review

Acceptance criteria:
- Talyx is positioned as a credible enterprise security product, not just a technical tool

---

## Immediate execution plan (next 2–4 sprints)

### Sprint 1: product loop and onboarding
- 1.1 install success path
- 1.2 guided first-run flow
- 1.3 default policy presets
- 1.4 post-init summary output

### Sprint 2: policy and drift automation
- 2.1 scope detection and safe defaults
- 2.2 baseline + approval workflow
- 2.3 drift monitoring
- 2.4 session analytics summary

### Sprint 3: reporting and analytics
- 3.1 canonical data model
- 3.2 executive summary metrics
- 3.3 JSON/CSV/SARIF exports
- 3.4 time-based diffing and change tracking

### Sprint 4: enterprise controls and docs
- 4.1 team policy rollout
- 4.2 admin overview and audit data
- 4.3 approval queue
- 7.1/7.2 docs and product story

---

## What “done” looks like

A user should be able to:

- purchase Talyx
- install it in one step
- run a first-time onboarding flow
- scan their project or machine immediately
- activate a license easily
- enable enforcement without deep understanding
- see a short summary of what was blocked and why
- review risk over time in a report
- manage project or team policy with clear approvals
- maintain a compliant and auditable record of agent-tool security

That is the product target.

---

## Recommended first implementation priorities

If we want to work in a disciplined way without breaking the system, the first 5 items to do are:

1. define the canonical product model and lifecycle states
2. build a guided first-run onboarding flow
3. standardize output and analytics schema for findings / decisions / sessions
4. implement default policy presets and baseline approval workflow
5. create the reporting layer for summaries and change tracking

These are the foundational workstreams that will make the rest of Talyx feel like one product instead of many modules.

---

## Final recommendation

Do not add a huge number of new detectors as the next move.

The next move is to make Talyx operationally coherent:

- easy to install
- obvious to activate
- automatic to enforce
- clear to understand
- reportable and reviewable
- enterprise-ready enough for rollout

That is the real product unlock.
