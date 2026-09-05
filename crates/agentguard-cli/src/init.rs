//! `agentguard init` — BUILD_PLAN.md §5a's config-rewrite enforcement,
//! plus `agentguard allow`/`why` for the manual-approval flow that goes
//! with it. This is the only code in the CLI that writes anything: the
//! decision cache (`~/.agentguard/decisions.json` by default) and, for MCP
//! servers found in a rewritable config, the agent's own config file (with
//! a one-time backup before the first rewrite).
//!
//! `scan`/`status` (main.rs) never call into this module — they only read.

use crate::pipeline::{collect, ScannedArtifact};
use crate::sanitize_for_display;
use agentguard_adapters::ConfigSourceKind;
use agentguard_core::{ArtifactKind, Capability, Decision, ProtectionLevel, RiskBand};
use agentguard_risk::RiskEngine;
use agentguard_store::{DecisionRecord, DecisionStore};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};

/// `--store` flag > `$AGENTGUARD_STORE` > `~/.agentguard/decisions.json`.
/// The env var and flag exist so tests/demos can point at an isolated
/// store instead of ever touching the real machine-wide one.
pub fn resolve_store(store_override: Option<PathBuf>) -> DecisionStore {
    match store_override {
        Some(path) => DecisionStore::open_at(path),
        None => DecisionStore::resolve(),
    }
}

/// Writes a scan result into the store, preserving a prior manual approval
/// ONLY if this artifact's score and decision are unchanged from what's
/// cached. This is a safety net independent of `check_drift` below — it
/// also catches score changes that aren't capability-driven (e.g. a
/// reputation-discount change from a future trust-graph sync): "the thing
/// I approved" should mean exactly that thing, not "whatever this
/// artifact_id points to now."
fn upsert_preserving_approval(store: &DecisionStore, mut record: DecisionRecord) -> io::Result<()> {
    if let Some(existing) = store.get(&record.artifact_id) {
        if existing.manually_approved
            && existing.total_score == record.total_score
            && existing.decision == record.decision
        {
            record.manually_approved = true;
        }
    }
    store.upsert(record)
}

/// BUILD_PLAN.md §8 — semantic drift. Compares a fresh scan against
/// whatever's cached for this artifact id. A content-hash change alone is
/// folded into the new baseline silently: per the product's own stated
/// design, "security capabilities changed" is the user-facing signal, not
/// "SHA-256 mismatch," and the user doesn't care about a hash changing if
/// nothing about what the artifact can actually DO changed (a comment
/// tweak, a version bump with no behavior change). Only when the content
/// changed AND a new dangerous capability (secret access, process
/// execution, or persistence) appeared that wasn't there before does this
/// force the decision to at least ASK, regardless of what the raw score
/// says, and return a plain-English reason naming exactly what was gained.
/// Never downgrades a decision — drift only makes things more cautious.
fn check_drift(store: &DecisionStore, s: &ScannedArtifact) -> (Decision, Option<String>) {
    let baseline_decision = s.decision;

    let Some(previous) = store.get(&s.artifact.id) else {
        return (baseline_decision, None); // first sighting — nothing to compare
    };
    let (Some(prev_hash), Some(new_hash)) = (&previous.content_hash, &s.artifact.content_hash)
    else {
        return (baseline_decision, None); // one side couldn't be hashed
    };
    if prev_hash == new_hash {
        return (baseline_decision, None); // unchanged
    }

    let old_caps: BTreeSet<Capability> = previous.capability_snapshot.iter().copied().collect();
    let new_caps = s.artifact.capability_set();
    let gained_dangerous: Vec<Capability> = new_caps
        .difference(&old_caps)
        .copied()
        .filter(|c| c.is_secret_access() || c.is_process_execution() || c.is_persistence())
        .collect();

    if gained_dangerous.is_empty() {
        return (baseline_decision, None); // content changed, nothing new & dangerous
    }

    let names: Vec<String> = gained_dangerous.iter().map(|c| c.to_string()).collect();
    let reason = format!(
        "SECURITY CAPABILITIES CHANGED since the last scan: this artifact's content changed and it now does something it didn't before -- gained: {}.",
        names.join(", ")
    );
    let decision = if matches!(baseline_decision, Decision::Allow | Decision::AllowLog) {
        Decision::Ask
    } else {
        baseline_decision
    };
    (decision, Some(reason))
}

/// The JSON key a `ConfigSourceKind`'s server map sits under — `None` for
/// a TOML config (Codex, which doesn't use this string-keyed restore path
/// at all — see `restore_remote_entry`'s dispatch by file extension) or a
/// shape with no flat server map (hooks). `"mcpServers"` for every
/// JSON-format agent except VS Code's Copilot Chat extension
/// (`"servers"` — see `ConfigSourceKind::VsCodeCopilotMcpJson`'s doc
/// comment). Kept as its own small function, matched exhaustively, so a
/// future `ConfigSourceKind` variant forces a decision here too.
fn json_top_level_key(kind: ConfigSourceKind) -> Option<String> {
    match kind {
        ConfigSourceKind::ClaudeCodeMcpServersJson
        | ConfigSourceKind::CursorMcpJson
        | ConfigSourceKind::WindsurfMcpJson
        | ConfigSourceKind::AntigravityMcpJson
        | ConfigSourceKind::GeminiCliSettingsJson
        | ConfigSourceKind::GitHubCopilotCliMcpJson
        | ConfigSourceKind::ClaudeDesktopMcpJson
        | ConfigSourceKind::KiroMcpJson
        | ConfigSourceKind::AmazonQMcpJson
        | ConfigSourceKind::ContinueMcpJson
        | ConfigSourceKind::DevinCliMcpJson
        | ConfigSourceKind::ClineMcpJson
        | ConfigSourceKind::RooCodeMcpJson
        | ConfigSourceKind::JetBrainsMcpJson
        | ConfigSourceKind::TabnineMcpJson => Some("mcpServers".to_string()),
        ConfigSourceKind::VsCodeCopilotMcpJson => Some("servers".to_string()),
        ConfigSourceKind::AmpMcpJson => Some("amp.mcpServers".to_string()),
        ConfigSourceKind::ZedMcpJson => Some("context_servers".to_string()),
        // OpenClaw's shape is nested two levels (`mcp.servers`) and
        // opencode's one level (`mcp`), neither a single flat top-level
        // key -- there's no single string this string-keyed restore path
        // can express, so `agentguard allow` can't currently restore a
        // removed remote entry for either this way. A real, documented
        // limitation (their remote-entry enforcement is scoped to
        // "remove," not "remove and reliably restore" until this restore
        // path is generalized to a nested key path, not just a single
        // string).
        ConfigSourceKind::OpenClawJson | ConfigSourceKind::OpenCodeMcpJson => None,
        ConfigSourceKind::ClaudeCodeHooksJson
        | ConfigSourceKind::CodexHooksJson
        | ConfigSourceKind::AntigravityHooksJson
        | ConfigSourceKind::GeminiCliHooksJson
        | ConfigSourceKind::GitHubCopilotCliHooksJson
        | ConfigSourceKind::DevinCliHooksJson
        | ConfigSourceKind::DevinCliProjectHooksJson
        | ConfigSourceKind::CodexMcpServersToml => None,
    }
}

fn record_for(store: &DecisionStore, s: &ScannedArtifact, level: ProtectionLevel) -> DecisionRecord {
    let mut reasons = Vec::new();
    reasons.extend(s.breakdown.static_evidence_reasons.clone());
    reasons.extend(s.breakdown.reputation_reasons.clone());
    reasons.extend(s.breakdown.context_reasons.clone());

    let (decision, drift_reason) = check_drift(store, s);
    if let Some(reason) = drift_reason {
        reasons.push(reason);
    }

    // Only for hooks — see DecisionRecord.shell_command's doc comment for
    // why this travels through the store instead of the rewritten config
    // text: embedding it there would let an outer shell re-interpret any
    // metacharacters in the command before the shim ever runs.
    let is_hook_shell_command = s
        .config_source
        .as_ref()
        .map(|cs| {
            matches!(
                cs.kind,
                ConfigSourceKind::ClaudeCodeHooksJson
                    | ConfigSourceKind::CodexHooksJson
                    | ConfigSourceKind::AntigravityHooksJson
                    | ConfigSourceKind::GeminiCliHooksJson
                    | ConfigSourceKind::GitHubCopilotCliHooksJson
                    | ConfigSourceKind::DevinCliHooksJson
                    | ConfigSourceKind::DevinCliProjectHooksJson
            )
        })
        .unwrap_or(false);
    let shell_command = if is_hook_shell_command {
        s.launch.as_ref().map(|l| l.command.clone())
    } else {
        None
    };

    // Remote MCP servers (no `launch` — no local process to wrap) are the
    // only artifacts with anything to snapshot here: see DecisionRecord's
    // `remote_entry_snapshot` doc comment for why `agentguard allow` needs
    // this saved now, at scan time, rather than re-reading the config
    // later (by the time it's approved the entry may already be gone).
    let is_remote = s.launch.is_none() && s.config_source.is_some();
    let (remote_entry_snapshot, config_path, config_entry_key, config_top_level_key) = if is_remote
    {
        (
            s.raw_config_entry.clone(),
            s.config_source.as_ref().map(|cs| cs.path.clone()),
            s.config_source.as_ref().map(|cs| cs.entry_key.clone()),
            s.config_source.as_ref().and_then(|cs| json_top_level_key(cs.kind)),
        )
    } else {
        (None, None, None, None)
    };

    // A Skill has no launch/config_source at all (see DecisionRecord's
    // quarantine_original_path doc comment for why moving the directory,
    // not a hook, is the only enforcement point) — its scan_root at scan
    // time is the only thing `agentguard allow` needs to restore it from
    // quarantine later, so it's captured here the same way a remote MCP
    // entry's config snapshot is: before any quarantine action happens.
    let quarantine_original_path = if s.artifact.kind == ArtifactKind::Skill {
        s.scan_root.clone()
    } else {
        None
    };

    DecisionRecord {
        artifact_id: s.artifact.id.clone(),
        name: s.artifact.name.clone(),
        band: s.band,
        decision,
        total_score: s.breakdown.total(),
        protection_level: level,
        scanned_at_unix: DecisionRecord::now_unix(),
        reasons,
        content_hash: s.artifact.content_hash.clone(),
        capability_snapshot: s.artifact.capability_set().into_iter().collect(),
        shell_command,
        manually_approved: false, // upsert_preserving_approval fixes this up
        remote_entry_snapshot,
        config_path,
        config_entry_key,
        config_top_level_key,
        quarantine_original_path,
        quarantine_current_path: None, // a fresh scan means it's at its original location
    }
}

/// Finds `agentguard-shim(.exe)` next to the running `agentguard` binary.
/// v0 assumes both are built/installed side by side (true for this repo's
/// `target/debug|release/` layout and for the packaged installers in
/// `dist/` — see README's install section); a future packaged install with
/// a different layout should update this, not work around it elsewhere.
fn locate_shim() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let candidate = dir.join(format!("agentguard-shim{}", std::env::consts::EXE_SUFFIX));
    candidate.is_file().then_some(candidate)
}

struct RewriteOutcome {
    newly_protected: usize,
    already_protected: usize,
    /// Remote MCP entries removed from the live config because their
    /// effective decision is BLOCK/QUARANTINE or an unapproved ASK — see
    /// `remove_blocked_remote_entries_json`/`_toml`'s doc comment.
    removed_remote: usize,
    backup_path: Option<PathBuf>,
}

/// Rewrites one config file so each of `artifacts` launches through the
/// shim instead of directly, and removes any remote MCP entry whose
/// effective decision doesn't allow it to run. Backs up the original file
/// (once — never overwritten on subsequent runs) before the first write.
/// Idempotent: an entry already pointing at the shim is left alone and
/// counted as `already_protected`.
///
/// `shim_path` is `None` when `agentguard-shim` couldn't be located next
/// to this binary — local MCP servers and hooks can't be routed through
/// enforcement in that case, but remote-entry removal doesn't need the
/// shim at all (there's no process to launch), so it still proceeds.
///
/// Dispatches to a JSON path (Claude Code / Cursor's `mcpServers`, Claude
/// Code's hooks tree) or a TOML path (Codex's `[mcp_servers.*]`) based on
/// what kind the artifacts for this config file actually are — a
/// `by_config` group is always homogeneous (one physical file only ever
/// holds one agent's config in one format), so checking the first
/// artifact's kind is sufficient.
fn rewrite_config(
    config_path: &Path,
    artifacts: &[&ScannedArtifact],
    shim_path: Option<&Path>,
    store: &DecisionStore,
) -> io::Result<RewriteOutcome> {
    let is_toml = artifacts.iter().any(|s| {
        s.config_source
            .as_ref()
            .map(|cs| cs.kind == ConfigSourceKind::CodexMcpServersToml)
            .unwrap_or(false)
    });
    if is_toml {
        rewrite_config_toml(config_path, artifacts, shim_path, store)
    } else {
        rewrite_config_json(config_path, artifacts, shim_path, store)
    }
}

/// Effective decision for an artifact per `store`, folding in manual
/// approval — falls back to the just-computed scan decision if the store
/// write somehow didn't land (should not happen in practice: `run_init`
/// always upserts every scanned artifact before acting on any of them).
/// Shared by remote-MCP-entry removal and skill quarantine — both are
/// "there's no shim/hook interception point, so change what's on disk"
/// enforcement, just for different artifact shapes.
fn effective_decision_for(store: &DecisionStore, s: &ScannedArtifact) -> Decision {
    store
        .get(&s.artifact.id)
        .map(|r| r.effective_decision())
        .unwrap_or(s.decision)
}

/// An artifact with this effective decision has nothing physically
/// stopping it from being reached (no shim, no hook — see
/// `effective_decision_for`'s doc comment), so the only enforcement point
/// is changing what's on disk: removing a remote MCP entry from its config,
/// or moving a skill's directory out of `.claude/skills/`. Ask is included:
/// an ASK the user hasn't approved yet must not be reachable, same as
/// Block/Quarantine; `effective_decision` already turns an APPROVED Ask
/// into Allow, so this only ever fires for genuinely unapproved entries.
fn decision_requires_removal(decision: Decision) -> bool {
    matches!(decision, Decision::Block | Decision::Quarantine | Decision::Ask)
}

struct QuarantineOutcome {
    quarantined: usize,
    skipped_outside_project: usize,
}

/// Moves a flagged Skill's directory out of `.claude/skills/`.
///
/// Skills are architecturally different from MCP servers and hooks: there
/// is no `PreToolUse`-style interception point at all. Verified 2026-09-05
/// directly against Anthropic's own docs (code.claude.com/docs/en/hooks
/// lists every hook event Claude Code fires — no event corresponds to a
/// skill loading or being invoked; code.claude.com/docs/en/skills confirms
/// a skill's body reaches Claude by direct context injection, never as a
/// tool call). So unlike a hook or an MCP server, there's no "route it
/// through the shim" or "match it in PreToolUse" option to even consider —
/// the only lever is changing what's on disk, the same principle as remote
/// MCP entry removal: Claude Code's own skill-discovery walk can't find a
/// SKILL.md that isn't where it's looking.
///
/// The destination is a `.agentguard-quarantine/<name>` directory sibling
/// to `skills/` (i.e. inside `.claude/`, next to it) — deliberately NOT
/// nested inside `.claude/skills/` itself, so there's no question of
/// whether Claude Code's own one-level skill-discovery walk might still
/// find it there. `agentguard allow <id>` moves it back.
fn quarantine_skills(
    scanned: &[ScannedArtifact],
    store: &DecisionStore,
    project_root: &Path,
    include_user_config: bool,
) -> QuarantineOutcome {
    let mut quarantined = 0;
    let mut skipped_outside_project = 0;

    for s in scanned {
        if s.artifact.kind != ArtifactKind::Skill {
            continue;
        }
        let Some(scan_root) = &s.scan_root else { continue };
        if !decision_requires_removal(effective_decision_for(store, s)) {
            continue;
        }
        if !(include_user_config || scan_root.starts_with(project_root)) {
            skipped_outside_project += 1;
            continue;
        }
        if !scan_root.is_dir() {
            continue; // already moved (or gone) -- nothing to do this run
        }
        let Some(quarantine_dir) = quarantine_target_dir(scan_root) else {
            continue;
        };

        match move_skill_directory(scan_root, &quarantine_dir) {
            Ok(()) => {
                quarantined += 1;
                if let Some(mut record) = store.get(&s.artifact.id) {
                    record.quarantine_original_path = Some(scan_root.clone());
                    record.quarantine_current_path = Some(quarantine_dir);
                    if let Err(e) = store.upsert(record) {
                        eprintln!(
                            "agentguard: quarantined '{}' but failed to update the decision cache: {e}",
                            sanitize_for_display(&s.artifact.name)
                        );
                    }
                }
            }
            Err(e) => eprintln!(
                "agentguard: failed to quarantine skill '{}': {e}",
                sanitize_for_display(&s.artifact.name)
            ),
        }
    }

    QuarantineOutcome { quarantined, skipped_outside_project }
}

/// `.../.claude/skills/<name>` -> `.../.claude/.agentguard-quarantine/<name>`.
fn quarantine_target_dir(skill_dir: &Path) -> Option<PathBuf> {
    let skill_name = skill_dir.file_name()?;
    let skills_dir = skill_dir.parent()?; // .../.claude/skills
    let claude_dir = skills_dir.parent()?; // .../.claude
    Some(claude_dir.join(".agentguard-quarantine").join(skill_name))
}

fn move_skill_directory(from: &Path, to: &Path) -> io::Result<()> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if to.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("quarantine destination {} already exists", to.display()),
        ));
    }
    std::fs::rename(from, to)
}

/// JSON path: Claude Code / Cursor's `mcpServers` (flat map) and the hook
/// trees used by Claude Code, Codex, and Antigravity (nested, no flat key
/// — Claude Code/Codex share an identical `{"hooks": {...}}` wrapper,
/// confirmed against each vendor's own docs; Antigravity's root has no
/// wrapper at all, see `rewrite_hooks`'s `wrapper_key` parameter). Matching
/// `config_source.kind` exhaustively (no wildcard) means a future variant
/// with a different shape forces a deliberate decision here, not a silent
/// (and wrong) fallthrough into this logic.
fn rewrite_config_json(
    config_path: &Path,
    artifacts: &[&ScannedArtifact],
    shim_path: Option<&Path>,
    store: &DecisionStore,
) -> io::Result<RewriteOutcome> {
    let original_text = std::fs::read_to_string(config_path)?;
    let mut json: serde_json::Value = serde_json::from_str(&original_text)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let shim_str = shim_path.map(|p| p.display().to_string());

    let mut mcp_artifacts = Vec::new();
    let mut hook_artifacts = Vec::new();
    let mut remote_artifacts = Vec::new();
    let mut top_level_key = "mcpServers";
    // `Some("hooks")` for Claude Code/Codex's `{"hooks": {...}}` wrapper;
    // `None` for Antigravity, whose hooks.json root IS the event tree with
    // no wrapper key at all — see `ConfigSourceKind::AntigravityHooksJson`'s
    // doc comment. A config-file group is always homogeneous, same
    // reasoning as `top_level_key` above.
    let mut hooks_wrapper_key: Option<&str> = Some("hooks");
    for s in artifacts {
        let Some(config_source) = &s.config_source else {
            continue;
        };
        match config_source.kind {
            ConfigSourceKind::ClaudeCodeMcpServersJson
            | ConfigSourceKind::CursorMcpJson
            | ConfigSourceKind::WindsurfMcpJson
            | ConfigSourceKind::AntigravityMcpJson
            | ConfigSourceKind::GeminiCliSettingsJson
            | ConfigSourceKind::GitHubCopilotCliMcpJson
            | ConfigSourceKind::ClaudeDesktopMcpJson
            | ConfigSourceKind::KiroMcpJson
            | ConfigSourceKind::AmazonQMcpJson
            | ConfigSourceKind::ContinueMcpJson
            | ConfigSourceKind::DevinCliMcpJson
            | ConfigSourceKind::ClineMcpJson
            | ConfigSourceKind::RooCodeMcpJson
            | ConfigSourceKind::JetBrainsMcpJson
            | ConfigSourceKind::TabnineMcpJson => {
                if s.launch.is_some() {
                    mcp_artifacts.push(*s);
                } else {
                    remote_artifacts.push(*s);
                }
            }
            // The shapes with a different top-level key — see
            // `parse_mcp_servers_json`'s `top_level_key` doc comment. A
            // config-file group is always homogeneous (one physical file
            // only ever holds one agent's config), so it's safe to just
            // overwrite this on every matching artifact rather than
            // reconcile conflicting values.
            ConfigSourceKind::VsCodeCopilotMcpJson => {
                top_level_key = "servers";
                if s.launch.is_some() {
                    mcp_artifacts.push(*s);
                } else {
                    remote_artifacts.push(*s);
                }
            }
            ConfigSourceKind::AmpMcpJson => {
                top_level_key = "amp.mcpServers";
                if s.launch.is_some() {
                    mcp_artifacts.push(*s);
                } else {
                    remote_artifacts.push(*s);
                }
            }
            ConfigSourceKind::ZedMcpJson => {
                top_level_key = "context_servers";
                if s.launch.is_some() {
                    mcp_artifacts.push(*s);
                } else {
                    remote_artifacts.push(*s);
                }
            }
            // OpenClaw's shape is nested two levels (`{"mcp": {"servers":
            // {...}}}`) and opencode's one level (`{"mcp": {...}}`),
            // neither a single flat top-level key — the shared
            // `rewrite_mcp_servers`/`remove_blocked_remote_entries_json`
            // functions below only know how to look up ONE string key at
            // `json`'s own root, so they can't reach into a nested path.
            // Discovery/scoring still works fully (openclaw.rs/opencode.rs
            // each handle their own nested lookup independently) — this is
            // scoped as discovery-only for now, matching how Cursor/Codex
            // had discovery-only before their own enforcement was added
            // later, rather than forcing a real shape mismatch through a
            // mechanism that doesn't fit it. A future nested-path-aware
            // rewrite function would close this, not a quick patch here.
            ConfigSourceKind::OpenClawJson | ConfigSourceKind::OpenCodeMcpJson => {}
            ConfigSourceKind::ClaudeCodeHooksJson
            | ConfigSourceKind::CodexHooksJson
            | ConfigSourceKind::GeminiCliHooksJson
            | ConfigSourceKind::GitHubCopilotCliHooksJson
            | ConfigSourceKind::DevinCliHooksJson => {
                if s.launch.is_some() {
                    hook_artifacts.push(*s);
                }
            }
            ConfigSourceKind::AntigravityHooksJson | ConfigSourceKind::DevinCliProjectHooksJson => {
                hooks_wrapper_key = None;
                if s.launch.is_some() {
                    hook_artifacts.push(*s);
                }
            }
            // Never reached: rewrite_config routes any group containing a
            // Codex artifact to rewrite_config_toml instead, and a group
            // is always homogeneous. Matched anyway so a shape genuinely
            // different from both existing JSON shapes forces a decision
            // here rather than a silent fallthrough.
            ConfigSourceKind::CodexMcpServersToml => {}
        }
    }

    let (mcp_new, mcp_already) = match &shim_str {
        Some(s) => rewrite_mcp_servers(&mut json, &mcp_artifacts, s, top_level_key),
        None => (0, 0),
    };
    let (hook_new, hook_already) = match &shim_str {
        Some(s) => rewrite_hooks(&mut json, &hook_artifacts, s, hooks_wrapper_key),
        None => (0, 0),
    };
    let removed_remote =
        remove_blocked_remote_entries_json(&mut json, &remote_artifacts, store, top_level_key);
    let newly_protected = mcp_new + hook_new;
    let already_protected = mcp_already + hook_already;

    if newly_protected == 0 && removed_remote == 0 {
        return Ok(RewriteOutcome {
            newly_protected: 0,
            already_protected,
            removed_remote: 0,
            backup_path: None,
        });
    }

    let backup_path = PathBuf::from(format!("{}.agentguard-backup", config_path.display()));
    if !backup_path.exists() {
        std::fs::write(&backup_path, &original_text)?;
    }

    let pretty = serde_json::to_string_pretty(&json)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    std::fs::write(config_path, pretty)?;

    Ok(RewriteOutcome {
        newly_protected,
        already_protected,
        removed_remote,
        backup_path: Some(backup_path),
    })
}

/// Removes each remote artifact's entry from the (already-parsed)
/// `mcpServers` map when its effective decision doesn't allow it to run —
/// see `decision_requires_removal`. There's no shim to route a
/// remote server through (no local process to launch), so physically
/// deleting the entry from the live config is the only interception point:
/// the agent simply can't connect to a server that isn't listed. The
/// removed value was already snapshotted into the decision store at scan
/// time (`record_for`'s `remote_entry_snapshot`), so `agentguard allow`
/// can put it back later without needing this file to still contain it.
fn remove_blocked_remote_entries_json(
    json: &mut serde_json::Value,
    remote_artifacts: &[&ScannedArtifact],
    store: &DecisionStore,
    top_level_key: &str,
) -> usize {
    if remote_artifacts.is_empty() {
        return 0;
    }
    let Some(servers) = json.get_mut(top_level_key).and_then(|v| v.as_object_mut()) else {
        return 0;
    };
    let mut removed = 0;
    for s in remote_artifacts {
        let config_source = s.config_source.as_ref().unwrap(); // filtered by caller
        if !decision_requires_removal(effective_decision_for(store, s)) {
            continue;
        }
        if servers.remove(&config_source.entry_key).is_some() {
            removed += 1;
        }
    }
    removed
}

/// TOML path: Codex's `[mcp_servers.<entry_key>]` — structurally the same
/// flat-map-of-tables concept as `mcpServers`, just a different format
/// (verified against OpenAI's own docs — see codex.rs's module doc
/// comment). Parses leniently (agentguard_adapters::codex's
/// backslash-repair fallback — this machine's own real `~/.codex/
/// config.toml` needs it, confirmed live), so a file that only parses
/// after repair comes out the other side as valid TOML, which is a
/// reasonable side effect, not a goal in itself.
fn rewrite_config_toml(
    config_path: &Path,
    artifacts: &[&ScannedArtifact],
    shim_path: Option<&Path>,
    store: &DecisionStore,
) -> io::Result<RewriteOutcome> {
    let original_text = std::fs::read_to_string(config_path)?;
    let mut doc = agentguard_adapters::codex::parse_toml_leniently(&original_text).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "could not parse config.toml, even with the lenient backslash repair",
        )
    })?;
    let shim_str = shim_path.map(|p| p.display().to_string());

    let mut newly_protected = 0;
    let mut already_protected = 0;

    if let (Some(servers), Some(shim_str)) = (
        doc.get_mut("mcp_servers").and_then(|v| v.as_table_mut()),
        &shim_str,
    ) {
        for s in artifacts {
            let Some(config_source) = &s.config_source else {
                continue;
            };
            if config_source.kind != ConfigSourceKind::CodexMcpServersToml {
                continue;
            }
            let Some(launch) = &s.launch else { continue };

            let Some(entry) = servers
                .get_mut(&config_source.entry_key)
                .and_then(|v| v.as_table_mut())
            else {
                continue;
            };

            let current_command = entry.get("command").and_then(|v| v.as_str()).unwrap_or("");
            if current_command == shim_str.as_str() {
                already_protected += 1;
                continue;
            }

            let mut new_args = vec![
                toml::Value::String(s.artifact.id.clone()),
                toml::Value::String("--".to_string()),
                toml::Value::String(launch.command.clone()),
            ];
            new_args.extend(launch.args.iter().cloned().map(toml::Value::String));

            entry.insert("command".to_string(), toml::Value::String(shim_str.clone()));
            entry.insert("args".to_string(), toml::Value::Array(new_args));
            newly_protected += 1;
        }
    }

    let remote_artifacts: Vec<&ScannedArtifact> = artifacts
        .iter()
        .filter(|s| {
            s.launch.is_none()
                && s.config_source
                    .as_ref()
                    .map(|cs| cs.kind == ConfigSourceKind::CodexMcpServersToml)
                    .unwrap_or(false)
        })
        .copied()
        .collect();
    let removed_remote = remove_blocked_remote_entries_toml(&mut doc, &remote_artifacts, store);

    if newly_protected == 0 && removed_remote == 0 {
        return Ok(RewriteOutcome {
            newly_protected: 0,
            already_protected,
            removed_remote: 0,
            backup_path: None,
        });
    }

    let backup_path = PathBuf::from(format!("{}.agentguard-backup", config_path.display()));
    if !backup_path.exists() {
        std::fs::write(&backup_path, &original_text)?;
    }

    let pretty = toml::to_string_pretty(&doc)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    std::fs::write(config_path, pretty)?;

    Ok(RewriteOutcome {
        newly_protected,
        already_protected,
        removed_remote,
        backup_path: Some(backup_path),
    })
}

/// TOML equivalent of `remove_blocked_remote_entries_json` — see its doc
/// comment for why removal (not a shim wrap) is the enforcement mechanism
/// for remote MCP servers.
fn remove_blocked_remote_entries_toml(
    doc: &mut toml::Value,
    remote_artifacts: &[&ScannedArtifact],
    store: &DecisionStore,
) -> usize {
    if remote_artifacts.is_empty() {
        return 0;
    }
    let Some(servers) = doc.get_mut("mcp_servers").and_then(|v| v.as_table_mut()) else {
        return 0;
    };
    let mut removed = 0;
    for s in remote_artifacts {
        let config_source = s.config_source.as_ref().unwrap(); // filtered by caller
        if !decision_requires_removal(effective_decision_for(store, s)) {
            continue;
        }
        if servers.remove(&config_source.entry_key).is_some() {
            removed += 1;
        }
    }
    removed
}

/// Rewrites `{ "<top_level_key>": { "<entry_key>": { command, args } } }`
/// entries — a flat map, one lookup per artifact. `top_level_key` is
/// `"mcpServers"` for every agent covered so far except VS Code's Copilot
/// Chat extension (`"servers"` — see `ConfigSourceKind::
/// VsCodeCopilotMcpJson`'s doc comment).
fn rewrite_mcp_servers(
    json: &mut serde_json::Value,
    artifacts: &[&ScannedArtifact],
    shim_str: &str,
    top_level_key: &str,
) -> (usize, usize) {
    let mut newly_protected = 0;
    let mut already_protected = 0;
    let Some(servers) = json.get_mut(top_level_key).and_then(|v| v.as_object_mut()) else {
        return (0, 0);
    };

    for s in artifacts {
        let config_source = s.config_source.as_ref().unwrap(); // filtered by caller
        let launch = s.launch.as_ref().unwrap(); // filtered by caller

        let Some(entry) = servers
            .get_mut(&config_source.entry_key)
            .and_then(|v| v.as_object_mut())
        else {
            continue;
        };

        let current_command = entry.get("command").and_then(|c| c.as_str()).unwrap_or("");
        if current_command == shim_str {
            already_protected += 1;
            continue;
        }

        let mut new_args = vec![
            serde_json::Value::String(s.artifact.id.clone()),
            serde_json::Value::String("--".to_string()),
            serde_json::Value::String(launch.command.clone()),
        ];
        new_args.extend(launch.args.iter().cloned().map(serde_json::Value::String));

        entry.insert(
            "command".to_string(),
            serde_json::Value::String(shim_str.to_string()),
        );
        entry.insert("args".to_string(), serde_json::Value::Array(new_args));
        newly_protected += 1;
    }

    (newly_protected, already_protected)
}

/// Rewrites hook entries — shared by Claude Code's `settings.json`, Codex's
/// `hooks.json` (identical `{"hooks": {...}}` shape), and Antigravity's
/// `hooks.json` (no wrapper key at all — the root object IS the event
/// tree, see `ConfigSourceKind::AntigravityHooksJson`'s doc comment).
/// `wrapper_key` is `Some("hooks")` for the first two, `None` for
/// Antigravity. There's no flat key to look up by — a hook's `entry_key`
/// is `"hook-<i>"`, its index in the same depth-first, object-then-array
/// traversal order hooks_config.rs's `collect_command_strings` uses to
/// assign it in the first place (including its `"enabled": false` skip,
/// mirrored below so index numbering always matches what discovery
/// assigned) — so this walks the hooks tree in that identical order and
/// rewrites the i-th `"command"` field found for any index we have a
/// target for.
fn rewrite_hooks(
    json: &mut serde_json::Value,
    artifacts: &[&ScannedArtifact],
    shim_str: &str,
    wrapper_key: Option<&str>,
) -> (usize, usize) {
    let mut targets: BTreeMap<usize, &ScannedArtifact> = BTreeMap::new();
    for s in artifacts {
        let entry_key = &s.config_source.as_ref().unwrap().entry_key; // filtered by caller
        if let Some(idx_str) = entry_key.strip_prefix("hook-") {
            if let Ok(idx) = idx_str.parse::<usize>() {
                targets.insert(idx, s);
            }
        }
    }
    if targets.is_empty() {
        return (0, 0);
    }

    let hooks_val = match wrapper_key {
        Some(key) => match json.get_mut(key) {
            Some(v) => v,
            None => return (0, 0),
        },
        None => json,
    };

    let mut newly_protected = 0;
    let mut already_protected = 0;
    let mut index = 0usize;
    walk_and_rewrite_hook_commands(
        hooks_val,
        &mut index,
        &targets,
        shim_str,
        &mut newly_protected,
        &mut already_protected,
    );
    (newly_protected, already_protected)
}

fn walk_and_rewrite_hook_commands(
    value: &mut serde_json::Value,
    index: &mut usize,
    targets: &BTreeMap<usize, &ScannedArtifact>,
    shim_str: &str,
    newly_protected: &mut usize,
    already_protected: &mut usize,
) {
    match value {
        serde_json::Value::Object(map) => {
            // Mirrors hooks_config.rs's collect_command_strings: a hook
            // (Antigravity's shape) carrying "enabled": false never runs,
            // so it must be skipped here exactly as discovery skipped it —
            // otherwise the index numbering the two sides agree on would
            // silently drift apart.
            if matches!(map.get("enabled"), Some(serde_json::Value::Bool(false))) {
                return;
            }
            // Mirrors hooks_config.rs's collect_command_strings: GitHub
            // Copilot CLI's own canonical examples use "bash"/"powershell"
            // instead of "command" — see agentguard_adapters::
            // HOOK_COMMAND_FIELDS's doc comment. Each present field is its
            // own indexed target, same as discovery treats each one as a
            // separate raw command.
            for field in agentguard_adapters::HOOK_COMMAND_FIELDS {
                let has_command = matches!(map.get(field), Some(serde_json::Value::String(_)));
                if !has_command {
                    continue;
                }
                let this_index = *index;
                *index += 1;
                if let Some(s) = targets.get(&this_index) {
                    let current = map.get(field).and_then(|c| c.as_str()).unwrap_or("");
                    if current.starts_with(&format!("\"{shim_str}\"")) {
                        *already_protected += 1;
                    } else {
                        // Deliberately does NOT embed the real command —
                        // see DecisionRecord.shell_command's doc comment.
                        // This string is safe for the agent's own shell to
                        // re-parse: two quoted tokens (no metacharacters
                        // possible in either — the shim path is a
                        // filesystem path, the artifact id is hash-based,
                        // see hooks_config.rs's short_hash) and a literal
                        // flag, nothing else.
                        let wrapped = format!("\"{shim_str}\" \"{}\" --shell", s.artifact.id);
                        map.insert(field.to_string(), serde_json::Value::String(wrapped));
                        *newly_protected += 1;
                    }
                }
            }
            for v in map.values_mut() {
                walk_and_rewrite_hook_commands(
                    v,
                    index,
                    targets,
                    shim_str,
                    newly_protected,
                    already_protected,
                );
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                walk_and_rewrite_hook_commands(
                    item,
                    index,
                    targets,
                    shim_str,
                    newly_protected,
                    already_protected,
                );
            }
        }
        _ => {}
    }
}

pub fn run_init(
    project: &Path,
    level: ProtectionLevel,
    store_override: Option<PathBuf>,
    include_user_config: bool,
    fetch_registry: bool,
) {
    let project_root = project
        .canonicalize()
        .unwrap_or_else(|_| project.to_path_buf());
    let engine = RiskEngine::new();
    let scanned = collect(&project_root, &engine, level, fetch_registry);
    let store = resolve_store(store_override);

    if scanned.is_empty() {
        println!("No agent artifacts found under {}.", project_root.display());
        return;
    }

    for s in &scanned {
        let record = record_for(&store, s, level);
        if let Err(e) = upsert_preserving_approval(&store, record) {
            eprintln!(
                "agentguard: failed to write decision cache for '{}': {e}",
                sanitize_for_display(&s.artifact.name)
            );
        }
    }

    // SAFETY BOUNDARY: a config file outside `project_root` (the classic
    // case is `~/.claude.json`, Claude Code's user-scope MCP config) is
    // never rewritten unless the caller explicitly opts in. `discover()`
    // intentionally reports user-scope artifacts too (that's what makes
    // `scan`/`status` show your whole machine), but reporting is read-only
    // and rewriting a live config outside the project you pointed `init`
    // at is a different, much bigger action — it should never happen as a
    // side effect of scoping this to one project. This was a real bug, not
    // a hypothetical one: an early version of this command rewrote the
    // live ~/.claude.json on the machine it was built on.
    // Includes remote MCP entries (`launch: None`) as well as local
    // MCP-server/hook artifacts (`launch: Some`) — a remote entry has no
    // process for the shim to wrap, but it still needs to go through this
    // same per-config-file rewrite pass so a BLOCK/unapproved-ASK entry
    // gets physically removed from the live config (see rewrite_config's
    // doc comment).
    let mut by_config: BTreeMap<PathBuf, Vec<&ScannedArtifact>> = BTreeMap::new();
    let mut skipped_outside_project = 0usize;
    for s in &scanned {
        if let Some(cs) = &s.config_source {
            if include_user_config || cs.path.starts_with(&project_root) {
                by_config.entry(cs.path.clone()).or_default().push(s);
            } else {
                skipped_outside_project += 1;
            }
        }
    }

    println!("AgentGuard init\n");
    println!(
        "{} artifact(s) scanned and cached (protection level: {level_name}).",
        scanned.len(),
        level_name = level_name(level)
    );
    crate::pipeline::print_registry_fetch_summary(&scanned, fetch_registry);

    if skipped_outside_project > 0 {
        println!(
            "{skipped_outside_project} rewritable artifact(s) found outside {} (e.g. a user-level config) — NOT rewritten.",
            project_root.display()
        );
        println!("Re-run with --include-user-config to also protect those.");
    }

    // Skills go through a separate path from `by_config` below: they have
    // no shim-wrappable launch and no config-file entry to remove, so
    // there's nothing for `rewrite_config` to do with them. See
    // `quarantine_skills`'s doc comment for why moving the directory is
    // the only enforcement lever for this artifact kind, and why that
    // means this must run even when there's no rewritable config at all.
    let skill_outcome = quarantine_skills(&scanned, &store, &project_root, include_user_config);
    if skill_outcome.quarantined > 0 {
        println!(
            "{} skill(s) quarantined (blocked or awaiting approval) — moved out of .claude/skills/.",
            skill_outcome.quarantined
        );
        println!("Run `agentguard allow <id>` to approve and restore one.");
    }
    if skill_outcome.skipped_outside_project > 0 {
        println!(
            "{} flagged skill(s) found outside {} — NOT quarantined.",
            skill_outcome.skipped_outside_project,
            project_root.display()
        );
        println!("Re-run with --include-user-config to also quarantine those.");
    }

    if by_config.is_empty() {
        println!("No rewritable MCP server configs found inside this project — nothing more to route through enforcement.");
        print_risk_summary(&scanned);
        return;
    }

    // Missing shim only blocks local MCP-server/hook wrapping — remote
    // MCP entries have no local process for it to wrap in the first
    // place, so removing a blocked/unapproved one from the config still
    // goes ahead below.
    let shim_path = locate_shim();
    if shim_path.is_none() {
        eprintln!(
            "\nagentguard: could not find agentguard-shim next to this executable — local MCP servers and hooks were NOT routed through enforcement."
        );
        eprintln!("(remote MCP server blocking still applies; the decision cache above was still written.)");
    }

    let mut newly_protected_total = 0;
    let mut already_protected_total = 0;
    let mut removed_remote_total = 0;
    let mut backups = Vec::new();

    for (config_path, artifacts) in &by_config {
        match rewrite_config(config_path, artifacts, shim_path.as_deref(), &store) {
            Ok(outcome) => {
                newly_protected_total += outcome.newly_protected;
                already_protected_total += outcome.already_protected;
                removed_remote_total += outcome.removed_remote;
                if let Some(b) = outcome.backup_path {
                    backups.push(b);
                }
            }
            Err(e) => {
                eprintln!("agentguard: failed to rewrite {}: {e}", config_path.display());
            }
        }
    }

    println!(
        "{newly_protected_total} artifact(s) (MCP servers / hooks) newly routed through the enforcement shim."
    );
    if already_protected_total > 0 {
        println!("{already_protected_total} artifact(s) already protected (unchanged).");
    }
    if removed_remote_total > 0 {
        println!(
            "{removed_remote_total} remote MCP server entrie(s) removed from config (blocked or awaiting approval)."
        );
        println!("Run `agentguard allow <id>` to approve and restore one.");
    }
    if !backups.is_empty() {
        println!("\nOriginal config(s) backed up before the first rewrite:");
        for b in &backups {
            println!("  {}", b.display());
        }
    }
    print_risk_summary(&scanned);
}

fn print_risk_summary(scanned: &[ScannedArtifact]) {
    let critical = scanned.iter().filter(|s| s.band == RiskBand::Critical).count();
    let blocked = scanned.iter().filter(|s| s.decision == Decision::Block).count();
    println!("\n{critical} critical, {blocked} blocked.");
}

fn level_name(level: ProtectionLevel) -> &'static str {
    match level {
        ProtectionLevel::Quiet => "Quiet",
        ProtectionLevel::Balanced => "Balanced",
        ProtectionLevel::Strict => "Strict",
    }
}

pub fn run_allow(artifact_id: &str, store_override: Option<PathBuf>) {
    let store = resolve_store(store_override);
    match store.approve(artifact_id) {
        Ok(true) => {
            println!("Approved '{artifact_id}'.");
            println!("It will be allowed to run until it changes (a different score/decision on the next scan resets this).");
            restore_remote_entry_if_needed(&store, artifact_id);
            restore_quarantined_skill_if_needed(&store, artifact_id);
        }
        Ok(false) => {
            eprintln!(
                "agentguard: '{artifact_id}' has never been scanned. Run `agentguard scan` or `agentguard init` first."
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("agentguard: failed to update the decision cache: {e}");
            std::process::exit(1);
        }
    }
}

/// After approving a remote MCP server, put its entry back if `agentguard
/// init` previously removed it from the live config — see
/// `DecisionRecord::remote_entry_snapshot`'s doc comment for why this is
/// the only way to restore it (discovery can no longer find an entry
/// that's no longer in the file). A no-op for any non-remote artifact
/// (those fields are `None`) and for a remote entry that was never
/// removed in the first place (still present — nothing to do).
fn restore_remote_entry_if_needed(store: &DecisionStore, artifact_id: &str) {
    let Some(record) = store.get(artifact_id) else {
        return;
    };
    let (Some(snapshot), Some(config_path), Some(entry_key)) = (
        &record.remote_entry_snapshot,
        &record.config_path,
        &record.config_entry_key,
    ) else {
        return;
    };
    // Older store records written before `config_top_level_key` existed
    // won't have it — every JSON agent except VS Code used "mcpServers"
    // at the time, so that's the correct fallback, not a guess.
    let top_level_key = record.config_top_level_key.as_deref().unwrap_or("mcpServers");

    match restore_remote_entry(config_path, entry_key, snapshot, top_level_key) {
        Ok(true) => println!(
            "Restored '{}' in {}.",
            sanitize_for_display(entry_key),
            config_path.display()
        ),
        Ok(false) => {} // already present -- nothing to restore
        Err(e) => eprintln!(
            "agentguard: approved, but failed to restore the config entry at {}: {e}",
            config_path.display()
        ),
    }
}

/// After approving a Skill, move its directory back from quarantine — see
/// `quarantine_skills`'s doc comment for why moving it, not re-registering
/// a hook, is the enforcement mechanism this restores from. A no-op for
/// any non-Skill artifact (those fields are `None`) and for a skill that
/// was never quarantined in the first place.
fn restore_quarantined_skill_if_needed(store: &DecisionStore, artifact_id: &str) {
    let Some(mut record) = store.get(artifact_id) else {
        return;
    };
    let (Some(current), Some(original)) = (
        record.quarantine_current_path.clone(),
        record.quarantine_original_path.clone(),
    ) else {
        return;
    };

    if !current.is_dir() {
        eprintln!(
            "agentguard: approved, but the quarantined skill directory {} is missing -- nothing to restore.",
            current.display()
        );
        return;
    }
    if original.exists() {
        eprintln!(
            "agentguard: approved, but {} already exists -- not overwriting it. The quarantined copy is still at {}.",
            original.display(),
            current.display()
        );
        return;
    }

    match std::fs::rename(&current, &original) {
        Ok(()) => {
            println!("Restored skill to {}.", original.display());
            record.quarantine_current_path = None;
            if let Err(e) = store.upsert(record) {
                eprintln!(
                    "agentguard: restored the skill directory but failed to update the decision cache: {e}"
                );
            }
        }
        Err(e) => eprintln!(
            "agentguard: approved, but failed to restore the skill directory: {e}"
        ),
    }
}

/// Re-inserts `entry_key: snapshot` into `config_path`'s MCP-servers map if
/// it's missing, dispatching on JSON vs TOML by file extension (the same
/// two shapes `rewrite_config` handles; a `.toml` config is Codex's, every
/// other config in this codebase is one of the two JSON shapes). Returns
/// `Ok(false)` — not an error — when the entry is already present, so the
/// caller can tell "nothing to do" apart from "something went wrong."
fn restore_remote_entry(
    config_path: &Path,
    entry_key: &str,
    snapshot: &serde_json::Value,
    top_level_key: &str,
) -> io::Result<bool> {
    let is_toml = config_path.extension().and_then(|e| e.to_str()) == Some("toml");
    if is_toml {
        restore_remote_entry_toml(config_path, entry_key, snapshot)
    } else {
        restore_remote_entry_json(config_path, entry_key, snapshot, top_level_key)
    }
}

fn restore_remote_entry_json(
    config_path: &Path,
    entry_key: &str,
    snapshot: &serde_json::Value,
    top_level_key: &str,
) -> io::Result<bool> {
    let original_text = std::fs::read_to_string(config_path)?;
    let mut json: serde_json::Value = serde_json::from_str(&original_text)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let root = json
        .as_object_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "config root is not a JSON object"))?;
    let servers = root
        .entry(top_level_key.to_string())
        .or_insert_with(|| serde_json::Value::Object(Default::default()))
        .as_object_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("{top_level_key} is not an object")))?;

    if servers.contains_key(entry_key) {
        return Ok(false);
    }
    servers.insert(entry_key.to_string(), snapshot.clone());

    let pretty = serde_json::to_string_pretty(&json)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    std::fs::write(config_path, pretty)?;
    Ok(true)
}

fn restore_remote_entry_toml(
    config_path: &Path,
    entry_key: &str,
    snapshot: &serde_json::Value,
) -> io::Result<bool> {
    let original_text = std::fs::read_to_string(config_path)?;
    let mut doc = agentguard_adapters::codex::parse_toml_leniently(&original_text).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "could not parse config.toml, even with the lenient backslash repair",
        )
    })?;

    let root = doc
        .as_table_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "config root is not a TOML table"))?;
    let servers = root
        .entry("mcp_servers")
        .or_insert_with(|| toml::Value::Table(Default::default()))
        .as_table_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "mcp_servers is not a table"))?;

    if servers.contains_key(entry_key) {
        return Ok(false);
    }
    let toml_value: toml::Value = serde_json::from_value(snapshot.clone()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("saved snapshot doesn't convert back to TOML: {e}"),
        )
    })?;
    servers.insert(entry_key.to_string(), toml_value);

    let pretty = toml::to_string_pretty(&doc)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    std::fs::write(config_path, pretty)?;
    Ok(true)
}

pub fn run_why(artifact_id: &str, store_override: Option<PathBuf>) {
    let store = resolve_store(store_override);
    let Some(record) = store.get(artifact_id) else {
        eprintln!(
            "agentguard: '{artifact_id}' has never been scanned. Run `agentguard scan` or `agentguard init` first."
        );
        std::process::exit(1);
    };

    let approval_note = if record.manually_approved {
        " (manually approved -> effectively ALLOW)"
    } else {
        ""
    };
    println!(
        "{} — {} (score {}), decision: {}{approval_note}",
        sanitize_for_display(&record.name), record.band, record.total_score, record.decision
    );
    println!();
    for r in &record.reasons {
        println!("  {r}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentguard_adapters::{ConfigSource, LaunchCommand};
    use agentguard_core::{Artifact, ArtifactKind, ArtifactSource, PublisherIdentity, ScoreBreakdown};
    use std::collections::BTreeSet;

    fn unique_temp_dir(name: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "agentguard-init-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    fn synthetic_scanned_artifact(
        name: &str,
        config_path: PathBuf,
        command: &str,
        args: Vec<String>,
    ) -> ScannedArtifact {
        let source = ArtifactSource::LocalPath(command.to_string());
        let artifact = Artifact {
            id: format!("MCP server:{name}:local:{command}"),
            kind: ArtifactKind::McpServer,
            name: name.to_string(),
            version: None,
            publisher: PublisherIdentity::default(),
            source,
            content_hash: None,
            capabilities: vec![],
            discovered_by: BTreeSet::new(),
        };
        ScannedArtifact {
            agent_name: "codex",
            artifact,
            breakdown: ScoreBreakdown::default(),
            band: RiskBand::Low,
            decision: Decision::Allow,
            location: command.to_string(),
            launch: Some(LaunchCommand {
                command: command.to_string(),
                args,
            }),
            config_source: Some(ConfigSource {
                path: config_path,
                kind: ConfigSourceKind::CodexMcpServersToml,
                entry_key: name.to_string(),
            }),
            raw_config_entry: None,
            scan_root: None,
            registry_fetch: None,
        }
    }

    fn temp_store(dir: &Path) -> DecisionStore {
        DecisionStore::open_at(dir.join("decisions.json"))
    }

    #[test]
    fn rewrite_config_toml_routes_entry_through_shim_and_is_idempotent() {
        let dir = unique_temp_dir("toml-rewrite");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.toml");
        std::fs::write(
            &config_path,
            "[mcp_servers.example]\ncommand = \"node\"\nargs = [\"server.js\"]\n",
        )
        .unwrap();
        let shim_path = dir.join("agentguard-shim.exe");
        let store = temp_store(&dir);

        let scanned = synthetic_scanned_artifact(
            "example",
            config_path.clone(),
            "node",
            vec!["server.js".to_string()],
        );

        let outcome =
            rewrite_config_toml(&config_path, &[&scanned], Some(&shim_path), &store).unwrap();
        assert_eq!(outcome.newly_protected, 1);
        assert_eq!(outcome.already_protected, 0);
        assert!(outcome.backup_path.is_some());
        assert!(outcome.backup_path.unwrap().exists());

        let rewritten = std::fs::read_to_string(&config_path).unwrap();
        let parsed: toml::Value = toml::from_str(&rewritten).unwrap();
        let entry = parsed
            .get("mcp_servers")
            .and_then(|v| v.get("example"))
            .unwrap();
        assert_eq!(
            entry.get("command").and_then(|v| v.as_str()),
            Some(shim_path.display().to_string()).as_deref()
        );
        let entry_args: Vec<&str> = entry
            .get("args")
            .and_then(|v| v.as_array())
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(
            entry_args,
            vec!["MCP server:example:local:node", "--", "node", "server.js"]
        );

        // Idempotent: re-running against the now-rewritten file must not
        // re-wrap an already-protected entry.
        let outcome2 =
            rewrite_config_toml(&config_path, &[&scanned], Some(&shim_path), &store).unwrap();
        assert_eq!(outcome2.newly_protected, 0);
        assert_eq!(outcome2.already_protected, 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rewrite_config_toml_recovers_a_malformed_real_world_file() {
        // The same real-world breakage codex.rs's own tests cover for
        // discovery — confirming the rewrite path also survives it, not
        // just read-only parsing.
        let dir = unique_temp_dir("toml-rewrite-malformed");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.toml");
        std::fs::write(
            &config_path,
            "[mcp_servers.bastion]\ncommand = \"C:\\Users\\Hubby\\bastion.exe\"\n",
        )
        .unwrap();
        let shim_path = dir.join("agentguard-shim.exe");
        let store = temp_store(&dir);

        let scanned = synthetic_scanned_artifact(
            "bastion",
            config_path.clone(),
            r"C:\Users\Hubby\bastion.exe",
            vec![],
        );

        let outcome =
            rewrite_config_toml(&config_path, &[&scanned], Some(&shim_path), &store).unwrap();
        assert_eq!(outcome.newly_protected, 1);

        // And the rewritten file is now genuinely valid TOML, strictly.
        let rewritten = std::fs::read_to_string(&config_path).unwrap();
        assert!(toml::from_str::<toml::Value>(&rewritten).is_ok());

        std::fs::remove_dir_all(&dir).ok();
    }

    fn synthetic_remote_scanned_artifact(
        name: &str,
        config_path: PathBuf,
        url: &str,
        decision: Decision,
        band: RiskBand,
    ) -> ScannedArtifact {
        let source = ArtifactSource::RemoteUrl(url.to_string());
        let artifact = Artifact {
            id: format!("mcp-server:{name}:remote:{url}"),
            kind: ArtifactKind::McpServer,
            name: name.to_string(),
            version: None,
            publisher: PublisherIdentity::default(),
            source,
            content_hash: None,
            capabilities: vec![],
            discovered_by: BTreeSet::new(),
        };
        ScannedArtifact {
            agent_name: "claude-code",
            artifact,
            breakdown: ScoreBreakdown::default(),
            band,
            decision,
            location: url.to_string(),
            launch: None,
            config_source: Some(ConfigSource {
                path: config_path,
                kind: ConfigSourceKind::ClaudeCodeMcpServersJson,
                entry_key: name.to_string(),
            }),
            raw_config_entry: Some(serde_json::json!({ "type": "http", "url": url })),
            scan_root: None,
            registry_fetch: None,
        }
    }

    #[test]
    fn rewrite_config_json_removes_a_blocked_remote_entry_and_keeps_an_allowed_one() {
        let dir = unique_temp_dir("remote-removal");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("mcp.json");
        std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&serde_json::json!({
                "mcpServers": {
                    "evil": { "type": "http", "url": "https://evil.example.com/mcp" },
                    "good": { "type": "http", "url": "https://good.example.com/mcp" }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let store = temp_store(&dir);

        let evil = synthetic_remote_scanned_artifact(
            "evil",
            config_path.clone(),
            "https://evil.example.com/mcp",
            Decision::Block,
            RiskBand::Critical,
        );
        let good = synthetic_remote_scanned_artifact(
            "good",
            config_path.clone(),
            "https://good.example.com/mcp",
            Decision::Allow,
            RiskBand::Low,
        );

        // Store is empty -- effective_decision_for falls back to each
        // artifact's own scan decision, same as a fresh first-ever scan.
        let outcome = rewrite_config_json(&config_path, &[&evil, &good], None, &store).unwrap();
        assert_eq!(outcome.removed_remote, 1);
        assert_eq!(outcome.newly_protected, 0);
        assert!(outcome.backup_path.is_some());

        let rewritten: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert!(
            rewritten["mcpServers"].get("evil").is_none(),
            "a BLOCK-decision remote entry must be removed from the live config"
        );
        assert!(
            rewritten["mcpServers"].get("good").is_some(),
            "an ALLOW-decision remote entry must be left in place"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rewrite_config_json_leaves_a_manually_approved_ask_entry_in_place() {
        let dir = unique_temp_dir("remote-approved-stays");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("mcp.json");
        std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&serde_json::json!({
                "mcpServers": {
                    "askme": { "type": "http", "url": "https://askme.example.com/mcp" }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let store = temp_store(&dir);

        let askme = synthetic_remote_scanned_artifact(
            "askme",
            config_path.clone(),
            "https://askme.example.com/mcp",
            Decision::Ask,
            RiskBand::Medium,
        );
        // Simulate a prior `agentguard allow` -- the raw engine decision
        // is still Ask, but manual approval makes effective_decision()
        // Allow, which must keep the entry in the config.
        store
            .upsert(DecisionRecord {
                artifact_id: askme.artifact.id.clone(),
                name: askme.artifact.name.clone(),
                band: askme.band,
                decision: Decision::Ask,
                total_score: 40,
                protection_level: ProtectionLevel::Balanced,
                scanned_at_unix: DecisionRecord::now_unix(),
                reasons: vec![],
                content_hash: None,
                capability_snapshot: vec![],
                shell_command: None,
                manually_approved: true,
                remote_entry_snapshot: askme.raw_config_entry.clone(),
                config_path: Some(config_path.clone()),
                config_entry_key: Some("askme".to_string()),
                config_top_level_key: Some("mcpServers".to_string()),
                quarantine_original_path: None,
                quarantine_current_path: None,
            })
            .unwrap();

        let outcome = rewrite_config_json(&config_path, &[&askme], None, &store).unwrap();
        assert_eq!(outcome.removed_remote, 0);

        let rewritten: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert!(rewritten["mcpServers"].get("askme").is_some());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn restore_remote_entry_json_reinserts_a_removed_entry_and_is_idempotent() {
        let dir = unique_temp_dir("remote-restore-json");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("mcp.json");
        std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&serde_json::json!({ "mcpServers": {} })).unwrap(),
        )
        .unwrap();

        let snapshot = serde_json::json!({ "type": "http", "url": "https://mcp.linear.app/mcp" });
        let restored = restore_remote_entry_json(&config_path, "linear", &snapshot, "mcpServers").unwrap();
        assert!(restored);

        let rewritten: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(rewritten["mcpServers"]["linear"], snapshot);

        // Idempotent: an already-present entry is left alone, not
        // duplicated or clobbered, and reports "nothing to do."
        let restored_again =
            restore_remote_entry_json(&config_path, "linear", &snapshot, "mcpServers").unwrap();
        assert!(!restored_again);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn restore_remote_entry_json_uses_the_servers_key_for_vscode_copilot() {
        // Regression test for a real latent bug: this function used to
        // hardcode "mcpServers" everywhere, which is wrong for VS Code's
        // Copilot Chat extension (top-level key "servers" -- see
        // ConfigSourceKind::VsCodeCopilotMcpJson's doc comment). Proves
        // the fix actually inserts under "servers", not "mcpServers".
        let dir = unique_temp_dir("remote-restore-vscode");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("mcp.json");
        std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&serde_json::json!({ "servers": {} })).unwrap(),
        )
        .unwrap();

        let snapshot = serde_json::json!({ "type": "http", "url": "https://mcp.example.com/mcp" });
        let restored = restore_remote_entry_json(&config_path, "example", &snapshot, "servers").unwrap();
        assert!(restored);

        let rewritten: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(rewritten["servers"]["example"], snapshot);
        assert!(
            rewritten.get("mcpServers").is_none(),
            "must not create a spurious mcpServers key alongside the real servers one"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn restore_remote_entry_toml_reinserts_a_removed_entry() {
        let dir = unique_temp_dir("remote-restore-toml");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.toml");
        std::fs::write(&config_path, "").unwrap();

        let snapshot = serde_json::json!({ "url": "https://mcp.example.com" });
        let restored = restore_remote_entry_toml(&config_path, "example", &snapshot).unwrap();
        assert!(restored);

        let rewritten = std::fs::read_to_string(&config_path).unwrap();
        let parsed: toml::Value = toml::from_str(&rewritten).unwrap();
        assert_eq!(
            parsed.get("mcp_servers").and_then(|v| v.get("example")).and_then(|v| v.get("url")).and_then(|v| v.as_str()),
            Some("https://mcp.example.com")
        );

        let restored_again = restore_remote_entry_toml(&config_path, "example", &snapshot).unwrap();
        assert!(!restored_again);

        std::fs::remove_dir_all(&dir).ok();
    }

    fn synthetic_skill_scanned_artifact(
        name: &str,
        scan_root: PathBuf,
        decision: Decision,
        band: RiskBand,
    ) -> ScannedArtifact {
        let source = ArtifactSource::LocalPath(scan_root.display().to_string());
        let artifact = Artifact {
            id: format!("skill:{name}:local:{}", scan_root.display()),
            kind: ArtifactKind::Skill,
            name: name.to_string(),
            version: None,
            publisher: PublisherIdentity::default(),
            source,
            content_hash: None,
            capabilities: vec![],
            discovered_by: BTreeSet::new(),
        };
        ScannedArtifact {
            agent_name: "claude-code",
            artifact,
            breakdown: ScoreBreakdown::default(),
            band,
            decision,
            location: scan_root.display().to_string(),
            launch: None,
            config_source: None,
            raw_config_entry: None,
            scan_root: Some(scan_root),
            registry_fetch: None,
        }
    }

    #[test]
    fn quarantine_skills_moves_a_blocked_skill_and_leaves_an_allowed_one() {
        let dir = unique_temp_dir("skill-quarantine");
        let skills_dir = dir.join(".claude").join("skills");
        std::fs::create_dir_all(skills_dir.join("evil-skill")).unwrap();
        std::fs::write(skills_dir.join("evil-skill").join("SKILL.md"), "evil").unwrap();
        std::fs::create_dir_all(skills_dir.join("good-skill")).unwrap();
        std::fs::write(skills_dir.join("good-skill").join("SKILL.md"), "good").unwrap();
        let store = temp_store(&dir);

        let evil = synthetic_skill_scanned_artifact(
            "evil-skill",
            skills_dir.join("evil-skill"),
            Decision::Block,
            RiskBand::Critical,
        );
        let evil_id = evil.artifact.id.clone();
        let good = synthetic_skill_scanned_artifact(
            "good-skill",
            skills_dir.join("good-skill"),
            Decision::Allow,
            RiskBand::Low,
        );
        let scanned = vec![evil, good];

        // Real usage always upserts a record for every scanned artifact
        // before quarantining anything (run_init's own ordering) --
        // record_for is what actually captures quarantine_original_path.
        for s in &scanned {
            store.upsert(record_for(&store, s, ProtectionLevel::Balanced)).unwrap();
        }

        let outcome = quarantine_skills(&scanned, &store, &dir, false);
        assert_eq!(outcome.quarantined, 1);
        assert_eq!(outcome.skipped_outside_project, 0);

        assert!(
            !skills_dir.join("evil-skill").exists(),
            "the blocked skill must be moved out of .claude/skills/"
        );
        assert!(
            dir.join(".claude")
                .join(".agentguard-quarantine")
                .join("evil-skill")
                .join("SKILL.md")
                .exists(),
            "the blocked skill's content must survive the move, sibling to skills/"
        );
        assert!(
            skills_dir.join("good-skill").exists(),
            "an ALLOW-decision skill must stay in place"
        );

        let record = store.get(&evil_id).unwrap();
        assert_eq!(record.quarantine_original_path, Some(skills_dir.join("evil-skill")));
        assert_eq!(
            record.quarantine_current_path,
            Some(dir.join(".claude").join(".agentguard-quarantine").join("evil-skill"))
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn quarantine_skills_respects_the_project_safety_boundary() {
        let dir = unique_temp_dir("skill-quarantine-outside");
        let outside_dir = unique_temp_dir("skill-quarantine-outside-user-scope");
        let skills_dir = outside_dir.join(".claude").join("skills");
        std::fs::create_dir_all(skills_dir.join("evil-skill")).unwrap();
        std::fs::write(skills_dir.join("evil-skill").join("SKILL.md"), "evil").unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        let store = temp_store(&dir);

        let evil = synthetic_skill_scanned_artifact(
            "evil-skill",
            skills_dir.join("evil-skill"),
            Decision::Block,
            RiskBand::Critical,
        );
        let scanned = vec![evil];

        // dir (project_root) does NOT contain outside_dir's skill.
        let outcome = quarantine_skills(&scanned, &store, &dir, false);
        assert_eq!(outcome.quarantined, 0);
        assert_eq!(outcome.skipped_outside_project, 1);
        assert!(
            skills_dir.join("evil-skill").exists(),
            "a flagged skill outside --project must NOT be touched without --include-user-config"
        );

        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&outside_dir).ok();
    }

    #[test]
    fn restore_quarantined_skill_if_needed_moves_it_back_and_clears_the_record() {
        let dir = unique_temp_dir("skill-restore");
        let skills_dir = dir.join(".claude").join("skills");
        let quarantine_dir = dir.join(".claude").join(".agentguard-quarantine");
        std::fs::create_dir_all(&quarantine_dir.join("evil-skill")).unwrap();
        std::fs::write(quarantine_dir.join("evil-skill").join("SKILL.md"), "evil").unwrap();
        std::fs::create_dir_all(&skills_dir).unwrap();
        let store = temp_store(&dir);

        let artifact_id = "skill:evil-skill:local:test".to_string();
        store
            .upsert(DecisionRecord {
                artifact_id: artifact_id.clone(),
                name: "evil-skill".to_string(),
                band: RiskBand::Critical,
                decision: Decision::Block,
                total_score: 100,
                protection_level: ProtectionLevel::Balanced,
                scanned_at_unix: DecisionRecord::now_unix(),
                reasons: vec![],
                content_hash: None,
                capability_snapshot: vec![],
                shell_command: None,
                manually_approved: true,
                remote_entry_snapshot: None,
                config_path: None,
                config_entry_key: None,
                config_top_level_key: None,
                quarantine_original_path: Some(skills_dir.join("evil-skill")),
                quarantine_current_path: Some(quarantine_dir.join("evil-skill")),
            })
            .unwrap();

        restore_quarantined_skill_if_needed(&store, &artifact_id);

        assert!(
            skills_dir.join("evil-skill").join("SKILL.md").exists(),
            "the skill directory must be moved back to its original location"
        );
        assert!(!quarantine_dir.join("evil-skill").exists());

        let record = store.get(&artifact_id).unwrap();
        assert_eq!(
            record.quarantine_current_path, None,
            "the record must be cleared once restored, so a later scan doesn't think it's still quarantined"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
