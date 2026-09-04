//! `agentguard init` — BUILD_PLAN.md §5a's config-rewrite enforcement,
//! plus `agentguard allow`/`why` for the manual-approval flow that goes
//! with it. This is the only code in the CLI that writes anything: the
//! decision cache (`~/.agentguard/decisions.json` by default) and, for MCP
//! servers found in a rewritable config, the agent's own config file (with
//! a one-time backup before the first rewrite).
//!
//! `scan`/`status` (main.rs) never call into this module — they only read.

use crate::pipeline::{collect, ScannedArtifact};
use agentguard_adapters::ConfigSourceKind;
use agentguard_core::{Capability, Decision, ProtectionLevel, RiskBand};
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
        .map(|cs| cs.kind == ConfigSourceKind::ClaudeCodeHooksJson)
        .unwrap_or(false);
    let shell_command = if is_hook_shell_command {
        s.launch.as_ref().map(|l| l.command.clone())
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
    backup_path: Option<PathBuf>,
}

/// Rewrites one config file so each of `artifacts` launches through the
/// shim instead of directly. Backs up the original file (once — never
/// overwritten on subsequent runs) before the first write. Idempotent: an
/// entry already pointing at the shim is left alone and counted as
/// `already_protected`.
///
/// Dispatches per `ConfigSourceKind` because the two rewritable shapes are
/// structurally different: `mcpServers` is a flat `{name: {command,
/// args}}` map (one lookup); Claude Code's hooks config is a nested tree
/// with no flat key to look up by, so it's walked in the same order
/// discovery used to assign each hook's index-based id. Matching
/// exhaustively (no wildcard) means a future ConfigSourceKind variant with
/// a different shape forces a deliberate decision here, not a silent (and
/// wrong) fallthrough to one of these.
fn rewrite_config(
    config_path: &Path,
    artifacts: &[&ScannedArtifact],
    shim_path: &Path,
) -> io::Result<RewriteOutcome> {
    let original_text = std::fs::read_to_string(config_path)?;
    let mut json: serde_json::Value = serde_json::from_str(&original_text)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let shim_str = shim_path.display().to_string();

    let mut mcp_artifacts = Vec::new();
    let mut hook_artifacts = Vec::new();
    for s in artifacts {
        let Some(config_source) = &s.config_source else {
            continue;
        };
        if s.launch.is_none() {
            continue;
        }
        match config_source.kind {
            ConfigSourceKind::ClaudeCodeMcpServersJson | ConfigSourceKind::CursorMcpJson => {
                mcp_artifacts.push(*s)
            }
            ConfigSourceKind::ClaudeCodeHooksJson => hook_artifacts.push(*s),
        }
    }

    let (mcp_new, mcp_already) = rewrite_mcp_servers(&mut json, &mcp_artifacts, &shim_str);
    let (hook_new, hook_already) = rewrite_hooks(&mut json, &hook_artifacts, &shim_str);
    let newly_protected = mcp_new + hook_new;
    let already_protected = mcp_already + hook_already;

    if newly_protected == 0 {
        return Ok(RewriteOutcome {
            newly_protected: 0,
            already_protected,
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
        backup_path: Some(backup_path),
    })
}

/// Rewrites `{ "mcpServers": { "<entry_key>": { command, args } } }`
/// entries — a flat map, one lookup per artifact.
fn rewrite_mcp_servers(
    json: &mut serde_json::Value,
    artifacts: &[&ScannedArtifact],
    shim_str: &str,
) -> (usize, usize) {
    let mut newly_protected = 0;
    let mut already_protected = 0;
    let Some(servers) = json.get_mut("mcpServers").and_then(|v| v.as_object_mut()) else {
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

/// Rewrites Claude Code hook entries. There's no flat key to look up by —
/// a hook's `entry_key` is `"hook-<i>"`, its index in the same
/// depth-first, object-then-array traversal order
/// claude_code.rs's `collect_command_strings` uses to assign it in the
/// first place — so this walks `json["hooks"]` in that identical order and
/// rewrites the i-th `"command"` field found for any index we have a
/// target for.
fn rewrite_hooks(
    json: &mut serde_json::Value,
    artifacts: &[&ScannedArtifact],
    shim_str: &str,
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

    let Some(hooks_val) = json.get_mut("hooks") else {
        return (0, 0);
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
            let has_command = matches!(map.get("command"), Some(serde_json::Value::String(_)));
            if has_command {
                let this_index = *index;
                *index += 1;
                if let Some(s) = targets.get(&this_index) {
                    let current = map.get("command").and_then(|c| c.as_str()).unwrap_or("");
                    if current.starts_with(&format!("\"{shim_str}\"")) {
                        *already_protected += 1;
                    } else {
                        // Deliberately does NOT embed the real command —
                        // see DecisionRecord.shell_command's doc comment.
                        // This string is safe for Claude Code's own shell
                        // to re-parse: two quoted tokens (no
                        // metacharacters possible in either — the shim
                        // path is a filesystem path, the artifact id is
                        // hash-based, see claude_code.rs's short_hash) and
                        // a literal flag, nothing else.
                        let wrapped = format!("\"{shim_str}\" \"{}\" --shell", s.artifact.id);
                        map.insert("command".to_string(), serde_json::Value::String(wrapped));
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
) {
    let project_root = project
        .canonicalize()
        .unwrap_or_else(|_| project.to_path_buf());
    let engine = RiskEngine::new();
    let scanned = collect(&project_root, &engine, level);
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
                s.artifact.name
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
    let mut by_config: BTreeMap<PathBuf, Vec<&ScannedArtifact>> = BTreeMap::new();
    let mut skipped_outside_project = 0usize;
    for s in &scanned {
        if let (Some(_), Some(cs)) = (&s.launch, &s.config_source) {
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

    if skipped_outside_project > 0 {
        println!(
            "{skipped_outside_project} rewritable artifact(s) found outside {} (e.g. a user-level config) — NOT rewritten.",
            project_root.display()
        );
        println!("Re-run with --include-user-config to also protect those.");
    }

    if by_config.is_empty() {
        println!("No rewritable MCP server configs found inside this project — nothing to route through enforcement yet.");
        print_risk_summary(&scanned);
        return;
    }

    let Some(shim_path) = locate_shim() else {
        eprintln!(
            "\nagentguard: could not find agentguard-shim next to this executable — enforcement was NOT wired."
        );
        eprintln!("(the decision cache above was still written; `agentguard scan`/`status` still work.)");
        print_risk_summary(&scanned);
        return;
    };

    let mut newly_protected_total = 0;
    let mut already_protected_total = 0;
    let mut backups = Vec::new();

    for (config_path, artifacts) in &by_config {
        match rewrite_config(config_path, artifacts, &shim_path) {
            Ok(outcome) => {
                newly_protected_total += outcome.newly_protected;
                already_protected_total += outcome.already_protected;
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
        record.name, record.band, record.total_score, record.decision
    );
    println!();
    for r in &record.reasons {
        println!("  {r}");
    }
}
