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
use agentguard_core::{Decision, ProtectionLevel, RiskBand};
use agentguard_risk::RiskEngine;
use agentguard_store::{DecisionRecord, DecisionStore};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

/// `--store` flag > `$AGENTGUARD_STORE` > `~/.agentguard/decisions.json`.
/// The env var and flag exist so tests/demos can point at an isolated
/// store instead of ever touching the real machine-wide one.
pub fn resolve_store(store_override: Option<PathBuf>) -> DecisionStore {
    if let Some(path) = store_override {
        return DecisionStore::open_at(path);
    }
    if let Ok(path) = std::env::var("AGENTGUARD_STORE") {
        return DecisionStore::open_at(PathBuf::from(path));
    }
    match DecisionStore::open_default() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("agentguard: cannot determine decision store location: {e}");
            std::process::exit(1);
        }
    }
}

/// Writes a scan result into the store, preserving a prior manual approval
/// ONLY if this artifact's score and decision are unchanged from what's
/// cached. Any change resets approval and requires a fresh `agentguard
/// allow` — a cheap, honest stand-in for real hash-based drift detection
/// (not built yet): "the thing I approved" should mean exactly that thing,
/// not "whatever this artifact_id points to now."
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

fn record_for(s: &ScannedArtifact, level: ProtectionLevel) -> DecisionRecord {
    let mut reasons = Vec::new();
    reasons.extend(s.breakdown.static_evidence_reasons.clone());
    reasons.extend(s.breakdown.reputation_reasons.clone());
    reasons.extend(s.breakdown.context_reasons.clone());
    DecisionRecord {
        artifact_id: s.artifact.id.clone(),
        name: s.artifact.name.clone(),
        band: s.band,
        decision: s.decision,
        total_score: s.breakdown.total(),
        protection_level: level,
        scanned_at_unix: DecisionRecord::now_unix(),
        reasons,
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

/// Rewrites the `mcpServers` entries in one config file so each of
/// `artifacts` launches through the shim instead of directly. Backs up the
/// original file (once — never overwritten on subsequent runs) before the
/// first write. Idempotent: an entry already pointing at the shim is left
/// alone and counted as `already_protected`.
fn rewrite_config(
    config_path: &Path,
    artifacts: &[&ScannedArtifact],
    shim_path: &Path,
) -> io::Result<RewriteOutcome> {
    let original_text = std::fs::read_to_string(config_path)?;
    let mut json: serde_json::Value = serde_json::from_str(&original_text)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let Some(servers) = json.get_mut("mcpServers").and_then(|v| v.as_object_mut()) else {
        return Ok(RewriteOutcome {
            newly_protected: 0,
            already_protected: 0,
            backup_path: None,
        });
    };

    let shim_str = shim_path.display().to_string();
    let mut newly_protected = 0;
    let mut already_protected = 0;

    for s in artifacts {
        // Only one rewritable shape exists today; matching it exhaustively
        // (no wildcard) means adding a ConfigSourceKind variant forces a
        // deliberate decision here, not a silent no-op.
        let Some(config_source) = &s.config_source else {
            continue;
        };
        match config_source.kind {
            ConfigSourceKind::ClaudeCodeMcpServersJson => {}
        }
        let Some(launch) = &s.launch else { continue };

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
            serde_json::Value::String(shim_str.clone()),
        );
        entry.insert("args".to_string(), serde_json::Value::Array(new_args));
        newly_protected += 1;
    }

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
        let record = record_for(s, level);
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
            "{skipped_outside_project} MCP server(s) found outside {} (e.g. a user-level config) — NOT rewritten.",
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
        "{newly_protected_total} MCP server(s) newly routed through the enforcement shim."
    );
    if already_protected_total > 0 {
        println!("{already_protected_total} MCP server(s) already protected (unchanged).");
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
