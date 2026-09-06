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
        .filter(|c| {
            c.is_secret_access()
                || c.is_process_execution()
                || c.is_persistence()
                || c.is_content_influence()
        })
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

/// The JSON key PATH a `ConfigSourceKind`'s server map sits under, from
/// the config root. One segment for a flat map (`["mcpServers"]`,
/// `["servers"]`, `["context_servers"]`, or the literal dotted keys
/// `["amp.mcpServers"]` / `["cody.mcpServers"]` — a single segment that
/// happens to contain dots, NOT a two-level path), two for OpenClaw
/// (`["mcp", "servers"]`), one nesting level for opencode / Crush
/// (`["mcp"]`). `None` for a TOML config (Codex — see
/// `restore_remote_entry`'s dispatch by file extension), a real-YAML
/// config (Goose / Continue.dev / Aider — no JSON rewrite path yet,
/// STATUS.md 5c), or a shape with no flat server map (hooks). Matched
/// exhaustively so a future variant forces a decision here.
fn json_key_path(kind: ConfigSourceKind) -> Option<&'static [&'static str]> {
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
        | ConfigSourceKind::TabnineMcpJson
        // A Gemini CLI extension's `gemini-extension.json` and a Claude
        // Code plugin's `.mcp.json` — both the flat `{ "mcpServers":
        // {...} }` shape, so the standard rewrite path applies unchanged.
        | ConfigSourceKind::GeminiCliExtensionJson
        | ConfigSourceKind::ClaudeCodePluginMcpJson => Some(&["mcpServers"]),
        ConfigSourceKind::VsCodeCopilotMcpJson => Some(&["servers"]),
        ConfigSourceKind::AmpMcpJson => Some(&["amp.mcpServers"]),
        ConfigSourceKind::CodyMcpJson => Some(&["cody.mcpServers"]),
        ConfigSourceKind::ZedMcpJson => Some(&["context_servers"]),
        ConfigSourceKind::OpenClawJson => Some(&["mcp", "servers"]),
        ConfigSourceKind::OpenCodeMcpJson | ConfigSourceKind::CrushMcpJson => Some(&["mcp"]),
        // Warp's `~/.warp/.mcp.json` puts the servers at the JSON ROOT
        // (no wrapper key) — an empty path resolves to the root object in
        // `servers_map_mut` / `servers_map_mut_or_create`.
        ConfigSourceKind::WarpMcpJson => Some(&[]),
        // Real-YAML native formats — the JSON rewrite path can't parse or
        // re-emit these (STATUS.md 5c, still open pending a YAML-emit
        // decision). Discovery/scoring only.
        ConfigSourceKind::GooseMcpJson
        | ConfigSourceKind::ContinueYamlMcpJson
        | ConfigSourceKind::AiderMcpJson
        | ConfigSourceKind::OpenHandsMcpToml => None,
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

/// Navigates `json` through `path` (each segment a literal object key) and
/// returns the map at the end, if every segment exists and is an object.
fn servers_map_mut<'a>(
    json: &'a mut serde_json::Value,
    path: &[&str],
) -> Option<&'a mut serde_json::Map<String, serde_json::Value>> {
    let mut cur = json;
    for seg in path {
        cur = cur.as_object_mut()?.get_mut(*seg)?;
    }
    cur.as_object_mut()
}

/// Like `servers_map_mut` but creates any missing object along `path` —
/// for `agentguard allow`'s restore, which may run against a config the
/// entry (and its parent objects) were removed from.
fn servers_map_mut_or_create<'a>(
    json: &'a mut serde_json::Value,
    path: &[&str],
) -> io::Result<&'a mut serde_json::Map<String, serde_json::Value>> {
    let mut cur = json;
    for seg in path {
        let obj = cur.as_object_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, format!("config path segment before {seg} is not a JSON object"))
        })?;
        cur = obj
            .entry((*seg).to_string())
            .or_insert_with(|| serde_json::Value::Object(Default::default()));
    }
    cur.as_object_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "target of the config key path is not a JSON object"))
}

/// Where a REMOTE MCP entry for `kind` lives, for the snapshot / removal /
/// restore path: the key path to its container, and whether that
/// container is a name-keyed MAP (`false`) or a LIST whose elements carry
/// their own `name` field (`true`). `None` for a kind that can't hold a
/// removable remote entry (OpenHands — `stdio_servers` is local-only;
/// Codex TOML — its own restore path; hooks).
fn remote_entry_location(kind: ConfigSourceKind) -> Option<(&'static [&'static str], bool)> {
    match kind {
        ConfigSourceKind::GooseMcpJson => Some((&["mcpServers"], false)),
        ConfigSourceKind::ContinueYamlMcpJson => Some((&["mcpServers"], true)),
        ConfigSourceKind::AiderMcpJson => Some((&["mcp-server"], true)),
        _ => json_key_path(kind).map(|p| (p, false)),
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
    let location = if is_remote {
        s.config_source
            .as_ref()
            .and_then(|cs| remote_entry_location(cs.kind))
    } else {
        None
    };
    let (
        remote_entry_snapshot,
        config_path,
        config_entry_key,
        config_key_path,
        config_entry_is_list_element,
    ) = if is_remote {
        (
            s.raw_config_entry.clone(),
            s.config_source.as_ref().map(|cs| cs.path.clone()),
            s.config_source.as_ref().map(|cs| cs.entry_key.clone()),
            location.map(|(p, _)| p.iter().map(|s| s.to_string()).collect()),
            location.map(|(_, is_list)| is_list).unwrap_or(false),
        )
    } else {
        (None, None, None, None, false)
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
        config_key_path,
        config_entry_is_list_element,
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
    // Real-YAML native formats (Goose's `mcpServers:` map, Continue.dev's
    // and Aider's list-shaped `mcpServers`/`mcp-server`) and OpenHands'
    // array-of-tables TOML — a different rewrite path (`rewrite_config_value`)
    // that parses to a `serde_json::Value` via `serde_saphyr` / `toml`,
    // rewrites, and re-emits in the same format. A config-file group is
    // always homogeneous, so checking the first artifact's kind is enough.
    let value_format = artifacts
        .iter()
        .filter_map(|s| s.config_source.as_ref())
        .find_map(|cs| value_config_format(cs.kind));
    if is_toml {
        rewrite_config_toml(config_path, artifacts, shim_path, store)
    } else if let Some(format) = value_format {
        rewrite_config_value(config_path, artifacts, shim_path, store, format)
    } else {
        rewrite_config_json(config_path, artifacts, shim_path, store)
    }
}

/// The server container for a real-YAML / non-Codex-TOML config: a key
/// PATH from the root, and whether the servers sit in a name-keyed MAP
/// (Goose) or a LIST where each element carries its own `name` field
/// (Continue.dev, Aider, OpenHands). `None` for every JSON/Codex-TOML
/// kind — those go through `rewrite_config_json` / `rewrite_config_toml`.
fn value_config_format(kind: ConfigSourceKind) -> Option<ValueConfigFormat> {
    use ServerContainer::*;
    let (fmt, path, shape): (_, &'static [&'static str], _) = match kind {
        ConfigSourceKind::GooseMcpJson => (ValueFileFormat::Yaml, &["mcpServers"], Map),
        ConfigSourceKind::ContinueYamlMcpJson => (ValueFileFormat::Yaml, &["mcpServers"], ListByName),
        ConfigSourceKind::AiderMcpJson => (ValueFileFormat::Yaml, &["mcp-server"], ListByName),
        ConfigSourceKind::OpenHandsMcpToml => {
            (ValueFileFormat::Toml, &["mcp", "stdio_servers"], ListByName)
        }
        _ => return None,
    };
    Some(ValueConfigFormat { file: fmt, path, shape })
}

#[derive(Clone, Copy, PartialEq)]
enum ValueFileFormat {
    Yaml,
    Toml,
}

#[derive(Clone, Copy)]
enum ServerContainer {
    Map,
    ListByName,
}

#[derive(Clone, Copy)]
struct ValueConfigFormat {
    file: ValueFileFormat,
    path: &'static [&'static str],
    shape: ServerContainer,
}

/// Rewrite path for a real-YAML config (Goose / Continue.dev / Aider) or
/// OpenHands' array-of-tables TOML: parse the file into a
/// `serde_json::Value` (via `serde_saphyr` for YAML, `toml` for TOML),
/// shim-wrap the flagged local servers, remove any BLOCK/unapproved-ASK
/// remote entry (STATUS.md 5d), and re-emit in the same format.
///
/// Same limit the JSON path has: comments and exact formatting in the
/// user's file are not preserved (the `.agentguard-backup` written before
/// the first rewrite is the safety net).
fn rewrite_config_value(
    config_path: &Path,
    artifacts: &[&ScannedArtifact],
    shim_path: Option<&Path>,
    store: &DecisionStore,
    format: ValueConfigFormat,
) -> io::Result<RewriteOutcome> {
    let original_text = std::fs::read_to_string(config_path)?;
    let mut root: serde_json::Value = match format.file {
        ValueFileFormat::Yaml => serde_saphyr::from_str(&original_text)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?,
        ValueFileFormat::Toml => {
            let t: toml::Value = toml::from_str(&original_text)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            serde_json::to_value(t).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        }
    };

    let (local, remote): (Vec<&ScannedArtifact>, Vec<&ScannedArtifact>) =
        artifacts.iter().partition(|s| s.launch.is_some());

    // The shim is only needed to WRAP a local server; removing a remote
    // entry doesn't need it (there's no process to launch), same as the
    // JSON path.
    let (newly_protected, already_protected) = match shim_path.map(|p| p.display().to_string()) {
        Some(shim_str) => {
            rewrite_servers_in_value(&mut root, &local, &shim_str, format.path, format.shape)
        }
        None => (0, 0),
    };

    let removed_remote =
        remove_flagged_remote_in_value(&mut root, &remote, store, format.path, format.shape);

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

    let serialized = match format.file {
        ValueFileFormat::Yaml => {
            // Default options fold long strings into multi-line `>-`
            // block scalars — valid YAML, but ugly in a user's config
            // file and confusing to eyeball. A shim-wrapped entry's args
            // (an artifact id, a `--`, a real command path) are always
            // one-liners; keep them that way.
            let mut opts = serde_saphyr::SerializerOptions::default();
            opts.prefer_block_scalars = false;
            opts.min_fold_chars = usize::MAX;
            serde_saphyr::to_string_with_options(&root, opts)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
        }
        ValueFileFormat::Toml => toml::to_string_pretty(&root)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
    };
    std::fs::write(config_path, serialized)?;

    Ok(RewriteOutcome {
        newly_protected,
        already_protected,
        removed_remote,
        backup_path: Some(backup_path),
    })
}

/// Removes each remote artifact's entry from a `serde_json::Value` config
/// (a YAML map / list) when its effective decision doesn't allow it to run
/// — the value-format analog of `remove_blocked_remote_entries_json`. The
/// entry was snapshotted into the store at scan time (`record_for`), so
/// `agentguard allow` can restore it via `restore_remote_entry_value`.
fn remove_flagged_remote_in_value(
    root: &mut serde_json::Value,
    remote_artifacts: &[&ScannedArtifact],
    store: &DecisionStore,
    path: &[&str],
    shape: ServerContainer,
) -> usize {
    if remote_artifacts.is_empty() {
        return 0;
    }
    let mut cur = &mut *root;
    for seg in path {
        cur = match cur.get_mut(*seg) {
            Some(v) => v,
            None => return 0,
        };
    }

    let mut removed = 0;
    for s in remote_artifacts {
        let key = &s.config_source.as_ref().unwrap().entry_key; // filtered by caller
        if !decision_requires_removal(effective_decision_for(store, s)) {
            continue;
        }
        match shape {
            ServerContainer::Map => {
                if let Some(map) = cur.as_object_mut() {
                    if map.remove(key).is_some() {
                        removed += 1;
                    }
                }
            }
            ServerContainer::ListByName => {
                if let Some(list) = cur.as_array_mut() {
                    let before = list.len();
                    list.retain(|e| e.get("name").and_then(|n| n.as_str()) != Some(key.as_str()));
                    if list.len() < before {
                        removed += 1;
                    }
                }
            }
        }
    }
    removed
}

/// Shim-wraps each flagged local server in `root`, navigating `path` to
/// the container and matching by map key or by list element `name`. Only
/// the string-`command` + `args` shape (every YAML/OpenHands agent uses
/// it — opencode's array `command` is JSON-only).
fn rewrite_servers_in_value(
    root: &mut serde_json::Value,
    artifacts: &[&ScannedArtifact],
    shim_str: &str,
    path: &[&str],
    shape: ServerContainer,
) -> (usize, usize) {
    let mut cur = root;
    for seg in path {
        cur = match cur.get_mut(*seg) {
            Some(v) => v,
            None => return (0, 0),
        };
    }

    let mut newly = 0;
    let mut already = 0;

    match shape {
        ServerContainer::Map => {
            let Some(servers) = cur.as_object_mut() else { return (0, 0) };
            for s in artifacts {
                let key = &s.config_source.as_ref().unwrap().entry_key;
                if let Some(entry) = servers.get_mut(key).and_then(|v| v.as_object_mut()) {
                    match wrap_string_command_entry(entry, s, shim_str) {
                        Some(true) => newly += 1,
                        Some(false) => already += 1,
                        None => {}
                    }
                }
            }
        }
        ServerContainer::ListByName => {
            let Some(list) = cur.as_array_mut() else { return (0, 0) };
            for s in artifacts {
                let key = s.config_source.as_ref().unwrap().entry_key.clone();
                for elem in list.iter_mut() {
                    let Some(obj) = elem.as_object_mut() else { continue };
                    if obj.get("name").and_then(|n| n.as_str()) != Some(key.as_str()) {
                        continue;
                    }
                    match wrap_string_command_entry(obj, s, shim_str) {
                        Some(true) => newly += 1,
                        Some(false) => already += 1,
                        None => {}
                    }
                    break;
                }
            }
        }
    }

    (newly, already)
}

/// Rewrites one server object's string `command`/`args` to launch through
/// the shim. `Some(true)` = newly wrapped, `Some(false)` = already
/// wrapped, `None` = nothing to do (no launch on the artifact — should
/// not happen for a local server).
fn wrap_string_command_entry(
    entry: &mut serde_json::Map<String, serde_json::Value>,
    s: &ScannedArtifact,
    shim_str: &str,
) -> Option<bool> {
    let launch = s.launch.as_ref()?;
    if entry.get("command").and_then(|c| c.as_str()) == Some(shim_str) {
        return Some(false);
    }
    let mut args = vec![
        serde_json::Value::String(s.artifact.id.clone()),
        serde_json::Value::String("--".to_string()),
        serde_json::Value::String(launch.command.clone()),
    ];
    args.extend(launch.args.iter().cloned().map(serde_json::Value::String));
    entry.insert(
        "command".to_string(),
        serde_json::Value::String(shim_str.to_string()),
    );
    entry.insert("args".to_string(), serde_json::Value::Array(args));
    Some(true)
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
    // Key PATH from the config root to the server map — one segment for a
    // flat `{ "mcpServers": {...} }`, two for OpenClaw's `{ "mcp":
    // { "servers": {...} } }`, one nesting level for opencode / Crush's
    // `{ "mcp": {...} }`. A config-file group is always homogeneous (one
    // physical file, one agent, one shape), so overwriting this on every
    // matching artifact is safe.
    let mut key_path: &[&str] = &["mcpServers"];
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
            | ConfigSourceKind::TabnineMcpJson
            | ConfigSourceKind::GeminiCliExtensionJson
            | ConfigSourceKind::ClaudeCodePluginMcpJson => {
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
            ConfigSourceKind::VsCodeCopilotMcpJson
            | ConfigSourceKind::AmpMcpJson
            | ConfigSourceKind::CodyMcpJson
            | ConfigSourceKind::ZedMcpJson
            // Nested shapes: OpenClaw's `{"mcp": {"servers": {...}}}` and
            // opencode / Crush's `{"mcp": {...}}`. `rewrite_mcp_servers` /
            // `remove_blocked_remote_entries_json` now navigate a key
            // PATH (`servers_map_mut`), so these route through the exact
            // same rewrite as every flat-key agent. opencode additionally
            // stores a local server's `command` as an ARRAY — handled
            // inside `rewrite_mcp_servers`, which detects that shape and
            // rewrites `command` as `[<shim>, <id>, "--", <real>, ...]`.
            | ConfigSourceKind::OpenClawJson
            | ConfigSourceKind::OpenCodeMcpJson
            | ConfigSourceKind::CrushMcpJson
            // Warp: servers at the JSON root — `json_key_path` returns the
            // empty path, which `servers_map_mut` resolves to the root
            // object.
            | ConfigSourceKind::WarpMcpJson => {
                if let Some(cs) = &s.config_source {
                    if let Some(p) = json_key_path(cs.kind) {
                        key_path = p;
                    }
                }
                if s.launch.is_some() {
                    mcp_artifacts.push(*s);
                } else {
                    remote_artifacts.push(*s);
                }
            }
            // Real-YAML native formats (Goose / Continue.dev / Aider) and
            // OpenHands' array-of-tables TOML — this function parses with
            // serde_json::from_str, which fails outright on YAML, and
            // re-emitting would need a YAML/TOML writer this codebase
            // doesn't have yet (STATUS.md 5c). `rewrite_config`'s
            // `is_discovery_only_shape` short-circuits these before they
            // ever reach here; matched anyway so the compiler forces a
            // decision if that ever changes.
            ConfigSourceKind::GooseMcpJson
            | ConfigSourceKind::ContinueYamlMcpJson
            | ConfigSourceKind::AiderMcpJson
            | ConfigSourceKind::OpenHandsMcpToml => {}
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
        Some(s) => rewrite_mcp_servers(&mut json, &mcp_artifacts, s, key_path),
        None => (0, 0),
    };
    let (hook_new, hook_already) = match &shim_str {
        Some(s) => rewrite_hooks(&mut json, &hook_artifacts, s, hooks_wrapper_key),
        None => (0, 0),
    };
    let removed_remote =
        remove_blocked_remote_entries_json(&mut json, &remote_artifacts, store, key_path);
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
    key_path: &[&str],
) -> usize {
    if remote_artifacts.is_empty() {
        return 0;
    }
    let Some(servers) = servers_map_mut(json, key_path) else {
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

/// Rewrites `{ <key_path...>: { "<entry_key>": { command, args } } }`
/// entries so each launches through the shim. `key_path` is `["mcpServers"]`
/// for most agents, `["servers"]` for VS Code Copilot, `["mcp", "servers"]`
/// for OpenClaw, `["mcp"]` for opencode / Crush — see `json_key_path`.
///
/// Two per-entry `command` shapes are handled:
///  - string (`"command": "npx"`, `"args": ["-y", "pkg"]`) — every agent
///    except opencode. Rewritten to `command: "<shim>"`, `args:
///    ["<id>", "--", "npx", "-y", "pkg"]`.
///  - array  (`"command": ["npx", "-y", "pkg"]`) — opencode's local
///    server shape, which has no separate `args`. Rewritten to
///    `command: ["<shim>", "<id>", "--", "npx", "-y", "pkg"]`.
///
/// Both forms produce the exact `<id> -- <real-command> [args]` sequence
/// `agentguard-shim` and `mcp_config.rs`'s `unwrap_shim_invocation` expect,
/// so a re-scan sees through the wrapper back to the real command.
fn rewrite_mcp_servers(
    json: &mut serde_json::Value,
    artifacts: &[&ScannedArtifact],
    shim_str: &str,
    key_path: &[&str],
) -> (usize, usize) {
    let mut newly_protected = 0;
    let mut already_protected = 0;
    let Some(servers) = servers_map_mut(json, key_path) else {
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

        let uses_array_command = entry.get("command").map(|c| c.is_array()).unwrap_or(false);
        let already_wrapped = match entry.get("command") {
            Some(serde_json::Value::String(c)) => c == shim_str,
            Some(serde_json::Value::Array(a)) => {
                a.first().and_then(|v| v.as_str()) == Some(shim_str)
            }
            _ => false,
        };
        if already_wrapped {
            already_protected += 1;
            continue;
        }

        let real: Vec<serde_json::Value> = std::iter::once(launch.command.clone())
            .chain(launch.args.iter().cloned())
            .map(serde_json::Value::String)
            .collect();

        if uses_array_command {
            let mut cmd = vec![
                serde_json::Value::String(shim_str.to_string()),
                serde_json::Value::String(s.artifact.id.clone()),
                serde_json::Value::String("--".to_string()),
            ];
            cmd.extend(real);
            entry.insert("command".to_string(), serde_json::Value::Array(cmd));
        } else {
            let mut new_args = vec![
                serde_json::Value::String(s.artifact.id.clone()),
                serde_json::Value::String("--".to_string()),
            ];
            new_args.extend(real);
            entry.insert(
                "command".to_string(),
                serde_json::Value::String(shim_str.to_string()),
            );
            entry.insert("args".to_string(), serde_json::Value::Array(new_args));
        }
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
    // Older store records (written before `config_key_path`, or the even
    // older `config_top_level_key`) won't have it — every JSON agent
    // except VS Code used "mcpServers" at the top level then, so that's
    // the correct fallback, not a guess.
    let key_path: Vec<&str> = record
        .config_key_path
        .as_deref()
        .map(|p| p.iter().map(String::as_str).collect())
        .unwrap_or_else(|| vec!["mcpServers"]);

    match restore_remote_entry(
        config_path,
        entry_key,
        snapshot,
        &key_path,
        record.config_entry_is_list_element,
    ) {
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

/// Re-inserts `entry_key: snapshot` into `config_path`'s MCP-servers
/// container if it's missing, dispatching by file extension: `.toml` =
/// Codex (name-keyed table), `.yaml`/`.yml` = Goose (map) or Continue.dev
/// / Aider (list, `is_list_element`), everything else = a JSON config
/// (`servers_map_mut_or_create` navigates the nested key path). Returns
/// `Ok(false)` — not an error — when the entry is already present.
fn restore_remote_entry(
    config_path: &Path,
    entry_key: &str,
    snapshot: &serde_json::Value,
    key_path: &[&str],
    is_list_element: bool,
) -> io::Result<bool> {
    match config_path.extension().and_then(|e| e.to_str()) {
        Some("toml") => restore_remote_entry_toml(config_path, entry_key, snapshot),
        Some("yaml") | Some("yml") => {
            restore_remote_entry_yaml(config_path, entry_key, snapshot, key_path, is_list_element)
        }
        _ => restore_remote_entry_json(config_path, entry_key, snapshot, key_path),
    }
}

/// YAML analog of `restore_remote_entry_json` — Goose's `mcpServers:` map
/// (`is_list_element == false`) or Continue.dev's / Aider's list keyed by
/// each element's `name` field (`true`). Re-emits with the same
/// single-line-scalar options `rewrite_config_value` uses.
fn restore_remote_entry_yaml(
    config_path: &Path,
    entry_key: &str,
    snapshot: &serde_json::Value,
    key_path: &[&str],
    is_list_element: bool,
) -> io::Result<bool> {
    let original_text = std::fs::read_to_string(config_path)?;
    let mut root: serde_json::Value = serde_saphyr::from_str(&original_text)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    if is_list_element {
        let list = navigate_or_create_array(&mut root, key_path)?;
        let already = list
            .iter()
            .any(|e| e.get("name").and_then(|n| n.as_str()) == Some(entry_key));
        if already {
            return Ok(false);
        }
        list.push(snapshot.clone());
    } else {
        let map = servers_map_mut_or_create(&mut root, key_path)?;
        if map.contains_key(entry_key) {
            return Ok(false);
        }
        map.insert(entry_key.to_string(), snapshot.clone());
    }

    let mut opts = serde_saphyr::SerializerOptions::default();
    opts.prefer_block_scalars = false;
    opts.min_fold_chars = usize::MAX;
    let serialized = serde_saphyr::to_string_with_options(&root, opts)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    std::fs::write(config_path, serialized)?;
    Ok(true)
}

/// Navigates `path` in `root`, creating any missing object segment and a
/// missing final array, and returns the array at the end.
fn navigate_or_create_array<'a>(
    root: &'a mut serde_json::Value,
    path: &[&str],
) -> io::Result<&'a mut Vec<serde_json::Value>> {
    let (last, parents) = path
        .split_last()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty config key path"))?;
    let mut cur = root;
    for seg in parents {
        let obj = cur.as_object_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, format!("config segment before {seg} is not an object"))
        })?;
        cur = obj
            .entry((*seg).to_string())
            .or_insert_with(|| serde_json::Value::Object(Default::default()));
    }
    let obj = cur
        .as_object_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "config parent of the list is not an object"))?;
    obj.entry((*last).to_string())
        .or_insert_with(|| serde_json::Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "target of the config key path is not a list"))
}

fn restore_remote_entry_json(
    config_path: &Path,
    entry_key: &str,
    snapshot: &serde_json::Value,
    key_path: &[&str],
) -> io::Result<bool> {
    let original_text = std::fs::read_to_string(config_path)?;
    let mut json: serde_json::Value = serde_json::from_str(&original_text)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let servers = servers_map_mut_or_create(&mut json, key_path)?;
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

    /// A local MCP-server `ScannedArtifact` for a JSON-config agent, with
    /// its `ConfigSourceKind` parameterized — used for the nested-shape
    /// (OpenClaw / opencode / Crush) rewrite tests.
    fn local_json_artifact(
        name: &str,
        config_path: PathBuf,
        kind: ConfigSourceKind,
        command: &str,
        args: &[&str],
    ) -> ScannedArtifact {
        let source = ArtifactSource::LocalPath(command.to_string());
        ScannedArtifact {
            agent_name: "test-agent",
            artifact: Artifact {
                id: format!("MCP server:{name}:local:{command}"),
                kind: ArtifactKind::McpServer,
                name: name.to_string(),
                version: None,
                publisher: PublisherIdentity::default(),
                source,
                content_hash: None,
                capabilities: vec![],
                discovered_by: BTreeSet::new(),
            },
            breakdown: ScoreBreakdown::default(),
            band: RiskBand::Low,
            decision: Decision::Allow,
            location: command.to_string(),
            launch: Some(LaunchCommand {
                command: command.to_string(),
                args: args.iter().map(|s| s.to_string()).collect(),
            }),
            config_source: Some(ConfigSource {
                path: config_path,
                kind,
                entry_key: name.to_string(),
            }),
            raw_config_entry: None,
            scan_root: None,
            registry_fetch: None,
        }
    }

    #[test]
    fn rewrite_config_json_routes_a_crush_one_level_nested_entry() {
        let dir = unique_temp_dir("crush-rewrite");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("crush.json");
        std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&serde_json::json!({
                "mcp": { "filesystem": { "command": "npx", "args": ["-y", "@mcp/fs"] } }
            }))
            .unwrap(),
        )
        .unwrap();
        let store = temp_store(&dir);
        let shim = dir.join("agentguard-shim");
        std::fs::write(&shim, b"stub").unwrap();

        let art = local_json_artifact(
            "filesystem",
            config_path.clone(),
            ConfigSourceKind::CrushMcpJson,
            "npx",
            &["-y", "@mcp/fs"],
        );
        let outcome = rewrite_config_json(&config_path, &[&art], Some(&shim), &store).unwrap();
        assert_eq!(outcome.newly_protected, 1);

        let j: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(j["mcp"]["filesystem"]["command"], shim.display().to_string());
        assert_eq!(
            j["mcp"]["filesystem"]["args"],
            serde_json::json!([art.artifact.id, "--", "npx", "-y", "@mcp/fs"])
        );

        // idempotent
        let again = rewrite_config_json(&config_path, &[&art], Some(&shim), &store).unwrap();
        assert_eq!(again.newly_protected, 0);
        assert_eq!(again.already_protected, 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rewrite_config_json_routes_a_warp_root_level_entry() {
        // Warp's `~/.warp/.mcp.json` has the servers at the JSON root
        // (no `mcpServers` wrapper) — `json_key_path` returns `&[]`, and
        // `servers_map_mut` resolves that to the root object.
        let dir = unique_temp_dir("warp-rewrite");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join(".mcp.json");
        std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&serde_json::json!({
                "helper": { "command": "node", "args": ["h.js"] },
                "github": { "url": "https://api.githubcopilot.com/mcp/" }
            }))
            .unwrap(),
        )
        .unwrap();
        let store = temp_store(&dir);
        let shim = dir.join("agentguard-shim");
        std::fs::write(&shim, b"stub").unwrap();

        let art = local_json_artifact(
            "helper",
            config_path.clone(),
            ConfigSourceKind::WarpMcpJson,
            "node",
            &["h.js"],
        );
        let outcome = rewrite_config_json(&config_path, &[&art], Some(&shim), &store).unwrap();
        assert_eq!(outcome.newly_protected, 1);

        let j: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(j["helper"]["command"], shim.display().to_string());
        assert_eq!(
            j["helper"]["args"],
            serde_json::json!([art.artifact.id, "--", "node", "h.js"])
        );
        // the unrelated remote entry at the root is untouched
        assert_eq!(j["github"]["url"], "https://api.githubcopilot.com/mcp/");

        let again = rewrite_config_json(&config_path, &[&art], Some(&shim), &store).unwrap();
        assert_eq!(again.already_protected, 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rewrite_config_json_routes_an_openclaw_two_level_nested_entry() {
        let dir = unique_temp_dir("openclaw-rewrite");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("openclaw.json");
        std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&serde_json::json!({
                "mcp": { "servers": { "gh": { "command": "gh-mcp", "args": [] } } }
            }))
            .unwrap(),
        )
        .unwrap();
        let store = temp_store(&dir);
        let shim = dir.join("agentguard-shim");
        std::fs::write(&shim, b"stub").unwrap();

        let art = local_json_artifact(
            "gh",
            config_path.clone(),
            ConfigSourceKind::OpenClawJson,
            "gh-mcp",
            &[],
        );
        let outcome = rewrite_config_json(&config_path, &[&art], Some(&shim), &store).unwrap();
        assert_eq!(outcome.newly_protected, 1);

        let j: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(j["mcp"]["servers"]["gh"]["command"], shim.display().to_string());
        assert_eq!(
            j["mcp"]["servers"]["gh"]["args"],
            serde_json::json!([art.artifact.id, "--", "gh-mcp"])
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rewrite_config_json_wraps_an_opencode_array_shaped_command() {
        let dir = unique_temp_dir("opencode-rewrite");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("opencode.json");
        std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&serde_json::json!({
                "mcp": {
                    "everything": {
                        "type": "local",
                        "command": ["npx", "-y", "@mcp/everything"],
                        "env": { "TOKEN": "x" }
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let store = temp_store(&dir);
        let shim = dir.join("agentguard-shim");
        std::fs::write(&shim, b"stub").unwrap();

        // opencode.rs normalizes the array into command+args before this
        // point, so `launch` already holds the split form.
        let art = local_json_artifact(
            "everything",
            config_path.clone(),
            ConfigSourceKind::OpenCodeMcpJson,
            "npx",
            &["-y", "@mcp/everything"],
        );
        let outcome = rewrite_config_json(&config_path, &[&art], Some(&shim), &store).unwrap();
        assert_eq!(outcome.newly_protected, 1);

        let j: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        // command stays an ARRAY (opencode's shape); shim is argv[0].
        assert_eq!(
            j["mcp"]["everything"]["command"],
            serde_json::json!([
                shim.display().to_string(),
                art.artifact.id,
                "--",
                "npx",
                "-y",
                "@mcp/everything"
            ])
        );
        // no separate "args" key introduced, and other keys untouched
        assert!(j["mcp"]["everything"].get("args").is_none());
        assert_eq!(j["mcp"]["everything"]["type"], "local");
        assert_eq!(j["mcp"]["everything"]["env"]["TOKEN"], "x");

        // idempotent (already_wrapped detects the shim at array[0])
        let again = rewrite_config_json(&config_path, &[&art], Some(&shim), &store).unwrap();
        assert_eq!(again.newly_protected, 0);
        assert_eq!(again.already_protected, 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rewrite_config_json_routes_a_gemini_cli_extension_manifest() {
        // A Gemini CLI extension's gemini-extension.json is the same flat
        // `{ "mcpServers": {...} }` shape as settings.json, so the
        // standard JSON rewrite applies unchanged — this locks that in.
        let dir = unique_temp_dir("gemini-ext-rewrite");
        let ext_dir = dir.join(".gemini").join("extensions").join("helper");
        std::fs::create_dir_all(&ext_dir).unwrap();
        let config_path = ext_dir.join("gemini-extension.json");
        std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&serde_json::json!({
                "name": "helper",
                "version": "1.0.0",
                "mcpServers": { "helper": { "command": "node", "args": ["server.js"] } }
            }))
            .unwrap(),
        )
        .unwrap();
        let store = temp_store(&dir);
        let shim = dir.join("agentguard-shim");
        std::fs::write(&shim, b"stub").unwrap();

        let art = local_json_artifact(
            "helper",
            config_path.clone(),
            ConfigSourceKind::GeminiCliExtensionJson,
            "node",
            &["server.js"],
        );
        let outcome = rewrite_config_json(&config_path, &[&art], Some(&shim), &store).unwrap();
        assert_eq!(outcome.newly_protected, 1);

        let j: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(j["mcpServers"]["helper"]["command"], shim.display().to_string());
        assert_eq!(
            j["mcpServers"]["helper"]["args"],
            serde_json::json!([art.artifact.id, "--", "node", "server.js"])
        );
        // unrelated manifest keys preserved
        assert_eq!(j["name"], "helper");
        assert_eq!(j["version"], "1.0.0");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rewrite_config_json_removes_a_blocked_remote_entry_from_a_nested_map() {
        let dir = unique_temp_dir("opencode-remote");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("opencode.json");
        std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&serde_json::json!({
                "mcp": {
                    "evil": { "type": "remote", "url": "https://evil.example.com/mcp" },
                    "ok":   { "type": "remote", "url": "https://ok.example.com/mcp" }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let store = temp_store(&dir);

        let mut evil = synthetic_remote_scanned_artifact(
            "evil",
            config_path.clone(),
            "https://evil.example.com/mcp",
            Decision::Block,
            RiskBand::Critical,
        );
        evil.config_source.as_mut().unwrap().kind = ConfigSourceKind::OpenCodeMcpJson;
        let mut ok = synthetic_remote_scanned_artifact(
            "ok",
            config_path.clone(),
            "https://ok.example.com/mcp",
            Decision::Allow,
            RiskBand::Low,
        );
        ok.config_source.as_mut().unwrap().kind = ConfigSourceKind::OpenCodeMcpJson;

        let outcome = rewrite_config_json(&config_path, &[&evil, &ok], None, &store).unwrap();
        assert_eq!(outcome.removed_remote, 1);

        let j: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert!(j["mcp"].get("evil").is_none());
        assert!(j["mcp"].get("ok").is_some());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rewrite_config_value_wraps_a_goose_yaml_map() {
        let dir = unique_temp_dir("goose-yaml");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.yaml");
        std::fs::write(
            &config_path,
            "mcpServers:\n  sqlite:\n    command: npx\n    args:\n      - \"-y\"\n      - pkg\nother: 1\n",
        )
        .unwrap();
        let store = temp_store(&dir);
        let shim = dir.join("agentguard-shim");
        std::fs::write(&shim, b"stub").unwrap();

        let art = local_json_artifact(
            "sqlite",
            config_path.clone(),
            ConfigSourceKind::GooseMcpJson,
            "npx",
            &["-y", "pkg"],
        );
        let outcome = rewrite_config(&config_path, &[&art], Some(&shim), &store).unwrap();
        assert_eq!(outcome.newly_protected, 1);
        assert!(outcome.backup_path.is_some());

        // re-parse the emitted YAML
        let j: serde_json::Value =
            serde_saphyr::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(j["mcpServers"]["sqlite"]["command"], shim.display().to_string());
        assert_eq!(
            j["mcpServers"]["sqlite"]["args"],
            serde_json::json!([art.artifact.id, "--", "npx", "-y", "pkg"])
        );
        assert_eq!(j["other"], 1, "unrelated keys preserved");

        // idempotent
        let again = rewrite_config(&config_path, &[&art], Some(&shim), &store).unwrap();
        assert_eq!(again.newly_protected, 0);
        assert_eq!(again.already_protected, 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rewrite_config_value_wraps_an_aider_yaml_list() {
        let dir = unique_temp_dir("aider-yaml");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join(".aider.conf.yml");
        std::fs::write(
            &config_path,
            "mcp-server:\n  - name: fetch\n    command: node\n    args:\n      - fetch.js\n  - name: keep\n    command: node\n    args: []\n",
        )
        .unwrap();
        let store = temp_store(&dir);
        let shim = dir.join("agentguard-shim");
        std::fs::write(&shim, b"stub").unwrap();

        let art = local_json_artifact(
            "fetch",
            config_path.clone(),
            ConfigSourceKind::AiderMcpJson,
            "node",
            &["fetch.js"],
        );
        let outcome = rewrite_config(&config_path, &[&art], Some(&shim), &store).unwrap();
        assert_eq!(outcome.newly_protected, 1);

        let j: serde_json::Value =
            serde_saphyr::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        let list = j["mcp-server"].as_array().unwrap();
        let fetched = list.iter().find(|e| e["name"] == "fetch").unwrap();
        assert_eq!(fetched["command"], shim.display().to_string());
        assert_eq!(
            fetched["args"],
            serde_json::json!([art.artifact.id, "--", "node", "fetch.js"])
        );
        // the other list element is untouched
        let kept = list.iter().find(|e| e["name"] == "keep").unwrap();
        assert_eq!(kept["command"], "node");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rewrite_config_value_wraps_an_openhands_toml_stdio_server() {
        let dir = unique_temp_dir("openhands-toml");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.toml");
        std::fs::write(
            &config_path,
            "[mcp]\nstdio_servers = [\n  { name = \"tool\", command = \"node\", args = [\"t.js\"] },\n]\n",
        )
        .unwrap();
        let store = temp_store(&dir);
        let shim = dir.join("agentguard-shim");
        std::fs::write(&shim, b"stub").unwrap();

        let art = local_json_artifact(
            "tool",
            config_path.clone(),
            ConfigSourceKind::OpenHandsMcpToml,
            "node",
            &["t.js"],
        );
        let outcome = rewrite_config(&config_path, &[&art], Some(&shim), &store).unwrap();
        assert_eq!(outcome.newly_protected, 1);

        let reparsed: toml::Value =
            toml::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        let entry = reparsed["mcp"]["stdio_servers"].as_array().unwrap()[0]
            .as_table()
            .unwrap();
        assert_eq!(entry["command"].as_str().unwrap(), shim.display().to_string());
        let args: Vec<&str> = entry["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(args, vec![art.artifact.id.as_str(), "--", "node", "t.js"]);

        std::fs::remove_dir_all(&dir).ok();
    }

    fn remote_yaml_artifact(
        name: &str,
        config_path: PathBuf,
        kind: ConfigSourceKind,
        url: &str,
        decision: Decision,
    ) -> ScannedArtifact {
        let mut a = synthetic_remote_scanned_artifact(name, config_path, url, decision, RiskBand::High);
        a.config_source.as_mut().unwrap().kind = kind;
        a.raw_config_entry = Some(serde_json::json!({ "name": name, "url": url }));
        a
    }

    #[test]
    fn rewrite_config_value_removes_a_blocked_remote_from_a_yaml_list() {
        let dir = unique_temp_dir("yaml-list-remove");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join(".continue").join("config.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        std::fs::write(
            &config_path,
            "name: test\nmcpServers:\n  - name: evil\n    url: https://evil.example.com/mcp\n  - name: ok\n    url: https://ok.example.com/mcp\n",
        )
        .unwrap();
        let store = temp_store(&dir);

        let evil = remote_yaml_artifact(
            "evil",
            config_path.clone(),
            ConfigSourceKind::ContinueYamlMcpJson,
            "https://evil.example.com/mcp",
            Decision::Block,
        );
        let ok = remote_yaml_artifact(
            "ok",
            config_path.clone(),
            ConfigSourceKind::ContinueYamlMcpJson,
            "https://ok.example.com/mcp",
            Decision::Allow,
        );
        let outcome = rewrite_config(&config_path, &[&evil, &ok], None, &store).unwrap();
        assert_eq!(outcome.removed_remote, 1);

        let j: serde_json::Value =
            serde_saphyr::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        let list = j["mcpServers"].as_array().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["name"], "ok");
        assert_eq!(j["name"], "test", "unrelated keys preserved");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rewrite_config_value_removes_a_blocked_remote_from_a_goose_yaml_map() {
        let dir = unique_temp_dir("goose-remove");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.yaml");
        std::fs::write(
            &config_path,
            "mcpServers:\n  evil:\n    type: sse\n    url: https://evil.example.com/mcp\n  ok:\n    type: sse\n    url: https://ok.example.com/mcp\n",
        )
        .unwrap();
        let store = temp_store(&dir);

        let evil = remote_yaml_artifact(
            "evil",
            config_path.clone(),
            ConfigSourceKind::GooseMcpJson,
            "https://evil.example.com/mcp",
            Decision::Block,
        );
        let outcome = rewrite_config(&config_path, &[&evil], None, &store).unwrap();
        assert_eq!(outcome.removed_remote, 1);

        let j: serde_json::Value =
            serde_saphyr::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert!(j["mcpServers"].get("evil").is_none());
        assert!(j["mcpServers"].get("ok").is_some());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn restore_remote_entry_yaml_appends_to_a_list_and_is_idempotent() {
        let dir = unique_temp_dir("yaml-restore-list");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.yaml");
        std::fs::write(&config_path, "name: test\nmcpServers:\n  - name: kept\n    url: https://kept.example.com/mcp\n").unwrap();

        let snapshot = serde_json::json!({ "name": "back", "url": "https://back.example.com/mcp" });
        let restored =
            restore_remote_entry(&config_path, "back", &snapshot, &["mcpServers"], true).unwrap();
        assert!(restored);

        let j: serde_json::Value =
            serde_saphyr::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        let list = j["mcpServers"].as_array().unwrap();
        assert_eq!(list.len(), 2);
        assert!(list.iter().any(|e| e["name"] == "back"));

        // idempotent
        assert!(!restore_remote_entry(&config_path, "back", &snapshot, &["mcpServers"], true).unwrap());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn restore_remote_entry_yaml_inserts_into_a_map() {
        let dir = unique_temp_dir("yaml-restore-map");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.yaml");
        std::fs::write(&config_path, "other: 1\n").unwrap();

        let snapshot = serde_json::json!({ "type": "sse", "url": "https://back.example.com/mcp" });
        let restored =
            restore_remote_entry(&config_path, "back", &snapshot, &["mcpServers"], false).unwrap();
        assert!(restored);

        let j: serde_json::Value =
            serde_saphyr::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(j["mcpServers"]["back"], snapshot);
        assert_eq!(j["other"], 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn restore_remote_entry_json_reinserts_into_a_nested_map_and_creates_missing_parents() {
        let dir = unique_temp_dir("restore-nested");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("opencode.json");
        // `mcp` key was removed entirely along with the last entry.
        std::fs::write(&config_path, serde_json::json!({ "other": 1 }).to_string()).unwrap();

        let snapshot = serde_json::json!({ "type": "remote", "url": "https://back.example.com/mcp" });
        let restored =
            restore_remote_entry_json(&config_path, "back", &snapshot, &["mcp"]).unwrap();
        assert!(restored);

        let j: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(j["mcp"]["back"], snapshot);
        assert_eq!(j["other"], 1);

        // idempotent
        assert!(!restore_remote_entry_json(&config_path, "back", &snapshot, &["mcp"]).unwrap());

        std::fs::remove_dir_all(&dir).ok();
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
                config_key_path: Some(vec!["mcpServers".to_string()]),
                config_entry_is_list_element: false,
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
        let restored = restore_remote_entry_json(&config_path, "linear", &snapshot, &["mcpServers"]).unwrap();
        assert!(restored);

        let rewritten: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(rewritten["mcpServers"]["linear"], snapshot);

        // Idempotent: an already-present entry is left alone, not
        // duplicated or clobbered, and reports "nothing to do."
        let restored_again =
            restore_remote_entry_json(&config_path, "linear", &snapshot, &["mcpServers"]).unwrap();
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
        let restored = restore_remote_entry_json(&config_path, "example", &snapshot, &["servers"]).unwrap();
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
                config_key_path: None,
                config_entry_is_list_element: false,
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
