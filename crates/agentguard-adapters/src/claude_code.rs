//! Claude Code adapter — the only Tier-1 adapter with full enforcement
//! planned (BUILD_PLAN.md §0, §5b: `PreToolUse` hooks are a real
//! interception point). MCP server discovery delegates to mcp_config.rs
//! (shared with the Cursor adapter — same JSON shape); this file owns
//! what's specific to Claude Code: hooks and skills discovery, and its
//! own config file locations.
//!
//! Config file locations below are the documented/common ones as of this
//! writing. Claude Code's config layout has changed before and will change
//! again — treat `detect`/`discover` returning nothing as "check these
//! paths are still current," not as "no agent present," and keep this file
//! as the single place those paths live so a version bump is a local edit,
//! not a hunt through the codebase (this is the adapter-maintenance
//! treadmill called out in BUILD_PLAN.md's audit notes).

use crate::mcp_config::parse_mcp_servers_json;
use crate::{AgentAdapter, ConfigSource, ConfigSourceKind, DiscoveredArtifact, LaunchCommand};
use agentguard_core::{
    Artifact, ArtifactKind, ArtifactSource, Capability, CapabilityFinding, EvidenceBasis,
    PublisherIdentity,
};
use agentguard_store::DecisionStore;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// First 16 hex chars of a command's SHA-256 — plenty of collision
/// resistance for identifying hooks on one machine, and (unlike the raw
/// command) safe to embed in a shell-reparsed string. See the doc comment
/// where this is used in `parse_hooks` for why that safety property is
/// load-bearing, not cosmetic.
fn short_hash(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    let digest = hasher.finalize();
    digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

pub struct ClaudeCodeAdapter;

impl AgentAdapter for ClaudeCodeAdapter {
    fn agent_id(&self) -> &'static str {
        "claude-code"
    }

    fn agent_name(&self) -> &'static str {
        "Claude Code"
    }

    fn detect(&self, project_root: &Path) -> bool {
        let home = dirs::home_dir();
        project_root.join(".mcp.json").exists()
            || project_root.join(".claude").exists()
            || home
                .as_ref()
                .map(|h| h.join(".claude.json").exists())
                .unwrap_or(false)
            || home
                .as_ref()
                .map(|h| h.join(".claude").exists())
                .unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let mut out = Vec::new();
        let home = dirs::home_dir();

        // MCP servers — project scope (.mcp.json) and user scope
        // (~/.claude.json). Both sit directly in their own base dir, so
        // base_dir == the config's own parent for each.
        out.extend(parse_mcp_servers_json(
            &project_root.join(".mcp.json"),
            project_root,
            ConfigSourceKind::ClaudeCodeMcpServersJson,
            "claude-code",
            "Claude Code",
        ));
        if let Some(h) = &home {
            out.extend(parse_mcp_servers_json(
                &h.join(".claude.json"),
                h,
                ConfigSourceKind::ClaudeCodeMcpServersJson,
                "claude-code",
                "Claude Code",
            ));
        }

        // Hooks — project and user settings.json.
        out.extend(parse_hooks(
            &project_root.join(".claude").join("settings.json"),
        ));
        if let Some(h) = &home {
            out.extend(parse_hooks(&h.join(".claude").join("settings.json")));
        }

        // Skills — project and user skills directories.
        out.extend(discover_skills(&project_root.join(".claude").join("skills")));
        if let Some(h) = &home {
            out.extend(discover_skills(&h.join(".claude").join("skills")));
        }

        out
    }
}

fn discovered_by_set() -> BTreeSet<String> {
    let mut s = BTreeSet::new();
    s.insert("claude-code".to_string());
    s
}

/// Recursively pull every `"command"` string found under a JSON `hooks`
/// subtree. Deliberately schema-loose rather than modeling Claude Code's
/// exact hook config shape field-by-field — that shape has changed before,
/// and "find every command hooks would run" degrades gracefully across
/// schema versions where a strict struct would just fail to parse.
///
/// Each hook's `entry_key` (`"hook-<i>"`) is its index in this traversal
/// order — there's no flat map key the way `mcpServers` entries have one,
/// so the rewrite step in agentguard-cli's init.rs walks the tree in this
/// same order to find the matching occurrence.
fn parse_hooks(path: &Path) -> Vec<DiscoveredArtifact> {
    let mut out = Vec::new();
    let Ok(text) = fs::read_to_string(path) else {
        return out;
    };
    let Ok(json) = serde_json::from_str::<Value>(&text) else {
        return out;
    };
    let Some(hooks_val) = json.get("hooks") else {
        return out;
    };

    let mut raw_commands = Vec::new();
    collect_command_strings(hooks_val, &mut raw_commands);

    let store = DecisionStore::resolve();

    for (i, raw_cmd) in raw_commands.into_iter().enumerate() {
        // See through a hook already routed through agentguard-shim (from
        // a previous `agentguard init`) back to its real command — the
        // same reasoning, and the same bug class if skipped, as
        // mcp_config.rs's unwrap_shim_invocation for MCP servers.
        let cmd = unwrap_shim_hook_invocation(&raw_cmd, &store).unwrap_or(raw_cmd);

        // The artifact id must NEVER contain the raw command text: it gets
        // embedded verbatim into the rewritten hooks config entry, which
        // Claude Code re-parses through a real shell when the hook fires
        // (confirmed by $CLAUDE_PROJECT_DIR-style expansion in Claude
        // Code's own docs). A command containing shell metacharacters
        // (pipes, redirects) would have them interpreted by that OUTER
        // shell before agentguard-shim ever runs — found live: a fixture
        // hook command containing `|` caused cmd.exe to split the
        // rewritten line into a pipeline and run the later stages
        // directly, bypassing the shim's block entirely. Fixed by keying
        // identity on a hash of the command instead of the command text
        // itself; the real command travels separately, via the local
        // decision store (see init.rs's DecisionRecord.shell_command),
        // never through a shell-reparsed string.
        let source = ArtifactSource::LocalPath(format!("hook:{}", short_hash(&cmd)));
        let artifact = Artifact {
            id: Artifact::compute_id(ArtifactKind::Hook, &format!("hook-{i}"), &source),
            kind: ArtifactKind::Hook,
            name: cmd.clone(),
            version: None,
            publisher: PublisherIdentity::default(),
            source,
            content_hash: None,
            capabilities: vec![
                CapabilityFinding {
                    capability: Capability::Hook,
                    basis: EvidenceBasis::Declared,
                    evidence: "registered in Claude Code's hooks config".to_string(),
                    location: Some(path.display().to_string()),
                },
                CapabilityFinding {
                    capability: Capability::ExecuteShell,
                    basis: EvidenceBasis::Declared,
                    evidence: "hooks run a shell command on agent lifecycle events".to_string(),
                    location: Some(path.display().to_string()),
                },
            ],
            discovered_by: discovered_by_set(),
        };
        out.push(DiscoveredArtifact {
            artifact,
            scan_root: None,
            display_location: cmd.clone(),
            launch: Some(LaunchCommand {
                command: cmd,
                // Empty on purpose: a hook's `command` is one shell-syntax
                // STRING (Claude Code's own docs show shell variable
                // expansion like $CLAUDE_PROJECT_DIR inside it), not an
                // argv array the way an MCP server's command+args are —
                // there's nothing to split into separate args here.
                args: vec![],
            }),
            config_source: Some(ConfigSource {
                path: path.to_path_buf(),
                kind: ConfigSourceKind::ClaudeCodeHooksJson,
                entry_key: format!("hook-{i}"),
            }),
            raw_config_entry: None,
        });
    }

    out
}

/// If `command_str` matches the shell-mode wrapper this adapter writes
/// when `agentguard init` rewrites a hook (`"<shim-path>" "<artifact-id>"
/// --shell` — see agentguard-shim/src/main.rs's module doc comment for the
/// shim side of this contract), returns the original command string by
/// looking it up from the local decision store. The wrapped text itself
/// deliberately does NOT contain the real command — see
/// `DecisionRecord.shell_command`'s doc comment in agentguard-store for
/// why embedding it there would be a shell-injection hazard at the
/// wrapping layer (found live, not hypothetically, via a fixture whose
/// hook command contained a pipe character). `None` if the text doesn't
/// match the wrapper shape, or if the store has no record / no
/// `shell_command` for the extracted id — a degraded-but-safe fallback:
/// the caller then treats the wrapped text itself as the "command," a
/// worse capability signal but never a crash or, worse, a guess.
/// Takes `store` explicitly (rather than resolving one internally) so this
/// parsing logic is unit-testable with an isolated store instead of racing
/// on the real machine-wide one or a shared `AGENTGUARD_STORE` env var
/// across parallel test threads. `parse_hooks` resolves the real store
/// once and passes it down.
fn unwrap_shim_hook_invocation(command_str: &str, store: &DecisionStore) -> Option<String> {
    let trimmed = command_str.trim_start();
    let rest = trimmed.strip_prefix('"')?;
    let end_quote = rest.find('"')?;
    let shim_path_candidate = &rest[..end_quote];
    let looks_like_shim = Path::new(shim_path_candidate)
        .file_stem()
        .and_then(|s| s.to_str())
        .map(|s| s.eq_ignore_ascii_case("agentguard-shim"))
        .unwrap_or(false);
    if !looks_like_shim {
        return None;
    }

    let after_shim = rest[end_quote + 1..].trim_start();
    let after_id_quote = after_shim.strip_prefix('"')?;
    let id_end_quote = after_id_quote.find('"')?;
    let artifact_id = &after_id_quote[..id_end_quote];
    let after_id = after_id_quote[id_end_quote + 1..].trim();
    if after_id != "--shell" {
        return None;
    }

    store.get(artifact_id).and_then(|r| r.shell_command)
}

fn collect_command_strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(s)) = map.get("command") {
                out.push(s.clone());
            }
            for v in map.values() {
                collect_command_strings(v, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_command_strings(item, out);
            }
        }
        _ => {}
    }
}

/// Every subdirectory of `dir` containing a `SKILL.md` is treated as a
/// skill artifact. Its capabilities aren't populated here — the CLI hands
/// `scan_root` to agentguard-scanner for that.
fn discover_skills(dir: &Path) -> Vec<DiscoveredArtifact> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() && path.join("SKILL.md").exists() {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("skill")
                .to_string();
            let source = ArtifactSource::LocalPath(path.display().to_string());
            let artifact = Artifact {
                id: Artifact::compute_id(ArtifactKind::Skill, &name, &source),
                kind: ArtifactKind::Skill,
                name: name.clone(),
                version: None,
                publisher: PublisherIdentity::default(),
                source,
                content_hash: None,
                capabilities: vec![],
                discovered_by: discovered_by_set(),
            };
            out.push(DiscoveredArtifact {
                display_location: path.display().to_string(),
                scan_root: Some(path),
                artifact,
                launch: None,
                config_source: None,
                raw_config_entry: None,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentguard_store::DecisionRecord;

    fn unique_temp_dir(name: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "agentguard-claude-code-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    fn store_with_shell_command(artifact_id: &str, shell_command: &str) -> DecisionStore {
        let store = DecisionStore::open_at(unique_temp_dir("unwrap-store").with_extension("json"));
        store
            .upsert(DecisionRecord {
                artifact_id: artifact_id.to_string(),
                name: "test-hook".to_string(),
                band: agentguard_core::RiskBand::Low,
                decision: agentguard_core::Decision::Allow,
                total_score: 0,
                protection_level: agentguard_core::ProtectionLevel::Balanced,
                scanned_at_unix: DecisionRecord::now_unix(),
                reasons: vec![],
                content_hash: None,
                capability_snapshot: vec![],
                shell_command: Some(shell_command.to_string()),
                manually_approved: false,
                remote_entry_snapshot: None,
                config_path: None,
                config_entry_key: None,
                quarantine_original_path: None,
                quarantine_current_path: None,
            })
            .unwrap();
        store
    }

    #[test]
    fn unwraps_a_shim_hook_invocation_via_the_store() {
        // Explicit store injection (not AGENTGUARD_STORE / the real
        // machine store) — see unwrap_shim_hook_invocation's doc comment
        // for why: this keeps the test isolated from other tests running
        // in parallel in the same binary.
        let store = store_with_shell_command("abc123", "./scripts/audit-log.sh --verbose");
        let wrapped = r#""C:\tools\agentguard-shim.exe" "abc123" --shell"#;
        assert_eq!(
            unwrap_shim_hook_invocation(wrapped, &store),
            Some("./scripts/audit-log.sh --verbose".to_string())
        );
    }

    #[test]
    fn does_not_unwrap_a_plain_hook_command() {
        let store = DecisionStore::open_at(unique_temp_dir("unwrap-empty").with_extension("json"));
        assert_eq!(
            unwrap_shim_hook_invocation("$CLAUDE_PROJECT_DIR/.claude/hooks/guard.sh", &store),
            None
        );
        // Doesn't false-positive on an unrelated quoted command that
        // happens to use " -- " as a literal argument separator, and
        // (unlike the old text-only format) no longer accepts a trailing
        // "-- <command>" shape at all — shell mode takes no argv command.
        assert_eq!(
            unwrap_shim_hook_invocation(r#""/usr/bin/some-tool" --flag -- value"#, &store),
            None
        );
    }

    #[test]
    fn falls_back_gracefully_when_the_store_has_no_matching_record() {
        // Degraded-but-safe: looks like a wrapper shape, but the id isn't
        // in the store (e.g. store was cleared, or a different machine's
        // config got copied over) — must return None, never panic or
        // fabricate a command.
        let store = DecisionStore::open_at(unique_temp_dir("unwrap-miss").with_extension("json"));
        let wrapped = r#""C:\tools\agentguard-shim.exe" "does-not-exist" --shell"#;
        assert_eq!(unwrap_shim_hook_invocation(wrapped, &store), None);
    }

    #[test]
    fn parse_hooks_populates_launch_and_config_source() {
        let dir = unique_temp_dir("hooks-launch");
        std::fs::create_dir_all(&dir).unwrap();
        let settings_path = dir.join("settings.json");
        let settings = serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    { "matcher": "*", "hooks": [ { "type": "command", "command": "./scripts/audit-log.sh" } ] }
                ]
            }
        });
        std::fs::write(&settings_path, serde_json::to_string_pretty(&settings).unwrap()).unwrap();

        let discovered = parse_hooks(&settings_path);
        assert_eq!(discovered.len(), 1);
        let d = &discovered[0];
        assert_eq!(
            d.launch.as_ref().unwrap().command,
            "./scripts/audit-log.sh"
        );
        assert!(d.launch.as_ref().unwrap().args.is_empty());
        let cs = d.config_source.as_ref().unwrap();
        assert_eq!(cs.kind, ConfigSourceKind::ClaudeCodeHooksJson);
        assert_eq!(cs.entry_key, "hook-0");

        std::fs::remove_dir_all(&dir).ok();
    }

    // parse_hooks "sees through an already-wrapped entry" end to end is
    // covered at the unit level by unwraps_a_shim_hook_invocation_via_the_store
    // above — an integration-level version of this test would need to
    // control what DecisionStore::resolve() (called internally by
    // parse_hooks) resolves to, which means either mutating the
    // process-wide AGENTGUARD_STORE env var (races against other tests
    // running in parallel in this binary) or threading a store parameter
    // through the AgentAdapter trait for every adapter's sake, just for
    // this one case. Testing the pure unwrap function directly gives the
    // same regression coverage without either cost.

    #[test]
    fn hash_of_the_same_command_is_stable() {
        assert_eq!(short_hash("./scripts/audit-log.sh"), short_hash("./scripts/audit-log.sh"));
        assert_ne!(
            short_hash("./scripts/audit-log.sh"),
            short_hash("cat ~/.ssh/id_rsa")
        );
        // Purely hex — safe to embed in a shell-reparsed string, which is
        // the entire reason this exists instead of the raw command text.
        assert!(short_hash("anything with | pipes && metachars").chars().all(|c| c.is_ascii_hexdigit()));
    }
}
