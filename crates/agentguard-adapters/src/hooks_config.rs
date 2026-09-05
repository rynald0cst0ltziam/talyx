//! Shared hook-config discovery — factored out of claude_code.rs once Codex
//! was confirmed (learn.chatgpt.com/docs/hooks, two independent fetches,
//! 2026-09-05) to use the byte-for-byte identical JSON shape for its own
//! `.codex/hooks.json` / `~/.codex/hooks.json`: `{"hooks": {"<EventName>":
//! [{"matcher": ..., "hooks": [{"type": "command", "command": ...}]}]}}`.
//! Mirrors the `mcp_config.rs` -> `parse_server_map` extraction: one parser,
//! parameterized by `ConfigSourceKind`/agent id/display name, instead of a
//! second copy of the same logic per agent.

use crate::{ConfigSource, ConfigSourceKind, DiscoveredArtifact, LaunchCommand};
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
/// where this is used in `parse_hooks_json` for why that safety property is
/// load-bearing, not cosmetic.
fn short_hash(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    let digest = hasher.finalize();
    digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// Recursively pull every `"command"` string found under a JSON `hooks`
/// subtree. Deliberately schema-loose rather than modeling each agent's
/// exact hook config shape field-by-field — that shape has changed before
/// (Claude Code's own docs), and "find every command hooks would run"
/// degrades gracefully across schema versions where a strict struct would
/// just fail to parse.
///
/// Each hook's `entry_key` (`"hook-<i>"`) is its index in this traversal
/// order — there's no flat map key the way `mcpServers` entries have one,
/// so the rewrite step in agentguard-cli's init.rs walks the tree in this
/// same order to find the matching occurrence.
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

/// If `command_str` matches the shell-mode wrapper `agentguard init` writes
/// when it rewrites a hook (`"<shim-path>" "<artifact-id>" --shell` — see
/// agentguard-shim/src/main.rs's module doc comment for the shim side of
/// this contract), returns the original command string by looking it up
/// from the local decision store. The wrapped text itself deliberately does
/// NOT contain the real command — see `DecisionRecord.shell_command`'s doc
/// comment in agentguard-store for why embedding it there would be a
/// shell-injection hazard at the wrapping layer (found live, not
/// hypothetically, via a Claude Code fixture whose hook command contained a
/// pipe character — the same wrapper shape and the same risk apply
/// verbatim to any agent whose hooks run through a real shell, which is why
/// this is shared rather than reimplemented per agent). `None` if the text
/// doesn't match the wrapper shape, or if the store has no record / no
/// `shell_command` for the extracted id — a degraded-but-safe fallback: the
/// caller then treats the wrapped text itself as the "command," a worse
/// capability signal but never a crash or, worse, a guess. Takes `store`
/// explicitly (rather than resolving one internally) so this parsing logic
/// is unit-testable with an isolated store instead of racing on the real
/// machine-wide one or a shared `AGENTGUARD_STORE` env var across parallel
/// test threads.
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

/// Parses a `{"hooks": {...}}`-shaped hook config file into `DiscoveredArtifact`s.
/// Shared by Claude Code (`settings.json`) and Codex (`hooks.json`) — both
/// verified to use the identical JSON shape (see `ConfigSourceKind::
/// CodexHooksJson`'s doc comment for the citation). `kind`/`agent_id`/
/// `agent_display_name` are the only per-agent differences.
pub(crate) fn parse_hooks_json(
    path: &Path,
    kind: ConfigSourceKind,
    agent_id: &str,
) -> Vec<DiscoveredArtifact> {
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
    let mut discovered_by = BTreeSet::new();
    discovered_by.insert(agent_id.to_string());

    for (i, raw_cmd) in raw_commands.into_iter().enumerate() {
        // See through a hook already routed through agentguard-shim (from
        // a previous `agentguard init`) back to its real command — the
        // same reasoning, and the same bug class if skipped, as
        // mcp_config.rs's unwrap_shim_invocation for MCP servers.
        let cmd = unwrap_shim_hook_invocation(&raw_cmd, &store).unwrap_or(raw_cmd);

        // The artifact id must NEVER contain the raw command text: it gets
        // embedded verbatim into the rewritten hooks config entry, which
        // the agent re-parses through a real shell when the hook fires
        // (confirmed by $CLAUDE_PROJECT_DIR-style expansion in Claude
        // Code's own docs, and by a `$(git rev-parse --show-toplevel)`
        // command-substitution example in Codex's own hooks docs). A
        // command containing shell metacharacters (pipes, redirects) would
        // have them interpreted by that OUTER shell before agentguard-shim
        // ever runs — found live for Claude Code: a fixture hook command
        // containing `|` caused cmd.exe to split the rewritten line into a
        // pipeline and run the later stages directly, bypassing the shim's
        // block entirely. Fixed by keying identity on a hash of the
        // command instead of the command text itself; the real command
        // travels separately, via the local decision store (see init.rs's
        // DecisionRecord.shell_command), never through a shell-reparsed
        // string.
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
                    evidence: format!("registered in {agent_id}'s hooks config"),
                    location: Some(path.display().to_string()),
                },
                CapabilityFinding {
                    capability: Capability::ExecuteShell,
                    basis: EvidenceBasis::Declared,
                    evidence: "hooks run a shell command on agent lifecycle events".to_string(),
                    location: Some(path.display().to_string()),
                },
            ],
            discovered_by: discovered_by.clone(),
        };
        out.push(DiscoveredArtifact {
            artifact,
            scan_root: None,
            display_location: cmd.clone(),
            launch: Some(LaunchCommand {
                command: cmd,
                // Empty on purpose: a hook's `command` is one shell-syntax
                // STRING, not an argv array the way an MCP server's
                // command+args are — there's nothing to split into
                // separate args here.
                args: vec![],
            }),
            config_source: Some(ConfigSource {
                path: path.to_path_buf(),
                kind,
                entry_key: format!("hook-{i}"),
            }),
            raw_config_entry: None,
        });
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
            "agentguard-hooks-config-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn parse_hooks_json_populates_launch_and_config_source_for_codex() {
        let dir = unique_temp_dir("codex-hooks");
        std::fs::create_dir_all(&dir).unwrap();
        let hooks_path = dir.join("hooks.json");
        let hooks = serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Bash", "hooks": [ { "type": "command", "command": "./scripts/audit-log.sh" } ] }
                ]
            }
        });
        std::fs::write(&hooks_path, serde_json::to_string_pretty(&hooks).unwrap()).unwrap();

        let discovered = parse_hooks_json(&hooks_path, ConfigSourceKind::CodexHooksJson, "codex");
        assert_eq!(discovered.len(), 1);
        let d = &discovered[0];
        assert_eq!(d.launch.as_ref().unwrap().command, "./scripts/audit-log.sh");
        assert!(d.artifact.discovered_by.contains("codex"));
        let cs = d.config_source.as_ref().unwrap();
        assert_eq!(cs.kind, ConfigSourceKind::CodexHooksJson);
        assert_eq!(cs.entry_key, "hook-0");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parse_hooks_json_ignores_an_optional_description_field() {
        // Codex's docs show hooks.json carrying an optional top-level
        // "description" field alongside "hooks" — confirm it's simply
        // ignored, not mistaken for a hooks subtree.
        let dir = unique_temp_dir("codex-hooks-desc");
        std::fs::create_dir_all(&dir).unwrap();
        let hooks_path = dir.join("hooks.json");
        let hooks = serde_json::json!({
            "description": "Optional lifecycle hooks for this workspace.",
            "hooks": {
                "SessionStart": [
                    { "matcher": "startup|resume", "hooks": [ { "type": "command", "command": "echo hi" } ] }
                ]
            }
        });
        std::fs::write(&hooks_path, serde_json::to_string_pretty(&hooks).unwrap()).unwrap();

        let discovered = parse_hooks_json(&hooks_path, ConfigSourceKind::CodexHooksJson, "codex");
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].launch.as_ref().unwrap().command, "echo hi");

        std::fs::remove_dir_all(&dir).ok();
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
                config_top_level_key: None,
                quarantine_original_path: None,
                quarantine_current_path: None,
            })
            .unwrap();
        store
    }

    #[test]
    fn unwraps_a_shim_hook_invocation_via_the_store() {
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
            unwrap_shim_hook_invocation("$(git rev-parse --show-toplevel)/hooks/guard.sh", &store),
            None
        );
        assert_eq!(
            unwrap_shim_hook_invocation(r#""/usr/bin/some-tool" --flag -- value"#, &store),
            None
        );
    }

    #[test]
    fn falls_back_gracefully_when_the_store_has_no_matching_record() {
        let store = DecisionStore::open_at(unique_temp_dir("unwrap-miss").with_extension("json"));
        let wrapped = r#""C:\tools\agentguard-shim.exe" "does-not-exist" --shell"#;
        assert_eq!(unwrap_shim_hook_invocation(wrapped, &store), None);
    }

    #[test]
    fn hash_of_the_same_command_is_stable() {
        assert_eq!(short_hash("./scripts/audit-log.sh"), short_hash("./scripts/audit-log.sh"));
        assert_ne!(short_hash("./scripts/audit-log.sh"), short_hash("cat ~/.ssh/id_rsa"));
        assert!(short_hash("anything with | pipes && metachars")
            .chars()
            .all(|c| c.is_ascii_hexdigit()));
    }
}
