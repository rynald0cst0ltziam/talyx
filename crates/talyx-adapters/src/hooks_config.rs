//! Shared hook-config discovery — factored out of claude_code.rs once Codex
//! was confirmed (learn.chatgpt.com/docs/hooks, two independent fetches,
//! 2026-09-05) to use the byte-for-byte identical JSON shape for its own
//! `.codex/hooks.json` / `~/.codex/hooks.json`: `{"hooks": {"<EventName>":
//! [{"matcher": ..., "hooks": [{"type": "command", "command": ...}]}]}}`.
//! Mirrors the `mcp_config.rs` -> `parse_server_map` extraction: one parser,
//! parameterized by `ConfigSourceKind`/agent id/display name, instead of a
//! second copy of the same logic per agent.

use crate::{ConfigSource, ConfigSourceKind, DiscoveredArtifact, LaunchCommand};
use talyx_core::{
    Artifact, ArtifactKind, ArtifactSource, Capability, CapabilityFinding, EvidenceBasis,
    PublisherIdentity,
};
use talyx_store::DecisionStore;
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

/// Recursively pull every command string (see `crate::HOOK_COMMAND_FIELDS`) found
/// under a JSON `hooks` subtree. Deliberately schema-loose rather than
/// modeling each agent's exact hook config shape field-by-field — that
/// shape has changed before (Claude Code's own docs), and differs
/// outright between agents (Antigravity's per-hook-name map has no
/// `"hooks"` wrapper at all — see `parse_hooks_value`), so "find every
/// command hooks would run" degrades gracefully across schema shapes
/// where a strict struct would just fail to parse or need a bespoke
/// walker per agent.
///
/// An object carrying `"enabled": false` is skipped entirely — not
/// descended into at all — since that's Antigravity's confirmed (2026-09-
/// 05, antigravity.google/docs/hooks) way of disabling a hook without
/// deleting it; a disabled hook never runs, so surfacing it as live risk
/// would be a false positive. Harmless for every other agent, which
/// doesn't populate this field.
///
/// Each hook's `entry_key` (`"hook-<i>"`) is its index in this traversal
/// order — there's no flat map key the way `mcpServers` entries have one,
/// so the rewrite step in talyx-cli's init.rs walks the tree in this
/// same order (with the same enabled-skip rule) to find the matching
/// occurrence.
fn collect_command_strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            if matches!(map.get("enabled"), Some(Value::Bool(false))) {
                return;
            }
            for field in crate::HOOK_COMMAND_FIELDS {
                if let Some(Value::String(s)) = map.get(field) {
                    out.push(s.clone());
                }
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

/// If `command_str` matches the shell-mode wrapper `talyx init` writes
/// when it rewrites a hook (`"<shim-path>" "<artifact-id>" --shell` — see
/// talyx-shim/src/main.rs's module doc comment for the shim side of
/// this contract), returns the original command string by looking it up
/// from the local decision store. The wrapped text itself deliberately does
/// NOT contain the real command — see `DecisionRecord.shell_command`'s doc
/// comment in talyx-store for why embedding it there would be a
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
/// machine-wide one or a shared `TALYX_STORE` env var across parallel
/// test threads.
/// The file stem (name, minus a trailing `.ext`) of a path string,
/// treating BOTH `/` and `\` as separators regardless of the host OS.
/// `std::path::Path` only recognizes `\` as a separator when actually
/// running on Windows — a Windows-produced shim path (`C:\tools\
/// talyx-shim.exe`) embedded in a hook config that's shared across a team
/// (a committed `.claude/settings.json`, say) needs to be recognized the
/// same way on a teammate's Linux machine, or `talyx why` there silently
/// fails to unwrap it. Found via real cross-platform test verification,
/// not assumed.
pub(crate) fn file_stem_either_separator(path: &str) -> Option<&str> {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    if name.is_empty() {
        return None;
    }
    let without_ext = name.len().checked_sub(4).and_then(|i| {
        name[i..].eq_ignore_ascii_case(".exe").then(|| &name[..i])
    });
    Some(without_ext.unwrap_or(name))
}

fn unwrap_shim_hook_invocation(command_str: &str, store: &DecisionStore) -> Option<String> {
    let trimmed = command_str.trim_start();
    let rest = trimmed.strip_prefix('"')?;
    let end_quote = rest.find('"')?;
    let shim_path_candidate = &rest[..end_quote];
    let looks_like_shim = file_stem_either_separator(shim_path_candidate)
        .map(|s| s.eq_ignore_ascii_case("talyx-shim"))
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
/// CodexHooksJson`'s doc comment for the citation). `kind`/`agent_id` are
/// the only per-agent differences. Antigravity's `hooks.json` has no
/// `"hooks"` wrapper key at all (see `ConfigSourceKind::
/// AntigravityHooksJson`'s doc comment) — its own adapter reads the root
/// object directly and calls `parse_hooks_value` instead of this wrapper.
pub(crate) fn parse_hooks_json(
    path: &Path,
    kind: ConfigSourceKind,
    agent_id: &str,
) -> Vec<DiscoveredArtifact> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let Some(json) = crate::jsonc::parse_json_config(path, &text) else {
        return Vec::new();
    };
    let Some(hooks_val) = json.get("hooks") else {
        return Vec::new();
    };
    parse_hooks_value(hooks_val, path, kind, agent_id)
}

/// The shared per-entry walk: given the JSON value that actually holds the
/// hook event tree (already unwrapped from whatever agent-specific
/// container it started in — a `"hooks"` key for Claude Code/Codex, the
/// bare root object for Antigravity), finds every command, builds one
/// `DiscoveredArtifact` per command with the same hash-based-identity
/// safety property for every caller.
pub(crate) fn parse_hooks_value(
    hooks_val: &Value,
    path: &Path,
    kind: ConfigSourceKind,
    agent_id: &str,
) -> Vec<DiscoveredArtifact> {
    let mut out = Vec::new();
    let mut raw_commands = Vec::new();
    collect_command_strings(hooks_val, &mut raw_commands);

    let store = DecisionStore::resolve();
    let mut discovered_by = BTreeSet::new();
    discovered_by.insert(agent_id.to_string());

    for (i, raw_cmd) in raw_commands.into_iter().enumerate() {
        // See through a hook already routed through talyx-shim (from
        // a previous `talyx init`) back to its real command — the
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
        // have them interpreted by that OUTER shell before talyx-shim
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
    use talyx_store::DecisionRecord;

    fn unique_temp_dir(name: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "talyx-hooks-config-test-{}-{}-{}",
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
                band: talyx_core::RiskBand::Low,
                decision: talyx_core::Decision::Allow,
                total_score: 0,
                protection_level: talyx_core::ProtectionLevel::Balanced,
                scanned_at_unix: DecisionRecord::now_unix(),
                reasons: vec![],
                content_hash: None,
                capability_snapshot: vec![],
                shell_command: Some(shell_command.to_string()),
                manually_approved: false,
                remote_entry_snapshot: None,
                config_path: None,
                config_entry_key: None,
                config_key_path: None,
                config_entry_is_list_element: false,
                quarantine_original_path: None,
                quarantine_current_path: None,
                approved_launch: None,
            })
            .unwrap();
        store
    }

    #[test]
    fn unwraps_a_shim_hook_invocation_via_the_store() {
        let store = store_with_shell_command("abc123", "./scripts/audit-log.sh --verbose");
        let wrapped = r#""C:\tools\talyx-shim.exe" "abc123" --shell"#;
        assert_eq!(
            unwrap_shim_hook_invocation(wrapped, &store),
            Some("./scripts/audit-log.sh --verbose".to_string())
        );
    }

    #[test]
    fn recognizes_a_windows_backslash_shim_path_regardless_of_the_host_os() {
        // Found via real Linux verification (Docker, not assumed): a
        // Windows-produced shim path embedded in a hook config shared
        // across a team (a committed `.claude/settings.json`) needs to be
        // recognized on a teammate's Linux/macOS machine too, but
        // `Path::new(...).file_stem()` only treats `\` as a separator
        // when actually running on Windows — on Linux the whole string
        // was one opaque component and this returned `None`. This test
        // pins the specific regression rather than relying on the test
        // above happening to also exercise it only on a Windows CI runner.
        let store = store_with_shell_command("abc123", "./scripts/audit-log.sh --verbose");
        let windows_style = r#""C:\tools\talyx-shim.exe" "abc123" --shell"#;
        let posix_style = r#""/usr/local/bin/talyx-shim" "abc123" --shell"#;
        assert_eq!(
            unwrap_shim_hook_invocation(windows_style, &store),
            Some("./scripts/audit-log.sh --verbose".to_string()),
            "a Windows-style backslash path must unwrap on any host OS"
        );
        assert_eq!(
            unwrap_shim_hook_invocation(posix_style, &store),
            Some("./scripts/audit-log.sh --verbose".to_string()),
            "a POSIX-style forward-slash path (no .exe) must unwrap too"
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
        let wrapped = r#""C:\tools\talyx-shim.exe" "does-not-exist" --shell"#;
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
