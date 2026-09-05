//! Google Antigravity adapter. Config paths —
//! `~/.gemini/config/mcp_config.json` (global/user scope) and
//! `.agents/mcp_config.json` (project scope), both confirmed directly
//! against Antigravity's own docs, not assumed. Same `{ "mcpServers": {
//! "<name>": { command, args, env } } }` shape as Claude Code/Cursor,
//! reusing mcp_config.rs — Antigravity's remote-server field is
//! documented as `serverUrl` (NOT `url`), already handled by the shared
//! parser's fallback (see `ConfigSourceKind::AntigravityMcpJson`'s doc
//! comment for the deliberate distinction from Gemini CLI's own,
//! differently-shaped config that happens to share the `~/.gemini/`
//! parent directory).
//!
//! Hooks — `.agents/hooks.json` (project) / `~/.gemini/config/hooks.json`
//! (user), verified 2026-09-05 via two independent, mutually-agreeing
//! fetches (see `ConfigSourceKind::AntigravityHooksJson`'s doc comment for
//! why that cross-check mattered here). Unlike Claude Code/Codex, there's
//! no `"hooks"` wrapper key — the root object itself is a map of hook name
//! -> event map, so this reads the file directly and hands the whole root
//! to `hooks_config::parse_hooks_value` instead of going through
//! `parse_hooks_json`'s `"hooks"`-key extraction.

use crate::hooks_config::parse_hooks_value;
use crate::mcp_config::parse_mcp_servers_json;
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use serde_json::Value;
use std::fs;
use std::path::Path;

/// Antigravity's `hooks.json` has no `"hooks"` wrapper key — the root
/// object IS the hook-name -> event-map (see this module's doc comment and
/// `ConfigSourceKind::AntigravityHooksJson`), so the whole parsed root is
/// handed straight to the shared per-entry walk. `parse_hooks_value`'s own
/// `enabled: false` skip (in `collect_command_strings`) already handles a
/// disabled hook name correctly — no separate filtering needed here.
fn parse_antigravity_hooks(path: &Path) -> Vec<DiscoveredArtifact> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(json) = serde_json::from_str::<Value>(&text) else {
        return Vec::new();
    };
    if !json.is_object() {
        return Vec::new();
    }
    parse_hooks_value(&json, path, ConfigSourceKind::AntigravityHooksJson, "antigravity")
}

pub struct AntigravityAdapter;

impl AgentAdapter for AntigravityAdapter {
    fn agent_id(&self) -> &'static str {
        "antigravity"
    }

    fn agent_name(&self) -> &'static str {
        "Antigravity"
    }

    fn detect(&self, project_root: &Path) -> bool {
        let home = dirs::home_dir();
        project_root.join(".agents").exists()
            || home
                .as_ref()
                .map(|h| h.join(".gemini").join("config").exists())
                .unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let mut out = Vec::new();
        let home = dirs::home_dir();

        out.extend(parse_mcp_servers_json(
            &project_root.join(".agents").join("mcp_config.json"),
            project_root,
            ConfigSourceKind::AntigravityMcpJson,
            "mcpServers",
            "antigravity",
            "Antigravity",
        ));
        if let Some(h) = &home {
            out.extend(parse_mcp_servers_json(
                &h.join(".gemini").join("config").join("mcp_config.json"),
                h,
                ConfigSourceKind::AntigravityMcpJson,
                "mcpServers",
                "antigravity",
                "Antigravity",
            ));
        }

        out.extend(parse_antigravity_hooks(
            &project_root.join(".agents").join("hooks.json"),
        ));
        if let Some(h) = &home {
            out.extend(parse_antigravity_hooks(
                &h.join(".gemini").join("config").join("hooks.json"),
            ));
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentguard_core::ArtifactKind;

    fn unique_temp_dir(name: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "agentguard-antigravity-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn detects_project_scope_agents_dir() {
        let dir = unique_temp_dir("detect");
        std::fs::create_dir_all(dir.join(".agents")).unwrap();

        assert!(AntigravityAdapter.detect(&dir));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_project_scope_mcp_servers() {
        let dir = unique_temp_dir("discover-mcp");
        let agents_dir = dir.join(".agents");
        std::fs::create_dir_all(&agents_dir).unwrap();
        let config = serde_json::json!({
            "mcpServers": { "example": { "command": "some-binary", "args": [] } }
        });
        std::fs::write(
            agents_dir.join("mcp_config.json"),
            serde_json::to_string_pretty(&config).unwrap(),
        )
        .unwrap();

        let discovered = AntigravityAdapter.discover(&dir);
        let project_mcp_entries: Vec<_> = discovered
            .iter()
            .filter(|d| d.artifact.kind == ArtifactKind::McpServer)
            .filter(|d| {
                d.config_source
                    .as_ref()
                    .map(|cs| cs.path.starts_with(&dir))
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(project_mcp_entries.len(), 1);
        assert_eq!(project_mcp_entries[0].artifact.name, "example");
        assert!(project_mcp_entries[0].artifact.discovered_by.contains("antigravity"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_a_remote_server_via_serverurl_field() {
        // Antigravity's own docs document ONLY `serverUrl` for remote
        // servers, not `url` -- this is the field name that would have
        // silently gone undetected if the shared parser's remote check
        // hadn't been extended to also look for it.
        let dir = unique_temp_dir("discover-remote");
        let agents_dir = dir.join(".agents");
        std::fs::create_dir_all(&agents_dir).unwrap();
        let config = serde_json::json!({
            "mcpServers": { "remote-example": { "serverUrl": "https://mcp.example.com/mcp" } }
        });
        std::fs::write(
            agents_dir.join("mcp_config.json"),
            serde_json::to_string_pretty(&config).unwrap(),
        )
        .unwrap();

        let discovered = AntigravityAdapter.discover(&dir);
        let remote: Vec<_> = discovered
            .iter()
            .filter(|d| d.artifact.name == "remote-example")
            .collect();
        assert_eq!(remote.len(), 1);
        assert!(remote[0].launch.is_none());
        assert!(remote[0].config_source.is_some());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_an_enabled_hook_and_skips_a_disabled_one() {
        // Antigravity's hooks.json has no "hooks" wrapper key -- the root
        // IS the hook-name -> event-map -- and a hook name can carry
        // "enabled": false to disable it without deleting it. A disabled
        // hook never runs, so it must not be surfaced as live risk.
        let dir = unique_temp_dir("hooks");
        let agents_dir = dir.join(".agents");
        std::fs::create_dir_all(&agents_dir).unwrap();
        let hooks = serde_json::json!({
            "my-linter-hook": {
                "PostToolUse": [
                    { "matcher": "run_command", "hooks": [ { "type": "command", "command": "./scripts/lint.sh", "timeout": 10 } ] }
                ]
            },
            "safety-gate": {
                "enabled": false,
                "PreToolUse": [
                    { "matcher": "run_command", "hooks": [ { "command": "./scripts/safety-check.sh" } ] }
                ]
            }
        });
        std::fs::write(agents_dir.join("hooks.json"), serde_json::to_string_pretty(&hooks).unwrap())
            .unwrap();

        let discovered = AntigravityAdapter.discover(&dir);
        let hooks: Vec<_> = discovered
            .iter()
            .filter(|d| d.artifact.kind == ArtifactKind::Hook)
            .collect();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].launch.as_ref().unwrap().command, "./scripts/lint.sh");
        assert!(hooks[0].artifact.discovered_by.contains("antigravity"));
        assert_eq!(
            hooks[0].config_source.as_ref().unwrap().kind,
            ConfigSourceKind::AntigravityHooksJson
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
