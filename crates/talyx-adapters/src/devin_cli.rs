//! Devin CLI adapter -- a SEPARATE product from Windsurf/Devin Desktop/
//! Cascade (the IDE `windsurf.rs` targets). Verified 2026-09-05 via two
//! independent sources agreeing: docs.devin.ai/cli/extensibility/
//! configuration and /hooks/overview directly, cross-validated against
//! Warden-AI's own real, working registration code (github.com/
//! rynald0cst0ltziam/Warden-AI's `src/cli/register.ts`), which targets
//! these exact paths under "Devin CLI" as distinct from its own separate
//! "Windsurf/Devin" registration.
//!
//! MCP servers: `.devin/config.json` (project) and `~/.config/devin/
//! config.json` (macOS/Linux) / `%APPDATA%\devin\config.json` (Windows)
//! (user), with `mcp_config.json` confirmed as a legacy/alternative
//! filename at the same user-scope directory. Standard `{"mcpServers":
//! {...}}` shape.
//!
//! Hooks: `.devin/hooks.v1.json` (project scope) -- the root object IS the
//! event map directly (no `"hooks"` wrapper key), independently confirmed
//! by reading Warden-AI's own real, in-repo `.devin/hooks.v1.json` file,
//! not just docs prose. User-scope hooks nest under a `"hooks"` key
//! INSIDE `config.json` itself -- the opposite wrapper convention from the
//! project-scope file -- so this reuses the existing `parse_hooks_json`
//! (`"hooks"`-key extraction) for that file and `hooks_config::
//! parse_hooks_value` directly (no wrapper) for the standalone project
//! file.

use crate::hooks_config::{parse_hooks_json, parse_hooks_value};
use crate::mcp_config::parse_mcp_servers_json;
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub struct DevinCliAdapter;

impl AgentAdapter for DevinCliAdapter {
    fn agent_id(&self) -> &'static str {
        "devin-cli"
    }

    fn agent_name(&self) -> &'static str {
        "Devin CLI"
    }

    fn detect(&self, project_root: &Path) -> bool {
        project_root.join(".devin").join("config.json").exists()
            || project_root.join(".devin").join("hooks.v1.json").exists()
            || user_config_dir().map(|d| d.join("config.json").exists()).unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let mut out = Vec::new();

        // MCP servers -- project config.json.
        out.extend(parse_mcp_servers_json(
            &project_root.join(".devin").join("config.json"),
            project_root,
            ConfigSourceKind::DevinCliMcpJson,
            "mcpServers",
            "devin-cli",
            "Devin CLI",
        ));

        if let Some(user_dir) = user_config_dir() {
            // User-scope config.json, and its confirmed legacy/alternative
            // mcp_config.json filename at the same directory.
            out.extend(parse_mcp_servers_json(
                &user_dir.join("config.json"),
                &user_dir,
                ConfigSourceKind::DevinCliMcpJson,
                "mcpServers",
                "devin-cli",
                "Devin CLI",
            ));
            out.extend(parse_mcp_servers_json(
                &user_dir.join("mcp_config.json"),
                &user_dir,
                ConfigSourceKind::DevinCliMcpJson,
                "mcpServers",
                "devin-cli",
                "Devin CLI",
            ));

            // User-scope hooks -- nested under a "hooks" key INSIDE
            // config.json, same wrapper convention as Claude Code/Codex.
            out.extend(parse_hooks_json(
                &user_dir.join("config.json"),
                ConfigSourceKind::DevinCliHooksJson, // wrapped -- see its doc comment
                "devin-cli",
            ));
        }

        // Project-scope hooks -- the standalone hooks.v1.json file, whose
        // root IS the event map directly (no wrapper key).
        out.extend(parse_project_hooks(&project_root.join(".devin").join("hooks.v1.json")));

        out
    }
}

fn user_config_dir() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    if cfg!(windows) {
        Some(home.join("AppData").join("Roaming").join("devin"))
    } else {
        Some(home.join(".config").join("devin"))
    }
}

fn parse_project_hooks(path: &Path) -> Vec<DiscoveredArtifact> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(json) = serde_json::from_str::<Value>(&text) else {
        return Vec::new();
    };
    if !json.is_object() {
        return Vec::new();
    }
    parse_hooks_value(&json, path, ConfigSourceKind::DevinCliProjectHooksJson, "devin-cli")
}

#[cfg(test)]
mod tests {
    use super::*;
    use talyx_core::ArtifactKind;

    fn unique_temp_dir(name: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "talyx-devin-cli-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn detects_project_scope_config() {
        let dir = unique_temp_dir("detect");
        std::fs::create_dir_all(dir.join(".devin")).unwrap();
        std::fs::write(dir.join(".devin").join("config.json"), "{}").unwrap();

        assert!(DevinCliAdapter.detect(&dir));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_project_scope_mcp_servers() {
        let dir = unique_temp_dir("discover-mcp");
        std::fs::create_dir_all(dir.join(".devin")).unwrap();
        let config = serde_json::json!({
            "mcpServers": { "example": { "command": "some-binary", "args": [] } }
        });
        std::fs::write(
            dir.join(".devin").join("config.json"),
            serde_json::to_string_pretty(&config).unwrap(),
        )
        .unwrap();

        let discovered = DevinCliAdapter.discover(&dir);
        let mcp: Vec<_> = discovered
            .iter()
            .filter(|d| d.artifact.kind == ArtifactKind::McpServer)
            .filter(|d| d.config_source.as_ref().map(|cs| cs.path.starts_with(&dir)).unwrap_or(false))
            .collect();
        assert_eq!(mcp.len(), 1);
        assert_eq!(mcp[0].artifact.name, "example");
        assert!(mcp[0].artifact.discovered_by.contains("devin-cli"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_project_scope_hooks_with_no_wrapper_key() {
        let dir = unique_temp_dir("discover-hooks");
        std::fs::create_dir_all(dir.join(".devin")).unwrap();
        let hooks = serde_json::json!({
            "PreToolUse": [
                { "matcher": "exec", "hooks": [ { "type": "command", "command": "./scripts/check-command.sh" } ] }
            ]
        });
        std::fs::write(
            dir.join(".devin").join("hooks.v1.json"),
            serde_json::to_string_pretty(&hooks).unwrap(),
        )
        .unwrap();

        let discovered = DevinCliAdapter.discover(&dir);
        let hook = discovered
            .iter()
            .find(|d| d.artifact.kind == ArtifactKind::Hook)
            .expect("hook should be discovered");
        assert_eq!(hook.launch.as_ref().unwrap().command, "./scripts/check-command.sh");
        assert!(hook.artifact.discovered_by.contains("devin-cli"));
        assert_eq!(
            hook.config_source.as_ref().unwrap().kind,
            ConfigSourceKind::DevinCliProjectHooksJson
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn user_scope_config_json_hooks_use_the_wrapped_shape_via_shared_parse_hooks_json() {
        // Confirms the opposite convention from the project-scope file is
        // handled correctly: user-scope hooks nest under a "hooks" key
        // INSIDE config.json, so this exercises parse_hooks_json's
        // existing "hooks"-key extraction directly (the same function
        // Claude Code/Codex/Gemini CLI/Copilot CLI use), not the
        // no-wrapper parse_project_hooks path.
        let dir = unique_temp_dir("user-scope-hooks");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.json");
        let config = serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    { "matcher": "exec", "hooks": [ { "type": "command", "command": "./scripts/user-scope.sh" } ] }
                ]
            }
        });
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovered = crate::hooks_config::parse_hooks_json(
            &config_path,
            ConfigSourceKind::DevinCliHooksJson,
            "devin-cli",
        );
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].launch.as_ref().unwrap().command, "./scripts/user-scope.sh");

        std::fs::remove_dir_all(&dir).ok();
    }
}
