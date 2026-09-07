//! Kiro (AWS's AI IDE) adapter. Config paths -- verified 2026-09-05
//! against kiro.dev/docs/mcp/: `.kiro/settings/mcp.json` (project scope)
//! and `~/.kiro/settings/mcp.json` (user scope). Standard `{"mcpServers":
//! {"<name>": {command, args, env, disabled}}}` shape, identical in
//! structure to Claude Code/Cursor -- reuses mcp_config.rs unmodified,
//! including its shared `"disabled": true` skip (added specifically
//! because Kiro's own example config inlines `"disabled": false`).

use crate::mcp_config::parse_mcp_servers_json;
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use std::path::Path;

pub struct KiroAdapter;

impl AgentAdapter for KiroAdapter {
    fn agent_id(&self) -> &'static str {
        "kiro"
    }

    fn agent_name(&self) -> &'static str {
        "Kiro"
    }

    fn detect(&self, project_root: &Path) -> bool {
        let home = dirs::home_dir();
        project_root.join(".kiro").join("settings").join("mcp.json").exists()
            || home
                .as_ref()
                .map(|h| h.join(".kiro").join("settings").join("mcp.json").exists())
                .unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let mut out = Vec::new();
        let home = dirs::home_dir();

        out.extend(parse_mcp_servers_json(
            &project_root.join(".kiro").join("settings").join("mcp.json"),
            project_root,
            ConfigSourceKind::KiroMcpJson,
            "mcpServers",
            "kiro",
            "Kiro",
        ));
        if let Some(h) = &home {
            out.extend(parse_mcp_servers_json(
                &h.join(".kiro").join("settings").join("mcp.json"),
                h,
                ConfigSourceKind::KiroMcpJson,
                "mcpServers",
                "kiro",
                "Kiro",
            ));
        }

        out
    }
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
            "talyx-kiro-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn detects_project_scope_config() {
        let dir = unique_temp_dir("detect");
        let settings_dir = dir.join(".kiro").join("settings");
        std::fs::create_dir_all(&settings_dir).unwrap();
        std::fs::write(settings_dir.join("mcp.json"), "{}").unwrap();

        assert!(KiroAdapter.detect(&dir));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_project_scope_servers_and_skips_a_disabled_one() {
        let dir = unique_temp_dir("discover");
        let settings_dir = dir.join(".kiro").join("settings");
        std::fs::create_dir_all(&settings_dir).unwrap();
        let config = serde_json::json!({
            "mcpServers": {
                "fetch": { "command": "uvx", "args": ["mcp-server-fetch"], "disabled": false },
                "off": { "command": "uvx", "args": ["other"], "disabled": true }
            }
        });
        std::fs::write(settings_dir.join("mcp.json"), serde_json::to_string_pretty(&config).unwrap())
            .unwrap();

        let discovered = KiroAdapter.discover(&dir);
        let mcp: Vec<_> = discovered
            .iter()
            .filter(|d| d.artifact.kind == ArtifactKind::McpServer)
            .filter(|d| d.config_source.as_ref().map(|cs| cs.path.starts_with(&dir)).unwrap_or(false))
            .collect();
        assert_eq!(mcp.len(), 1);
        assert_eq!(mcp[0].artifact.name, "fetch");
        assert!(mcp[0].artifact.discovered_by.contains("kiro"));

        std::fs::remove_dir_all(&dir).ok();
    }
}
