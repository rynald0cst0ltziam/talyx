//! Tabnine adapter. Verified 2026-09-05 against docs.tabnine.com's own
//! MCP setup docs. Path: `.tabnine/mcp_servers.json` (project scope) and
//! `~/.tabnine/mcp_servers.json` (user scope). Standard `{"mcpServers":
//! {...}}` shape, reusing mcp_config.rs unmodified.

use crate::mcp_config::parse_mcp_servers_json;
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use std::path::Path;

pub struct TabnineAdapter;

impl AgentAdapter for TabnineAdapter {
    fn agent_id(&self) -> &'static str {
        "tabnine"
    }

    fn agent_name(&self) -> &'static str {
        "Tabnine"
    }

    fn detect(&self, project_root: &Path) -> bool {
        let home = dirs::home_dir();
        project_root.join(".tabnine").join("mcp_servers.json").exists()
            || home
                .as_ref()
                .map(|h| h.join(".tabnine").join("mcp_servers.json").exists())
                .unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let mut out = Vec::new();
        let home = dirs::home_dir();

        out.extend(parse_mcp_servers_json(
            &project_root.join(".tabnine").join("mcp_servers.json"),
            project_root,
            ConfigSourceKind::TabnineMcpJson,
            "mcpServers",
            "tabnine",
            "Tabnine",
        ));
        if let Some(h) = &home {
            out.extend(parse_mcp_servers_json(
                &h.join(".tabnine").join("mcp_servers.json"),
                h,
                ConfigSourceKind::TabnineMcpJson,
                "mcpServers",
                "tabnine",
                "Tabnine",
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
            "talyx-tabnine-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn detects_project_scope_config() {
        let dir = unique_temp_dir("detect");
        std::fs::create_dir_all(dir.join(".tabnine")).unwrap();
        std::fs::write(dir.join(".tabnine").join("mcp_servers.json"), "{}").unwrap();

        assert!(TabnineAdapter.detect(&dir));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_project_scope_servers() {
        let dir = unique_temp_dir("discover");
        std::fs::create_dir_all(dir.join(".tabnine")).unwrap();
        let config = serde_json::json!({
            "mcpServers": {
                "example": { "command": "server-executable", "args": ["arg1"], "env": { "API_KEY": "x" } }
            }
        });
        std::fs::write(
            dir.join(".tabnine").join("mcp_servers.json"),
            serde_json::to_string_pretty(&config).unwrap(),
        )
        .unwrap();

        let discovered = TabnineAdapter.discover(&dir);
        let mcp: Vec<_> = discovered
            .iter()
            .filter(|d| d.artifact.kind == ArtifactKind::McpServer)
            .filter(|d| d.config_source.as_ref().map(|cs| cs.path.starts_with(&dir)).unwrap_or(false))
            .collect();
        assert_eq!(mcp.len(), 1);
        assert_eq!(mcp[0].artifact.name, "example");
        assert!(mcp[0].artifact.discovered_by.contains("tabnine"));

        std::fs::remove_dir_all(&dir).ok();
    }
}
