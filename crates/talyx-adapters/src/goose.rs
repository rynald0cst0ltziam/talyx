//! Goose (Block's AI agent) adapter. Verified 2026-09-05 against multiple
//! independent sources agreeing: `~/.config/goose/config.yaml`, user
//! scope, real YAML but a name-keyed MAP under `mcpServers:` -- the same
//! shape every JSON-based agent uses, just serialized differently, unlike
//! Continue.dev's genuinely list-shaped `mcpServers` in YAML. Parsed via
//! `mcp_config::parse_mcp_servers_yaml`, reusing the shared
//! `parse_server_map` completely unmodified.

use crate::mcp_config::parse_mcp_servers_yaml;
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use std::path::{Path, PathBuf};

pub struct GooseAdapter;

impl AgentAdapter for GooseAdapter {
    fn agent_id(&self) -> &'static str {
        "goose"
    }

    fn agent_name(&self) -> &'static str {
        "Goose"
    }

    fn detect(&self, _project_root: &Path) -> bool {
        config_path().map(|p| p.exists()).unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let Some(path) = config_path() else {
            return Vec::new();
        };
        parse_mcp_servers_yaml(&path, project_root, ConfigSourceKind::GooseMcpJson, "mcpServers", "goose", "Goose")
    }
}

fn config_path() -> Option<PathBuf> {
    Some(dirs::home_dir()?.join(".config").join("goose").join("config.yaml"))
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
            "talyx-goose-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn parses_the_shared_mcp_servers_shape_from_real_yaml() {
        // Same rationale as claude_desktop.rs's/zed.rs's tests: config_path()
        // resolves a fixed home-relative path that can't be redirected in
        // a unit test, so this exercises the YAML parsing path directly.
        let dir = unique_temp_dir("parse");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.yaml");
        std::fs::write(
            &path,
            "mcpServers:\n  sqlite:\n    command: npx\n    args:\n      - \"-y\"\n      - \"@modelcontextprotocol/server-sqlite\"\n",
        )
        .unwrap();

        let discovered =
            parse_mcp_servers_yaml(&path, &dir, ConfigSourceKind::GooseMcpJson, "mcpServers", "goose", "Goose");
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].artifact.name, "sqlite");
        assert!(discovered[0].artifact.discovered_by.contains("goose"));
        assert_eq!(discovered[0].artifact.kind, ArtifactKind::McpServer);
        let launch = discovered[0].launch.as_ref().unwrap();
        assert_eq!(launch.command, "npx");
        assert_eq!(launch.args, vec!["-y", "@modelcontextprotocol/server-sqlite"]);

        std::fs::remove_dir_all(&dir).ok();
    }
}
