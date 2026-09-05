//! Zed editor adapter. Verified 2026-09-05 directly against zed.dev/docs/
//! assistant/model-context-protocol: Zed calls MCP servers "context
//! servers", top-level key `"context_servers"` (NOT `"mcpServers"`, and
//! not the `"mcp_servers"` a competitor's unverified registration code
//! guessed either -- see `ConfigSourceKind::ZedMcpJson`'s doc comment).
//! Otherwise the familiar per-server shape (`command`/`args`/`env` local,
//! `url`/`headers` remote), so this reuses mcp_config.rs unmodified via
//! its `top_level_key` parameter.
//!
//! Settings path uses `dirs::config_dir()` (each OS's proper special
//! config folder), user scope only -- no project-scope settings file
//! documented for context servers specifically.

use crate::mcp_config::parse_mcp_servers_json;
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use std::path::{Path, PathBuf};

pub struct ZedAdapter;

impl AgentAdapter for ZedAdapter {
    fn agent_id(&self) -> &'static str {
        "zed"
    }

    fn agent_name(&self) -> &'static str {
        "Zed"
    }

    fn detect(&self, _project_root: &Path) -> bool {
        settings_path().map(|p| p.exists()).unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let Some(path) = settings_path() else {
            return Vec::new();
        };
        parse_mcp_servers_json(
            &path,
            project_root,
            ConfigSourceKind::ZedMcpJson,
            "context_servers",
            "zed",
            "Zed",
        )
    }
}

fn settings_path() -> Option<PathBuf> {
    Some(dirs::config_dir()?.join("Zed").join("settings.json"))
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
            "agentguard-zed-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn discovers_servers_under_context_servers_not_mcpservers() {
        let dir = unique_temp_dir("parse");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        let config = serde_json::json!({
            "context_servers": {
                "local-mcp-server": { "command": "some-command", "args": ["arg-1"], "env": {} }
            }
        });
        std::fs::write(&path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovered = parse_mcp_servers_json(&path, &dir, ConfigSourceKind::ZedMcpJson, "context_servers", "zed", "Zed");
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].artifact.name, "local-mcp-server");
        assert!(discovered[0].artifact.discovered_by.contains("zed"));
        assert_eq!(discovered[0].artifact.kind, ArtifactKind::McpServer);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn does_not_discover_entries_under_a_plain_mcpservers_key() {
        let dir = unique_temp_dir("wrong-key");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        let config = serde_json::json!({
            "mcpServers": { "example": { "command": "some-binary", "args": [] } }
        });
        std::fs::write(&path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovered = parse_mcp_servers_json(&path, &dir, ConfigSourceKind::ZedMcpJson, "context_servers", "zed", "Zed");
        assert!(discovered.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }
}
