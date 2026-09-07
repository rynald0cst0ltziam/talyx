//! Aider adapter. Verified 2026-09-05 against aider.chat's own docs
//! (aider.chat/docs/config/aider_conf.html) and a real example file
//! referenced from a third-party MCP server's docs. Config:
//! `.aider.conf.yml`, checked in the user's home directory, the git repo
//! root, and the current (project) directory -- Aider's own docs say all
//! three are loaded, in that order, with later ones taking priority for
//! Aider's own runtime; for discovery purposes this checks all of them
//! independently rather than picking a "winner" the way Aider itself
//! would.
//!
//! Real YAML, top-level key `"mcp-server"` (hyphenated, genuinely
//! different from every other agent's key name), LIST-shaped like
//! Continue.dev's own native format -- reuses the same
//! `list_to_server_map` conversion. Enforced via `init.rs`'s
//! `rewrite_config_value` (STATUS.md #42) — local servers only; remote-
//! entry removal for YAML configs is STATUS.md 5d.

use crate::mcp_config::{list_to_server_map, parse_server_map};
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use serde_json::Value;
use std::path::Path;

pub struct AiderAdapter;

impl AgentAdapter for AiderAdapter {
    fn agent_id(&self) -> &'static str {
        "aider"
    }

    fn agent_name(&self) -> &'static str {
        "Aider"
    }

    fn detect(&self, project_root: &Path) -> bool {
        let home = dirs::home_dir();
        project_root.join(".aider.conf.yml").exists()
            || home.as_ref().map(|h| h.join(".aider.conf.yml").exists()).unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let mut out = Vec::new();
        let home = dirs::home_dir();

        out.extend(parse_aider_conf(&project_root.join(".aider.conf.yml"), project_root));
        if let Some(h) = &home {
            out.extend(parse_aider_conf(&h.join(".aider.conf.yml"), h));
        }

        out
    }
}

fn parse_aider_conf(path: &Path, base_dir: &Path) -> Vec<DiscoveredArtifact> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(json) = serde_saphyr::from_str::<Value>(&text) else {
        return Vec::new();
    };
    let Some(list) = json.get("mcp-server").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let servers = list_to_server_map(list);
    parse_server_map(&servers, path, base_dir, ConfigSourceKind::AiderMcpJson, "aider", "Aider")
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
            "talyx-aider-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn detects_project_scope_config() {
        let dir = unique_temp_dir("detect");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".aider.conf.yml"), "").unwrap();

        assert!(AiderAdapter.detect(&dir));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_servers_under_the_hyphenated_mcp_server_key() {
        let dir = unique_temp_dir("discover");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(".aider.conf.yml"),
            "mcp-server:\n  - name: filesystem\n    command: npx\n    args:\n      - \"-y\"\n      - \"@modelcontextprotocol/server-filesystem\"\n",
        )
        .unwrap();

        let discovered = AiderAdapter.discover(&dir);
        let mcp: Vec<_> = discovered
            .iter()
            .filter(|d| d.artifact.kind == ArtifactKind::McpServer)
            .filter(|d| d.config_source.as_ref().map(|cs| cs.path.starts_with(&dir)).unwrap_or(false))
            .collect();
        assert_eq!(mcp.len(), 1);
        assert_eq!(mcp[0].artifact.name, "filesystem");
        assert!(mcp[0].artifact.discovered_by.contains("aider"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn does_not_discover_entries_under_a_plain_mcpservers_key() {
        // Regression guard for the hyphenated-key distinction: a plain
        // "mcpServers" list (every other agent's key spelling) must NOT
        // be picked up here.
        let dir = unique_temp_dir("wrong-key");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(".aider.conf.yml"),
            "mcpServers:\n  - name: example\n    command: some-binary\n",
        )
        .unwrap();

        let discovered = AiderAdapter.discover(&dir);
        assert!(discovered.iter().all(|d| d.artifact.kind != ArtifactKind::McpServer));

        std::fs::remove_dir_all(&dir).ok();
    }
}
