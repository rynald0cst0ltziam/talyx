//! Sourcegraph Amp adapter. Config paths -- verified 2026-09-05 against
//! ampcode.com/docs/customize/mcp: `~/.config/amp/settings.json` (user
//! scope) and `.amp/settings.json` (project/workspace scope). The
//! top-level key is LITERALLY the dotted string `"amp.mcpServers"` (a
//! VS-Code-settings-style flat key, not a nested `{"amp": {...}}`
//! object) -- reuses `parse_mcp_servers_json`'s existing `top_level_key`
//! parameter unmodified, the same mechanism already proven for VS Code
//! Copilot's `"servers"` key.
//!
//! A real trust distinction from Amp's own docs, documented but not
//! independently re-implemented here (same as Codex's analogous "trusted
//! projects only" caveat): MCP servers declared in the WORKSPACE file
//! (`.amp/settings.json`) require explicit approval before running;
//! servers in the GLOBAL file do not.
//!
//! A separate `.amp/mcp.json` file (for bundling servers with skills) is
//! mentioned in Amp's docs without a confirmed JSON shape -- deliberately
//! not covered here, not guessed at.

use crate::mcp_config::parse_mcp_servers_json;
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use std::path::Path;

const TOP_LEVEL_KEY: &str = "amp.mcpServers";

pub struct AmpAdapter;

impl AgentAdapter for AmpAdapter {
    fn agent_id(&self) -> &'static str {
        "amp"
    }

    fn agent_name(&self) -> &'static str {
        "Amp"
    }

    fn detect(&self, project_root: &Path) -> bool {
        let home = dirs::home_dir();
        project_root.join(".amp").join("settings.json").exists()
            || home
                .as_ref()
                .map(|h| h.join(".config").join("amp").join("settings.json").exists())
                .unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let mut out = Vec::new();
        let home = dirs::home_dir();

        out.extend(parse_mcp_servers_json(
            &project_root.join(".amp").join("settings.json"),
            project_root,
            ConfigSourceKind::AmpMcpJson,
            TOP_LEVEL_KEY,
            "amp",
            "Amp",
        ));
        if let Some(h) = &home {
            out.extend(parse_mcp_servers_json(
                &h.join(".config").join("amp").join("settings.json"),
                h,
                ConfigSourceKind::AmpMcpJson,
                TOP_LEVEL_KEY,
                "amp",
                "Amp",
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
            "agentguard-amp-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn detects_project_scope_settings() {
        let dir = unique_temp_dir("detect");
        std::fs::create_dir_all(dir.join(".amp")).unwrap();
        std::fs::write(dir.join(".amp").join("settings.json"), "{}").unwrap();

        assert!(AmpAdapter.detect(&dir));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_servers_under_the_dotted_amp_mcpservers_key() {
        let dir = unique_temp_dir("discover");
        std::fs::create_dir_all(dir.join(".amp")).unwrap();
        let config = serde_json::json!({
            "amp.mcpServers": {
                "playwright": { "command": "npx", "args": ["-y", "@playwright/mcp@latest"] }
            }
        });
        std::fs::write(
            dir.join(".amp").join("settings.json"),
            serde_json::to_string_pretty(&config).unwrap(),
        )
        .unwrap();

        let discovered = AmpAdapter.discover(&dir);
        let mcp: Vec<_> = discovered
            .iter()
            .filter(|d| d.artifact.kind == ArtifactKind::McpServer)
            .filter(|d| d.config_source.as_ref().map(|cs| cs.path.starts_with(&dir)).unwrap_or(false))
            .collect();
        assert_eq!(mcp.len(), 1);
        assert_eq!(mcp[0].artifact.name, "playwright");
        assert!(mcp[0].artifact.discovered_by.contains("amp"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_a_remote_server_via_url_field() {
        let dir = unique_temp_dir("discover-remote");
        std::fs::create_dir_all(dir.join(".amp")).unwrap();
        let config = serde_json::json!({
            "amp.mcpServers": {
                "linear": { "url": "https://mcp.linear.app/sse" }
            }
        });
        std::fs::write(
            dir.join(".amp").join("settings.json"),
            serde_json::to_string_pretty(&config).unwrap(),
        )
        .unwrap();

        let discovered = AmpAdapter.discover(&dir);
        let remote: Vec<_> = discovered.iter().filter(|d| d.artifact.name == "linear").collect();
        assert_eq!(remote.len(), 1);
        assert!(remote[0].launch.is_none());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn does_not_discover_entries_under_a_plain_mcpservers_key() {
        // Regression guard for the dotted-key distinction: a plain
        // "mcpServers" key (not "amp.mcpServers") must NOT be picked up --
        // proves this adapter actually checks the literal dotted string,
        // not just any recognizable MCP-servers-shaped object.
        let dir = unique_temp_dir("wrong-key");
        std::fs::create_dir_all(dir.join(".amp")).unwrap();
        let config = serde_json::json!({
            "mcpServers": { "example": { "command": "some-binary", "args": [] } }
        });
        std::fs::write(
            dir.join(".amp").join("settings.json"),
            serde_json::to_string_pretty(&config).unwrap(),
        )
        .unwrap();

        let discovered = AmpAdapter.discover(&dir);
        assert!(discovered.iter().all(|d| d.artifact.kind != ArtifactKind::McpServer));

        std::fs::remove_dir_all(&dir).ok();
    }
}
