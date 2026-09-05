//! JetBrains AI Assistant / Junie adapter. Verified 2026-09-05 directly
//! against junie.jetbrains.com/docs/junie-plugin-mcp-settings.html and
//! junie-cli-mcp-configuration.html: `.junie/mcp/mcp.json` (project
//! scope) and `~/.junie/mcp/mcp.json` (user/global scope) -- a completely
//! different, more specific path than a competitor's own unverified,
//! formulaic guess for the same product (see `ConfigSourceKind::
//! JetBrainsMcpJson`'s doc comment). Standard `{"mcpServers": {...}}`
//! shape, reusing mcp_config.rs unmodified.

use crate::mcp_config::parse_mcp_servers_json;
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use std::path::Path;

pub struct JetBrainsAdapter;

impl AgentAdapter for JetBrainsAdapter {
    fn agent_id(&self) -> &'static str {
        "jetbrains"
    }

    fn agent_name(&self) -> &'static str {
        "JetBrains AI Assistant"
    }

    fn detect(&self, project_root: &Path) -> bool {
        let home = dirs::home_dir();
        project_root.join(".junie").join("mcp").join("mcp.json").exists()
            || home
                .as_ref()
                .map(|h| h.join(".junie").join("mcp").join("mcp.json").exists())
                .unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let mut out = Vec::new();
        let home = dirs::home_dir();

        out.extend(parse_mcp_servers_json(
            &project_root.join(".junie").join("mcp").join("mcp.json"),
            project_root,
            ConfigSourceKind::JetBrainsMcpJson,
            "mcpServers",
            "jetbrains",
            "JetBrains AI Assistant",
        ));
        if let Some(h) = &home {
            out.extend(parse_mcp_servers_json(
                &h.join(".junie").join("mcp").join("mcp.json"),
                h,
                ConfigSourceKind::JetBrainsMcpJson,
                "mcpServers",
                "jetbrains",
                "JetBrains AI Assistant",
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
            "agentguard-jetbrains-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn detects_project_scope_config() {
        let dir = unique_temp_dir("detect");
        std::fs::create_dir_all(dir.join(".junie").join("mcp")).unwrap();
        std::fs::write(dir.join(".junie").join("mcp").join("mcp.json"), "{}").unwrap();

        assert!(JetBrainsAdapter.detect(&dir));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_project_scope_servers() {
        let dir = unique_temp_dir("discover");
        std::fs::create_dir_all(dir.join(".junie").join("mcp")).unwrap();
        let config = serde_json::json!({
            "mcpServers": { "example": { "command": "some-binary", "args": [] } }
        });
        std::fs::write(
            dir.join(".junie").join("mcp").join("mcp.json"),
            serde_json::to_string_pretty(&config).unwrap(),
        )
        .unwrap();

        let discovered = JetBrainsAdapter.discover(&dir);
        let mcp: Vec<_> = discovered
            .iter()
            .filter(|d| d.artifact.kind == ArtifactKind::McpServer)
            .filter(|d| d.config_source.as_ref().map(|cs| cs.path.starts_with(&dir)).unwrap_or(false))
            .collect();
        assert_eq!(mcp.len(), 1);
        assert_eq!(mcp[0].artifact.name, "example");
        assert!(mcp[0].artifact.discovered_by.contains("jetbrains"));

        std::fs::remove_dir_all(&dir).ok();
    }
}
