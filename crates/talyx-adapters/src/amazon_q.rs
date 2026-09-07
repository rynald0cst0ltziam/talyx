//! Amazon Q Developer CLI adapter. TWO real, distinct MCP surfaces, both
//! verified 2026-09-05 directly against AWS's own docs and the
//! aws/amazon-q-developer-cli GitHub repo's `agent-format.md`:
//!
//! 1. The "legacy" fixed-path files -- `~/.aws/amazonq/mcp.json` (global)
//!    and `.amazonq/mcp.json` (workspace). AWS's own docs call these
//!    "legacy" but they remain a real, currently-functional config
//!    surface, not removed -- standard `{"mcpServers": {...}}` shape.
//!
//! 2. The newer named "custom agent" files: each an arbitrarily-NAMED
//!    `*.json` file (the filename becomes the agent's name) inside
//!    `~/.aws/amazonq/cli-agents/` (CLI) or `~/.aws/amazonq/agents/`
//!    (IDE) -- same `"mcpServers"` field, nested inside a larger per-agent
//!    config object alongside unrelated fields (model, permissions, etc).
//!    Handled the same way `github_copilot_cli.rs` handles Copilot CLI's
//!    own glob-of-files hooks directory: enumerate `*.json`, parse each
//!    independently.
//!
//! Both surfaces use the identical `{"mcpServers": {"<name>": {command,
//! args, env, timeout}}}` shape for the servers themselves, so both reuse
//! mcp_config.rs unmodified.

use crate::mcp_config::parse_mcp_servers_json;
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use std::path::Path;

pub struct AmazonQAdapter;

impl AgentAdapter for AmazonQAdapter {
    fn agent_id(&self) -> &'static str {
        "amazon-q"
    }

    fn agent_name(&self) -> &'static str {
        "Amazon Q Developer CLI"
    }

    fn detect(&self, project_root: &Path) -> bool {
        let home = dirs::home_dir();
        project_root.join(".amazonq").join("mcp.json").exists()
            || home
                .as_ref()
                .map(|h| {
                    h.join(".aws").join("amazonq").join("mcp.json").exists()
                        || h.join(".aws").join("amazonq").join("cli-agents").exists()
                        || h.join(".aws").join("amazonq").join("agents").exists()
                })
                .unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let mut out = Vec::new();
        let home = dirs::home_dir();

        // Legacy fixed-path files.
        out.extend(parse_mcp_servers_json(
            &project_root.join(".amazonq").join("mcp.json"),
            project_root,
            ConfigSourceKind::AmazonQMcpJson,
            "mcpServers",
            "amazon-q",
            "Amazon Q Developer CLI",
        ));
        if let Some(h) = &home {
            out.extend(parse_mcp_servers_json(
                &h.join(".aws").join("amazonq").join("mcp.json"),
                h,
                ConfigSourceKind::AmazonQMcpJson,
                "mcpServers",
                "amazon-q",
                "Amazon Q Developer CLI",
            ));

            // Newer named custom-agent files -- arbitrary filenames, so
            // enumerate the directories rather than checking one fixed
            // path.
            out.extend(parse_agent_files_dir(&h.join(".aws").join("amazonq").join("cli-agents"), h));
            out.extend(parse_agent_files_dir(&h.join(".aws").join("amazonq").join("agents"), h));
        }

        out
    }
}

fn parse_agent_files_dir(dir: &Path, base_dir: &Path) -> Vec<DiscoveredArtifact> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    let mut json_files: Vec<std::path::PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    json_files.sort();
    for path in json_files {
        out.extend(parse_mcp_servers_json(
            &path,
            base_dir,
            ConfigSourceKind::AmazonQMcpJson,
            "mcpServers",
            "amazon-q",
            "Amazon Q Developer CLI",
        ));
    }
    out
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
            "talyx-amazon-q-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn detects_project_scope_legacy_mcp_json() {
        let dir = unique_temp_dir("detect");
        std::fs::create_dir_all(dir.join(".amazonq")).unwrap();
        std::fs::write(dir.join(".amazonq").join("mcp.json"), "{}").unwrap();

        assert!(AmazonQAdapter.detect(&dir));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_project_scope_legacy_mcp_json() {
        let dir = unique_temp_dir("discover-legacy");
        std::fs::create_dir_all(dir.join(".amazonq")).unwrap();
        let config = serde_json::json!({
            "mcpServers": { "fetch": { "command": "fetch3.1", "args": [] } }
        });
        std::fs::write(dir.join(".amazonq").join("mcp.json"), serde_json::to_string_pretty(&config).unwrap())
            .unwrap();

        let discovered = AmazonQAdapter.discover(&dir);
        let mcp: Vec<_> = discovered
            .iter()
            .filter(|d| d.artifact.kind == ArtifactKind::McpServer)
            .filter(|d| d.config_source.as_ref().map(|cs| cs.path.starts_with(&dir)).unwrap_or(false))
            .collect();
        assert_eq!(mcp.len(), 1);
        assert_eq!(mcp[0].artifact.name, "fetch");
        assert!(mcp[0].artifact.discovered_by.contains("amazon-q"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_mcp_servers_from_arbitrarily_named_agent_files_in_a_directory() {
        // The newer "custom agent" surface uses arbitrary filenames (the
        // filename becomes the agent's name) inside a directory, not one
        // fixed path -- this proves the glob-based discovery works
        // independent of what the agent file happens to be named.
        let agents_dir = unique_temp_dir("agent-files");
        std::fs::create_dir_all(&agents_dir).unwrap();
        let agent_config = serde_json::json!({
            "name": "my-custom-agent",
            "mcpServers": {
                "git": { "command": "git-mcp", "args": [], "timeout": 120000 }
            }
        });
        std::fs::write(
            agents_dir.join("whatever-i-named-it.json"),
            serde_json::to_string_pretty(&agent_config).unwrap(),
        )
        .unwrap();

        let discovered = parse_agent_files_dir(&agents_dir, &agents_dir);
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].artifact.name, "git");

        std::fs::remove_dir_all(&agents_dir).ok();
    }
}
