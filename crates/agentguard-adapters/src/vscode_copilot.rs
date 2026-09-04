//! VS Code (GitHub Copilot Chat) adapter — same locked v0 scope as the
//! other config-gating-only adapters (BUILD_PLAN.md §0). Distinct from
//! `github_copilot_cli.rs`: this is the VS Code editor extension, a
//! different product with a different config file and shape, not just a
//! different path for the same tool.
//!
//! Config path — `.vscode/mcp.json`, workspace scope, verified 2026-09-05
//! against code.visualstudio.com/docs/agents/reference/mcp-configuration.
//! The top-level key is **`"servers"`**, not `"mcpServers"` — confirmed
//! directly rather than assumed identical to every other tool's shape;
//! `parse_mcp_servers_json` gained an explicit `top_level_key` parameter
//! specifically to support this without forking the shared parser.
//!
//! User-level VS Code MCP settings sync through VS Code's own
//! account-based Settings Sync mechanism rather than a predictable local
//! dot-file — not verified to have a stable on-disk path worth reading
//! directly, so deliberately not covered here rather than guessed at.
//! Workspace-scope `.vscode/mcp.json` is the well-documented, stable,
//! file-based one this adapter covers.

use crate::mcp_config::parse_mcp_servers_json;
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use std::path::Path;

pub struct VsCodeCopilotAdapter;

impl AgentAdapter for VsCodeCopilotAdapter {
    fn agent_id(&self) -> &'static str {
        "vscode-copilot"
    }

    fn agent_name(&self) -> &'static str {
        "VS Code (Copilot)"
    }

    fn detect(&self, project_root: &Path) -> bool {
        project_root.join(".vscode").join("mcp.json").exists()
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        parse_mcp_servers_json(
            &project_root.join(".vscode").join("mcp.json"),
            project_root,
            ConfigSourceKind::VsCodeCopilotMcpJson,
            "servers",
            "vscode-copilot",
            "VS Code (Copilot)",
        )
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
            "agentguard-vscode-copilot-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn discovers_servers_under_the_servers_key_not_mcpservers() {
        let dir = unique_temp_dir("discover");
        let vscode_dir = dir.join(".vscode");
        std::fs::create_dir_all(&vscode_dir).unwrap();
        let config = serde_json::json!({
            "servers": { "example": { "command": "some-binary", "args": [] } }
        });
        std::fs::write(vscode_dir.join("mcp.json"), serde_json::to_string_pretty(&config).unwrap())
            .unwrap();

        assert!(VsCodeCopilotAdapter.detect(&dir));
        let discovered = VsCodeCopilotAdapter.discover(&dir);
        let mcp_entries: Vec<_> =
            discovered.iter().filter(|d| d.artifact.kind == ArtifactKind::McpServer).collect();
        assert_eq!(mcp_entries.len(), 1);
        assert_eq!(mcp_entries[0].artifact.name, "example");
        assert!(mcp_entries[0].artifact.discovered_by.contains("vscode-copilot"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn does_not_discover_entries_under_an_mcpservers_key() {
        // Regression test locking in the field-name distinction this
        // module's doc comment calls out: a file using "mcpServers" (the
        // wrong key for this format) must not be picked up.
        let dir = unique_temp_dir("wrong-key");
        let vscode_dir = dir.join(".vscode");
        std::fs::create_dir_all(&vscode_dir).unwrap();
        let config = serde_json::json!({
            "mcpServers": { "example": { "command": "some-binary", "args": [] } }
        });
        std::fs::write(vscode_dir.join("mcp.json"), serde_json::to_string_pretty(&config).unwrap())
            .unwrap();

        let discovered = VsCodeCopilotAdapter.discover(&dir);
        assert!(discovered.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }
}
