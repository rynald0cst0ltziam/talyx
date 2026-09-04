//! GitHub Copilot CLI adapter — same locked v0 scope as Cursor/Windsurf/
//! Antigravity/Gemini CLI (BUILD_PLAN.md §0): discovery + config-gating
//! only, no hook-level enforcement claim (no hooks mechanism documented
//! for Copilot CLI as of this writing).
//!
//! Config paths — verified 2026-09-05 against docs.github.com/en/
//! copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers: Copilot
//! CLI reads MCP servers from `.mcp.json` in the project root OR
//! `.github/mcp.json`, both `{ "mcpServers": {...} }` shape (as of a June
//! 2026 change — it no longer reads `.vscode/mcp.json`, which is VS
//! Code's own separate config with a different top-level key; see
//! `vscode_copilot.rs`).
//!
//! **Deliberately does NOT check `.mcp.json`** — that exact file is
//! already discovered by `claude_code.rs`'s adapter (Claude Code reads
//! the identical path). Checking it again here would report every entry
//! in a shared `.mcp.json` twice, once per adapter — the same class of
//! bug this codebase already found and fixed once for `.cursorrules`
//! duplicating between Cursor's adapter and Unknown Agent Mode's generic
//! marker list. This adapter only ever looks at `.github/mcp.json`,
//! Copilot CLI's other, non-shared location. A project using ONLY
//! Copilot CLI's `.mcp.json` (not `.github/mcp.json`) still gets that
//! entry discovered — just attributed to Claude Code's adapter rather
//! than this one, a real but honestly-documented attribution gap, not a
//! missed detection.

use crate::mcp_config::parse_mcp_servers_json;
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use std::path::Path;

pub struct GitHubCopilotCliAdapter;

impl AgentAdapter for GitHubCopilotCliAdapter {
    fn agent_id(&self) -> &'static str {
        "github-copilot-cli"
    }

    fn agent_name(&self) -> &'static str {
        "GitHub Copilot CLI"
    }

    fn detect(&self, project_root: &Path) -> bool {
        project_root.join(".github").join("mcp.json").exists()
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        parse_mcp_servers_json(
            &project_root.join(".github").join("mcp.json"),
            project_root,
            ConfigSourceKind::GitHubCopilotCliMcpJson,
            "mcpServers",
            "github-copilot-cli",
            "GitHub Copilot CLI",
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
            "agentguard-copilot-cli-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn discovers_github_mcp_json() {
        let dir = unique_temp_dir("discover");
        let github_dir = dir.join(".github");
        std::fs::create_dir_all(&github_dir).unwrap();
        let config = serde_json::json!({
            "mcpServers": { "example": { "command": "some-binary", "args": [] } }
        });
        std::fs::write(github_dir.join("mcp.json"), serde_json::to_string_pretty(&config).unwrap())
            .unwrap();

        assert!(GitHubCopilotCliAdapter.detect(&dir));
        let discovered = GitHubCopilotCliAdapter.discover(&dir);
        let mcp_entries: Vec<_> =
            discovered.iter().filter(|d| d.artifact.kind == ArtifactKind::McpServer).collect();
        assert_eq!(mcp_entries.len(), 1);
        assert_eq!(mcp_entries[0].artifact.name, "example");
        assert!(mcp_entries[0].artifact.discovered_by.contains("github-copilot-cli"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn does_not_discover_a_bare_project_root_mcp_json() {
        // Regression test for the deliberate scope decision in this
        // module's doc comment: a bare .mcp.json (Claude Code's file,
        // which Copilot CLI also reads per its own docs) must NOT be
        // picked up here too, or every entry in it would be reported
        // twice.
        let dir = unique_temp_dir("no-duplicate");
        std::fs::create_dir_all(&dir).unwrap();
        let config = serde_json::json!({
            "mcpServers": { "example": { "command": "some-binary", "args": [] } }
        });
        std::fs::write(dir.join(".mcp.json"), serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovered = GitHubCopilotCliAdapter.discover(&dir);
        assert!(discovered.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }
}
