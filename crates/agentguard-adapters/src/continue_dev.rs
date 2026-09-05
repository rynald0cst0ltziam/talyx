//! Continue.dev adapter -- JSON-only, PARTIAL coverage, deliberately.
//! Verified 2026-09-05 against docs.continue.dev/customize/deep-dives/mcp:
//! Continue's NATIVE, preferred format is actually YAML (`config.yaml`'s
//! own `mcpServers` key is a LIST of `{name, command, args}` objects, not
//! a name-keyed map -- a genuinely different shape from every other agent
//! this codebase covers), and `.continue/mcpServers/*.yaml`/`*.yml` files
//! use the same list shape. Neither YAML surface is covered here -- would
//! need a YAML parsing dependency this workspace doesn't have yet, plus a
//! bespoke list-shaped (not map-shaped) parser. Scoped as a deliberate,
//! documented follow-up rather than guessed at or silently skipped
//! without a record. See `ConfigSourceKind::ContinueMcpJson`'s doc
//! comment for the full citation.
//!
//! What IS covered: `.continue/mcpServers/*.json` (project) and
//! `~/.continue/mcpServers/*.json` (user) -- a glob of files, same
//! pattern as Amazon Q's/Copilot CLI's own directories, standard
//! `{"mcpServers": {...}}` shape. Continue's own docs explicitly permit
//! dropping in "JSON MCP configuration from another tool" unchanged into
//! this directory, so a real, standard-shaped JSON file placed there is
//! genuinely a supported, documented mechanism, not an edge case.

use crate::mcp_config::parse_mcp_servers_json;
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use std::path::Path;

pub struct ContinueDevAdapter;

impl AgentAdapter for ContinueDevAdapter {
    fn agent_id(&self) -> &'static str {
        "continue-dev"
    }

    fn agent_name(&self) -> &'static str {
        "Continue.dev"
    }

    fn detect(&self, project_root: &Path) -> bool {
        let home = dirs::home_dir();
        project_root.join(".continue").exists()
            || home.as_ref().map(|h| h.join(".continue").exists()).unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let mut out = Vec::new();
        let home = dirs::home_dir();

        out.extend(parse_mcp_servers_dir(
            &project_root.join(".continue").join("mcpServers"),
            project_root,
        ));
        if let Some(h) = &home {
            out.extend(parse_mcp_servers_dir(
                &h.join(".continue").join("mcpServers"),
                h,
            ));
        }

        out
    }
}

fn parse_mcp_servers_dir(dir: &Path, base_dir: &Path) -> Vec<DiscoveredArtifact> {
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
            ConfigSourceKind::ContinueMcpJson,
            "mcpServers",
            "continue-dev",
            "Continue.dev",
        ));
    }
    out
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
            "agentguard-continue-dev-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn detects_project_scope_continue_dir() {
        let dir = unique_temp_dir("detect");
        std::fs::create_dir_all(dir.join(".continue")).unwrap();

        assert!(ContinueDevAdapter.detect(&dir));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_a_json_file_dropped_into_the_mcpservers_directory() {
        let dir = unique_temp_dir("discover");
        let mcp_dir = dir.join(".continue").join("mcpServers");
        std::fs::create_dir_all(&mcp_dir).unwrap();
        let config = serde_json::json!({
            "mcpServers": { "sqlite": { "command": "npx", "args": ["-y", "mcp-sqlite"] } }
        });
        std::fs::write(mcp_dir.join("mcp.json"), serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovered = ContinueDevAdapter.discover(&dir);
        let mcp: Vec<_> = discovered
            .iter()
            .filter(|d| d.artifact.kind == ArtifactKind::McpServer)
            .filter(|d| d.config_source.as_ref().map(|cs| cs.path.starts_with(&dir)).unwrap_or(false))
            .collect();
        assert_eq!(mcp.len(), 1);
        assert_eq!(mcp[0].artifact.name, "sqlite");
        assert!(mcp[0].artifact.discovered_by.contains("continue-dev"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ignores_yaml_files_in_the_same_directory_not_yet_supported() {
        // Documents the real, deliberate gap: a .yaml file in the same
        // directory (Continue's actual native format) is silently not
        // parsed -- this test exists so a future YAML-support change
        // updates this assertion deliberately, not by surprise.
        let dir = unique_temp_dir("yaml-gap");
        let mcp_dir = dir.join(".continue").join("mcpServers");
        std::fs::create_dir_all(&mcp_dir).unwrap();
        std::fs::write(
            mcp_dir.join("servers.yaml"),
            "mcpServers:\n  - name: SQLite MCP\n    command: npx\n    args: [\"-y\", \"mcp-sqlite\"]\n",
        )
        .unwrap();

        let discovered = ContinueDevAdapter.discover(&dir);
        assert!(discovered.iter().all(|d| d.artifact.kind != ArtifactKind::McpServer));

        std::fs::remove_dir_all(&dir).ok();
    }
}
