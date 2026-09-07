//! Sourcegraph Cody adapter. Verified 2026-09-05 via multiple independent
//! sources quoting a complete, consistent example (a direct fetch of
//! Sourcegraph's own docs page returned 403, so this relies on
//! cross-checked secondary quotations of the real config shape rather
//! than a single source -- see `ConfigSourceKind::CodyMcpJson`'s doc
//! comment). Top-level key is the dotted string `"cody.mcpServers"`, the
//! same VS-Code-settings convention as Amp -- but living in VS Code's OWN
//! general settings file: `.vscode/settings.json` (project) or `<VS Code
//! User dir>/settings.json` (global, sibling to the `globalStorage`
//! directory Cline/Roo Code use). Deliberately different from VS Code
//! Copilot's own `.vscode/mcp.json` -- no double-reporting risk.

use crate::cline::vs_code_global_storage_dir;
use crate::mcp_config::parse_mcp_servers_json;
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use std::path::{Path, PathBuf};

const TOP_LEVEL_KEY: &str = "cody.mcpServers";

pub struct CodyAdapter;

impl AgentAdapter for CodyAdapter {
    fn agent_id(&self) -> &'static str {
        "cody"
    }

    fn agent_name(&self) -> &'static str {
        "Cody"
    }

    fn detect(&self, project_root: &Path) -> bool {
        project_root.join(".vscode").join("settings.json").exists() || user_settings_path().map(|p| p.exists()).unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let mut out = Vec::new();

        out.extend(parse_mcp_servers_json(
            &project_root.join(".vscode").join("settings.json"),
            project_root,
            ConfigSourceKind::CodyMcpJson,
            TOP_LEVEL_KEY,
            "cody",
            "Cody",
        ));
        if let Some(path) = user_settings_path() {
            if let Some(dir) = path.parent() {
                out.extend(parse_mcp_servers_json(
                    &path,
                    dir,
                    ConfigSourceKind::CodyMcpJson,
                    TOP_LEVEL_KEY,
                    "cody",
                    "Cody",
                ));
            }
        }

        out
    }
}

/// `<VS Code User dir>/settings.json` -- the sibling of the
/// `globalStorage` directory `cline.rs`'s `vs_code_global_storage_dir()`
/// already resolves.
fn user_settings_path() -> Option<PathBuf> {
    Some(vs_code_global_storage_dir()?.parent()?.join("settings.json"))
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
            "talyx-cody-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn detects_project_scope_vscode_settings() {
        let dir = unique_temp_dir("detect");
        std::fs::create_dir_all(dir.join(".vscode")).unwrap();
        std::fs::write(dir.join(".vscode").join("settings.json"), "{}").unwrap();

        assert!(CodyAdapter.detect(&dir));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_servers_under_the_dotted_cody_mcpservers_key() {
        let dir = unique_temp_dir("discover");
        std::fs::create_dir_all(dir.join(".vscode")).unwrap();
        let config = serde_json::json!({
            "cody.mcpServers": {
                "example": { "command": "npx", "args": ["mcp-remote"] }
            }
        });
        std::fs::write(
            dir.join(".vscode").join("settings.json"),
            serde_json::to_string_pretty(&config).unwrap(),
        )
        .unwrap();

        let discovered = CodyAdapter.discover(&dir);
        let mcp: Vec<_> = discovered
            .iter()
            .filter(|d| d.artifact.kind == ArtifactKind::McpServer)
            .filter(|d| d.config_source.as_ref().map(|cs| cs.path.starts_with(&dir)).unwrap_or(false))
            .collect();
        assert_eq!(mcp.len(), 1);
        assert_eq!(mcp[0].artifact.name, "example");
        assert!(mcp[0].artifact.discovered_by.contains("cody"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn does_not_discover_entries_under_the_plain_servers_key() {
        // Regression guard for the deliberate distinction from VS Code
        // Copilot's own .vscode/mcp.json ("servers" key, different file
        // entirely) -- a "servers" key inside settings.json itself (not
        // "cody.mcpServers") must not be picked up here.
        let dir = unique_temp_dir("wrong-key");
        std::fs::create_dir_all(dir.join(".vscode")).unwrap();
        let config = serde_json::json!({
            "servers": { "example": { "command": "some-binary" } }
        });
        std::fs::write(
            dir.join(".vscode").join("settings.json"),
            serde_json::to_string_pretty(&config).unwrap(),
        )
        .unwrap();

        let discovered = CodyAdapter.discover(&dir);
        assert!(discovered.iter().all(|d| d.artifact.kind != ArtifactKind::McpServer));

        std::fs::remove_dir_all(&dir).ok();
    }
}
