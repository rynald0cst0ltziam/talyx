//! Cline adapter -- a VS Code extension (`saoudrizwan.claude-dev`).
//! Verified 2026-09-05 by cross-referencing Warden-AI's own real
//! registration code (github.com/rynald0cst0ltziam/Warden-AI's `src/cli/
//! register.ts`), which embeds this exact, specific VS Code extension id
//! in a `globalStorage` path -- not a generic guessed location. A real
//! extension id isn't something to guess by accident, unlike the batch of
//! unverified `~/.config/<name>/mcp.json`-shaped entries the same file
//! also lists for several other tools (this codebase does NOT build on
//! those without independent per-product verification -- one of them,
//! Claude Desktop's path in that same file, was directly checked and
//! found wrong).
//!
//! Path: `<VS Code globalStorage>/saoudrizwan.claude-dev/settings/
//! cline_mcp_settings.json`, user scope only (no project-scope file
//! documented). OS-specific base per VS Code's own convention:
//! `%APPDATA%\Code\User\globalStorage` (Windows), `~/Library/Application
//! Support/Code/User/globalStorage` (macOS), `~/.config/Code/User/
//! globalStorage` (Linux). Standard `{"mcpServers": {...}}` shape.

use crate::mcp_config::parse_mcp_servers_json;
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use std::path::{Path, PathBuf};

const EXTENSION_ID: &str = "saoudrizwan.claude-dev";
const SETTINGS_FILENAME: &str = "cline_mcp_settings.json";

pub struct ClineAdapter;

impl AgentAdapter for ClineAdapter {
    fn agent_id(&self) -> &'static str {
        "cline"
    }

    fn agent_name(&self) -> &'static str {
        "Cline"
    }

    fn detect(&self, _project_root: &Path) -> bool {
        settings_path().map(|p| p.exists()).unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let Some(path) = settings_path() else {
            return Vec::new();
        };
        parse_mcp_servers_json(&path, project_root, ConfigSourceKind::ClineMcpJson, "mcpServers", "cline", "Cline")
    }
}

/// `vs_code_global_storage_dir()` is shared with `roo_code.rs` -- both
/// extensions live under the same VS Code `globalStorage` root, differing
/// only in extension id and settings filename (which happen to be
/// identical here, `cline_mcp_settings.json`, per Roo Code's own
/// Cline-compatible design).
pub(crate) fn vs_code_global_storage_dir() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    if cfg!(windows) {
        Some(home.join("AppData").join("Roaming").join("Code").join("User").join("globalStorage"))
    } else if cfg!(target_os = "macos") {
        Some(
            home.join("Library")
                .join("Application Support")
                .join("Code")
                .join("User")
                .join("globalStorage"),
        )
    } else {
        Some(home.join(".config").join("Code").join("User").join("globalStorage"))
    }
}

fn settings_path() -> Option<PathBuf> {
    Some(vs_code_global_storage_dir()?.join(EXTENSION_ID).join("settings").join(SETTINGS_FILENAME))
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
            "agentguard-cline-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn parses_the_shared_mcp_servers_shape_directly() {
        // Same rationale as claude_desktop.rs's test: settings_path()
        // resolves a fixed OS directory that can't be redirected in a
        // unit test, so this exercises the parsing path directly.
        let dir = unique_temp_dir("parse");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cline_mcp_settings.json");
        let config = serde_json::json!({
            "mcpServers": { "example": { "command": "some-binary", "args": [] } }
        });
        std::fs::write(&path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovered = parse_mcp_servers_json(&path, &dir, ConfigSourceKind::ClineMcpJson, "mcpServers", "cline", "Cline");
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].artifact.name, "example");
        assert!(discovered[0].artifact.discovered_by.contains("cline"));
        assert_eq!(discovered[0].artifact.kind, ArtifactKind::McpServer);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn settings_path_includes_the_real_extension_id() {
        let path = settings_path().expect("home dir should resolve on a real OS");
        assert!(path.to_string_lossy().contains("saoudrizwan.claude-dev"));
        assert!(path.ends_with("settings/cline_mcp_settings.json"));
    }
}
