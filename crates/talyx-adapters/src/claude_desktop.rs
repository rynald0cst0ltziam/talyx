//! Claude Desktop adapter — a distinct product from Claude Code (a
//! chat-only desktop app with no coding-agent tool-execution loop, no
//! hooks/skills mechanism). Config path — verified 2026-09-05 across
//! multiple independent sources agreeing on the same three OS-specific
//! locations: `~/Library/Application Support/Claude/
//! claude_desktop_config.json` (macOS), `%APPDATA%\Claude\
//! claude_desktop_config.json` (Windows), `~/.config/Claude/
//! claude_desktop_config.json` (Linux) -- i.e. `dirs::config_dir()`, not
//! `dirs::home_dir()` like every other agent covered so far. User-scope
//! only; Claude Desktop has no per-project concept at all. Same `{
//! "mcpServers": {...} }` shape as Claude Code/Cursor, reusing
//! mcp_config.rs.
//!
//! Known, documented limitation carried over from the primary source: on
//! Windows MSIX installs, the app's "Edit Config" button may open a
//! different file than the one it actually reads (MSIX filesystem
//! virtualization) -- not resolved further here.

use crate::mcp_config::parse_mcp_servers_json;
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use std::path::Path;

pub struct ClaudeDesktopAdapter;

impl AgentAdapter for ClaudeDesktopAdapter {
    fn agent_id(&self) -> &'static str {
        "claude-desktop"
    }

    fn agent_name(&self) -> &'static str {
        "Claude Desktop"
    }

    fn detect(&self, _project_root: &Path) -> bool {
        config_path().map(|p| p.exists()).unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let Some(path) = config_path() else {
            return Vec::new();
        };
        parse_mcp_servers_json(
            &path,
            project_root,
            ConfigSourceKind::ClaudeDesktopMcpJson,
            "mcpServers",
            "claude-desktop",
            "Claude Desktop",
        )
    }
}

fn config_path() -> Option<std::path::PathBuf> {
    Some(dirs::config_dir()?.join("Claude").join("claude_desktop_config.json"))
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
            "talyx-claude-desktop-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn parses_the_shared_mcp_servers_shape_directly() {
        // detect()/discover() resolve a fixed OS config directory that
        // can't be redirected in a unit test (dirs::config_dir() ignores
        // env-var overrides, same reasoning already documented for
        // dirs::home_dir() elsewhere in this codebase) -- so this test
        // exercises the parsing path directly, the same shared function
        // discover() calls, rather than the full adapter method.
        let dir = unique_temp_dir("parse");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("claude_desktop_config.json");
        let config = serde_json::json!({
            "mcpServers": { "example": { "command": "some-binary", "args": [] } }
        });
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovered = parse_mcp_servers_json(
            &config_path,
            &dir,
            ConfigSourceKind::ClaudeDesktopMcpJson,
            "mcpServers",
            "claude-desktop",
            "Claude Desktop",
        );
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].artifact.name, "example");
        assert!(discovered[0].artifact.discovered_by.contains("claude-desktop"));
        assert_eq!(discovered[0].artifact.kind, ArtifactKind::McpServer);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn config_path_uses_the_os_config_directory_not_home() {
        let path = config_path().expect("config_dir should resolve on a real OS");
        assert!(path.ends_with("Claude/claude_desktop_config.json"));
    }
}
