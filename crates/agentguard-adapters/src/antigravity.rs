//! Google Antigravity adapter — same locked v0 scope as Cursor/Windsurf
//! (BUILD_PLAN.md §0): discovery + config-gating only, no hook-level
//! enforcement claim. Antigravity's own docs (verified 2026-09-05,
//! antigravity.google/docs/mcp/) describe separate Skills/Hooks/Plugins
//! extensibility systems in passing but without concrete file paths or
//! payload shapes to build real discovery against — deliberately not
//! guessed at here, same principle as this whole codebase's "fall
//! through rather than guess" design. Revisit once that's documented
//! concretely or can be verified against a real installation.
//!
//! Config paths — `~/.gemini/config/mcp_config.json` (global/user scope)
//! and `.agents/mcp_config.json` (project scope), both confirmed directly
//! against Antigravity's own docs, not assumed. Same `{ "mcpServers": {
//! "<name>": { command, args, env } } }` shape as Claude Code/Cursor,
//! reusing mcp_config.rs — Antigravity's remote-server field is
//! documented as `serverUrl` (NOT `url`), already handled by the shared
//! parser's fallback (see `ConfigSourceKind::AntigravityMcpJson`'s doc
//! comment for the deliberate distinction from Gemini CLI's own,
//! differently-shaped config that happens to share the `~/.gemini/`
//! parent directory).

use crate::mcp_config::parse_mcp_servers_json;
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use std::path::Path;

pub struct AntigravityAdapter;

impl AgentAdapter for AntigravityAdapter {
    fn agent_id(&self) -> &'static str {
        "antigravity"
    }

    fn agent_name(&self) -> &'static str {
        "Antigravity"
    }

    fn detect(&self, project_root: &Path) -> bool {
        let home = dirs::home_dir();
        project_root.join(".agents").exists()
            || home
                .as_ref()
                .map(|h| h.join(".gemini").join("config").exists())
                .unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let mut out = Vec::new();
        let home = dirs::home_dir();

        out.extend(parse_mcp_servers_json(
            &project_root.join(".agents").join("mcp_config.json"),
            project_root,
            ConfigSourceKind::AntigravityMcpJson,
            "antigravity",
            "Antigravity",
        ));
        if let Some(h) = &home {
            out.extend(parse_mcp_servers_json(
                &h.join(".gemini").join("config").join("mcp_config.json"),
                h,
                ConfigSourceKind::AntigravityMcpJson,
                "antigravity",
                "Antigravity",
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
            "agentguard-antigravity-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn detects_project_scope_agents_dir() {
        let dir = unique_temp_dir("detect");
        std::fs::create_dir_all(dir.join(".agents")).unwrap();

        assert!(AntigravityAdapter.detect(&dir));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_project_scope_mcp_servers() {
        let dir = unique_temp_dir("discover-mcp");
        let agents_dir = dir.join(".agents");
        std::fs::create_dir_all(&agents_dir).unwrap();
        let config = serde_json::json!({
            "mcpServers": { "example": { "command": "some-binary", "args": [] } }
        });
        std::fs::write(
            agents_dir.join("mcp_config.json"),
            serde_json::to_string_pretty(&config).unwrap(),
        )
        .unwrap();

        let discovered = AntigravityAdapter.discover(&dir);
        let project_mcp_entries: Vec<_> = discovered
            .iter()
            .filter(|d| d.artifact.kind == ArtifactKind::McpServer)
            .filter(|d| {
                d.config_source
                    .as_ref()
                    .map(|cs| cs.path.starts_with(&dir))
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(project_mcp_entries.len(), 1);
        assert_eq!(project_mcp_entries[0].artifact.name, "example");
        assert!(project_mcp_entries[0].artifact.discovered_by.contains("antigravity"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_a_remote_server_via_serverurl_field() {
        // Antigravity's own docs document ONLY `serverUrl` for remote
        // servers, not `url` -- this is the field name that would have
        // silently gone undetected if the shared parser's remote check
        // hadn't been extended to also look for it.
        let dir = unique_temp_dir("discover-remote");
        let agents_dir = dir.join(".agents");
        std::fs::create_dir_all(&agents_dir).unwrap();
        let config = serde_json::json!({
            "mcpServers": { "remote-example": { "serverUrl": "https://mcp.example.com/mcp" } }
        });
        std::fs::write(
            agents_dir.join("mcp_config.json"),
            serde_json::to_string_pretty(&config).unwrap(),
        )
        .unwrap();

        let discovered = AntigravityAdapter.discover(&dir);
        let remote: Vec<_> = discovered
            .iter()
            .filter(|d| d.artifact.name == "remote-example")
            .collect();
        assert_eq!(remote.len(), 1);
        assert!(remote[0].launch.is_none());
        assert!(remote[0].config_source.is_some());

        std::fs::remove_dir_all(&dir).ok();
    }
}
