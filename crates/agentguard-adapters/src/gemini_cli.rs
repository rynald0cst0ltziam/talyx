//! Gemini CLI adapter — same locked v0 scope as Cursor/Windsurf/
//! Antigravity (BUILD_PLAN.md §0): discovery + config-gating only, no
//! hook-level enforcement claim. No hooks/skills/plugins mechanism is
//! documented for Gemini CLI as of this writing (verified against
//! google-gemini/gemini-cli's own docs, not assumed absent).
//!
//! Config paths — `.gemini/settings.json` (project scope) and
//! `~/.gemini/settings.json` (user scope), both confirmed directly
//! against the tool's own docs (github.com/google-gemini/gemini-cli/
//! blob/main/docs/tools/mcp-server.md). `settings.json` carries other
//! Gemini CLI settings alongside `mcpServers` — irrelevant here since
//! `parse_mcp_servers_json` only ever looks at that one key, the same as
//! Claude Code's `~/.claude.json` (also a general settings file, not an
//! MCP-only one). Distinct from Antigravity's config despite sharing a
//! `~/.gemini/` parent directory — see `ConfigSourceKind::
//! GeminiCliSettingsJson`'s doc comment.
//!
//! Remote servers split into `url` (SSE) and `httpUrl` (HTTP streaming)
//! — two distinct field names, neither of which is `serverUrl` — both
//! now handled by the shared parser's remote-detection fallback chain.

use crate::mcp_config::parse_mcp_servers_json;
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use agentguard_core::{Artifact, ArtifactKind, ArtifactSource, PublisherIdentity};
use std::collections::BTreeSet;
use std::path::Path;

pub struct GeminiCliAdapter;

impl AgentAdapter for GeminiCliAdapter {
    fn agent_id(&self) -> &'static str {
        "gemini-cli"
    }

    fn agent_name(&self) -> &'static str {
        "Gemini CLI"
    }

    fn detect(&self, project_root: &Path) -> bool {
        let home = dirs::home_dir();
        project_root.join(".gemini").exists()
            || project_root.join("GEMINI.md").exists()
            || home
                .as_ref()
                .map(|h| h.join(".gemini").join("settings.json").exists())
                .unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let mut out = Vec::new();
        let home = dirs::home_dir();

        out.extend(parse_mcp_servers_json(
            &project_root.join(".gemini").join("settings.json"),
            project_root,
            ConfigSourceKind::GeminiCliSettingsJson,
            "mcpServers",
            "gemini-cli",
            "Gemini CLI",
        ));
        if let Some(h) = &home {
            out.extend(parse_mcp_servers_json(
                &h.join(".gemini").join("settings.json"),
                h,
                ConfigSourceKind::GeminiCliSettingsJson,
                "mcpServers",
                "gemini-cli",
                "Gemini CLI",
            ));
        }

        // GEMINI.md — Gemini CLI's project-instructions/memory file
        // (verified against google-gemini/gemini-cli's own docs:
        // github.com/google-gemini/gemini-cli/blob/main/docs/cli/
        // gemini-md.md), analogous to Claude Code's CLAUDE.md. Visibility
        // only, no capability scanning — it's instruction/prompt text,
        // not executable code, same reasoning as `.cursorrules`/
        // `.windsurfrules`. Was previously (wrongly) covered by Unknown
        // Agent Mode's generic marker list before this adapter existed —
        // removed from there to avoid the double-report bug already found
        // and fixed once for `.cursorrules`.
        let gemini_md_path = project_root.join("GEMINI.md");
        if gemini_md_path.exists() {
            out.push(config_fingerprint(&gemini_md_path, "GEMINI.md"));
        }

        out
    }
}

fn config_fingerprint(path: &Path, marker: &str) -> DiscoveredArtifact {
    let source = ArtifactSource::LocalPath(path.display().to_string());
    let mut discovered_by = BTreeSet::new();
    discovered_by.insert("gemini-cli".to_string());
    let artifact = Artifact {
        id: Artifact::compute_id(ArtifactKind::AgentConfig, marker, &source),
        kind: ArtifactKind::AgentConfig,
        name: marker.to_string(),
        version: None,
        publisher: PublisherIdentity::default(),
        source,
        content_hash: None,
        capabilities: vec![],
        discovered_by,
    };
    DiscoveredArtifact {
        display_location: path.display().to_string(),
        scan_root: None,
        artifact,
        launch: None,
        config_source: None,
        raw_config_entry: None,
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
            "agentguard-gemini-cli-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn detects_project_scope_gemini_dir() {
        let dir = unique_temp_dir("detect");
        std::fs::create_dir_all(dir.join(".gemini")).unwrap();

        assert!(GeminiCliAdapter.detect(&dir));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_project_scope_mcp_servers_alongside_other_settings() {
        // settings.json is a general settings file, not MCP-only --
        // discovery must still find mcpServers even with unrelated keys
        // present alongside it.
        let dir = unique_temp_dir("discover-mcp");
        let gemini_dir = dir.join(".gemini");
        std::fs::create_dir_all(&gemini_dir).unwrap();
        let config = serde_json::json!({
            "theme": "dark",
            "mcpServers": { "example": { "command": "some-binary", "args": [] } }
        });
        std::fs::write(
            gemini_dir.join("settings.json"),
            serde_json::to_string_pretty(&config).unwrap(),
        )
        .unwrap();

        let discovered = GeminiCliAdapter.discover(&dir);
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
        assert!(project_mcp_entries[0].artifact.discovered_by.contains("gemini-cli"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_a_remote_server_via_httpurl_field() {
        // Gemini CLI's own docs document `url` (SSE) and `httpUrl` (HTTP
        // streaming) as the two remote fields -- neither is `serverUrl`.
        // This is the one that would have silently gone undetected if
        // the shared parser's fallback chain hadn't been extended.
        let dir = unique_temp_dir("discover-remote");
        let gemini_dir = dir.join(".gemini");
        std::fs::create_dir_all(&gemini_dir).unwrap();
        let config = serde_json::json!({
            "mcpServers": { "remote-example": { "httpUrl": "https://mcp.example.com/mcp" } }
        });
        std::fs::write(
            gemini_dir.join("settings.json"),
            serde_json::to_string_pretty(&config).unwrap(),
        )
        .unwrap();

        let discovered = GeminiCliAdapter.discover(&dir);
        let remote: Vec<_> = discovered.iter().filter(|d| d.artifact.name == "remote-example").collect();
        assert_eq!(remote.len(), 1);
        assert!(remote[0].launch.is_none());
        assert!(remote[0].config_source.is_some());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_gemini_md_for_visibility_only() {
        let dir = unique_temp_dir("discover-gemini-md");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("GEMINI.md"), "Be helpful.").unwrap();

        let discovered = GeminiCliAdapter.discover(&dir);
        let fingerprints: Vec<_> = discovered.iter().filter(|d| d.artifact.name == "GEMINI.md").collect();
        assert_eq!(fingerprints.len(), 1);
        assert_eq!(fingerprints[0].artifact.kind, ArtifactKind::AgentConfig);
        assert!(fingerprints[0].scan_root.is_none());

        std::fs::remove_dir_all(&dir).ok();
    }
}
