//! Cursor adapter — BUILD_PLAN.md §0's locked v0 scope decision: discovery
//! and config-gating only, no hook-level enforcement claim. Cursor has no
//! confirmed equivalent to Claude Code's `PreToolUse` hooks as of this
//! writing, so this adapter never claims in-agent interception — only the
//! same config-rewrite mechanism (§5a) that works without any agent
//! cooperation, via mcp_config.rs (shared with Claude Code — Cursor's
//! `.cursor/mcp.json` / `~/.cursor/mcp.json` use the identical
//! `{ "mcpServers": {...} }` shape as of this writing).
//!
//! Paths below are documented/common as of this writing — same caveat as
//! claude_code.rs: treat empty discovery as "check these paths are still
//! current," not "no Cursor here."
//!
//! Which underlying LLM Cursor is configured to use (Claude, GPT, Grok —
//! Cursor added Grok support at some point) is irrelevant to this adapter
//! and always has been: discovery operates at the artifact/config layer
//! (what MCP servers and rules files are on disk), not the model layer.
//! Nothing here needs updating when Cursor adds or changes model backends
//! — noted explicitly so that's a documented judgment call, not a silent
//! assumption.

use crate::mcp_config::parse_mcp_servers_json;
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use agentguard_core::{Artifact, ArtifactKind, ArtifactSource, PublisherIdentity};
use std::collections::BTreeSet;
use std::path::Path;

pub struct CursorAdapter;

impl AgentAdapter for CursorAdapter {
    fn agent_id(&self) -> &'static str {
        "cursor"
    }

    fn agent_name(&self) -> &'static str {
        "Cursor"
    }

    fn detect(&self, project_root: &Path) -> bool {
        let home = dirs::home_dir();
        project_root.join(".cursor").exists()
            || project_root.join(".cursorrules").exists()
            || home
                .as_ref()
                .map(|h| h.join(".cursor").exists())
                .unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let mut out = Vec::new();
        let home = dirs::home_dir();

        // MCP servers — project scope (.cursor/mcp.json) and user scope
        // (~/.cursor/mcp.json). base_dir is project_root/home, NOT the
        // .cursor/ subdirectory the config file itself sits in — relative
        // script paths in the config are relative to the project root.
        out.extend(parse_mcp_servers_json(
            &project_root.join(".cursor").join("mcp.json"),
            project_root,
            ConfigSourceKind::CursorMcpJson,
            "mcpServers",
            "cursor",
            "Cursor",
        ));
        if let Some(h) = &home {
            out.extend(parse_mcp_servers_json(
                &h.join(".cursor").join("mcp.json"),
                h,
                ConfigSourceKind::CursorMcpJson,
                "mcpServers",
                "cursor",
                "Cursor",
            ));
        }

        // .cursorrules — instruction/prompt text fed straight into the
        // agent's context. Content-scanned (agentguard-scanner's
        // content.rs: prompt-injection phrasing, hidden Unicode, encoded
        // payloads, exfiltration directives) via its `scan_root`, the same
        // way a skill's SKILL.md now is — a poisoned `.cursorrules`
        // committed to a shared repo is a real supply-chain vector.
        let rules_path = project_root.join(".cursorrules");
        if rules_path.exists() {
            out.push(config_fingerprint(&rules_path, ".cursorrules"));
        }
        let rules_mdc = project_root.join(".cursor").join("rules");
        if rules_mdc.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&rules_mdc) {
                for e in entries.flatten() {
                    let p = e.path();
                    if p.extension().and_then(|x| x.to_str()) == Some("mdc") {
                        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("rule.mdc");
                        out.push(config_fingerprint(&p, &format!(".cursor/rules/{name}")));
                    }
                }
            }
        }

        out
    }
}

fn config_fingerprint(path: &Path, marker: &str) -> DiscoveredArtifact {
    let source = ArtifactSource::LocalPath(path.display().to_string());
    let mut discovered_by = BTreeSet::new();
    discovered_by.insert("cursor".to_string());
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
        // A single instruction file — the CLI scans it as `scan_root` (see
        // pipeline.rs's `root.is_file()` branch) and content.rs analyzes
        // its prose for prompt-injection / hidden-text / encoded payloads.
        scan_root: Some(path.to_path_buf()),
        artifact,
        launch: None,
        config_source: None,
        raw_config_entry: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_dir(name: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "agentguard-cursor-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn detects_project_scope_cursorrules() {
        let dir = unique_temp_dir("detect");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".cursorrules"), "be helpful").unwrap();

        assert!(CursorAdapter.detect(&dir));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_project_scope_mcp_servers() {
        // `discover()` also merges in the real machine's user-scope
        // ~/.cursor/mcp.json (by design — that's what makes `status` show
        // your whole machine), so this test must not assume it's the only
        // thing found: a dev machine that actually uses Cursor will have
        // real entries there too. Filter to just this test's own project
        // dir rather than asserting a bare total count.
        let dir = unique_temp_dir("discover-mcp");
        let cursor_dir = dir.join(".cursor");
        std::fs::create_dir_all(&cursor_dir).unwrap();
        let config = serde_json::json!({
            "mcpServers": { "example": { "command": "some-binary", "args": [] } }
        });
        std::fs::write(
            cursor_dir.join("mcp.json"),
            serde_json::to_string_pretty(&config).unwrap(),
        )
        .unwrap();

        let discovered = CursorAdapter.discover(&dir);
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
        assert!(project_mcp_entries[0].artifact.discovered_by.contains("cursor"));

        std::fs::remove_dir_all(&dir).ok();
    }
}
