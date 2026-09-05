//! Windsurf/Devin Desktop adapter — same locked v0 scope as Cursor
//! (BUILD_PLAN.md §0): discovery + config-gating only, no hook-level
//! enforcement claim. "Windsurf" was rebranded to "Devin Desktop" on
//! 2026-06-02 (Cognition, which also makes Devin, acquired Windsurf in
//! 2025) — shipped as an automatic over-the-air update, no reinstall, no
//! new install path. Re-verified 2026-09-05 directly against the CURRENT
//! docs.devin.ai/desktop/cascade/mcp page (the IDE's AI feature is called
//! "Cascade") that the rebrand did NOT change the config path or shape at
//! all: still `~/.codeium/windsurf/mcp_config.json`, still `{"mcpServers":
//! {...}}`. This module is kept under its original "windsurf" name/agent
//! id rather than renamed, since that's still the literal path component
//! and is how the product is referenced across this codebase's trust
//! seed/tests; "Devin Desktop" is documented here as the current product
//! name for anyone searching for it.
//!
//! An EARLIER note in this session's investigation claimed Devin
//! Desktop's hooks use "the same format as Claude Code hooks" — that
//! claim did NOT survive re-verification (see STATUS.md's retraction) and
//! is NOT repeated here: whether Cascade has any hook mechanism at all
//! remains genuinely unresolved, not built, not guessed at. Windsurf's
//! own docs (as re-checked) don't document any hooks/skills/plugins
//! extensibility mechanism beyond MCP servers themselves, so there's
//! nothing else to discover here — a narrower surface than Claude Code or
//! even Cursor, not an oversight.
//!
//! Config path: `~/.codeium/windsurf/mcp_config.json`, user scope ONLY —
//! confirmed directly (not assumed) that there's no project-scoped
//! equivalent, unlike Claude Code/Cursor/Codex. Same `{ "mcpServers": {
//! "<name>": { command, args, env } } }` shape, reusing mcp_config.rs —
//! the remote-server field is documented as accepting either `url` or
//! `serverUrl`, both handled by the shared parser already.
//!
//! Rules-file visibility: Windsurf's project-root rules file is
//! `.windsurfrules` (legacy, but confirmed still read as of this
//! writing) — newer projects are steered toward `.windsurf/rules/` or,
//! post-rebrand, `.devin/rules/`. Only the legacy single-file path is
//! fingerprinted here, matching this adapter's overall "narrower, don't
//! overclaim" scope; the newer directory-based rule locations are a gap
//! worth closing later, not silently claimed as covered.

use crate::mcp_config::parse_mcp_servers_json;
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use agentguard_core::{Artifact, ArtifactKind, ArtifactSource, PublisherIdentity};
use std::collections::BTreeSet;
use std::path::Path;

pub struct WindsurfAdapter;

impl AgentAdapter for WindsurfAdapter {
    fn agent_id(&self) -> &'static str {
        "windsurf"
    }

    fn agent_name(&self) -> &'static str {
        "Windsurf"
    }

    fn detect(&self, project_root: &Path) -> bool {
        let home = dirs::home_dir();
        project_root.join(".windsurfrules").exists()
            || project_root.join(".windsurf").exists()
            || home
                .as_ref()
                .map(|h| h.join(".codeium").join("windsurf").exists())
                .unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let mut out = Vec::new();
        let home = dirs::home_dir();

        // User-scope only — see this module's doc comment for why there's
        // no project-scope equivalent to also check.
        if let Some(h) = &home {
            out.extend(parse_mcp_servers_json(
                &h.join(".codeium").join("windsurf").join("mcp_config.json"),
                h,
                ConfigSourceKind::WindsurfMcpJson,
                "mcpServers",
                "windsurf",
                "Windsurf",
            ));
        }

        let rules_path = project_root.join(".windsurfrules");
        if rules_path.exists() {
            out.push(config_fingerprint(&rules_path, ".windsurfrules"));
        }

        out
    }
}

fn config_fingerprint(path: &Path, marker: &str) -> DiscoveredArtifact {
    let source = ArtifactSource::LocalPath(path.display().to_string());
    let mut discovered_by = BTreeSet::new();
    discovered_by.insert("windsurf".to_string());
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

    fn unique_temp_dir(name: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "agentguard-windsurf-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn detects_project_scope_windsurfrules() {
        let dir = unique_temp_dir("detect");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".windsurfrules"), "be helpful").unwrap();

        assert!(WindsurfAdapter.detect(&dir));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discover_never_looks_for_a_project_scope_mcp_config() {
        // The defining difference from Cursor/Claude Code: no
        // .windsurf/mcp_config.json project-scope file exists in
        // Windsurf's own design, so writing one here must have zero
        // effect on discovery -- proves this adapter doesn't accidentally
        // grow a project-scope path some future edit might add by
        // copy-pasting Cursor's shape without checking.
        let dir = unique_temp_dir("no-project-scope");
        let windsurf_dir = dir.join(".windsurf");
        std::fs::create_dir_all(&windsurf_dir).unwrap();
        let config = serde_json::json!({
            "mcpServers": { "example": { "command": "some-binary", "args": [] } }
        });
        std::fs::write(
            windsurf_dir.join("mcp_config.json"),
            serde_json::to_string_pretty(&config).unwrap(),
        )
        .unwrap();

        let discovered = WindsurfAdapter.discover(&dir);
        let project_scoped: Vec<_> = discovered
            .iter()
            .filter(|d| d.artifact.kind == ArtifactKind::McpServer)
            .filter(|d| {
                d.config_source
                    .as_ref()
                    .map(|cs| cs.path.starts_with(&dir))
                    .unwrap_or(false)
            })
            .collect();
        assert!(project_scoped.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }
}
