//! Warp adapter — the last agent from the competitive-landscape sweep to
//! be closed out.
//!
//! MCP config: `~/.warp/.mcp.json` on **every** platform
//! (`%USERPROFILE%\.warp\.mcp.json` on Windows), verified 2026-09-06
//! against docs.warp.dev/terminal/settings/file-locations/ ("MCP server
//! configuration ... always live[s] in your home directory on every
//! platform") and docs.warp.dev/reference/cli/mcp-servers/. User scope
//! only — no project-scope equivalent — and shared between Warp Stable
//! and Preview.
//!
//! Shape: a **flat map of servers at the JSON root**, per the CLI docs'
//! own example (`{ "github": { "url": ... }, "sentry": { "command":
//! "npx", "args": [...] } }`), NOT wrapped in `mcpServers`. See
//! `mcp_config::parse_mcp_servers_json_root_or_wrapped` — it accepts
//! either form.
//!
//! Skills: `~/.warp/skills/<name>/SKILL.md` — content-scanned as
//! instruction files (a Warp skill's markdown is injected into the
//! agent's context, same attack surface as a Claude Code skill). Warp's
//! agent config also lives at `~/.agents/` (home scope); a hook/rule
//! mechanism there isn't documented in a way worth building against yet,
//! so it's deliberately not covered — same "don't guess" discipline as
//! Windsurf's hooks.

use crate::mcp_config::parse_mcp_servers_json_root_or_wrapped;
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use agentguard_core::{Artifact, ArtifactKind, ArtifactSource, PublisherIdentity};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

pub struct WarpAdapter;

impl AgentAdapter for WarpAdapter {
    fn agent_id(&self) -> &'static str {
        "warp"
    }

    fn agent_name(&self) -> &'static str {
        "Warp"
    }

    fn detect(&self, _project_root: &Path) -> bool {
        dirs::home_dir()
            .map(|h| h.join(".warp").exists())
            .unwrap_or(false)
    }

    fn discover(&self, _project_root: &Path) -> Vec<DiscoveredArtifact> {
        let mut out = Vec::new();
        let Some(home) = dirs::home_dir() else {
            return out;
        };

        out.extend(parse_mcp_servers_json_root_or_wrapped(
            &home.join(".warp").join(".mcp.json"),
            &home,
            ConfigSourceKind::WarpMcpJson,
            "warp",
            "Warp",
        ));

        out.extend(discover_warp_skills(&home.join(".warp").join("skills")));

        out
    }
}

/// Every `~/.warp/skills/<name>/` directory with a `SKILL.md` — scanned
/// for prompt-injection / hidden content via `scan_root`.
fn discover_warp_skills(skills_dir: &Path) -> Vec<DiscoveredArtifact> {
    let Ok(entries) = fs::read_dir(skills_dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() || !dir.join("SKILL.md").is_file() {
            continue;
        }
        let name = dir.file_name().and_then(|n| n.to_str()).unwrap_or("skill").to_string();
        let source = ArtifactSource::LocalPath(dir.display().to_string());
        let mut discovered_by = BTreeSet::new();
        discovered_by.insert("warp".to_string());
        out.push(DiscoveredArtifact {
            display_location: dir.display().to_string(),
            scan_root: Some(dir.clone()),
            artifact: Artifact {
                id: Artifact::compute_id(ArtifactKind::Skill, &name, &source),
                kind: ArtifactKind::Skill,
                name,
                version: None,
                publisher: PublisherIdentity::default(),
                source,
                content_hash: None,
                capabilities: vec![],
                discovered_by,
            },
            launch: None,
            config_source: None,
            raw_config_entry: None,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_dir(name: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "agentguard-warp-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    /// Drives `discover` against a fake `~/.warp` by parsing the file
    /// directly (the adapter's own `discover` reads the real home dir,
    /// which a test can't redirect — same limitation as Windsurf / Zed).
    fn parse(dir: &std::path::Path) -> Vec<DiscoveredArtifact> {
        parse_mcp_servers_json_root_or_wrapped(
            &dir.join(".mcp.json"),
            dir,
            ConfigSourceKind::WarpMcpJson,
            "warp",
            "Warp",
        )
    }

    #[test]
    fn parses_the_flat_root_shape_from_warps_own_docs() {
        let dir = unique_temp_dir("flat");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(".mcp.json"),
            r#"{
              "github": { "url": "https://api.githubcopilot.com/mcp/" },
              "local-helper": { "command": "node", "args": ["./helper.js"] }
            }"#,
        )
        .unwrap();

        let found = parse(&dir);
        let names: Vec<_> = found.iter().map(|d| d.artifact.name.as_str()).collect();
        assert!(names.contains(&"github"));
        assert!(names.contains(&"local-helper"));
        let local = found.iter().find(|d| d.artifact.name == "local-helper").unwrap();
        assert!(local.launch.is_some());
        assert_eq!(
            local.config_source.as_ref().unwrap().kind,
            ConfigSourceKind::WarpMcpJson
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn also_accepts_a_hand_written_mcpservers_wrapper() {
        let dir = unique_temp_dir("wrapped");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(".mcp.json"),
            r#"{ "mcpServers": { "x": { "command": "y", "args": [] } } }"#,
        )
        .unwrap();
        assert_eq!(parse(&dir).len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_unrelated_json_object_is_not_mistaken_for_servers() {
        let dir = unique_temp_dir("unrelated");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".mcp.json"), r#"{ "theme": "dark", "fontSize": 13 }"#).unwrap();
        assert!(parse(&dir).is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_a_warp_skill_for_content_scanning() {
        let dir = unique_temp_dir("skill");
        let skill = dir.join("skills").join("summarizer");
        std::fs::create_dir_all(&skill).unwrap();
        std::fs::write(skill.join("SKILL.md"), "Summarize the input.").unwrap();

        let found = discover_warp_skills(&dir.join("skills"));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].artifact.kind, ArtifactKind::Skill);
        assert_eq!(found[0].scan_root.as_deref(), Some(skill.as_path()));
        assert!(found[0].artifact.discovered_by.contains("warp"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
