//! Crush (Charmbracelet) adapter. Verified 2026-09-05 by reading the real
//! source (github.com/charmbracelet/crush's `internal/config/config.go`/
//! `load.go`), not docs -- `type MCPs map[string]MCPConfig` confirms a
//! standard name-keyed map nested one level under `"mcp"`, close enough
//! to the familiar shape that this reuses `parse_server_map` after a
//! one-level unwrap, same pattern as opencode's own `"mcp"` key.
//!
//! Paths: `crush.json`/`.crush.json` (project root -- the dotfile variant
//! takes priority per the real source) or `<config_dir>/crush/crush.json`
//! (user/global, via `dirs::config_dir()`).
//!
//! Crush's CURRENT primary format is actually `crushrc`, a Bash SCRIPT
//! (not a declarative file at all) that `crush.json` is now deprecated in
//! favor of, though still supported. `crushrc` is NOT covered here --
//! parsing arbitrary shell-script logic to know what it declares is a
//! fundamentally different, harder problem than every other adapter in
//! this codebase solves, left as an honestly-named gap rather than
//! guessed at.

use crate::mcp_config::parse_server_map;
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use std::path::Path;

pub struct CrushAdapter;

impl AgentAdapter for CrushAdapter {
    fn agent_id(&self) -> &'static str {
        "crush"
    }

    fn agent_name(&self) -> &'static str {
        "Crush"
    }

    fn detect(&self, project_root: &Path) -> bool {
        project_root.join("crush.json").exists()
            || project_root.join(".crush.json").exists()
            || global_config_path().map(|p| p.exists()).unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let mut out = Vec::new();

        // The dotfile variant takes priority per Crush's own source, but
        // for discovery both are checked independently rather than
        // picking a "winner" -- either could be the one Crush actually
        // loads depending on what else is present.
        out.extend(parse_crush_config(&project_root.join(".crush.json"), project_root));
        out.extend(parse_crush_config(&project_root.join("crush.json"), project_root));
        if let Some(path) = global_config_path() {
            if let Some(dir) = path.parent() {
                out.extend(parse_crush_config(&path, dir));
            }
        }

        out
    }
}

fn global_config_path() -> Option<std::path::PathBuf> {
    Some(dirs::config_dir()?.join("crush").join("crush.json"))
}

fn parse_crush_config(path: &Path, base_dir: &Path) -> Vec<DiscoveredArtifact> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Some(json) = crate::jsonc::parse_json_config(path, &text) else {
        return Vec::new();
    };
    let Some(servers) = json.get("mcp").and_then(|m| m.as_object()) else {
        return Vec::new();
    };
    parse_server_map(servers, path, base_dir, ConfigSourceKind::CrushMcpJson, "crush", "Crush")
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
            "talyx-crush-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn detects_project_scope_crush_json() {
        let dir = unique_temp_dir("detect");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("crush.json"), "{}").unwrap();

        assert!(CrushAdapter.detect(&dir));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_a_server_nested_under_mcp_and_skips_a_disabled_one() {
        let dir = unique_temp_dir("discover");
        std::fs::create_dir_all(&dir).unwrap();
        let config = serde_json::json!({
            "mcp": {
                "live": { "command": "some-binary", "args": [], "type": "stdio" },
                "off": { "command": "some-binary", "args": [], "type": "stdio", "disabled": true }
            }
        });
        std::fs::write(dir.join("crush.json"), serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovered = CrushAdapter.discover(&dir);
        let mcp: Vec<_> = discovered
            .iter()
            .filter(|d| d.artifact.kind == ArtifactKind::McpServer)
            .filter(|d| d.config_source.as_ref().map(|cs| cs.path.starts_with(&dir)).unwrap_or(false))
            .collect();
        assert_eq!(mcp.len(), 1);
        assert_eq!(mcp[0].artifact.name, "live");
        assert!(mcp[0].artifact.discovered_by.contains("crush"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_a_remote_server_via_url_field() {
        let dir = unique_temp_dir("discover-remote");
        std::fs::create_dir_all(&dir).unwrap();
        let config = serde_json::json!({
            "mcp": { "hosted": { "type": "http", "url": "https://mcp.example.com/mcp" } }
        });
        std::fs::write(dir.join(".crush.json"), serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovered = CrushAdapter.discover(&dir);
        let remote: Vec<_> = discovered.iter().filter(|d| d.artifact.name == "hosted").collect();
        assert_eq!(remote.len(), 1);
        assert!(remote[0].launch.is_none());

        std::fs::remove_dir_all(&dir).ok();
    }
}
