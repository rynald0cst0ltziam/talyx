//! OpenClaw adapter. Config path -- verified 2026-09-05 against
//! docs.openclaw.ai/tools/mcp: `~/.openclaw/openclaw.json`, user scope
//! (no project-scope file documented -- not assumed to exist). Genuinely
//! different nesting from every other agent: servers sit under
//! `mcp.servers`, TWO levels deep (`{"mcp": {"servers": {"<name>":
//! {...}}}}`), not a flat top-level `mcpServers` key -- so this doesn't
//! reuse `parse_mcp_servers_json`'s single-key lookup. Instead this
//! navigates the two levels itself, then hands the inner map straight to
//! the same shared `mcp_config::parse_server_map` every other agent uses,
//! after filtering out entries marked `"enabled": false` -- OpenClaw's own
//! field name, inverted from Kiro's `"disabled"`, so it's checked here
//! rather than relying on `parse_server_map`'s own `"disabled"` check
//! (which looks for the opposite field name).
//!
//! OpenClaw itself has some gateway/router characteristics (per-agent
//! server routing via `agents.<name>.mcpServers`, a scoped config editor,
//! its own "gateway" docs section) but ships a CLI end users install and
//! run directly -- matching Snyk agent-scan's own classification of it as
//! a scannable agent, not purely an enterprise-deployed gateway product.

use crate::mcp_config::parse_server_map;
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use serde_json::Value;
use std::path::Path;

pub struct OpenClawAdapter;

impl AgentAdapter for OpenClawAdapter {
    fn agent_id(&self) -> &'static str {
        "openclaw"
    }

    fn agent_name(&self) -> &'static str {
        "OpenClaw"
    }

    fn detect(&self, _project_root: &Path) -> bool {
        dirs::home_dir()
            .map(|h| h.join(".openclaw").join("openclaw.json").exists())
            .unwrap_or(false)
    }

    fn discover(&self, _project_root: &Path) -> Vec<DiscoveredArtifact> {
        let Some(h) = dirs::home_dir() else {
            return Vec::new();
        };
        parse_openclaw_config(&h.join(".openclaw").join("openclaw.json"), &h)
    }
}

fn parse_openclaw_config(path: &Path, base_dir: &Path) -> Vec<DiscoveredArtifact> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(json) = serde_json::from_str::<Value>(&text) else {
        return Vec::new();
    };
    let Some(servers) = json
        .get("mcp")
        .and_then(|m| m.get("servers"))
        .and_then(|s| s.as_object())
    else {
        return Vec::new();
    };

    // OpenClaw's own field for disabling a server is "enabled": false --
    // inverted from Kiro's "disabled": true, so filter it out here before
    // handing entries to the shared parser (which checks the opposite
    // field name and would not catch this).
    let live: serde_json::Map<String, Value> = servers
        .iter()
        .filter(|(_, cfg)| !matches!(cfg.get("enabled"), Some(Value::Bool(false))))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    parse_server_map(&live, path, base_dir, ConfigSourceKind::OpenClawJson, "openclaw", "OpenClaw")
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
            "talyx-openclaw-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn discovers_a_server_nested_two_levels_under_mcp_servers() {
        let dir = unique_temp_dir("discover");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("openclaw.json");
        let config = serde_json::json!({
            "mcp": {
                "servers": {
                    "docs": {
                        "url": "https://mcp.example.com/mcp",
                        "transport": "streamable-http"
                    }
                }
            }
        });
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovered = parse_openclaw_config(&config_path, &dir);
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].artifact.name, "docs");
        assert!(discovered[0].artifact.discovered_by.contains("openclaw"));
        assert_eq!(
            discovered[0].config_source.as_ref().unwrap().kind,
            ConfigSourceKind::OpenClawJson
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn skips_a_server_marked_enabled_false() {
        let dir = unique_temp_dir("disabled");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("openclaw.json");
        let config = serde_json::json!({
            "mcp": {
                "servers": {
                    "live": { "command": "some-binary" },
                    "off": { "command": "some-binary", "enabled": false }
                }
            }
        });
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovered = parse_openclaw_config(&config_path, &dir);
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].artifact.name, "live");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn does_not_discover_a_flat_top_level_mcpservers_key() {
        // Regression guard: OpenClaw's shape is nested two levels under
        // "mcp.servers" -- a flat top-level "mcpServers" key (every other
        // agent's shape) must NOT be picked up here.
        let dir = unique_temp_dir("wrong-shape");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("openclaw.json");
        let config = serde_json::json!({
            "mcpServers": { "example": { "command": "some-binary" } }
        });
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovered = parse_openclaw_config(&config_path, &dir);
        assert!(discovered.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn artifact_kind_is_mcp_server() {
        let dir = unique_temp_dir("kind");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("openclaw.json");
        let config = serde_json::json!({
            "mcp": { "servers": { "docs": { "command": "some-binary" } } }
        });
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovered = parse_openclaw_config(&config_path, &dir);
        assert_eq!(discovered[0].artifact.kind, ArtifactKind::McpServer);

        std::fs::remove_dir_all(&dir).ok();
    }
}
