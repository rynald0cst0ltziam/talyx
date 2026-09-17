//! Continue.dev adapter. Verified 2026-09-05 against docs.continue.dev/
//! customize/deep-dives/mcp: Continue's NATIVE, preferred format is YAML
//! -- `config.yaml`'s own `mcpServers` key is a LIST of `{name, command,
//! args}` objects, not a name-keyed map, a genuinely different shape from
//! every other agent this codebase covers (see `ConfigSourceKind::
//! ContinueMcpJson`'s doc comment). `.continue/mcpServers/*.yaml`/`*.yml`
//! files use the same list shape, wrapped with sibling metadata fields
//! (`name`/`version`/`schema`) that are irrelevant to parsing. Handled by
//! converting the list into the name-keyed map `parse_server_map` expects
//! (`list_to_server_map`) before handing it off -- the shared parser
//! itself stays untouched, the same "normalize at the edge" approach
//! already used for opencode's array-shaped `command` field.
//!
//! Covered: `config.yaml` (project `.continue/config.yaml`, user
//! `~/.continue/config.yaml`) and every `*.json`/`*.yaml`/`*.yml` file in
//! `.continue/mcpServers/` (project) and `~/.continue/mcpServers/`
//! (user) -- a glob of files, same pattern as Amazon Q's/Copilot CLI's
//! own directories. Continue's own docs explicitly permit dropping in
//! "JSON MCP configuration from another tool" unchanged into that
//! directory, so a standard `{"mcpServers": {...}}` JSON file there is a
//! genuinely supported, documented mechanism, not an edge case -- kept
//! working alongside the new YAML support, not replaced by it.
//!
//! The legacy `config.json` (deprecated per Continue's own docs, loaded
//! only when no `config.yaml` is present) is NOT covered -- would need
//! confirming its own top-level shape (map or list) independently rather
//! than assuming it matches either the JSON glob files or config.yaml's
//! list; left as a known, named gap rather than guessed at.

use crate::mcp_config::{list_to_server_map, parse_mcp_servers_json, parse_server_map};
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use serde_json::Value;
use std::path::Path;

pub struct ContinueDevAdapter;

impl AgentAdapter for ContinueDevAdapter {
    fn agent_id(&self) -> &'static str {
        "continue-dev"
    }

    fn agent_name(&self) -> &'static str {
        "Continue.dev"
    }

    fn detect(&self, project_root: &Path) -> bool {
        let home = dirs::home_dir();
        project_root.join(".continue").exists()
            || home.as_ref().map(|h| h.join(".continue").exists()).unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let mut out = Vec::new();
        let home = dirs::home_dir();

        out.extend(parse_config_yaml(&project_root.join(".continue").join("config.yaml"), project_root));
        out.extend(parse_mcp_servers_dir(&project_root.join(".continue").join("mcpServers"), project_root));
        if let Some(h) = &home {
            out.extend(parse_config_yaml(&h.join(".continue").join("config.yaml"), h));
            out.extend(parse_mcp_servers_dir(&h.join(".continue").join("mcpServers"), h));
        }

        out
    }
}

fn parse_config_yaml(path: &Path, base_dir: &Path) -> Vec<DiscoveredArtifact> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(json) = serde_saphyr::from_str::<Value>(crate::jsonc::strip_bom(&text)) else {
        return Vec::new();
    };
    let Some(list) = json.get("mcpServers").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let servers = list_to_server_map(list);
    parse_server_map(&servers, path, base_dir, ConfigSourceKind::ContinueYamlMcpJson, "continue-dev", "Continue.dev")
}

fn parse_mcp_servers_dir(dir: &Path, base_dir: &Path) -> Vec<DiscoveredArtifact> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    let mut files: Vec<std::path::PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            matches!(p.extension().and_then(|e| e.to_str()), Some("json") | Some("yaml") | Some("yml"))
        })
        .collect();
    files.sort();
    for path in files {
        let is_yaml = matches!(path.extension().and_then(|e| e.to_str()), Some("yaml") | Some("yml"));
        if is_yaml {
            // The bundle-file shape wraps the same list under sibling
            // name/version/schema metadata, but the list itself is
            // identical to config.yaml's -- reuse the same conversion.
            let Ok(text) = std::fs::read_to_string(&path) else { continue };
            let Ok(json) = serde_saphyr::from_str::<Value>(crate::jsonc::strip_bom(&text)) else { continue };
            let Some(list) = json.get("mcpServers").and_then(|v| v.as_array()) else { continue };
            let servers = list_to_server_map(list);
            out.extend(parse_server_map(
                &servers,
                &path,
                base_dir,
                ConfigSourceKind::ContinueYamlMcpJson,
                "continue-dev",
                "Continue.dev",
            ));
        } else {
            out.extend(parse_mcp_servers_json(
                &path,
                base_dir,
                ConfigSourceKind::ContinueMcpJson,
                "mcpServers",
                "continue-dev",
                "Continue.dev",
            ));
        }
    }
    out
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
            "talyx-continue-dev-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn detects_project_scope_continue_dir() {
        let dir = unique_temp_dir("detect");
        std::fs::create_dir_all(dir.join(".continue")).unwrap();

        assert!(ContinueDevAdapter.detect(&dir));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_a_json_file_dropped_into_the_mcpservers_directory() {
        let dir = unique_temp_dir("discover-json");
        let mcp_dir = dir.join(".continue").join("mcpServers");
        std::fs::create_dir_all(&mcp_dir).unwrap();
        let config = serde_json::json!({
            "mcpServers": { "sqlite": { "command": "npx", "args": ["-y", "mcp-sqlite"] } }
        });
        std::fs::write(mcp_dir.join("mcp.json"), serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovered = ContinueDevAdapter.discover(&dir);
        let mcp: Vec<_> = discovered
            .iter()
            .filter(|d| d.artifact.kind == ArtifactKind::McpServer)
            .filter(|d| d.config_source.as_ref().map(|cs| cs.path.starts_with(&dir)).unwrap_or(false))
            .collect();
        assert_eq!(mcp.len(), 1);
        assert_eq!(mcp[0].artifact.name, "sqlite");
        assert!(mcp[0].artifact.discovered_by.contains("continue-dev"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_the_real_list_shaped_mcpservers_from_config_yaml() {
        // Regression test proving the actual native format now works --
        // this exact shape (a LIST, not a map) previously wasn't parsed
        // at all.
        let dir = unique_temp_dir("discover-config-yaml");
        std::fs::create_dir_all(dir.join(".continue")).unwrap();
        std::fs::write(
            dir.join(".continue").join("config.yaml"),
            "mcpServers:\n  - name: SQLite MCP\n    command: npx\n    args:\n      - \"-y\"\n      - \"mcp-sqlite\"\n",
        )
        .unwrap();

        let discovered = ContinueDevAdapter.discover(&dir);
        let mcp: Vec<_> = discovered
            .iter()
            .filter(|d| d.artifact.kind == ArtifactKind::McpServer)
            .filter(|d| d.config_source.as_ref().map(|cs| cs.path.starts_with(&dir)).unwrap_or(false))
            .collect();
        assert_eq!(mcp.len(), 1);
        assert_eq!(mcp[0].artifact.name, "SQLite MCP");
        let launch = mcp[0].launch.as_ref().unwrap();
        assert_eq!(launch.command, "npx");
        assert_eq!(launch.args, vec!["-y", "mcp-sqlite"]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_a_yaml_bundle_file_from_the_mcpservers_directory() {
        let dir = unique_temp_dir("discover-yaml-bundle");
        let mcp_dir = dir.join(".continue").join("mcpServers");
        std::fs::create_dir_all(&mcp_dir).unwrap();
        std::fs::write(
            mcp_dir.join("playwright.yaml"),
            "name: Playwright mcpServer\nversion: 0.0.1\nschema: v1\nmcpServers:\n  - name: Browser search\n    command: npx\n    args:\n      - \"@playwright/mcp\"\n",
        )
        .unwrap();

        let discovered = ContinueDevAdapter.discover(&dir);
        let mcp: Vec<_> = discovered
            .iter()
            .filter(|d| d.artifact.kind == ArtifactKind::McpServer)
            .filter(|d| d.config_source.as_ref().map(|cs| cs.path.starts_with(&dir)).unwrap_or(false))
            .collect();
        assert_eq!(mcp.len(), 1);
        assert_eq!(mcp[0].artifact.name, "Browser search");

        std::fs::remove_dir_all(&dir).ok();
    }
}
