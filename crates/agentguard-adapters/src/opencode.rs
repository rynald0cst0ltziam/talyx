//! opencode adapter. Verified 2026-09-05 against opencode.ai's own docs
//! (opencode.ai/docs/config/, /docs/mcp-servers/) and independently
//! cross-validated by Snyk's `agent-scan` also listing it in its own
//! supported-agent set. Config: `opencode.json` (project root) or
//! `~/.config/opencode/opencode.json` (user/global) -- servers sit under
//! a `"mcp"` key, ONE level of nesting (not a flat top-level `mcpServers`
//! map), the same pattern already proven for OpenClaw's (two-level)
//! nesting.
//!
//! A genuinely different per-server shape, not just a different key name:
//! a LOCAL server's `"command"` field is an ARRAY of strings
//! (`["npx", "-y", "pkg"]`, combining what every other agent splits into
//! separate `command`+`args`), and environment variables use
//! `"environment"`, not `"env"`. Feeding this directly into the shared
//! `parse_server_map` (which expects `command` as a STRING) would parse
//! every local server's command as empty -- a real, silent
//! under-detection bug, not a cosmetic mismatch. Fixed by normalizing
//! each entry (split `command[0]` into `command`, the rest into `args`,
//! rename `environment` to `env`) before handing the map to the shared
//! parser, keeping `parse_server_map` itself untouched for a shape only
//! this one agent uses. Remote servers (`"type": "remote", "url": ...,
//! "headers": {...}`) already match the shared shape exactly, so they
//! pass through unmodified.
//!
//! A `.jsonc` variant (JSON with comments) is also documented but not
//! handled -- `serde_json` doesn't parse comments, so a `.jsonc` file
//! with real comments fails to parse and is silently skipped, same as any
//! malformed JSON elsewhere in this codebase.

use crate::mcp_config::parse_server_map;
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use serde_json::Value;
use std::path::Path;

/// Normalizes opencode's per-server shape into the one `parse_server_map`
/// expects: a local server's `"command"` array becomes a string `command`
/// plus an `args` array (first element is the command, the rest are
/// args); `"environment"` is renamed to `"env"`. A remote server (has
/// `"url"`) already matches the shared shape and passes through
/// unchanged. An entry with `"enabled": false` is dropped entirely --
/// opencode's own confirmed way to disable a server without deleting it,
/// same "don't flag an inert entry as live risk" principle as every other
/// agent's own enabled/disabled flag.
fn normalize_server_map(servers: &serde_json::Map<String, Value>) -> serde_json::Map<String, Value> {
    let mut out = serde_json::Map::new();
    for (name, cfg) in servers {
        if matches!(cfg.get("enabled"), Some(Value::Bool(false))) {
            continue;
        }
        let Some(cfg_obj) = cfg.as_object() else {
            continue;
        };
        if cfg_obj.contains_key("url") {
            // Remote shape already matches -- pass through.
            out.insert(name.clone(), cfg.clone());
            continue;
        }
        let mut normalized = cfg_obj.clone();
        if let Some(command_array) = cfg_obj.get("command").and_then(|c| c.as_array()) {
            let parts: Vec<String> =
                command_array.iter().filter_map(|v| v.as_str().map(String::from)).collect();
            if let Some((first, rest)) = parts.split_first() {
                normalized.insert("command".to_string(), Value::String(first.clone()));
                normalized.insert(
                    "args".to_string(),
                    Value::Array(rest.iter().map(|s| Value::String(s.clone())).collect()),
                );
            }
        }
        if let Some(environment) = normalized.remove("environment") {
            normalized.insert("env".to_string(), environment);
        }
        out.insert(name.clone(), Value::Object(normalized));
    }
    out
}

pub struct OpenCodeAdapter;

impl AgentAdapter for OpenCodeAdapter {
    fn agent_id(&self) -> &'static str {
        "opencode"
    }

    fn agent_name(&self) -> &'static str {
        "opencode"
    }

    fn detect(&self, project_root: &Path) -> bool {
        let home = dirs::home_dir();
        project_root.join("opencode.json").exists()
            || home
                .as_ref()
                .map(|h| h.join(".config").join("opencode").join("opencode.json").exists())
                .unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let mut out = Vec::new();
        let home = dirs::home_dir();

        out.extend(parse_opencode_config(&project_root.join("opencode.json"), project_root));
        if let Some(h) = &home {
            out.extend(parse_opencode_config(
                &h.join(".config").join("opencode").join("opencode.json"),
                h,
            ));
        }

        out
    }
}

fn parse_opencode_config(path: &Path, base_dir: &Path) -> Vec<DiscoveredArtifact> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(json) = serde_json::from_str::<Value>(&text) else {
        return Vec::new();
    };
    let Some(servers) = json.get("mcp").and_then(|m| m.as_object()) else {
        return Vec::new();
    };
    let normalized = normalize_server_map(servers);
    parse_server_map(&normalized, path, base_dir, ConfigSourceKind::OpenCodeMcpJson, "opencode", "opencode")
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
            "agentguard-opencode-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn discovers_a_local_server_with_array_shaped_command() {
        // Regression test for the real normalize_server_map fix: without
        // it, this server's array-shaped "command" would parse as an
        // empty command string (silent under-detection), not a crash --
        // the more dangerous failure mode.
        let dir = unique_temp_dir("discover-local");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("opencode.json");
        let config = serde_json::json!({
            "$schema": "https://opencode.ai/config.json",
            "mcp": {
                "everything": {
                    "type": "local",
                    "command": ["npx", "-y", "@modelcontextprotocol/server-everything"],
                    "environment": { "MY_ENV_VAR": "value" }
                }
            }
        });
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovered = parse_opencode_config(&config_path, &dir);
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].artifact.name, "everything");
        let launch = discovered[0].launch.as_ref().expect("local server should have a launch command");
        assert_eq!(launch.command, "npx");
        assert_eq!(launch.args, vec!["-y", "@modelcontextprotocol/server-everything"]);
        let caps: Vec<_> = discovered[0].artifact.capabilities.iter().map(|c| c.capability).collect();
        assert!(
            caps.contains(&agentguard_core::Capability::EnvironmentVariables),
            "the renamed \"environment\" -> \"env\" field should still be picked up"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn skips_a_server_marked_enabled_false() {
        let dir = unique_temp_dir("disabled");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("opencode.json");
        let config = serde_json::json!({
            "mcp": {
                "off": { "type": "local", "command": ["npx", "pkg"], "enabled": false }
            }
        });
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovered = parse_opencode_config(&config_path, &dir);
        assert!(discovered.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_a_remote_server_via_url_field() {
        let dir = unique_temp_dir("discover-remote");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("opencode.json");
        let config = serde_json::json!({
            "mcp": {
                "hosted": { "type": "remote", "url": "http://localhost:3000/mcp/http" }
            }
        });
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovered = parse_opencode_config(&config_path, &dir);
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].artifact.name, "hosted");
        assert!(discovered[0].launch.is_none());
        assert!(discovered[0].artifact.discovered_by.contains("opencode"));
        assert_eq!(discovered[0].artifact.kind, ArtifactKind::McpServer);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn does_not_discover_a_flat_top_level_mcpservers_key() {
        let dir = unique_temp_dir("wrong-shape");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("opencode.json");
        let config = serde_json::json!({
            "mcpServers": { "example": { "command": "some-binary" } }
        });
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovered = parse_opencode_config(&config_path, &dir);
        assert!(discovered.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }
}
