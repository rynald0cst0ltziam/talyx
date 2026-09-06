//! Google Antigravity adapter. Config paths —
//! `~/.gemini/config/mcp_config.json` (global/user scope) and
//! `.agents/mcp_config.json` (project scope), both confirmed directly
//! against Antigravity's own docs, not assumed. Same `{ "mcpServers": {
//! "<name>": { command, args, env } } }` shape as Claude Code/Cursor,
//! reusing mcp_config.rs — Antigravity's remote-server field is
//! documented as `serverUrl` (NOT `url`), already handled by the shared
//! parser's fallback (see `ConfigSourceKind::AntigravityMcpJson`'s doc
//! comment for the deliberate distinction from Gemini CLI's own,
//! differently-shaped config that happens to share the `~/.gemini/`
//! parent directory).
//!
//! Hooks — `.agents/hooks.json` (project) / `~/.gemini/config/hooks.json`
//! (user), verified 2026-09-05 via two independent, mutually-agreeing
//! fetches (see `ConfigSourceKind::AntigravityHooksJson`'s doc comment for
//! why that cross-check mattered here). Unlike Claude Code/Codex, there's
//! no `"hooks"` wrapper key — the root object itself is a map of hook name
//! -> event map, so this reads the file directly and hands the whole root
//! to `hooks_config::parse_hooks_value` instead of going through
//! `parse_hooks_json`'s `"hooks"`-key extraction.
//!
//! Plugins — verified 2026-09-06 against antigravity.google/docs/ide/
//! plugins/: Antigravity loads a plugin from `~/.gemini/config/plugins/
//! <name>/` (global) or `.agents/plugins/<name>/` / `_agents/plugins/
//! <name>/` (workspace). A plugin directory is `plugin.json` plus any of
//! `mcp_config.json` (same `{ "mcpServers": {...} }` shape as the
//! top-level one — reuses `AntigravityMcpJson`), `hooks.json` (same
//! wrapper-less shape), `rules/*.md`, and `skills/<name>/SKILL.md`. This
//! is a second config surface the standalone-file discovery above does
//! NOT cover — a plugin can ship a malicious MCP server, hook, or
//! injection-bearing rule/skill file. `rules/` and `skills/` markdown are
//! content-scanned as instruction files (same treatment as a top-level
//! rules file); quarantine-style skill enforcement is a documented
//! follow-up, not claimed here.

use crate::hooks_config::parse_hooks_value;
use crate::mcp_config::parse_mcp_servers_json;
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use agentguard_core::{Artifact, ArtifactKind, ArtifactSource, PublisherIdentity};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// Antigravity's `hooks.json` has no `"hooks"` wrapper key — the root
/// object IS the hook-name -> event-map (see this module's doc comment and
/// `ConfigSourceKind::AntigravityHooksJson`), so the whole parsed root is
/// handed straight to the shared per-entry walk. `parse_hooks_value`'s own
/// `enabled: false` skip (in `collect_command_strings`) already handles a
/// disabled hook name correctly — no separate filtering needed here.
fn parse_antigravity_hooks(path: &Path) -> Vec<DiscoveredArtifact> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(json) = serde_json::from_str::<Value>(&text) else {
        return Vec::new();
    };
    if !json.is_object() {
        return Vec::new();
    }
    parse_hooks_value(&json, path, ConfigSourceKind::AntigravityHooksJson, "antigravity")
}

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
            || project_root.join("_agents").join("plugins").is_dir()
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
            "mcpServers",
            "antigravity",
            "Antigravity",
        ));
        if let Some(h) = &home {
            out.extend(parse_mcp_servers_json(
                &h.join(".gemini").join("config").join("mcp_config.json"),
                h,
                ConfigSourceKind::AntigravityMcpJson,
                "mcpServers",
                "antigravity",
                "Antigravity",
            ));
        }

        out.extend(parse_antigravity_hooks(
            &project_root.join(".agents").join("hooks.json"),
        ));
        if let Some(h) = &home {
            out.extend(parse_antigravity_hooks(
                &h.join(".gemini").join("config").join("hooks.json"),
            ));
        }

        // Plugins — a second config surface. Workspace plugins live under
        // `.agents/plugins/` or `_agents/plugins/`; global ones under
        // `~/.gemini/config/plugins/`.
        for ws in [".agents", "_agents"] {
            out.extend(parse_antigravity_plugins(&project_root.join(ws).join("plugins")));
        }
        if let Some(h) = &home {
            out.extend(parse_antigravity_plugins(
                &h.join(".gemini").join("config").join("plugins"),
            ));
        }

        out
    }
}

/// Discovers every plugin under a `plugins/` directory: each plugin's
/// `mcp_config.json` (reusing the standard MCP parse + rewrite path),
/// `hooks.json` (wrapper-less, same as the top-level one), and its
/// `rules/*.md` / `skills/*/SKILL.md` markdown (content-scanned as
/// instruction files). A directory is only treated as a plugin if it
/// contains `plugin.json`.
fn parse_antigravity_plugins(plugins_dir: &Path) -> Vec<DiscoveredArtifact> {
    let Ok(entries) = fs::read_dir(plugins_dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let plugin_dir = entry.path();
        if !plugin_dir.is_dir() || !plugin_dir.join("plugin.json").is_file() {
            continue;
        }
        let plugin_name = plugin_dir.file_name().and_then(|n| n.to_str()).unwrap_or("plugin");

        out.extend(parse_mcp_servers_json(
            &plugin_dir.join("mcp_config.json"),
            &plugin_dir,
            ConfigSourceKind::AntigravityMcpJson,
            "mcpServers",
            "antigravity",
            "Antigravity",
        ));
        out.extend(parse_antigravity_hooks(&plugin_dir.join("hooks.json")));

        for (subdir, glob_leaf) in [("rules", None), ("skills", Some("SKILL.md"))] {
            let Ok(sub) = fs::read_dir(plugin_dir.join(subdir)) else {
                continue;
            };
            for md in sub.flatten() {
                let p = md.path();
                let (scan_path, label) = match glob_leaf {
                    // rules/<name>.md
                    None if p.extension().and_then(|e| e.to_str()) == Some("md") => {
                        (p.clone(), p.file_name().and_then(|n| n.to_str()).unwrap_or("rule.md").to_string())
                    }
                    // skills/<name>/SKILL.md
                    Some(leaf) if p.is_dir() && p.join(leaf).is_file() => {
                        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("skill");
                        (p.join(leaf), format!("{name}/{leaf}"))
                    }
                    _ => continue,
                };
                out.push(plugin_instruction_fingerprint(
                    &scan_path,
                    &format!("{plugin_name}/{subdir}/{label}"),
                ));
            }
        }
    }
    out
}

fn plugin_instruction_fingerprint(path: &Path, marker: &str) -> DiscoveredArtifact {
    let source = ArtifactSource::LocalPath(path.display().to_string());
    let mut discovered_by = BTreeSet::new();
    discovered_by.insert("antigravity".to_string());
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

    #[test]
    fn discovers_an_mcp_server_and_a_rule_from_a_workspace_plugin() {
        let dir = unique_temp_dir("plugin");
        let plugin = dir.join(".agents").join("plugins").join("shady");
        std::fs::create_dir_all(plugin.join("rules")).unwrap();
        std::fs::write(plugin.join("plugin.json"), r#"{"name":"shady"}"#).unwrap();
        std::fs::write(
            plugin.join("mcp_config.json"),
            serde_json::to_string(&serde_json::json!({
                "mcpServers": { "helper": { "command": "node", "args": ["s.js"] } }
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(plugin.join("rules").join("style.md"), "Always use tabs.").unwrap();

        let discovered = AntigravityAdapter.discover(&dir);
        let server = discovered
            .iter()
            .find(|d| d.artifact.kind == ArtifactKind::McpServer && d.artifact.name == "helper");
        assert!(server.is_some(), "plugin mcp_config.json server should be discovered");
        assert_eq!(
            server.unwrap().config_source.as_ref().unwrap().kind,
            ConfigSourceKind::AntigravityMcpJson
        );

        let rule = discovered
            .iter()
            .find(|d| d.artifact.kind == ArtifactKind::AgentConfig && d.artifact.name == "shady/rules/style.md");
        assert!(rule.is_some(), "plugin rule markdown should be content-scanned");
        assert!(rule.unwrap().scan_root.is_some());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ignores_a_plugin_directory_without_plugin_json() {
        let dir = unique_temp_dir("noplugin");
        let plugin = dir.join(".agents").join("plugins").join("not-a-plugin");
        std::fs::create_dir_all(&plugin).unwrap();
        std::fs::write(
            plugin.join("mcp_config.json"),
            r#"{"mcpServers":{"x":{"command":"y"}}}"#,
        )
        .unwrap();

        let discovered = AntigravityAdapter.discover(&dir);
        assert!(!discovered.iter().any(|d| d.artifact.name == "x"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_an_enabled_hook_and_skips_a_disabled_one() {
        // Antigravity's hooks.json has no "hooks" wrapper key -- the root
        // IS the hook-name -> event-map -- and a hook name can carry
        // "enabled": false to disable it without deleting it. A disabled
        // hook never runs, so it must not be surfaced as live risk.
        let dir = unique_temp_dir("hooks");
        let agents_dir = dir.join(".agents");
        std::fs::create_dir_all(&agents_dir).unwrap();
        let hooks = serde_json::json!({
            "my-linter-hook": {
                "PostToolUse": [
                    { "matcher": "run_command", "hooks": [ { "type": "command", "command": "./scripts/lint.sh", "timeout": 10 } ] }
                ]
            },
            "safety-gate": {
                "enabled": false,
                "PreToolUse": [
                    { "matcher": "run_command", "hooks": [ { "command": "./scripts/safety-check.sh" } ] }
                ]
            }
        });
        std::fs::write(agents_dir.join("hooks.json"), serde_json::to_string_pretty(&hooks).unwrap())
            .unwrap();

        let discovered = AntigravityAdapter.discover(&dir);
        let hooks: Vec<_> = discovered
            .iter()
            .filter(|d| d.artifact.kind == ArtifactKind::Hook)
            .collect();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].launch.as_ref().unwrap().command, "./scripts/lint.sh");
        assert!(hooks[0].artifact.discovered_by.contains("antigravity"));
        assert_eq!(
            hooks[0].config_source.as_ref().unwrap().kind,
            ConfigSourceKind::AntigravityHooksJson
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
