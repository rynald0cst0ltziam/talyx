//! Claude Code adapter — the only Tier-1 adapter with full enforcement
//! planned (BUILD_PLAN.md §0, §5b: `PreToolUse` hooks are a real
//! interception point). MCP server discovery delegates to mcp_config.rs
//! (shared with the Cursor adapter — same JSON shape); this file owns
//! what's specific to Claude Code: hooks and skills discovery, and its
//! own config file locations.
//!
//! Config file locations below are the documented/common ones as of this
//! writing. Claude Code's config layout has changed before and will change
//! again — treat `detect`/`discover` returning nothing as "check these
//! paths are still current," not as "no agent present," and keep this file
//! as the single place those paths live so a version bump is a local edit,
//! not a hunt through the codebase (this is the adapter-maintenance
//! treadmill called out in BUILD_PLAN.md's audit notes).

use crate::mcp_config::parse_mcp_servers_json;
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use agentguard_core::{
    Artifact, ArtifactKind, ArtifactSource, Capability, CapabilityFinding, EvidenceBasis,
    PublisherIdentity,
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

pub struct ClaudeCodeAdapter;

impl AgentAdapter for ClaudeCodeAdapter {
    fn agent_id(&self) -> &'static str {
        "claude-code"
    }

    fn agent_name(&self) -> &'static str {
        "Claude Code"
    }

    fn detect(&self, project_root: &Path) -> bool {
        let home = dirs::home_dir();
        project_root.join(".mcp.json").exists()
            || project_root.join(".claude").exists()
            || home
                .as_ref()
                .map(|h| h.join(".claude.json").exists())
                .unwrap_or(false)
            || home
                .as_ref()
                .map(|h| h.join(".claude").exists())
                .unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let mut out = Vec::new();
        let home = dirs::home_dir();

        // MCP servers — project scope (.mcp.json) and user scope
        // (~/.claude.json). Both sit directly in their own base dir, so
        // base_dir == the config's own parent for each.
        out.extend(parse_mcp_servers_json(
            &project_root.join(".mcp.json"),
            project_root,
            ConfigSourceKind::ClaudeCodeMcpServersJson,
            "claude-code",
            "Claude Code",
        ));
        if let Some(h) = &home {
            out.extend(parse_mcp_servers_json(
                &h.join(".claude.json"),
                h,
                ConfigSourceKind::ClaudeCodeMcpServersJson,
                "claude-code",
                "Claude Code",
            ));
        }

        // Hooks — project and user settings.json.
        out.extend(parse_hooks(
            &project_root.join(".claude").join("settings.json"),
        ));
        if let Some(h) = &home {
            out.extend(parse_hooks(&h.join(".claude").join("settings.json")));
        }

        // Skills — project and user skills directories.
        out.extend(discover_skills(&project_root.join(".claude").join("skills")));
        if let Some(h) = &home {
            out.extend(discover_skills(&h.join(".claude").join("skills")));
        }

        out
    }
}

fn discovered_by_set() -> BTreeSet<String> {
    let mut s = BTreeSet::new();
    s.insert("claude-code".to_string());
    s
}

/// Recursively pull every `"command"` string found under a JSON `hooks`
/// subtree. Deliberately schema-loose rather than modeling Claude Code's
/// exact hook config shape field-by-field — that shape has changed before,
/// and "find every command hooks would run" degrades gracefully across
/// schema versions where a strict struct would just fail to parse.
fn parse_hooks(path: &Path) -> Vec<DiscoveredArtifact> {
    let mut out = Vec::new();
    let Ok(text) = fs::read_to_string(path) else {
        return out;
    };
    let Ok(json) = serde_json::from_str::<Value>(&text) else {
        return out;
    };
    let Some(hooks_val) = json.get("hooks") else {
        return out;
    };

    let mut commands = Vec::new();
    collect_command_strings(hooks_val, &mut commands);

    for (i, cmd) in commands.into_iter().enumerate() {
        let source = ArtifactSource::LocalPath(cmd.clone());
        let artifact = Artifact {
            id: Artifact::compute_id(ArtifactKind::Hook, &format!("hook-{i}-{cmd}"), &source),
            kind: ArtifactKind::Hook,
            name: cmd.clone(),
            version: None,
            publisher: PublisherIdentity::default(),
            source,
            content_hash: None,
            capabilities: vec![
                CapabilityFinding {
                    capability: Capability::Hook,
                    basis: EvidenceBasis::Declared,
                    evidence: "registered in Claude Code's hooks config".to_string(),
                    location: Some(path.display().to_string()),
                },
                CapabilityFinding {
                    capability: Capability::ExecuteShell,
                    basis: EvidenceBasis::Declared,
                    evidence: "hooks run a shell command on agent lifecycle events".to_string(),
                    location: Some(path.display().to_string()),
                },
            ],
            discovered_by: discovered_by_set(),
        };
        out.push(DiscoveredArtifact {
            artifact,
            scan_root: None,
            display_location: cmd,
            // Hooks are technically rewritable the same way MCP servers
            // are (single fixed command), but config-rewrite support for
            // them is out of v0 scope — see BUILD_PLAN.md's scope notes.
            // Caching a decision for a hook (via `agentguard init`) still
            // works; nothing currently enforces it.
            launch: None,
            config_source: None,
        });
    }

    out
}

fn collect_command_strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(s)) = map.get("command") {
                out.push(s.clone());
            }
            for v in map.values() {
                collect_command_strings(v, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_command_strings(item, out);
            }
        }
        _ => {}
    }
}

/// Every subdirectory of `dir` containing a `SKILL.md` is treated as a
/// skill artifact. Its capabilities aren't populated here — the CLI hands
/// `scan_root` to agentguard-scanner for that.
fn discover_skills(dir: &Path) -> Vec<DiscoveredArtifact> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() && path.join("SKILL.md").exists() {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("skill")
                .to_string();
            let source = ArtifactSource::LocalPath(path.display().to_string());
            let artifact = Artifact {
                id: Artifact::compute_id(ArtifactKind::Skill, &name, &source),
                kind: ArtifactKind::Skill,
                name: name.clone(),
                version: None,
                publisher: PublisherIdentity::default(),
                source,
                content_hash: None,
                capabilities: vec![],
                discovered_by: discovered_by_set(),
            };
            out.push(DiscoveredArtifact {
                display_location: path.display().to_string(),
                scan_root: Some(path),
                artifact,
                launch: None,
                config_source: None,
            });
        }
    }
    out
}
