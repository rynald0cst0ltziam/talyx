//! Claude Code adapter — the only Tier-1 adapter with full enforcement
//! planned (BUILD_PLAN.md §0, §5b: `PreToolUse` hooks are a real
//! interception point). This module only does discovery for now; the
//! enforcement shim (§5a) and hook integration (§5b) are separate,
//! not-yet-built pieces that will consume what this adapter finds.
//!
//! Config file locations below are the documented/common ones as of this
//! writing. Claude Code's config layout has changed before and will change
//! again — treat `detect`/`discover` returning nothing as "check these
//! paths are still current," not as "no agent present," and keep this file
//! as the single place those paths live so a version bump is a local edit,
//! not a hunt through the codebase (this is the adapter-maintenance
//! treadmill called out in BUILD_PLAN.md's audit notes).

use crate::{AgentAdapter, DiscoveredArtifact};
use agentguard_core::{
    Artifact, ArtifactKind, ArtifactSource, Capability, CapabilityFinding, EvidenceBasis,
    PublisherIdentity,
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

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

        // MCP servers — project scope (.mcp.json) and user scope (~/.claude.json).
        out.extend(parse_mcp_servers(&project_root.join(".mcp.json")));
        if let Some(h) = &home {
            out.extend(parse_mcp_servers(&h.join(".claude.json")));
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

/// Parse a Claude Code-style `{ "mcpServers": { name: { command, args, env } } }`
/// config file. Used for both `.mcp.json` (project scope) and `.claude.json`
/// (user scope) — both use this same shape as of this writing.
fn parse_mcp_servers(path: &Path) -> Vec<DiscoveredArtifact> {
    let mut out = Vec::new();
    let Ok(text) = fs::read_to_string(path) else {
        return out;
    };
    let Ok(json) = serde_json::from_str::<Value>(&text) else {
        return out;
    };
    let Some(servers) = json.get("mcpServers").and_then(|v| v.as_object()) else {
        return out;
    };

    for (name, cfg) in servers {
        let command = cfg.get("command").and_then(|c| c.as_str()).unwrap_or("");
        let args: Vec<String> = cfg
            .get("args")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let has_env = cfg
            .get("env")
            .and_then(|e| e.as_object())
            .map(|o| !o.is_empty())
            .unwrap_or(false);

        let (source, scan_root, display_location) = classify_command(command, &args);

        let mut capabilities = vec![CapabilityFinding {
            capability: Capability::SpawnProcess,
            basis: EvidenceBasis::Declared,
            evidence: "launched as a subprocess by Claude Code's MCP config".to_string(),
            location: Some(path.display().to_string()),
        }];
        if has_env {
            capabilities.push(CapabilityFinding {
                capability: Capability::EnvironmentVariables,
                basis: EvidenceBasis::Declared,
                evidence: "MCP config supplies environment variables to this server".to_string(),
                location: Some(path.display().to_string()),
            });
        }

        let artifact = Artifact {
            id: Artifact::compute_id(ArtifactKind::McpServer, name, &source),
            kind: ArtifactKind::McpServer,
            name: name.clone(),
            version: None,
            publisher: guess_publisher(&source),
            source,
            content_hash: None,
            capabilities,
            discovered_by: discovered_by_set(),
        };

        out.push(DiscoveredArtifact {
            artifact,
            scan_root,
            display_location,
        });
    }

    out
}

/// Best-effort classification of an MCP server's launch command into a
/// source we can reason about. Deliberately conservative: anything we can't
/// confidently classify falls through to a bare LocalPath with no scan_root
/// rather than guessing — an artifact with thin evidence lands with fewer
/// findings, which is a weaker signal, not a wrong one.
fn classify_command(command: &str, args: &[String]) -> (ArtifactSource, Option<PathBuf>, String) {
    let runner = Path::new(command)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(command)
        .to_lowercase();

    if matches!(runner.as_str(), "npx" | "npm" | "pnpm" | "yarn" | "bunx") {
        if let Some(pkg) = args.iter().find(|a| !a.starts_with('-')) {
            let source = ArtifactSource::Registry {
                name: pkg.clone(),
                registry: "npm".to_string(),
            };
            return (source, None, format!("npm:{pkg} (via {command})"));
        }
    }
    if matches!(runner.as_str(), "uvx" | "pipx" | "pip" | "uv") {
        if let Some(pkg) = args.iter().find(|a| !a.starts_with('-')) {
            let source = ArtifactSource::Registry {
                name: pkg.clone(),
                registry: "pypi".to_string(),
            };
            return (source, None, format!("pypi:{pkg} (via {command})"));
        }
    }

    // Looks like a local script/binary path rather than a package runner.
    let looks_like_path = command.contains('/') || command.contains('\\');
    if looks_like_path {
        let path = PathBuf::from(command);
        let scan_root = if path.is_file() {
            Some(path.clone())
        } else if path.is_dir() {
            Some(path.clone())
        } else {
            None
        };
        return (
            ArtifactSource::LocalPath(command.to_string()),
            scan_root,
            command.to_string(),
        );
    }

    // Bare command name (e.g. a globally-installed binary) — treat as an
    // executable we can identify but not statically scan.
    (
        ArtifactSource::LocalPath(command.to_string()),
        None,
        command.to_string(),
    )
}

fn guess_publisher(source: &ArtifactSource) -> PublisherIdentity {
    match source {
        ArtifactSource::Registry { name, .. } => {
            // Scoped npm packages (@org/pkg) name the org explicitly; use
            // that as the publisher guess. Never set `verified` here —
            // verification is an explicit step (BUILD_PLAN.md §7), not an
            // inference from a package name.
            let guessed = if let Some(stripped) = name.strip_prefix('@') {
                stripped.split('/').next().unwrap_or(name).to_string()
            } else {
                name.clone()
            };
            PublisherIdentity {
                name: Some(guessed),
                repo_url: None,
                verified: false,
            }
        }
        ArtifactSource::GitUrl(url) => PublisherIdentity {
            name: Some(url.clone()),
            repo_url: Some(url.clone()),
            verified: false,
        },
        ArtifactSource::LocalPath(_) => PublisherIdentity::default(),
    }
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
            });
        }
    }
    out
}
